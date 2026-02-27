#!/usr/bin/env python3
"""
Synthetic Firmware Generator — Build Orchestrator

Reads compiled .o files from the oracle output, extracts raw machine code,
and synthesizes realistic firmware images with section-level ground truth
labels for ISA detection ML training.
"""

import argparse
import hashlib
import json
import logging
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import asdict
from pathlib import Path
from random import Random
from typing import Any

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from oracle.firmware.config import (
    ISA_FAMILIES,
    FirmwareGenConfig,
    get_firmware_triples,
)
from oracle.firmware.extractor import BlobExtractor, BlobIndex
from oracle.firmware.headers import (
    generate_header,
    generate_trailer,
)
from oracle.firmware.layout import (
    ImageLayout,
    LayoutEngine,
    SectionSpec,
    SectionType,
)

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# String pool for string table sections
# ---------------------------------------------------------------------------

_STRING_POOL = [
    b"Copyright (c) 2024 Firmware Corp. All rights reserved.\x00",
    b"Build: release-v3.2.1-ga7f3c2d\x00",
    b"ERROR: initialization failed\x00",
    b"WARNING: low memory condition\x00",
    b"firmware.bin\x00",
    b"bootloader\x00",
    b"kernel\x00",
    b"rootfs\x00",
    b"/dev/mtdblock0\x00",
    b"/dev/ttyS0\x00",
    b"eth0\x00",
    b"wlan0\x00",
    b"DHCP client started\x00",
    b"Hardware revision: %d.%d\x00",
    b"Serial: %08X%08X\x00",
    b"Linux version 4.14.180\x00",
    b"U-Boot 2019.07\x00",
    b"Starting kernel ...\x00",
    b"Booting from flash...\x00",
    b"Image verified OK\x00",
    b"CRC check passed\x00",
    b"Decompressing...\x00",
    b"Init complete.\x00",
    b"GPIO initialized\x00",
    b"SPI flash detected: W25Q128\x00",
    b"DDR3 SDRAM: 128 MB\x00",
    b"CPU: ARMv7 Processor rev 4 (v7l)\x00",
    b"Machine: Generic DT based system\x00",
]

# Filesystem magic signatures
_FS_MAGICS = {
    "squashfs": b"hsqs",  # little-endian SquashFS
    "jffs2": b"\x85\x19",  # JFFS2 magic
    "cramfs": b"E=\xcd\x28",  # CramFS magic
    "romfs": b"-rom1fs-",
}


# ---------------------------------------------------------------------------
# Worker function (runs in child process)
# ---------------------------------------------------------------------------


def generate_single_image(task: dict[str, Any]) -> dict[str, Any]:
    """
    Assemble a single firmware image from its layout specification.

    Takes and returns dicts for pickle compatibility.
    """
    from oracle.firmware.config import ISA_FAMILIES
    from oracle.firmware.headers import generate_header, generate_trailer
    from oracle.firmware.layout import SectionType

    start_time = time.time()

    layout = task["layout"]
    objects_dir = Path(task["objects_dir"])
    firmware_dir = Path(task["firmware_dir"])
    seed = layout["seed"]
    rng = Random(seed)

    image_id = layout["image_id"]
    total_size = layout["total_size"]
    primary_isa = layout["primary_isa"]
    header_type = layout["header_type"]
    trailer_type = layout["trailer_type"]
    all_families = layout["all_isa_families"]
    isa_label = layout.get("isa_label", "+".join(sorted(all_families)))

    # Pre-fill with 0xFF (NOR flash erased state)
    image = bytearray(b"\xFF" * total_size)

    # Track actual section info for metadata
    actual_sections = []

    for section in layout["sections"]:
        sec_type = section["section_type"]
        offset = section["offset"]
        size = section["size"]
        fill_params = section.get("fill_params", {})

        if sec_type == "header":
            # Generate header
            family_info = ISA_FAMILIES.get(primary_isa)
            endianness = family_info.endianness if family_info else "little"
            base_addr = family_info.typical_base_addr if family_info else 0

            result = generate_header(
                header_type,
                endianness,
                rng,
                total_size=total_size,
                base_addr=base_addr,
                family_name=primary_isa,
            )
            header_data = result.data
            # Write header (may differ from estimated size)
            actual_size = min(len(header_data), size)
            image[offset:offset + actual_size] = header_data[:actual_size]

            actual_sections.append({
                "offset": offset,
                "size": actual_size,
                "type": "header",
                "isa_family": None,
                "details": result.metadata,
            })

        elif sec_type == "code":
            isa_family = section.get("isa_family")
            blob_triple = fill_params.get("blob_triple", "")
            blob_program = fill_params.get("blob_program", "")
            blob_config = fill_params.get("blob_config", "")

            # Find and read the blob
            blob_path = (
                objects_dir / isa_family / blob_triple / blob_config
                / f"{blob_program}.bin"
            )

            code_data = b""
            source_triple = blob_triple
            source_program = blob_program
            source_config = blob_config

            if blob_path.exists():
                code_data = blob_path.read_bytes()
            else:
                # Fallback: find any blob from this family
                family_dir = objects_dir / isa_family
                if family_dir.exists():
                    for bin_file in family_dir.rglob("*.bin"):
                        try:
                            code_data = bin_file.read_bytes()
                            rel = bin_file.relative_to(family_dir)
                            parts = rel.parts
                            if len(parts) >= 3:
                                source_triple = parts[0]
                                source_config = parts[1]
                                source_program = rel.stem
                        except (OSError, ValueError):
                            continue
                        if code_data:
                            break

            if code_data:
                # Fill section, repeating blob if needed
                written = 0
                while written < size:
                    chunk = code_data[:size - written]
                    image[offset + written:offset + written + len(chunk)] = chunk
                    written += len(chunk)

            actual_sections.append({
                "offset": offset,
                "size": size,
                "type": "code",
                "isa_family": isa_family,
                "source_triple": source_triple,
                "source_program": source_program,
                "source_config": source_config,
            })

        elif sec_type == "padding":
            fill_byte = fill_params.get("fill_byte", 0xFF)
            image[offset:offset + size] = bytes([fill_byte]) * size
            actual_sections.append({
                "offset": offset,
                "size": size,
                "type": "padding",
                "isa_family": None,
                "details": {"pattern": fill_params.get("pattern", "0xFF")},
            })

        elif sec_type == "string_table":
            # Fill with strings from pool
            buf = bytearray()
            while len(buf) < size:
                s = rng.choice(_STRING_POOL)
                buf.extend(s)
            image[offset:offset + size] = buf[:size]
            actual_sections.append({
                "offset": offset,
                "size": size,
                "type": "string_table",
                "isa_family": None,
                "details": {"source": "generated"},
            })

        elif sec_type == "filesystem":
            # Write FS magic then random data
            fs_type = fill_params.get("fs_type", "squashfs")
            magic = _FS_MAGICS.get(fs_type, b"\x00" * 4)
            image[offset:offset + len(magic)] = magic
            rand_data = rng.randbytes(size - len(magic))
            image[offset + len(magic):offset + size] = rand_data
            actual_sections.append({
                "offset": offset,
                "size": size,
                "type": "filesystem",
                "isa_family": None,
                "details": {"fs_type": fs_type},
            })

        elif sec_type == "random":
            rand_data = rng.randbytes(size)
            image[offset:offset + size] = rand_data
            actual_sections.append({
                "offset": offset,
                "size": size,
                "type": "random",
                "isa_family": None,
                "details": {"source": "random"},
            })

        elif sec_type == "rodata":
            # Mix of strings and structured data
            buf = bytearray()
            while len(buf) < size:
                if rng.random() < 0.5:
                    buf.extend(rng.choice(_STRING_POOL))
                else:
                    # Some "structured" data: repeated 4-byte values
                    val = rng.randint(0, 0xFFFFFFFF)
                    for _ in range(rng.randint(4, 32)):
                        buf.extend(val.to_bytes(4, "little"))
            image[offset:offset + size] = buf[:size]
            actual_sections.append({
                "offset": offset,
                "size": size,
                "type": "rodata",
                "isa_family": None,
                "details": {"source": "generated"},
            })

        elif sec_type == "trailer":
            # Will be computed after all other sections
            pass

    # Compute and write trailer
    if trailer_type != "none":
        # Trailer covers everything before the trailer
        trailer_offset = total_size - _get_trailer_size(trailer_type)
        pre_trailer = bytes(image[:trailer_offset])
        trailer_result = generate_trailer(trailer_type, pre_trailer)
        trailer_data = trailer_result.data
        image[trailer_offset:trailer_offset + len(trailer_data)] = trailer_data

        actual_sections.append({
            "offset": trailer_offset,
            "size": len(trailer_data),
            "type": "trailer",
            "isa_family": None,
            "details": trailer_result.metadata,
        })

    # Finalize image bytes
    image_bytes = bytes(image)

    # Compute hashes
    sha256 = hashlib.sha256(image_bytes).hexdigest()
    md5 = hashlib.md5(image_bytes).hexdigest()

    # Write files into ISA subdirectory
    sub_dir = firmware_dir / isa_label
    sub_dir.mkdir(parents=True, exist_ok=True)
    bin_path = sub_dir / f"{image_id}.bin"
    json_path = sub_dir / f"{image_id}.json"

    bin_path.write_bytes(image_bytes)

    # Compute code stats
    code_sections = [s for s in actual_sections if s["type"] == "code"]
    code_bytes = sum(s["size"] for s in code_sections)

    metadata = {
        "image": {
            "id": image_id,
            "path": f"{isa_label}/{bin_path.name}",
            "size_bytes": total_size,
            "sha256": sha256,
            "md5": md5,
        },
        "isa": {
            "primary": primary_isa,
            "all": all_families,
            "is_multi_isa": len(all_families) > 1,
        },
        "structure": {
            "header_type": header_type,
            "trailer_type": trailer_type,
            "num_sections": len(actual_sections),
            "num_code_sections": len(code_sections),
            "code_bytes": code_bytes,
            "code_fraction": round(code_bytes / total_size, 3) if total_size > 0 else 0,
        },
        "sections": actual_sections,
        "generation": {
            "seed": seed,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        },
    }

    with open(json_path, "w") as f:
        json.dump(metadata, f, indent=2)

    duration_ms = int((time.time() - start_time) * 1000)

    return {
        "image_id": image_id,
        "success": True,
        "size_bytes": total_size,
        "primary_isa": primary_isa,
        "isa_label": isa_label,
        "is_multi_isa": len(all_families) > 1,
        "num_sections": len(actual_sections),
        "code_bytes": code_bytes,
        "duration_ms": duration_ms,
    }


def _get_trailer_size(trailer_type: str) -> int:
    sizes = {"crc32": 4, "md5": 16, "sha256": 32, "none": 0}
    return sizes.get(trailer_type, 0)


# ---------------------------------------------------------------------------
# Layout → task dict conversion
# ---------------------------------------------------------------------------


def _layout_to_dict(layout: ImageLayout) -> dict[str, Any]:
    """Convert ImageLayout to a pickle-safe dict."""
    sections = []
    for s in layout.sections:
        sections.append({
            "offset": s.offset,
            "size": s.size,
            "section_type": s.section_type.value,
            "alignment": s.alignment,
            "isa_family": s.isa_family,
            "fill_params": s.fill_params,
        })

    return {
        "image_id": layout.image_id,
        "total_size": layout.total_size,
        "primary_isa": layout.primary_isa,
        "header_type": layout.header_type,
        "trailer_type": layout.trailer_type,
        "sections": sections,
        "all_isa_families": layout.all_isa_families,
        "isa_label": layout.isa_label,
        "seed": layout.seed,
    }


# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------


class FirmwareManifestBuilder:
    """Collects generation results and writes manifest files."""

    def __init__(self) -> None:
        self.results: list[dict[str, Any]] = []
        self.errors: list[dict[str, Any]] = []

    def add_result(self, result: dict[str, Any]) -> None:
        if result.get("success"):
            self.results.append(result)
        else:
            self.errors.append(result)

    def save(self, firmware_dir: Path, config: FirmwareGenConfig) -> None:
        """Write manifest.json and images.jsonl."""
        # Summary stats
        total = len(self.results) + len(self.errors)
        multi_isa_count = sum(1 for r in self.results if r.get("is_multi_isa"))
        total_bytes = sum(r.get("size_bytes", 0) for r in self.results)
        total_code = sum(r.get("code_bytes", 0) for r in self.results)

        # ISA distribution (by primary ISA)
        isa_counts: dict[str, int] = {}
        for r in self.results:
            isa = r.get("primary_isa", "unknown")
            isa_counts[isa] = isa_counts.get(isa, 0) + 1

        # Per-directory counts (by isa_label)
        dir_counts: dict[str, int] = {}
        for r in self.results:
            label = r.get("isa_label", "unknown")
            dir_counts[label] = dir_counts.get(label, 0) + 1

        manifest = {
            "generator": "oracle.firmware.build_firmware",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "config": {
                "seed": config.seed,
                "num_images": config.num_images,
                "min_size": config.min_size,
                "max_size": config.max_size,
                "multi_isa_probability": config.multi_isa_probability,
            },
            "summary": {
                "total_generated": len(self.results),
                "total_failed": len(self.errors),
                "total_bytes": total_bytes,
                "total_code_bytes": total_code,
                "avg_code_fraction": round(total_code / total_bytes, 3) if total_bytes else 0,
                "multi_isa_count": multi_isa_count,
                "multi_isa_fraction": round(multi_isa_count / len(self.results), 3) if self.results else 0,
                "isa_distribution": dict(sorted(isa_counts.items())),
                "directory_counts": dict(sorted(dir_counts.items())),
            },
        }

        manifest_path = firmware_dir / "manifest.json"
        with open(manifest_path, "w") as f:
            json.dump(manifest, f, indent=2)

        # Write JSONL for easy streaming
        jsonl_path = firmware_dir / "images.jsonl"
        with open(jsonl_path, "w") as f:
            for r in self.results:
                f.write(json.dumps(r) + "\n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Synthetic Firmware Generator — synthesize firmware images with ground truth labels"
    )
    parser.add_argument(
        "--oracle-output",
        type=Path,
        default=Path(__file__).parent.parent.parent / "output",
        help="Source of ELF .o files (default: ../output)",
    )
    parser.add_argument(
        "--objects-dir",
        type=Path,
        default=Path(__file__).parent.parent.parent / "objects",
        help="Extraction cache directory (default: ../objects)",
    )
    parser.add_argument(
        "--firmware-dir",
        type=Path,
        default=Path(__file__).parent.parent.parent / "firmware",
        help="Output directory for firmware images (default: ../firmware)",
    )
    parser.add_argument(
        "--num-images", "-n",
        type=int,
        default=1000,
        help="Number of firmware images to generate",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Master seed for deterministic generation",
    )
    parser.add_argument(
        "--min-size",
        type=int,
        default=4096,
        help="Minimum firmware image size in bytes",
    )
    parser.add_argument(
        "--max-size",
        type=int,
        default=16 * 1024 * 1024,
        help="Maximum firmware image size in bytes",
    )
    parser.add_argument(
        "--multi-isa-probability",
        type=float,
        default=0.15,
        help="Probability of generating multi-ISA images",
    )
    parser.add_argument(
        "--families",
        nargs="+",
        default=None,
        help="Limit to specific ISA families",
    )
    parser.add_argument(
        "--images-per-combo",
        type=int,
        default=20,
        help="Minimum number of images per ISA combination/directory (default: 20)",
    )
    parser.add_argument(
        "--jobs", "-j",
        type=int,
        default=8,
        help="Number of parallel generation jobs",
    )
    parser.add_argument(
        "--extract-only",
        action="store_true",
        help="Only extract blobs, don't generate firmware",
    )
    parser.add_argument(
        "--skip-extraction",
        action="store_true",
        help="Skip extraction, use existing objects cache",
    )
    parser.add_argument(
        "--force-extract",
        action="store_true",
        help="Force re-extraction even if cache exists",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Generate layouts but don't write firmware images",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output",
    )

    args = parser.parse_args()

    # Setup logging
    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-5s %(message)s",
        datefmt="%H:%M:%S",
    )

    config = FirmwareGenConfig(
        seed=args.seed,
        num_images=args.num_images,
        min_size=args.min_size,
        max_size=args.max_size,
        multi_isa_probability=args.multi_isa_probability,
        parallel_jobs=args.jobs,
        oracle_output_dir=args.oracle_output,
        objects_dir=args.objects_dir,
        firmware_dir=args.firmware_dir,
        families=args.families,
        min_images_per_combo=args.images_per_combo,
        force_extract=args.force_extract,
        verbose=args.verbose,
    )

    # -----------------------------------------------------------------------
    # Phase 1: Extract
    # -----------------------------------------------------------------------
    if not args.skip_extraction:
        log.info("Phase 1: Extracting binary blobs from %s", args.oracle_output)
        extractor = BlobExtractor()
        total, success, cached = extractor.extract_all(
            oracle_output_dir=args.oracle_output,
            objects_dir=args.objects_dir,
            jobs=args.jobs,
            force=args.force_extract,
            verbose=args.verbose,
        )
        log.info(
            "Extraction complete: %d total, %d success (%d cached), %d failed",
            total, success, cached, total - success,
        )
        if args.extract_only:
            return
    else:
        log.info("Phase 1: Skipping extraction (using existing cache)")

    # -----------------------------------------------------------------------
    # Phase 2: Index
    # -----------------------------------------------------------------------
    log.info("Phase 2: Indexing blob cache at %s", args.objects_dir)
    blob_index = BlobIndex(args.objects_dir)

    summary = blob_index.summary()
    if not summary:
        log.error("No blobs found! Run extraction first.")
        sys.exit(1)

    log.info("Blob index: %d families, %d total blobs",
             len(summary), sum(summary.values()))
    for family, count in sorted(summary.items()):
        log.info("  %-15s %5d blobs", family, count)

    # Filter families if requested
    if config.families:
        available = set(blob_index.families())
        requested = set(config.families)
        missing = requested - available
        if missing:
            log.warning("Requested families not available: %s", missing)

    # -----------------------------------------------------------------------
    # Phase 3: Layout
    # -----------------------------------------------------------------------
    log.info("Phase 3: Generating %d image layouts (seed=%d)", config.num_images, config.seed)
    engine = LayoutEngine(blob_index, config)
    layouts = engine.generate_batch(config.num_images, config.seed)

    # Report layout statistics
    multi_count = sum(1 for l in layouts if l.is_multi_isa)
    total_code = sum(l.code_bytes for l in layouts)
    total_size = sum(l.total_size for l in layouts)
    log.info(
        "Layouts: %d images, %d multi-ISA (%.1f%%), %.1f MiB total, %.1f%% code",
        len(layouts),
        multi_count,
        100 * multi_count / len(layouts) if layouts else 0,
        total_size / (1024 * 1024),
        100 * total_code / total_size if total_size else 0,
    )

    if args.dry_run:
        log.info("=== DRY RUN — not writing firmware images ===")

        # Per-family quotas / directory distribution
        dir_counts: dict[str, int] = {}
        for layout in layouts:
            dir_counts[layout.isa_label] = dir_counts.get(layout.isa_label, 0) + 1
        log.info("Directory distribution (%d directories):", len(dir_counts))
        for label, cnt in sorted(dir_counts.items()):
            log.info("  %-30s %4d images", label + "/", cnt)

        # Print a few sample layouts
        log.info("Sample layouts:")
        for layout in layouts[:5]:
            log.info(
                "  %s: %d bytes, %s (%s), %d sections, %d code, header=%s trailer=%s",
                layout.image_id,
                layout.total_size,
                layout.primary_isa,
                layout.isa_label,
                len(layout.sections),
                len(layout.code_sections),
                layout.header_type,
                layout.trailer_type,
            )
        if len(layouts) > 5:
            log.info("  ... and %d more", len(layouts) - 5)
        return

    # -----------------------------------------------------------------------
    # Phase 4: Generate
    # -----------------------------------------------------------------------
    log.info("Phase 4: Generating firmware images with %d workers", config.parallel_jobs)
    args.firmware_dir.mkdir(parents=True, exist_ok=True)

    # Prepare tasks
    tasks = []
    for layout in layouts:
        tasks.append({
            "layout": _layout_to_dict(layout),
            "objects_dir": str(args.objects_dir),
            "firmware_dir": str(args.firmware_dir),
        })

    manifest_builder = FirmwareManifestBuilder()
    start_time = time.time()
    completed = 0

    with ProcessPoolExecutor(max_workers=config.parallel_jobs) as executor:
        futures = {
            executor.submit(generate_single_image, t): t
            for t in tasks
        }

        for future in as_completed(futures):
            completed += 1
            try:
                result = future.result()
                manifest_builder.add_result(result)

                if args.verbose and result.get("success"):
                    log.debug(
                        "Generated %s: %d bytes, %s, %d sections, %dms",
                        result["image_id"],
                        result["size_bytes"],
                        result["primary_isa"],
                        result["num_sections"],
                        result["duration_ms"],
                    )
            except Exception as e:
                manifest_builder.add_result({
                    "success": False,
                    "error": str(e),
                })
                log.warning("Worker error: %s", e)

            # Progress
            if completed % 50 == 0 or completed == len(tasks):
                elapsed = time.time() - start_time
                rate = completed / elapsed if elapsed > 0 else 0
                eta = (len(tasks) - completed) / rate if rate > 0 else 0
                log.info(
                    "Progress: %d/%d (%.0f%%) | %.1f img/s | ETA: %.0fs",
                    completed, len(tasks),
                    100 * completed / len(tasks),
                    rate, eta,
                )

    # Save manifest
    log.info("Saving manifest...")
    manifest_builder.save(args.firmware_dir, config)

    # Final summary
    elapsed = time.time() - start_time
    n_ok = len(manifest_builder.results)
    n_err = len(manifest_builder.errors)
    total_bytes = sum(r.get("size_bytes", 0) for r in manifest_builder.results)

    log.info("=== Generation Complete ===")
    log.info("Time: %.1fs", elapsed)
    log.info("Images: %d generated, %d failed", n_ok, n_err)
    log.info("Total size: %.1f MiB", total_bytes / (1024 * 1024))
    log.info("Output: %s", args.firmware_dir)
    log.info("Manifest: %s", args.firmware_dir / "manifest.json")


if __name__ == "__main__":
    main()
