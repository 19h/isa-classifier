"""ELF .o → raw binary extraction and blob indexing."""

import logging
import subprocess
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from random import Random
from typing import Any

from .config import EXCLUDED_TRIPLES, TRIPLE_TO_FAMILY

log = logging.getLogger(__name__)

LLVM_OBJCOPY = "/opt/homebrew/opt/llvm@20/bin/llvm-objcopy"


@dataclass
class ExtractionResult:
    """Result of a single blob extraction."""

    source: str
    output: str | None
    success: bool
    error: str | None = None
    size_bytes: int = 0


def _extract_single(task: dict[str, Any]) -> dict[str, Any]:
    """Extract a single .o file to raw binary. Runs in worker process."""
    elf_path = Path(task["elf_path"])
    output_path = Path(task["output_path"])

    # Skip if cache is fresh
    if (
        not task.get("force")
        and output_path.exists()
        and output_path.stat().st_mtime >= elf_path.stat().st_mtime
    ):
        size = output_path.stat().st_size
        if size > 0:
            return {
                "source": str(elf_path),
                "output": str(output_path),
                "success": True,
                "cached": True,
                "size_bytes": size,
            }

    # Ensure output directory
    output_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        result = subprocess.run(
            [
                LLVM_OBJCOPY,
                "-O", "binary",
                "--only-section=.text",
                str(elf_path),
                str(output_path),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        if result.returncode != 0:
            return {
                "source": str(elf_path),
                "output": None,
                "success": False,
                "error": result.stderr[:200],
                "size_bytes": 0,
            }

        # Check output isn't empty
        if not output_path.exists() or output_path.stat().st_size == 0:
            if output_path.exists():
                output_path.unlink()
            return {
                "source": str(elf_path),
                "output": None,
                "success": False,
                "error": "Empty .text section",
                "size_bytes": 0,
            }

        return {
            "source": str(elf_path),
            "output": str(output_path),
            "success": True,
            "cached": False,
            "size_bytes": output_path.stat().st_size,
        }

    except subprocess.TimeoutExpired:
        return {
            "source": str(elf_path),
            "output": None,
            "success": False,
            "error": "Timeout",
            "size_bytes": 0,
        }
    except Exception as e:
        return {
            "source": str(elf_path),
            "output": None,
            "success": False,
            "error": str(e)[:200],
            "size_bytes": 0,
        }


class BlobExtractor:
    """Extracts raw machine code from ELF .o files using llvm-objcopy."""

    def __init__(self, objcopy_path: str = LLVM_OBJCOPY):
        self.objcopy_path = objcopy_path

    def extract(self, elf_path: Path, output_path: Path, force: bool = False) -> ExtractionResult:
        """Extract a single .o file to raw binary."""
        result = _extract_single({
            "elf_path": str(elf_path),
            "output_path": str(output_path),
            "force": force,
        })
        return ExtractionResult(
            source=result["source"],
            output=result.get("output"),
            success=result["success"],
            error=result.get("error"),
            size_bytes=result.get("size_bytes", 0),
        )

    def extract_all(
        self,
        oracle_output_dir: Path,
        objects_dir: Path,
        jobs: int = 8,
        force: bool = False,
        verbose: bool = False,
    ) -> tuple[int, int, int]:
        """
        Batch-extract all .o files from oracle output to objects directory.

        Returns (total, success, skipped_cached) counts.
        """
        # Discover all .o files, mapped to output paths
        tasks = []
        for o_file in sorted(oracle_output_dir.rglob("*.o")):
            # Parse path: output/{triple}/{config}/{prog}.o
            rel = o_file.relative_to(oracle_output_dir)
            parts = rel.parts
            if len(parts) < 3:
                continue

            triple = parts[0]
            if triple in EXCLUDED_TRIPLES:
                continue

            family = TRIPLE_TO_FAMILY.get(triple)
            if family is None:
                continue

            # Output: objects/{family}/{triple}/{config}/{prog}.bin
            out_rel = Path(family) / rel.with_suffix(".bin")
            out_path = objects_dir / out_rel

            tasks.append({
                "elf_path": str(o_file),
                "output_path": str(out_path),
                "force": force,
            })

        if not tasks:
            log.warning("No .o files found in %s", oracle_output_dir)
            return 0, 0, 0

        total = len(tasks)
        success = 0
        cached = 0
        failed = 0

        log.info("Extracting %d objects with %d workers...", total, jobs)

        with ProcessPoolExecutor(max_workers=jobs) as executor:
            futures = {executor.submit(_extract_single, t): t for t in tasks}

            for i, future in enumerate(as_completed(futures), 1):
                result = future.result()
                if result["success"]:
                    success += 1
                    if result.get("cached"):
                        cached += 1
                    elif verbose:
                        log.info(
                            "Extracted %s (%d bytes)",
                            result["output"],
                            result["size_bytes"],
                        )
                else:
                    failed += 1
                    if verbose:
                        log.warning(
                            "Failed %s: %s",
                            result["source"],
                            result.get("error", "unknown"),
                        )

                if i % 500 == 0 or i == total:
                    log.info(
                        "Progress: %d/%d (ok=%d, cached=%d, fail=%d)",
                        i, total, success, cached, failed,
                    )

        return total, success, cached


@dataclass
class BlobInfo:
    """Info about a cached blob file."""

    path: Path
    family: str
    triple: str
    config: str
    program: str
    size_bytes: int


class BlobIndex:
    """Index of extracted binary blobs for firmware assembly."""

    def __init__(self, objects_dir: Path):
        self.objects_dir = objects_dir
        self._blobs_by_family: dict[str, list[BlobInfo]] = {}
        self._scan()

    def _scan(self) -> None:
        """Scan objects directory and index all blobs."""
        if not self.objects_dir.exists():
            log.warning("Objects directory does not exist: %s", self.objects_dir)
            return

        for bin_file in sorted(self.objects_dir.rglob("*.bin")):
            # Path: objects/{family}/{triple}/{config}/{prog}.bin
            rel = bin_file.relative_to(self.objects_dir)
            parts = rel.parts
            if len(parts) < 4:
                continue

            size = bin_file.stat().st_size
            if size == 0:
                continue

            family = parts[0]
            triple = parts[1]
            config = parts[2]
            program = rel.stem

            info = BlobInfo(
                path=bin_file,
                family=family,
                triple=triple,
                config=config,
                program=program,
                size_bytes=size,
            )

            if family not in self._blobs_by_family:
                self._blobs_by_family[family] = []
            self._blobs_by_family[family].append(info)

        total = sum(len(v) for v in self._blobs_by_family.values())
        log.info(
            "Indexed %d blobs across %d families",
            total,
            len(self._blobs_by_family),
        )

    def families(self) -> list[str]:
        """List available ISA families."""
        return sorted(self._blobs_by_family.keys())

    def blob_count(self, family: str) -> int:
        """Number of blobs for a family."""
        return len(self._blobs_by_family.get(family, []))

    def get_blobs(self, family: str) -> list[BlobInfo]:
        """Get all blobs for an ISA family."""
        return self._blobs_by_family.get(family, [])

    def get_random_blob(self, family: str, rng: Random) -> BlobInfo | None:
        """Get a random blob for an ISA family."""
        blobs = self._blobs_by_family.get(family, [])
        if not blobs:
            return None
        return rng.choice(blobs)

    def get_blob_data(self, blob: BlobInfo) -> bytes:
        """Read raw bytes from a blob file."""
        return blob.path.read_bytes()

    def summary(self) -> dict[str, int]:
        """Return family → blob count mapping."""
        return {f: len(blobs) for f, blobs in sorted(self._blobs_by_family.items())}
