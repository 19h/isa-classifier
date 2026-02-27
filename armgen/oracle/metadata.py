"""Metadata generation for compiled binaries."""

import hashlib
import json
import os
import subprocess
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import ProgramConfig, TargetConfig, CompilationConfig


@dataclass
class BinaryMetadata:
    """Metadata for a single compiled binary."""
    # Binary info
    path: str
    size_bytes: int
    format: str

    # Source info
    program_name: str
    program_language: str
    program_category: str
    source_file: str

    # Target info
    target_triple: str
    target_arch: str
    target_endianness: str
    target_pointer_width: int

    # Compilation info
    optimization: str
    debug: str
    lto: str
    pic: str
    stack_protection: str
    cpu: str
    compiler_command: str

    # Hashes
    sha256: str
    md5: str

    # Timestamps
    build_timestamp: str

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "binary": {
                "path": self.path,
                "size_bytes": self.size_bytes,
                "format": self.format,
            },
            "source": {
                "program": self.program_name,
                "language": self.program_language,
                "category": self.program_category,
                "file": self.source_file,
            },
            "target": {
                "triple": self.target_triple,
                "arch": self.target_arch,
                "endianness": self.target_endianness,
                "pointer_width": self.target_pointer_width,
            },
            "compilation": {
                "optimization": self.optimization,
                "debug": self.debug,
                "lto": self.lto,
                "pic": self.pic,
                "stack_protection": self.stack_protection,
                "cpu": self.cpu,
                "command": self.compiler_command,
            },
            "hashes": {
                "sha256": self.sha256,
                "md5": self.md5,
            },
            "build_timestamp": self.build_timestamp,
        }


def compute_hashes(file_path: Path) -> tuple[str, str]:
    """Compute SHA256 and MD5 hashes of a file."""
    sha256_hash = hashlib.sha256()
    md5_hash = hashlib.md5()

    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256_hash.update(chunk)
            md5_hash.update(chunk)

    return sha256_hash.hexdigest(), md5_hash.hexdigest()


def detect_binary_format(file_path: Path) -> str:
    """Detect the binary format using file command."""
    try:
        result = subprocess.run(
            ["file", "-b", str(file_path)],
            capture_output=True,
            text=True,
            timeout=5,
        )
        output = result.stdout.strip()

        # Parse common formats
        if "ELF 64-bit" in output:
            if "x86-64" in output:
                return "elf64-x86-64"
            elif "ARM aarch64" in output:
                return "elf64-aarch64"
            elif "RISC-V" in output:
                return "elf64-riscv"
            elif "PowerPC" in output or "ppc64" in output:
                return "elf64-ppc64"
            elif "S/390" in output:
                return "elf64-s390"
            elif "MIPS" in output:
                return "elf64-mips"
            elif "SPARC" in output:
                return "elf64-sparc"
            return "elf64"
        elif "ELF 32-bit" in output:
            if "Intel 80386" in output:
                return "elf32-i386"
            elif "ARM" in output:
                return "elf32-arm"
            elif "RISC-V" in output:
                return "elf32-riscv"
            elif "MIPS" in output:
                return "elf32-mips"
            elif "PowerPC" in output:
                return "elf32-ppc"
            elif "SPARC" in output:
                return "elf32-sparc"
            return "elf32"
        elif "Mach-O 64-bit" in output:
            if "x86_64" in output:
                return "macho64-x86-64"
            elif "arm64" in output:
                return "macho64-arm64"
            return "macho64"
        elif "Mach-O" in output:
            return "macho32"
        elif "WebAssembly" in output or "wasm" in output.lower():
            return "wasm"
        elif "BPF" in output:
            return "bpf"
        elif "LLVM IR" in output:
            return "llvm-ir"
        elif "CUDA" in output or "PTX" in output:
            return "ptx"
        elif "data" in output.lower():
            return "raw"
        else:
            return output[:50]  # Return truncated file output
    except Exception:
        return "unknown"


def generate_metadata(
    binary_path: Path,
    program: ProgramConfig,
    target: TargetConfig,
    config: CompilationConfig,
    compiler_command: list[str],
) -> BinaryMetadata:
    """Generate metadata for a compiled binary."""
    sha256, md5 = compute_hashes(binary_path)
    binary_format = detect_binary_format(binary_path)

    return BinaryMetadata(
        path=str(binary_path),
        size_bytes=binary_path.stat().st_size,
        format=binary_format,
        program_name=program.name,
        program_language=program.language,
        program_category=program.category,
        source_file=str(program.source),
        target_triple=target.triple,
        target_arch=target.arch,
        target_endianness=target.endianness,
        target_pointer_width=target.pointer_width,
        optimization=config.optimization,
        debug=config.debug,
        lto=config.lto,
        pic=config.pic,
        stack_protection=config.stack_protection,
        cpu=config.cpu,
        compiler_command=" ".join(compiler_command),
        sha256=sha256,
        md5=md5,
        build_timestamp=datetime.now(timezone.utc).isoformat(),
    )


def save_metadata(metadata: BinaryMetadata, output_path: Path) -> None:
    """Save metadata to JSON file."""
    json_path = output_path.with_suffix(".json")
    with open(json_path, "w") as f:
        json.dump(metadata.to_dict(), f, indent=2)


@dataclass
class ManifestEntry:
    """Entry in the master manifest."""
    path: str
    program: str
    target: str
    config_id: str
    size_bytes: int
    sha256: str


class ManifestBuilder:
    """Builds the master manifest file."""

    def __init__(self):
        self.entries: list[ManifestEntry] = []
        self.targets: set[str] = set()
        self.programs: set[str] = set()
        self.configs: set[str] = set()
        self.total_size: int = 0
        self.success_count: int = 0
        self.failure_count: int = 0
        self.skip_count: int = 0

    def add_success(self, metadata: BinaryMetadata, config_id: str) -> None:
        """Add a successful build to the manifest."""
        self.entries.append(ManifestEntry(
            path=metadata.path,
            program=metadata.program_name,
            target=metadata.target_triple,
            config_id=config_id,
            size_bytes=metadata.size_bytes,
            sha256=metadata.sha256,
        ))
        self.targets.add(metadata.target_triple)
        self.programs.add(metadata.program_name)
        self.configs.add(config_id)
        self.total_size += metadata.size_bytes
        self.success_count += 1

    def add_failure(self) -> None:
        """Record a failed build."""
        self.failure_count += 1

    def add_skip(self) -> None:
        """Record a skipped build."""
        self.skip_count += 1

    def save(self, output_dir: Path, compiler_version: str) -> None:
        """Save the manifest to disk."""
        manifest = {
            "oracle": {
                "name": "binary-sample-oracle",
                "version": "1.0.0",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "compiler": compiler_version,
            },
            "summary": {
                "total_binaries": len(self.entries),
                "total_size_bytes": self.total_size,
                "targets": len(self.targets),
                "programs": len(self.programs),
                "configurations": len(self.configs),
                "successful": self.success_count,
                "failed": self.failure_count,
                "skipped": self.skip_count,
            },
            "targets": sorted(self.targets),
            "programs": sorted(self.programs),
            "configurations": sorted(self.configs),
            "binaries": [asdict(e) for e in self.entries],
        }

        manifest_path = output_dir / "manifest.json"
        with open(manifest_path, "w") as f:
            json.dump(manifest, f, indent=2)

        # Also save a line-delimited version for streaming
        jsonl_path = output_dir / "binaries.jsonl"
        with open(jsonl_path, "w") as f:
            for entry in self.entries:
                f.write(json.dumps(asdict(entry)) + "\n")
