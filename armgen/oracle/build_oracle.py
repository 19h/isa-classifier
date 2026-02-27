#!/usr/bin/env python3
"""
Binary Sample Oracle - Build Orchestrator

Compiles sample programs across multiple architectures and configurations
to generate training data for ML-based ISA detection.
"""

import argparse
import json
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from oracle.config import (
    get_all_targets,
    get_target_config,
    get_cpu_options,
    CompilationConfig,
)
from oracle.compiler import ClangCompiler, is_valid_combination
from oracle.matrix import (
    discover_programs,
    generate_build_matrix,
    BuildTask,
    estimate_build_count,
)
from oracle.metadata import (
    generate_metadata,
    save_metadata,
    ManifestBuilder,
)


@dataclass
class BuildResult:
    """Result of a single build attempt."""
    task_id: str
    success: bool
    output_path: str | None
    error: str | None
    duration_ms: int
    command: list[str]


def build_single_task(task_dict: dict[str, Any]) -> dict[str, Any]:
    """
    Build a single task. This function runs in a worker process.

    Takes and returns dicts to avoid pickling issues with dataclasses.
    """
    from oracle.config import ProgramConfig, TargetConfig, CompilationConfig
    from oracle.compiler import ClangCompiler
    from oracle.metadata import generate_metadata, save_metadata

    start_time = time.time()

    # Reconstruct objects from dict
    program = ProgramConfig(**task_dict["program"])
    target = TargetConfig(**task_dict["target"])
    config = CompilationConfig(**task_dict["config"])
    output_path = Path(task_dict["output_path"])

    # Ensure output directory exists
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Compile
    compiler = ClangCompiler()
    result = compiler.compile(program, target, config, output_path)

    duration_ms = int((time.time() - start_time) * 1000)

    if result.success:
        # Generate metadata
        metadata = generate_metadata(
            output_path, program, target, config, result.command
        )
        save_metadata(metadata, output_path)

        return {
            "task_id": task_dict["task_id"],
            "success": True,
            "output_path": str(output_path),
            "error": None,
            "duration_ms": duration_ms,
            "command": result.command,
            "metadata": metadata.to_dict(),
        }
    else:
        return {
            "task_id": task_dict["task_id"],
            "success": False,
            "output_path": None,
            "error": result.stderr[:500] if result.stderr else "Unknown error",
            "duration_ms": duration_ms,
            "command": result.command,
            "metadata": None,
        }


def task_to_dict(task: BuildTask) -> dict[str, Any]:
    """Convert BuildTask to a pickle-safe dictionary."""
    return {
        "task_id": task.task_id(),
        "program": {
            "name": task.program.name,
            "source": str(task.program.source),
            "language": task.program.language,
            "category": task.program.category,
            "requires_libc": task.program.requires_libc,
            "requires_threads": task.program.requires_threads,
            "requires_exceptions": task.program.requires_exceptions,
            "cpp_std": task.program.cpp_std,
            "c_std": task.program.c_std,
            "extra_flags": task.program.extra_flags,
            "skip_targets": task.program.skip_targets,
        },
        "target": {
            "triple": task.target.triple,
            "arch": task.target.arch,
            "endianness": task.target.endianness,
            "pointer_width": task.target.pointer_width,
            "supports_dynamic": task.target.supports_dynamic,
            "supports_threads": task.target.supports_threads,
            "supports_exceptions": task.target.supports_exceptions,
            "is_freestanding": task.target.is_freestanding,
            "sysroot": str(task.target.sysroot) if task.target.sysroot else None,
            "extra_flags": task.target.extra_flags,
        },
        "config": {
            "optimization": task.config.optimization,
            "debug": task.config.debug,
            "lto": task.config.lto,
            "pic": task.config.pic,
            "stack_protection": task.config.stack_protection,
            "cpu": task.config.cpu,
            "relocation_model": task.config.relocation_model,
            "code_model": task.config.code_model,
        },
        "output_path": str(task.output_path),
    }


def main():
    parser = argparse.ArgumentParser(
        description="Binary Sample Oracle - Generate cross-compiled binaries for ML training"
    )
    parser.add_argument(
        "--programs-dir",
        type=Path,
        default=Path(__file__).parent.parent / "programs",
        help="Directory containing source programs",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(__file__).parent.parent / "output",
        help="Output directory for compiled binaries",
    )
    parser.add_argument(
        "--targets",
        nargs="+",
        default=None,
        help="Target triples to compile for (default: all)",
    )
    parser.add_argument(
        "--programs",
        nargs="+",
        default=None,
        help="Program names to compile (default: all)",
    )
    parser.add_argument(
        "--optimizations",
        nargs="+",
        default=["O0", "O2", "O3", "Os"],
        help="Optimization levels",
    )
    parser.add_argument(
        "--debug-levels",
        nargs="+",
        default=["none"],
        help="Debug info levels",
    )
    parser.add_argument(
        "--lto-modes",
        nargs="+",
        default=["none"],
        help="LTO modes",
    )
    parser.add_argument(
        "--pic-modes",
        nargs="+",
        default=["none"],
        help="PIC modes",
    )
    parser.add_argument(
        "--include-cpu-variants",
        action="store_true",
        help="Include CPU-specific variants for each target",
    )
    parser.add_argument(
        "--jobs",
        "-j",
        type=int,
        default=8,
        help="Number of parallel build jobs",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be built without actually building",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Verbose output",
    )

    args = parser.parse_args()

    # Discover programs
    print(f"Discovering programs in {args.programs_dir}...")
    all_programs = discover_programs(args.programs_dir)

    if args.programs:
        programs = [p for p in all_programs if p.name in args.programs]
    else:
        programs = all_programs

    print(f"Found {len(programs)} programs")

    # Get targets
    if args.targets:
        targets = args.targets
    else:
        targets = get_all_targets()

    print(f"Targeting {len(targets)} architectures")

    # Generate build matrix
    print("Generating build matrix...")
    tasks = []
    skipped = []
    invalid = []

    for task, is_valid, reason in generate_build_matrix(
        programs=programs,
        targets=targets,
        output_dir=args.output_dir,
        optimizations=args.optimizations,
        debug_levels=args.debug_levels,
        lto_modes=args.lto_modes,
        pic_modes=args.pic_modes,
        include_cpu_variants=args.include_cpu_variants,
    ):
        if is_valid:
            tasks.append(task)
        else:
            invalid.append((task.task_id(), reason))

    print(f"Valid build tasks: {len(tasks)}")
    print(f"Invalid combinations skipped: {len(invalid)}")

    if args.dry_run:
        print("\n=== DRY RUN ===")
        print(f"\nWould build {len(tasks)} binaries:")
        for task in tasks[:20]:
            print(f"  {task.task_id()}")
        if len(tasks) > 20:
            print(f"  ... and {len(tasks) - 20} more")

        print(f"\nSkipped {len(invalid)} invalid combinations:")
        for task_id, reason in invalid[:10]:
            print(f"  {task_id}: {reason}")
        if len(invalid) > 10:
            print(f"  ... and {len(invalid) - 10} more")
        return

    # Create output directory
    args.output_dir.mkdir(parents=True, exist_ok=True)

    # Get compiler info
    compiler = ClangCompiler()
    compiler_version = compiler.get_version()
    print(f"Using compiler: {compiler_version}")

    # Initialize manifest builder
    manifest = ManifestBuilder()
    for _ in invalid:
        manifest.add_skip()

    # Build!
    print(f"\nStarting build with {args.jobs} parallel jobs...")
    start_time = time.time()

    # Convert tasks to dicts for multiprocessing
    task_dicts = [task_to_dict(task) for task in tasks]

    completed = 0
    success = 0
    failed = 0
    errors_log = []

    with ProcessPoolExecutor(max_workers=args.jobs) as executor:
        futures = {
            executor.submit(build_single_task, td): td
            for td in task_dicts
        }

        for future in as_completed(futures):
            completed += 1
            try:
                result = future.result()
                if result["success"]:
                    success += 1
                    # Reconstruct metadata for manifest
                    from oracle.metadata import BinaryMetadata
                    meta_dict = result["metadata"]
                    metadata = BinaryMetadata(
                        path=meta_dict["binary"]["path"],
                        size_bytes=meta_dict["binary"]["size_bytes"],
                        format=meta_dict["binary"]["format"],
                        program_name=meta_dict["source"]["program"],
                        program_language=meta_dict["source"]["language"],
                        program_category=meta_dict["source"]["category"],
                        source_file=meta_dict["source"]["file"],
                        target_triple=meta_dict["target"]["triple"],
                        target_arch=meta_dict["target"]["arch"],
                        target_endianness=meta_dict["target"]["endianness"],
                        target_pointer_width=meta_dict["target"]["pointer_width"],
                        optimization=meta_dict["compilation"]["optimization"],
                        debug=meta_dict["compilation"]["debug"],
                        lto=meta_dict["compilation"]["lto"],
                        pic=meta_dict["compilation"]["pic"],
                        stack_protection=meta_dict["compilation"]["stack_protection"],
                        cpu=meta_dict["compilation"]["cpu"],
                        compiler_command=meta_dict["compilation"]["command"],
                        sha256=meta_dict["hashes"]["sha256"],
                        md5=meta_dict["hashes"]["md5"],
                        build_timestamp=meta_dict["build_timestamp"],
                    )
                    manifest.add_success(metadata, result["task_id"].split("_")[-1])
                else:
                    failed += 1
                    manifest.add_failure()
                    errors_log.append({
                        "task_id": result["task_id"],
                        "error": result["error"],
                        "command": " ".join(result["command"]),
                    })
                    if args.verbose:
                        print(f"\nFailed: {result['task_id']}: {result['error'][:100]}")
            except Exception as e:
                failed += 1
                manifest.add_failure()
                if args.verbose:
                    print(f"\nException: {e}")

            # Progress update
            pct = 100 * completed // len(tasks)
            elapsed = time.time() - start_time
            rate = completed / elapsed if elapsed > 0 else 0
            eta = (len(tasks) - completed) / rate if rate > 0 else 0
            print(
                f"\rProgress: {completed}/{len(tasks)} ({pct}%) | "
                f"Success: {success} | Failed: {failed} | "
                f"Rate: {rate:.1f}/s | ETA: {eta:.0f}s",
                end="",
                flush=True,
            )

    print()  # Newline after progress

    # Save manifest
    print("Saving manifest...")
    manifest.save(args.output_dir, compiler_version)

    # Save error log
    if errors_log:
        errors_path = args.output_dir / "errors.json"
        with open(errors_path, "w") as f:
            json.dump(errors_log, f, indent=2)
        print(f"Errors saved to {errors_path}")

    # Summary
    elapsed = time.time() - start_time
    print(f"\n=== Build Complete ===")
    print(f"Total time: {elapsed:.1f}s")
    print(f"Successful: {success}")
    print(f"Failed: {failed}")
    print(f"Skipped: {len(invalid)}")
    print(f"Output directory: {args.output_dir}")
    print(f"Manifest: {args.output_dir / 'manifest.json'}")


if __name__ == "__main__":
    main()
