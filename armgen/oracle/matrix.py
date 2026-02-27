"""Configuration matrix expansion for generating all build combinations."""

from dataclasses import dataclass
from itertools import product
from pathlib import Path
from typing import Iterator

from .config import (
    CompilationConfig,
    ProgramConfig,
    TargetConfig,
    get_target_config,
    get_cpu_options,
    get_all_targets,
)
from .compiler import is_valid_combination


@dataclass
class BuildTask:
    """A single build task representing one program/target/config combination."""
    program: ProgramConfig
    target: TargetConfig
    config: CompilationConfig
    output_path: Path

    def task_id(self) -> str:
        """Generate unique task identifier."""
        return f"{self.program.name}_{self.target.triple}_{self.config.config_id()}"


# Default configuration options
DEFAULT_OPTIMIZATIONS = ["O0", "O1", "O2", "O3", "Os", "Oz"]
DEFAULT_DEBUG = ["none", "dwarf4"]
DEFAULT_LTO = ["none", "thin"]
DEFAULT_PIC = ["none", "pic"]
DEFAULT_SSP = ["none", "strong"]


def expand_configurations(
    optimizations: list[str] | None = None,
    debug_levels: list[str] | None = None,
    lto_modes: list[str] | None = None,
    pic_modes: list[str] | None = None,
    ssp_modes: list[str] | None = None,
    cpu_options: list[str] | None = None,
) -> Iterator[CompilationConfig]:
    """Generate all configuration combinations."""
    opts = optimizations or DEFAULT_OPTIMIZATIONS
    debugs = debug_levels or ["none"]
    ltos = lto_modes or ["none"]
    pics = pic_modes or ["none"]
    ssps = ssp_modes or ["none"]
    cpus = cpu_options or ["generic"]

    for opt, debug, lto, pic, ssp, cpu in product(opts, debugs, ltos, pics, ssps, cpus):
        yield CompilationConfig(
            optimization=opt,
            debug=debug,
            lto=lto,
            pic=pic,
            stack_protection=ssp,
            cpu=cpu,
        )


def discover_programs(programs_dir: Path) -> list[ProgramConfig]:
    """Discover all programs in the programs directory."""
    programs = []

    for source_file in sorted(programs_dir.glob("*.c")):
        name = source_file.stem
        # Remove numeric prefix if present (e.g., "01_hello_world" -> "hello_world")
        if "_" in name and name.split("_")[0].isdigit():
            display_name = "_".join(name.split("_")[1:])
        else:
            display_name = name

        # Determine category from name prefix
        category = categorize_program(display_name)

        # Determine requirements from name/content
        requires_threads = "thread" in display_name.lower()
        requires_libc = not display_name.startswith("min_") and not display_name.startswith("asm_")

        programs.append(ProgramConfig(
            name=display_name,
            source=source_file,
            language="c",
            category=category,
            requires_libc=requires_libc,
            requires_threads=requires_threads,
            c_std="c11",
        ))

    for source_file in sorted(programs_dir.glob("*.cpp")):
        name = source_file.stem
        if "_" in name and name.split("_")[0].isdigit():
            display_name = "_".join(name.split("_")[1:])
        else:
            display_name = name

        category = categorize_program(display_name)
        requires_threads = "thread" in display_name.lower()
        requires_exceptions = "exception" in display_name.lower()

        programs.append(ProgramConfig(
            name=display_name,
            source=source_file,
            language="cpp",
            category=category,
            requires_libc=True,
            requires_threads=requires_threads,
            requires_exceptions=requires_exceptions,
            cpp_std="c++17",
        ))

    return programs


def categorize_program(name: str) -> str:
    """Categorize a program based on its name."""
    prefixes = {
        "min_": "minimal",
        "simd_": "simd",
        "fp_": "floating_point",
        "int_": "integer",
        "syscall_": "syscall",
        "asm_": "assembly",
        "cf_": "control_flow",
        "call_": "calling_convention",
        "mem_": "memory",
        "cpp_": "cpp_features",
    }
    for prefix, category in prefixes.items():
        if name.startswith(prefix):
            return category
    return "general"


def generate_build_matrix(
    programs: list[ProgramConfig],
    targets: list[str],
    output_dir: Path,
    optimizations: list[str] | None = None,
    debug_levels: list[str] | None = None,
    lto_modes: list[str] | None = None,
    pic_modes: list[str] | None = None,
    ssp_modes: list[str] | None = None,
    include_cpu_variants: bool = False,
) -> Iterator[tuple[BuildTask, bool, str]]:
    """
    Generate the full build matrix.

    Yields (BuildTask, is_valid, reason) tuples.
    """
    for target_triple in targets:
        try:
            target = get_target_config(target_triple)
        except ValueError as e:
            continue

        # Get CPU options for this target if requested
        cpu_options = get_cpu_options(target_triple) if include_cpu_variants else ["generic"]

        for program in programs:
            for config in expand_configurations(
                optimizations=optimizations,
                debug_levels=debug_levels,
                lto_modes=lto_modes,
                pic_modes=pic_modes,
                ssp_modes=ssp_modes,
                cpu_options=cpu_options,
            ):
                # Determine output path (object file with .o extension)
                config_dir = config.config_id()
                output_path = output_dir / target_triple / config_dir / f"{program.name}.o"

                task = BuildTask(
                    program=program,
                    target=target,
                    config=config,
                    output_path=output_path,
                )

                # Check validity
                is_valid, reason = is_valid_combination(program, target, config)
                yield task, is_valid, reason


def estimate_build_count(
    num_programs: int,
    num_targets: int,
    num_optimizations: int = 6,
    num_debug: int = 2,
    num_lto: int = 2,
    num_pic: int = 2,
    num_ssp: int = 2,
    avg_cpu_variants: float = 1.5,
) -> int:
    """Estimate total number of builds."""
    configs_per_target = (
        num_optimizations * num_debug * num_lto * num_pic * num_ssp * avg_cpu_variants
    )
    # Rough estimate - not all combinations are valid
    validity_factor = 0.7
    return int(num_programs * num_targets * configs_per_target * validity_factor)
