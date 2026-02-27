"""Binary Sample Oracle - Cross-compilation framework for ML training data generation."""

from .config import (
    OracleConfig,
    ProgramConfig,
    TargetConfig,
    CompilationConfig,
    get_target_config,
    get_cpu_options,
    get_all_targets,
    TARGET_DATABASE,
)
from .compiler import ClangCompiler, CompileResult, is_valid_combination
from .matrix import (
    BuildTask,
    discover_programs,
    expand_configurations,
    generate_build_matrix,
    estimate_build_count,
)
from .metadata import (
    BinaryMetadata,
    ManifestBuilder,
    generate_metadata,
    save_metadata,
    compute_hashes,
    detect_binary_format,
)

__all__ = [
    # Config
    "OracleConfig",
    "ProgramConfig",
    "TargetConfig",
    "CompilationConfig",
    "get_target_config",
    "get_cpu_options",
    "get_all_targets",
    "TARGET_DATABASE",
    # Compiler
    "ClangCompiler",
    "CompileResult",
    "is_valid_combination",
    # Matrix
    "BuildTask",
    "discover_programs",
    "expand_configurations",
    "generate_build_matrix",
    "estimate_build_count",
    # Metadata
    "BinaryMetadata",
    "ManifestBuilder",
    "generate_metadata",
    "save_metadata",
    "compute_hashes",
    "detect_binary_format",
    # Firmware subpackage
    "firmware",
]
