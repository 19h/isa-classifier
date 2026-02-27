"""Clang compiler wrapper for cross-compilation."""

import subprocess
import shutil
from dataclasses import dataclass
from pathlib import Path

from .config import TargetConfig, CompilationConfig, ProgramConfig


@dataclass
class CompileResult:
    success: bool
    output_path: Path | None
    command: list[str]
    stdout: str
    stderr: str
    return_code: int


class ClangCompiler:
    """Wrapper for clang cross-compilation."""

    def __init__(self, clang_path: str | None = None):
        self.clang = clang_path or shutil.which("clang") or "clang"
        self.clangpp = (
            clang_path.replace("clang", "clang++")
            if clang_path
            else (shutil.which("clang++") or "clang++")
        )

    def compile(
        self,
        program: ProgramConfig,
        target: TargetConfig,
        config: CompilationConfig,
        output_path: Path,
    ) -> CompileResult:
        """Compile a program for the specified target and configuration."""
        if target.arch == "tricore":
            return self._compile_tricore(program, target, config, output_path)

        # Select compiler based on language
        compiler = self.clangpp if program.language == "cpp" else self.clang

        # Build command
        cmd = [compiler]

        # Target triple
        cmd.append(f"--target={target.triple}")

        # Always compile to object file for cross-compilation
        # This avoids the need for sysroots with headers/libraries
        # Object files still contain all the instruction patterns we need for ML training
        cmd.append("-c")

        # Sysroot if available (for finding target-specific headers)
        if target.sysroot:
            cmd.append(f"--sysroot={target.sysroot}")

        # Freestanding mode for embedded/bare-metal targets
        if target.is_freestanding:
            cmd.extend(["-ffreestanding", "-nostdlib"])

        # Configuration flags (optimization, debug, etc.)
        cmd.extend(config.to_flags())

        # CPU targeting
        if config.cpu != "generic":
            if target.arch in ("aarch64", "arm", "armv7", "thumbv7m"):
                cmd.append(f"-mcpu={config.cpu}")
            elif target.arch in ("x86_64", "i686"):
                cmd.append(f"-march={config.cpu}")
            elif target.arch in ("riscv64", "riscv32"):
                cmd.append(f"-march={config.cpu}")
            elif target.arch in ("nvptx64",):
                cmd.append(f"-march={config.cpu}")
            elif target.arch in ("amdgcn",):
                cmd.append(f"-mcpu={config.cpu}")

        # Language standard
        if program.language == "cpp" and program.cpp_std:
            cmd.append(f"-std={program.cpp_std}")
        elif program.language == "c" and program.c_std:
            cmd.append(f"-std={program.c_std}")
        elif program.language == "cpp":
            cmd.append("-std=c++17")
        elif program.language == "c":
            cmd.append("-std=c11")

        # Disable exceptions/RTTI for targets that don't support them
        if program.language == "cpp":
            if not target.supports_exceptions or not program.requires_exceptions:
                cmd.append("-fno-exceptions")
            cmd.append("-fno-rtti")  # Generally not needed for our test programs

        # Warning flags
        cmd.extend(["-Wall", "-Wextra"])

        # Program-specific extra flags
        cmd.extend(program.extra_flags)

        # Target-specific extra flags
        cmd.extend(target.extra_flags)

        # Output file
        cmd.extend(["-o", str(output_path)])

        # Source file
        cmd.append(str(program.source))

        # Run compilation
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )
            return CompileResult(
                success=result.returncode == 0,
                output_path=output_path if result.returncode == 0 else None,
                command=cmd,
                stdout=result.stdout,
                stderr=result.stderr,
                return_code=result.returncode,
            )
        except subprocess.TimeoutExpired:
            return CompileResult(
                success=False,
                output_path=None,
                command=cmd,
                stdout="",
                stderr="Compilation timed out",
                return_code=-1,
            )
        except Exception as e:
            return CompileResult(
                success=False,
                output_path=None,
                command=cmd,
                stdout="",
                stderr=str(e),
                return_code=-1,
            )

    def _compile_tricore(
        self,
        program: ProgramConfig,
        target: TargetConfig,
        config: CompilationConfig,
        output_path: Path,
    ) -> CompileResult:
        """Compile a program for TriCore using the GCC toolchain via OrbStack."""
        # Use Linux translation (orb -m x86) with mac paths in /mnt/mac/
        mac_toolchain_dir = "/Users/int/dev/isa-harvester/armgen/tools/tricore/bin"
        linux_toolchain_dir = f"/mnt/mac{mac_toolchain_dir}"

        compiler_name = (
            "tricore-elf-c++" if program.language == "cpp" else "tricore-elf-gcc"
        )
        compiler_path = f"{linux_toolchain_dir}/{compiler_name}"

        cmd = ["orb", "-m", "x86", compiler_path]

        cmd.append("-c")

        if target.is_freestanding:
            cmd.extend(["-ffreestanding", "-nostdlib"])

        opt = config.optimization
        if opt == "Oz":
            opt = "Os"
        elif opt == "O2_unroll":
            opt = "O2"
            cmd.append("-funroll-loops")
        elif opt == "O2_no_vec":
            opt = "O2"
        cmd.append(f"-{opt}")

        if config.debug in ("dwarf4", "dwarf5", "dwarf2"):
            cmd.append("-g")
        elif config.debug == "line_tables":
            cmd.append("-g1")

        if config.lto != "none":
            cmd.append("-flto")

        if config.pic in ("pic", "pie"):
            cmd.append("-mcode-pic")

        if config.cpu != "generic":
            cmd.append(f"-mcpu={config.cpu}")

        if program.language == "cpp" and program.cpp_std:
            cmd.append(f"-std={program.cpp_std}")
        elif program.language == "c" and program.c_std:
            cmd.append(f"-std={program.c_std}")
        elif program.language == "cpp":
            cmd.append("-std=c++17")
        elif program.language == "c":
            cmd.append("-std=c11")

        if program.language == "cpp":
            if not target.supports_exceptions or not program.requires_exceptions:
                cmd.append("-fno-exceptions")
            cmd.append("-fno-rtti")

        cmd.extend(["-Wall", "-Wextra"])
        cmd.extend(program.extra_flags)
        cmd.extend(target.extra_flags)

        def to_orb_path(p: Path) -> str:
            p_str = str(Path(p).resolve())
            if p_str.startswith("/Users/"):
                return f"/mnt/mac{p_str}"
            return p_str

        cmd.extend(["-o", to_orb_path(output_path)])
        cmd.append(to_orb_path(program.source))

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )
            return CompileResult(
                success=result.returncode == 0,
                output_path=output_path if result.returncode == 0 else None,
                command=cmd,
                stdout=result.stdout,
                stderr=result.stderr,
                return_code=result.returncode,
            )
        except subprocess.TimeoutExpired:
            return CompileResult(
                success=False,
                output_path=None,
                command=cmd,
                stdout="",
                stderr="Compilation timed out",
                return_code=-1,
            )
        except Exception as e:
            return CompileResult(
                success=False,
                output_path=None,
                command=cmd,
                stdout="",
                stderr=str(e),
                return_code=-1,
            )

    def get_version(self) -> str:
        """Get clang version string."""
        try:
            result = subprocess.run(
                [self.clang, "--version"],
                capture_output=True,
                text=True,
            )
            return result.stdout.split("\n")[0]
        except Exception:
            return "unknown"


def is_valid_combination(
    program: ProgramConfig,
    target: TargetConfig,
    config: CompilationConfig,
) -> tuple[bool, str]:
    """Check if a program/target/config combination is valid."""
    # Check if target is in program's skip list
    for skip_pattern in program.skip_targets:
        if skip_pattern in target.triple:
            return False, f"Program skips target pattern: {skip_pattern}"

    # Freestanding targets can't use libc
    if target.is_freestanding and program.requires_libc:
        return False, "Program requires libc but target is freestanding"

    # Thread support
    if program.requires_threads and not target.supports_threads:
        return False, "Program requires threads but target doesn't support them"

    # Exception support for C++
    if program.requires_exceptions and not target.supports_exceptions:
        return False, "Program requires exceptions but target doesn't support them"

    # Dynamic linking
    if config.pic in ("pic", "pie") and not target.supports_dynamic:
        return False, "PIC/PIE requested but target doesn't support dynamic linking"

    # LTO typically requires linker support
    if config.lto != "none" and target.is_freestanding:
        return False, "LTO not supported for freestanding targets"

    return True, "OK"
