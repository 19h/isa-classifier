"""Configuration loading and validation for the Binary Sample Oracle."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
import yaml


@dataclass
class OracleConfig:
    output_dir: Path
    parallel_jobs: int = 8
    continue_on_error: bool = True
    generate_manifest: bool = True
    calculate_hashes: list[str] = field(default_factory=lambda: ["sha256"])


@dataclass
class ProgramConfig:
    name: str
    source: Path
    language: str  # "c" or "cpp"
    category: str
    requires_libc: bool = True
    requires_threads: bool = False
    requires_exceptions: bool = False
    cpp_std: str | None = None  # e.g., "c++17"
    c_std: str | None = None  # e.g., "c11"
    extra_flags: list[str] = field(default_factory=list)
    skip_targets: list[str] = field(default_factory=list)


@dataclass
class TargetConfig:
    triple: str
    arch: str
    endianness: str  # "little" or "big"
    pointer_width: int  # 32 or 64
    supports_dynamic: bool = True
    supports_threads: bool = True
    supports_exceptions: bool = True
    is_freestanding: bool = False
    sysroot: Path | None = None
    extra_flags: list[str] = field(default_factory=list)


@dataclass
class CompilationConfig:
    optimization: str  # "O0", "O1", "O2", "O3", "Os", "Oz", "Ofast"
    debug: str = "none"  # "none", "line_tables", "dwarf2", "dwarf4", "dwarf5"
    lto: str = "none"  # "none", "thin", "full"
    pic: str = "none"  # "none", "pic", "pie"
    stack_protection: str = "none"  # "none", "basic", "strong", "all"
    cpu: str = "generic"
    relocation_model: str = "default"
    code_model: str = "default"

    def to_flags(self) -> list[str]:
        """Convert configuration to compiler flags."""
        flags = []

        # Optimization
        opt_map = {
            "O0": ["-O0"],
            "O1": ["-O1"],
            "O2": ["-O2"],
            "O3": ["-O3"],
            "Os": ["-Os"],
            "Oz": ["-Oz"],
            "Ofast": ["-Ofast"],
            "O2_unroll": ["-O2", "-funroll-loops"],
            "O2_no_vec": ["-O2", "-fno-vectorize", "-fno-slp-vectorize"],
        }
        flags.extend(opt_map.get(self.optimization, [f"-{self.optimization}"]))

        # Debug info
        debug_map = {
            "none": [],
            "line_tables": ["-gline-tables-only"],
            "dwarf2": ["-g", "-gdwarf-2"],
            "dwarf4": ["-g", "-gdwarf-4"],
            "dwarf5": ["-g", "-gdwarf-5"],
        }
        flags.extend(debug_map.get(self.debug, []))

        # LTO
        if self.lto == "thin":
            flags.append("-flto=thin")
        elif self.lto == "full":
            flags.append("-flto=full")

        # PIC/PIE
        if self.pic == "pic":
            flags.append("-fPIC")
        elif self.pic == "pie":
            flags.extend(["-fPIE", "-pie"])

        # Stack protection
        ssp_map = {
            "none": [],
            "basic": ["-fstack-protector"],
            "strong": ["-fstack-protector-strong"],
            "all": ["-fstack-protector-all"],
        }
        flags.extend(ssp_map.get(self.stack_protection, []))

        return flags

    def config_id(self) -> str:
        """Generate a unique identifier for this configuration."""
        parts = [self.optimization]
        if self.debug != "none":
            parts.append(self.debug)
        if self.lto != "none":
            parts.append(f"lto_{self.lto}")
        if self.pic != "none":
            parts.append(self.pic)
        if self.stack_protection != "none":
            parts.append(f"ssp_{self.stack_protection}")
        if self.cpu != "generic":
            parts.append(self.cpu.replace("-", "_").replace("+", "_"))
        return "_".join(parts)


# Target database with architecture properties
TARGET_DATABASE: dict[str, dict[str, Any]] = {
    # x86 family
    "x86_64-unknown-linux-gnu": {
        "arch": "x86_64",
        "endianness": "little",
        "pointer_width": 64,
        "cpu_options": [
            "generic",
            "x86-64",
            "x86-64-v2",
            "x86-64-v3",
            "x86-64-v4",
            "skylake",
            "znver3",
        ],
    },
    "x86_64-unknown-linux-musl": {
        "arch": "x86_64",
        "endianness": "little",
        "pointer_width": 64,
        "cpu_options": ["generic", "x86-64", "x86-64-v2", "x86-64-v3", "x86-64-v4"],
    },
    "i686-unknown-linux-gnu": {
        "arch": "i686",
        "endianness": "little",
        "pointer_width": 32,
        "cpu_options": ["generic", "i686", "pentium4", "core2"],
    },
    # ARM family
    "aarch64-unknown-linux-gnu": {
        "arch": "aarch64",
        "endianness": "little",
        "pointer_width": 64,
        "cpu_options": [
            "generic",
            "armv8-a",
            "armv8.2-a",
            "armv8.2-a+sve",
            "cortex-a72",
            "apple-m1",
        ],
    },
    "aarch64-unknown-linux-musl": {
        "arch": "aarch64",
        "endianness": "little",
        "pointer_width": 64,
        "cpu_options": ["generic", "armv8-a", "armv8.2-a"],
    },
    "arm-unknown-linux-gnueabi": {
        "arch": "arm",
        "endianness": "little",
        "pointer_width": 32,
        "cpu_options": ["generic", "arm7tdmi", "cortex-a7"],
    },
    "arm-unknown-linux-gnueabihf": {
        "arch": "arm",
        "endianness": "little",
        "pointer_width": 32,
        "cpu_options": ["generic", "cortex-a7", "cortex-a15"],
    },
    "armv7-unknown-linux-gnueabihf": {
        "arch": "armv7",
        "endianness": "little",
        "pointer_width": 32,
        "cpu_options": ["generic", "cortex-a7", "cortex-a15", "cortex-a53"],
    },
    "thumbv7m-none-eabi": {
        "arch": "thumbv7m",
        "endianness": "little",
        "pointer_width": 32,
        "is_freestanding": True,
        "supports_dynamic": False,
        "supports_threads": False,
        "cpu_options": ["generic", "cortex-m3", "cortex-m4"],
    },
    # RISC-V
    "riscv64-unknown-linux-gnu": {
        "arch": "riscv64",
        "endianness": "little",
        "pointer_width": 64,
        "cpu_options": ["generic", "rv64gc", "rv64gcv"],
    },
    "riscv32-unknown-linux-gnu": {
        "arch": "riscv32",
        "endianness": "little",
        "pointer_width": 32,
        "cpu_options": ["generic", "rv32gc"],
    },
    "riscv64-unknown-elf": {
        "arch": "riscv64",
        "endianness": "little",
        "pointer_width": 64,
        "is_freestanding": True,
        "supports_dynamic": False,
        "cpu_options": ["generic", "rv64gc"],
    },
    "riscv32-unknown-elf": {
        "arch": "riscv32",
        "endianness": "little",
        "pointer_width": 32,
        "is_freestanding": True,
        "supports_dynamic": False,
        "cpu_options": ["generic", "rv32gc"],
    },
    # TriCore family
    "tricore-unknown-elf": {
        "arch": "tricore",
        "endianness": "little",
        "pointer_width": 32,
        "cpu_options": ["generic", "tc1796", "tc1798", "tc27xx", "tc39xx", "tc49xx"],
        "supports_dynamic": False,
        "supports_threads": False,
        "supports_exceptions": False,
        "is_freestanding": False,
    },
    # MIPS
    "mips-unknown-linux-gnu": {
        "arch": "mips",
        "endianness": "big",
        "pointer_width": 32,
        "cpu_options": ["generic", "mips32", "mips32r2"],
    },
    "mipsel-unknown-linux-gnu": {
        "arch": "mipsel",
        "endianness": "little",
        "pointer_width": 32,
        "cpu_options": ["generic", "mips32", "mips32r2"],
    },
    "mips64-unknown-linux-gnuabi64": {
        "arch": "mips64",
        "endianness": "big",
        "pointer_width": 64,
        "cpu_options": ["generic", "mips64", "mips64r2"],
    },
    "mips64el-unknown-linux-gnuabi64": {
        "arch": "mips64el",
        "endianness": "little",
        "pointer_width": 64,
        "cpu_options": ["generic", "mips64", "mips64r2"],
    },
    # PowerPC
    "powerpc64-unknown-linux-gnu": {
        "arch": "ppc64",
        "endianness": "big",
        "pointer_width": 64,
        "cpu_options": ["generic", "pwr8", "pwr9"],
    },
    "powerpc64le-unknown-linux-gnu": {
        "arch": "ppc64le",
        "endianness": "little",
        "pointer_width": 64,
        "cpu_options": ["generic", "pwr8", "pwr9", "pwr10"],
    },
    "powerpc-unknown-linux-gnu": {
        "arch": "ppc",
        "endianness": "big",
        "pointer_width": 32,
        "cpu_options": ["generic", "ppc", "ppc64"],
    },
    # SPARC
    "sparc64-unknown-linux-gnu": {
        "arch": "sparc64",
        "endianness": "big",
        "pointer_width": 64,
        "cpu_options": ["generic", "v9", "ultrasparc"],
    },
    "sparc-unknown-linux-gnu": {
        "arch": "sparc",
        "endianness": "big",
        "pointer_width": 32,
        "cpu_options": ["generic", "v8", "v9"],
    },
    # SystemZ
    "s390x-unknown-linux-gnu": {
        "arch": "s390x",
        "endianness": "big",
        "pointer_width": 64,
        "cpu_options": ["generic", "z13", "z14", "z15"],
    },
    # LoongArch
    "loongarch64-unknown-linux-gnu": {
        "arch": "loongarch64",
        "endianness": "little",
        "pointer_width": 64,
        "cpu_options": ["generic", "la464"],
    },
    # WebAssembly
    "wasm32-unknown-unknown": {
        "arch": "wasm32",
        "endianness": "little",
        "pointer_width": 32,
        "is_freestanding": True,
        "supports_dynamic": False,
        "supports_threads": False,
        "cpu_options": ["generic", "mvp", "bleeding-edge"],
    },
    "wasm32-wasi": {
        "arch": "wasm32",
        "endianness": "little",
        "pointer_width": 32,
        "supports_dynamic": False,
        "cpu_options": ["generic", "mvp"],
    },
    # Embedded
    "avr-unknown-unknown": {
        "arch": "avr",
        "endianness": "little",
        "pointer_width": 16,
        "is_freestanding": True,
        "supports_dynamic": False,
        "supports_threads": False,
        "supports_exceptions": False,
        "cpu_options": ["generic", "atmega328p", "atmega2560"],
    },
    "msp430-none-elf": {
        "arch": "msp430",
        "endianness": "little",
        "pointer_width": 16,
        "is_freestanding": True,
        "supports_dynamic": False,
        "supports_threads": False,
        "supports_exceptions": False,
        "cpu_options": ["generic", "msp430", "msp430x"],
    },
    "hexagon-unknown-linux-musl": {
        "arch": "hexagon",
        "endianness": "little",
        "pointer_width": 32,
        "cpu_options": ["generic", "hexagonv60", "hexagonv66"],
    },
    # GPU/Accelerator
    "nvptx64-nvidia-cuda": {
        "arch": "nvptx64",
        "endianness": "little",
        "pointer_width": 64,
        "is_freestanding": True,
        "supports_dynamic": False,
        "supports_threads": False,
        "supports_exceptions": False,
        "cpu_options": ["sm_50", "sm_60", "sm_70", "sm_80"],
    },
    "amdgcn-amd-amdhsa": {
        "arch": "amdgcn",
        "endianness": "little",
        "pointer_width": 64,
        "is_freestanding": True,
        "supports_dynamic": False,
        "supports_threads": False,
        "supports_exceptions": False,
        "cpu_options": ["gfx900", "gfx1010", "gfx1030"],
    },
    # Special
    "bpf-unknown-none": {
        "arch": "bpf",
        "endianness": "little",
        "pointer_width": 64,
        "is_freestanding": True,
        "supports_dynamic": False,
        "supports_threads": False,
        "supports_exceptions": False,
        "cpu_options": ["generic", "v1", "v2", "v3"],
    },
    "ve-unknown-linux-gnu": {
        "arch": "ve",
        "endianness": "little",
        "pointer_width": 64,
        "cpu_options": ["generic"],
    },
    "lanai-unknown-unknown": {
        "arch": "lanai",
        "endianness": "big",
        "pointer_width": 32,
        "is_freestanding": True,
        "supports_dynamic": False,
        "cpu_options": ["generic"],
    },
    "xcore-unknown-unknown": {
        "arch": "xcore",
        "endianness": "little",
        "pointer_width": 32,
        "is_freestanding": True,
        "supports_dynamic": False,
        "cpu_options": ["generic"],
    },
}


def get_target_config(triple: str) -> TargetConfig:
    """Get target configuration from the database."""
    if triple not in TARGET_DATABASE:
        raise ValueError(f"Unknown target: {triple}")

    info = TARGET_DATABASE[triple]
    return TargetConfig(
        triple=triple,
        arch=info["arch"],
        endianness=info["endianness"],
        pointer_width=info["pointer_width"],
        supports_dynamic=info.get("supports_dynamic", True),
        supports_threads=info.get("supports_threads", True),
        supports_exceptions=info.get("supports_exceptions", True),
        is_freestanding=info.get("is_freestanding", False),
    )


def get_cpu_options(triple: str) -> list[str]:
    """Get available CPU targeting options for a target."""
    if triple not in TARGET_DATABASE:
        return ["generic"]
    return TARGET_DATABASE[triple].get("cpu_options", ["generic"])


def load_config(config_path: Path) -> dict[str, Any]:
    """Load configuration from YAML file."""
    with open(config_path) as f:
        return yaml.safe_load(f)


def get_all_targets() -> list[str]:
    """Get list of all known targets."""
    return list(TARGET_DATABASE.keys())
