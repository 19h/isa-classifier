"""ISA family mapping and firmware generation configuration."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class IsaFamily:
    """Firmware-relevant ISA family grouping multiple target triples."""

    name: str
    endianness: str  # "little" or "big"
    pointer_width: int  # 16, 32, or 64
    triples: list[str]
    header_types: list[str]
    typical_base_addr: int = 0x08000000
    alignment: int = 4


# ISA family definitions — groups the target triples into firmware-relevant families
ISA_FAMILIES: dict[str, IsaFamily] = {
    "arm32": IsaFamily(
        name="arm32",
        endianness="little",
        pointer_width=32,
        triples=[
            "arm-unknown-linux-gnueabi",
            "arm-unknown-linux-gnueabihf",
            "armv7-unknown-linux-gnueabihf",
        ],
        header_types=["vector_table_arm", "uboot", "android_boot", "bare"],
        typical_base_addr=0x00000000,
        alignment=4,
    ),
    "thumb": IsaFamily(
        name="thumb",
        endianness="little",
        pointer_width=32,
        triples=["thumbv7m-none-eabi"],
        header_types=["vector_table_cortexm", "bare"],
        typical_base_addr=0x08000000,
        alignment=2,
    ),
    "aarch64": IsaFamily(
        name="aarch64",
        endianness="little",
        pointer_width=64,
        triples=[
            "aarch64-unknown-linux-gnu",
            "aarch64-unknown-linux-musl",
        ],
        header_types=["uboot", "android_boot", "bare"],
        typical_base_addr=0x40000000,
        alignment=4,
    ),
    "x86": IsaFamily(
        name="x86",
        endianness="little",
        pointer_width=32,
        triples=["i686-unknown-linux-gnu"],
        header_types=["bios_boot", "uefi_stub", "bare"],
        typical_base_addr=0x00007C00,
        alignment=1,
    ),
    "x86_64": IsaFamily(
        name="x86_64",
        endianness="little",
        pointer_width=64,
        triples=[
            "x86_64-unknown-linux-gnu",
            "x86_64-unknown-linux-musl",
        ],
        header_types=["uefi_stub", "bios_boot", "uboot", "bare"],
        typical_base_addr=0x00100000,
        alignment=1,
    ),
    "riscv32": IsaFamily(
        name="riscv32",
        endianness="little",
        pointer_width=32,
        triples=[
            "riscv32-unknown-linux-gnu",
            "riscv32-unknown-elf",
        ],
        header_types=["opensbi_stub", "uboot", "bare"],
        typical_base_addr=0x80000000,
        alignment=4,
    ),
    "riscv64": IsaFamily(
        name="riscv64",
        endianness="little",
        pointer_width=64,
        triples=[
            "riscv64-unknown-linux-gnu",
            "riscv64-unknown-elf",
        ],
        header_types=["opensbi_stub", "uboot", "bare"],
        typical_base_addr=0x80000000,
        alignment=4,
    ),
    "mips32_be": IsaFamily(
        name="mips32_be",
        endianness="big",
        pointer_width=32,
        triples=["mips-unknown-linux-gnu"],
        header_types=["boot_vector_mips", "uboot", "tplink", "bare"],
        typical_base_addr=0xBFC00000,
        alignment=4,
    ),
    "mips32_le": IsaFamily(
        name="mips32_le",
        endianness="little",
        pointer_width=32,
        triples=["mipsel-unknown-linux-gnu"],
        header_types=["boot_vector_mips", "uboot", "tplink", "bare"],
        typical_base_addr=0xBFC00000,
        alignment=4,
    ),
    "mips64_be": IsaFamily(
        name="mips64_be",
        endianness="big",
        pointer_width=64,
        triples=["mips64-unknown-linux-gnuabi64"],
        header_types=["boot_vector_mips", "uboot", "bare"],
        typical_base_addr=0xFFFFFFFF80000000,
        alignment=4,
    ),
    "mips64_le": IsaFamily(
        name="mips64_le",
        endianness="little",
        pointer_width=64,
        triples=["mips64el-unknown-linux-gnuabi64"],
        header_types=["boot_vector_mips", "uboot", "bare"],
        typical_base_addr=0xFFFFFFFF80000000,
        alignment=4,
    ),
    "ppc32": IsaFamily(
        name="ppc32",
        endianness="big",
        pointer_width=32,
        triples=["powerpc-unknown-linux-gnu"],
        header_types=["uboot", "bare"],
        typical_base_addr=0x00000000,
        alignment=4,
    ),
    "ppc64_be": IsaFamily(
        name="ppc64_be",
        endianness="big",
        pointer_width=64,
        triples=["powerpc64-unknown-linux-gnu"],
        header_types=["uboot", "bare"],
        typical_base_addr=0x00000000,
        alignment=4,
    ),
    "ppc64_le": IsaFamily(
        name="ppc64_le",
        endianness="little",
        pointer_width=64,
        triples=["powerpc64le-unknown-linux-gnu"],
        header_types=["uboot", "bare"],
        typical_base_addr=0x00000000,
        alignment=4,
    ),
    "sparc32": IsaFamily(
        name="sparc32",
        endianness="big",
        pointer_width=32,
        triples=["sparc-unknown-linux-gnu"],
        header_types=["uboot", "bare"],
        typical_base_addr=0x00000000,
        alignment=4,
    ),
    "sparc64": IsaFamily(
        name="sparc64",
        endianness="big",
        pointer_width=64,
        triples=["sparc64-unknown-linux-gnu"],
        header_types=["uboot", "bare"],
        typical_base_addr=0x00000000,
        alignment=4,
    ),
    "s390x": IsaFamily(
        name="s390x",
        endianness="big",
        pointer_width=64,
        triples=["s390x-unknown-linux-gnu"],
        header_types=["uboot", "bare"],
        typical_base_addr=0x00000000,
        alignment=4,
    ),
    "loongarch64": IsaFamily(
        name="loongarch64",
        endianness="little",
        pointer_width=64,
        triples=["loongarch64-unknown-linux-gnu"],
        header_types=["uboot", "bare"],
        typical_base_addr=0x9000000000000000,
        alignment=4,
    ),
    "avr": IsaFamily(
        name="avr",
        endianness="little",
        pointer_width=16,
        triples=["avr-unknown-unknown"],
        header_types=["avr_vector_table", "bare"],
        typical_base_addr=0x0000,
        alignment=2,
    ),
    "msp430": IsaFamily(
        name="msp430",
        endianness="little",
        pointer_width=16,
        triples=["msp430-none-elf"],
        header_types=["msp430_vector_table", "bare"],
        typical_base_addr=0xC000,
        alignment=2,
    ),
    "hexagon": IsaFamily(
        name="hexagon",
        endianness="little",
        pointer_width=32,
        triples=["hexagon-unknown-linux-musl"],
        header_types=["qualcomm_mbn", "bare"],
        typical_base_addr=0x00000000,
        alignment=4,
    ),
}

# Triples excluded from firmware generation (not firmware targets)
EXCLUDED_TRIPLES: set[str] = {
    "wasm32-unknown-unknown",
    "wasm32-wasi",
    "nvptx64-nvidia-cuda",
    "amdgcn-amd-amdhsa",
    "bpf-unknown-none",
    "ve-unknown-linux-gnu",
    "lanai-unknown-unknown",
    "xcore-unknown-unknown",
}

# Precomputed reverse map: triple → family name
TRIPLE_TO_FAMILY: dict[str, str] = {}
for _family_name, _family in ISA_FAMILIES.items():
    for _triple in _family.triples:
        TRIPLE_TO_FAMILY[_triple] = _family_name

# Multi-ISA affinity table: plausible combinations seen in real firmware
# Maps primary family → list of (secondary_family, weight) pairs
MULTI_ISA_AFFINITY: dict[str, list[tuple[str, float]]] = {
    "arm32": [("thumb", 3.0), ("aarch64", 1.0)],
    "thumb": [("arm32", 3.0)],
    "aarch64": [("arm32", 2.0), ("thumb", 1.0)],
    "x86_64": [("x86", 2.0), ("arm32", 1.0)],
    "x86": [("x86_64", 1.0)],
    "mips32_be": [("mips32_le", 0.5)],
    "mips32_le": [("mips32_be", 0.5)],
    "mips64_be": [("mips32_be", 2.0)],
    "mips64_le": [("mips32_le", 2.0)],
    "riscv64": [("riscv32", 2.0)],
    "riscv32": [("riscv64", 1.0)],
    "ppc64_be": [("ppc32", 1.0)],
    "ppc64_le": [("ppc32", 0.5)],
    "hexagon": [("arm32", 2.0), ("aarch64", 1.0)],
}


@dataclass
class FirmwareGenConfig:
    """Configuration for firmware image generation."""

    seed: int = 42
    num_images: int = 1000
    min_size: int = 4096
    max_size: int = 16 * 1024 * 1024  # 16 MiB
    multi_isa_probability: float = 0.15
    parallel_jobs: int = 8
    oracle_output_dir: Path = field(default_factory=lambda: Path("../output"))
    objects_dir: Path = field(default_factory=lambda: Path("../objects"))
    firmware_dir: Path = field(default_factory=lambda: Path("../firmware"))
    families: list[str] | None = None  # None = all families
    min_images_per_combo: int = 20
    force_extract: bool = False
    verbose: bool = False


def get_isa_family(name: str) -> IsaFamily:
    """Get an ISA family by name."""
    if name not in ISA_FAMILIES:
        raise ValueError(f"Unknown ISA family: {name}")
    return ISA_FAMILIES[name]


def get_family_for_triple(triple: str) -> str | None:
    """Get the ISA family name for a target triple, or None if excluded."""
    return TRIPLE_TO_FAMILY.get(triple)


def get_firmware_triples() -> list[str]:
    """Get all target triples that are valid firmware targets."""
    return list(TRIPLE_TO_FAMILY.keys())
