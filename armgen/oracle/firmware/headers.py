"""ISA-specific header/trailer generators for synthetic firmware images."""

import hashlib
import struct
import time
import zlib
from dataclasses import dataclass, field
from random import Random
from typing import Any


@dataclass
class HeaderResult:
    """Result of a header generator."""

    data: bytes
    entry_point_offset: int  # offset into image where code starts
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class TrailerResult:
    """Result of a trailer generator."""

    data: bytes
    metadata: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# ISA-specific vector tables
# ---------------------------------------------------------------------------


def vector_table_cortexm(
    endianness: str, rng: Random, code_offset: int = 0, **kwargs: Any
) -> HeaderResult:
    """
    Cortex-M vector table: Initial SP at offset 0, Reset handler at offset 4,
    followed by 14 exception vectors (NMI, HardFault, etc.).
    64 bytes minimum (16 vectors × 4 bytes).
    """
    base_addr = kwargs.get("base_addr", 0x08000000)
    num_vectors = rng.choice([16, 32, 48, 64])  # 64–256 bytes
    fmt = "<I"  # Cortex-M is always little-endian

    vectors = []
    # Initial SP — typically top of SRAM
    sp = rng.choice([0x20005000, 0x20010000, 0x20020000, 0x20040000])
    vectors.append(sp)

    # Reset vector → points to code start (must be odd for Thumb)
    reset_addr = base_addr + (num_vectors * 4) | 1
    vectors.append(reset_addr)

    # Remaining exception vectors — plausible handler addresses
    for i in range(num_vectors - 2):
        handler = base_addr + (num_vectors * 4) + rng.randint(0, 0x1000)
        handler |= 1  # Thumb bit
        vectors.append(handler)

    data = struct.pack(f"<{num_vectors}I", *vectors)
    return HeaderResult(
        data=data,
        entry_point_offset=len(data),
        metadata={"header_type": "vector_table_cortexm", "num_vectors": num_vectors},
    )


def vector_table_arm(
    endianness: str, rng: Random, code_offset: int = 0, **kwargs: Any
) -> HeaderResult:
    """
    Classic ARM vector table: 8 branch instructions at 0x0.
    Each is a B (branch) instruction: 0xEA000000 + offset.
    32 bytes total.
    """
    fmt = "<I" if endianness == "little" else ">I"
    vectors = []
    for i in range(8):
        # ARM branch: 0xEA000000 | (offset >> 2 - 2)
        # Point to somewhere reasonable after the table
        target_offset = 32 + rng.randint(0, 0x800)
        branch_offset = (target_offset - (i * 4) - 8) >> 2
        branch_offset &= 0x00FFFFFF
        instr = 0xEA000000 | branch_offset
        vectors.append(instr)

    data = b"".join(struct.pack(fmt, v) for v in vectors)
    return HeaderResult(
        data=data,
        entry_point_offset=len(data),
        metadata={"header_type": "vector_table_arm"},
    )


def boot_vector_mips(
    endianness: str, rng: Random, code_offset: int = 0, **kwargs: Any
) -> HeaderResult:
    """
    MIPS boot vector: lui+ori+jr trampoline at reset vector.
    Loads a 32-bit address into $t0 and jumps to it.
    16 bytes (4 instructions including branch delay slot NOP).
    """
    base_addr = kwargs.get("base_addr", 0xBFC00000)
    fmt = ">I" if endianness == "big" else "<I"

    # Target address (code entry after header)
    target = base_addr + 32
    upper = (target >> 16) & 0xFFFF
    lower = target & 0xFFFF

    # lui $t0, upper     (0x3C080000 | upper)
    # ori $t0, $t0, lower (0x35080000 | lower)
    # jr $t0             (0x01000008)
    # nop                (0x00000000) — branch delay slot
    instrs = [
        0x3C080000 | upper,
        0x35080000 | lower,
        0x01000008,
        0x00000000,
    ]

    # Optionally add padding to 32 bytes
    while len(instrs) < 8:
        instrs.append(0x00000000)  # NOP padding

    data = b"".join(struct.pack(fmt, i) for i in instrs)
    return HeaderResult(
        data=data,
        entry_point_offset=len(data),
        metadata={"header_type": "boot_vector_mips"},
    )


def avr_vector_table(
    endianness: str, rng: Random, code_offset: int = 0, **kwargs: Any
) -> HeaderResult:
    """
    AVR interrupt vector table: RJMP instructions for each vector.
    ATmega328P: 26 vectors, ATmega2560: 57 vectors.
    Each vector is 2 bytes (RJMP) or 4 bytes (JMP for larger devices).
    """
    # AVR is always little-endian
    use_jmp = rng.choice([True, False])
    num_vectors = rng.choice([26, 35, 57])

    vectors = bytearray()
    if use_jmp:
        # JMP instructions (4 bytes each): 0x940C + 16-bit addr
        vec_size = 4
        for i in range(num_vectors):
            target = num_vectors * vec_size + rng.randint(0, 0x100)
            # JMP encoding: 1001_010k_kkkk_110k kkkk_kkkk_kkkk_kkkk
            lo = target & 0xFFFF
            hi = (target >> 16) & 0x3F
            word1 = 0x940C | ((hi & 0x3E) << 3) | (hi & 0x01)
            vectors.extend(struct.pack("<HH", word1, lo))
    else:
        # RJMP instructions (2 bytes each): 0xCxxx
        vec_size = 2
        for i in range(num_vectors):
            target_offset = num_vectors - i - 1 + rng.randint(0, 0x20)
            target_offset &= 0x0FFF
            rjmp = 0xC000 | target_offset
            vectors.extend(struct.pack("<H", rjmp))

    data = bytes(vectors)
    return HeaderResult(
        data=data,
        entry_point_offset=len(data),
        metadata={
            "header_type": "avr_vector_table",
            "num_vectors": num_vectors,
            "use_jmp": use_jmp,
        },
    )


def msp430_vector_table(
    endianness: str, rng: Random, code_offset: int = 0, **kwargs: Any
) -> HeaderResult:
    """
    MSP430 interrupt vector table: 16 vectors at 0xFFE0–0xFFFE.
    Each is a 16-bit address. We generate plausible code addresses.
    32 bytes total.
    """
    # MSP430 is little-endian
    vectors = []
    code_base = rng.choice([0xC000, 0xC200, 0xE000, 0xF000])
    for i in range(16):
        addr = code_base + rng.randint(0, 0x1000)
        addr &= 0xFFFE  # must be even
        vectors.append(addr)

    data = struct.pack("<16H", *vectors)
    return HeaderResult(
        data=data,
        entry_point_offset=0,  # MSP430 vectors are at end of flash, code is elsewhere
        metadata={"header_type": "msp430_vector_table", "code_base": code_base},
    )


# ---------------------------------------------------------------------------
# Firmware container headers
# ---------------------------------------------------------------------------


def uboot(
    endianness: str, rng: Random, code_offset: int = 0, **kwargs: Any
) -> HeaderResult:
    """
    U-Boot legacy image header: 64 bytes.
    Magic: 0x27051956, always big-endian header fields.
    """
    image_size = kwargs.get("total_size", 65536)
    data_size = max(0, image_size - 64) & 0xFFFFFFFF

    # U-Boot header is always big-endian regardless of target
    magic = 0x27051956
    header_crc = 0  # placeholder, updated after
    timestamp = int(time.time()) - rng.randint(0, 365 * 24 * 3600)
    timestamp &= 0xFFFFFFFF
    data_crc = 0  # placeholder
    load_addr = kwargs.get("base_addr", 0x80008000) & 0xFFFFFFFF
    ep = load_addr  # entry point = load address

    os_type = rng.choice([5, 17, 20])  # Linux=5, firmware=17, flat_dt=20
    arch_map = {
        "arm32": 2, "thumb": 2, "aarch64": 22,
        "x86": 6, "x86_64": 6,
        "mips32_be": 5, "mips32_le": 5, "mips64_be": 5, "mips64_le": 5,
        "ppc32": 7, "ppc64_be": 7, "ppc64_le": 7,
        "riscv32": 27, "riscv64": 27,
    }
    family = kwargs.get("family_name", "arm32")
    arch = arch_map.get(family, 0)
    img_type = rng.choice([2, 5])  # kernel=2, firmware=5
    comp = rng.choice([0, 1, 2, 3])  # none, gzip, bzip2, lzma

    # Image name (32 bytes, null-padded)
    names = [
        b"Linux Kernel Image",
        b"U-Boot Firmware",
        b"Ramdisk Image",
        b"FIT Image",
        b"OpenWrt firmware",
    ]
    name = rng.choice(names)
    name_padded = name[:32].ljust(32, b"\x00")

    # Pack header (big-endian)
    header = struct.pack(
        ">IIIIIIIBBBB32s",
        magic,
        header_crc,
        timestamp,
        data_size,
        load_addr,
        ep,
        data_crc,
        os_type,
        arch,
        img_type,
        comp,
        name_padded,
    )

    # Compute header CRC (zero out CRC field first)
    header_for_crc = header[:4] + b"\x00\x00\x00\x00" + header[8:]
    crc = zlib.crc32(header_for_crc) & 0xFFFFFFFF
    header = header[:4] + struct.pack(">I", crc) + header[8:]

    return HeaderResult(
        data=header,
        entry_point_offset=64,
        metadata={"header_type": "uboot", "arch": arch, "comp": comp},
    )


def android_boot(
    endianness: str, rng: Random, code_offset: int = 0, **kwargs: Any
) -> HeaderResult:
    """
    Android boot image header (v0/v1 simplified).
    Magic: ANDROID!, ~1632 bytes.
    """
    image_size = kwargs.get("total_size", 65536)

    magic = b"ANDROID!"
    kernel_size = image_size - 2048
    kernel_addr = 0x10008000
    ramdisk_size = 0
    ramdisk_addr = 0x11000000
    second_size = 0
    second_addr = 0x10F00000
    tags_addr = 0x10000100
    page_size = 2048
    header_version = rng.choice([0, 1])
    os_version = 0

    # cmdline (512 bytes + 1024 bytes extra)
    cmdlines = [
        b"console=ttyMSM0,115200n8 androidboot.console=ttyMSM0",
        b"console=ttyS0,115200 root=/dev/ram0 androidboot.hardware=qcom",
        b"console=ttyHSL0,115200,n8 androidboot.console=ttyHSL0",
    ]
    cmdline = rng.choice(cmdlines)
    cmdline_padded = cmdline[:512].ljust(512, b"\x00")

    # SHA hash (32 bytes)
    sha = rng.randbytes(32)

    extra_cmdline = b"\x00" * 1024

    # Build header
    header = bytearray()
    header.extend(magic)  # 8
    header.extend(struct.pack("<I", kernel_size))  # 12
    header.extend(struct.pack("<I", kernel_addr))  # 16
    header.extend(struct.pack("<I", ramdisk_size))  # 20
    header.extend(struct.pack("<I", ramdisk_addr))  # 24
    header.extend(struct.pack("<I", second_size))  # 28
    header.extend(struct.pack("<I", second_addr))  # 32
    header.extend(struct.pack("<I", tags_addr))  # 36
    header.extend(struct.pack("<I", page_size))  # 40
    header.extend(struct.pack("<I", header_version))  # 44
    header.extend(struct.pack("<I", os_version))  # 48
    header.extend(cmdline_padded)  # 560
    header.extend(sha)  # 592
    header.extend(extra_cmdline)  # 1616
    # Pad to page_size boundary
    while len(header) < page_size:
        header.append(0)

    return HeaderResult(
        data=bytes(header[:page_size]),
        entry_point_offset=page_size,
        metadata={"header_type": "android_boot", "page_size": page_size},
    )


def tplink(
    endianness: str, rng: Random, code_offset: int = 0, **kwargs: Any
) -> HeaderResult:
    """
    TP-Link firmware header: vendor info, version, hardware ID, MD5.
    512 bytes total.
    """
    image_size = kwargs.get("total_size", 65536)

    header = bytearray(512)

    # Vendor name at offset 0 (32 bytes)
    vendor = rng.choice([b"TP-LINK Technologies", b"TP-LINK", b"Archer"])
    header[0:len(vendor)] = vendor

    # Firmware version at offset 32 (32 bytes)
    ver = f"ver. {rng.randint(1,5)}.{rng.randint(0,20)}.{rng.randint(0,9)}".encode()
    header[32:32 + len(ver)] = ver

    # Hardware ID at offset 64 (4 bytes, big-endian)
    hw_ids = [0x00000001, 0x07500002, 0x09700001, 0x0C500001]
    struct.pack_into(">I", header, 64, rng.choice(hw_ids))

    # Firmware length at offset 68 (4 bytes, big-endian)
    struct.pack_into(">I", header, 68, image_size)

    # MD5 hash at offset 76 (16 bytes) — placeholder
    header[76:92] = rng.randbytes(16)

    return HeaderResult(
        data=bytes(header),
        entry_point_offset=512,
        metadata={"header_type": "tplink"},
    )


def mediatek(
    endianness: str, rng: Random, code_offset: int = 0, **kwargs: Any
) -> HeaderResult:
    """
    MediaTek bootloader header with BRLYT/BLOADER magic.
    512–2048 bytes.
    """
    size = rng.choice([512, 1024, 2048])
    header = bytearray(size)

    # Device header at offset 0
    magic = rng.choice([b"BRLYT", b"BLOADER"])
    header[0:len(magic)] = magic

    # Version (4 bytes at offset 8)
    struct.pack_into("<I", header, 8, rng.randint(1, 4))

    # Boot region start (4 bytes at offset 12)
    struct.pack_into("<I", header, 12, size)

    # Boot region length (4 bytes at offset 16)
    boot_len = kwargs.get("total_size", 65536) - size
    struct.pack_into("<I", header, 16, boot_len)

    # Device info string at offset 32 (32 bytes)
    dev_info = rng.choice([b"MT7621", b"MT7628", b"MT6753", b"MT8173"])
    header[32:32 + len(dev_info)] = dev_info

    return HeaderResult(
        data=bytes(header),
        entry_point_offset=size,
        metadata={"header_type": "mediatek", "size": size},
    )


def qualcomm_mbn(
    endianness: str, rng: Random, code_offset: int = 0, **kwargs: Any
) -> HeaderResult:
    """
    Qualcomm MBN (Melf Boot Notation) image header.
    40-byte image descriptor.
    """
    image_size = kwargs.get("total_size", 65536)

    # MBN header fields (little-endian)
    image_id = rng.choice([0x03, 0x05, 0x07, 0x0D, 0x15])  # SBL, TZ, APPSBL, etc.
    header_vsn = 3
    image_src = 40  # offset to code
    image_dest = kwargs.get("base_addr", 0x80000000)
    code_size = image_size - 40
    sig_ptr = 0
    sig_size = 0
    cert_chain_ptr = 0
    cert_chain_size = 0
    magic = 0x00000005  # SBL magic

    data = struct.pack(
        "<IIIIIIIIII",
        image_id,
        header_vsn,
        image_src,
        image_dest,
        code_size,
        sig_ptr,
        sig_size,
        cert_chain_ptr,
        cert_chain_size,
        magic,
    )

    return HeaderResult(
        data=data,
        entry_point_offset=40,
        metadata={"header_type": "qualcomm_mbn", "image_id": image_id},
    )


def bios_boot(
    endianness: str, rng: Random, code_offset: int = 0, **kwargs: Any
) -> HeaderResult:
    """
    x86 BIOS boot sector: JMP + NOP, BPB fields, 0x55AA signature.
    512 bytes total.
    """
    header = bytearray(512)

    # JMP short + NOP (3 bytes)
    jmp_offset = rng.randint(0x3C, 0x58)  # jump past BPB
    header[0] = 0xEB  # JMP short
    header[1] = jmp_offset
    header[2] = 0x90  # NOP

    # OEM name (8 bytes at offset 3)
    oem_names = [b"MSWIN4.1", b"mkdosfs ", b"MSDOS5.0", b"IBM  3.3"]
    oem = rng.choice(oem_names)
    header[3:11] = oem

    # BPB (BIOS Parameter Block) — realistic FAT16/32 values
    struct.pack_into("<H", header, 11, 512)  # bytes per sector
    header[13] = rng.choice([1, 2, 4, 8])  # sectors per cluster
    struct.pack_into("<H", header, 14, rng.choice([1, 32]))  # reserved sectors
    header[16] = 2  # number of FATs
    struct.pack_into("<H", header, 17, rng.choice([0, 512]))  # root entries
    struct.pack_into("<H", header, 19, 0)  # total sectors 16
    header[21] = 0xF8  # media descriptor (hard disk)

    # Boot signature at 510
    header[510] = 0x55
    header[511] = 0xAA

    return HeaderResult(
        data=bytes(header),
        entry_point_offset=jmp_offset + 2,  # after the JMP target
        metadata={"header_type": "bios_boot"},
    )


def uefi_stub(
    endianness: str, rng: Random, code_offset: int = 0, **kwargs: Any
) -> HeaderResult:
    """
    Minimal PE/COFF header for UEFI: MZ + PE signature.
    512–1024 bytes.
    """
    size = rng.choice([512, 768, 1024])
    header = bytearray(size)

    # MZ header
    header[0:2] = b"MZ"

    # e_lfanew: offset to PE signature (at offset 0x3C)
    pe_offset = 0x80
    struct.pack_into("<I", header, 0x3C, pe_offset)

    # PE signature
    header[pe_offset:pe_offset + 4] = b"PE\x00\x00"

    # COFF header (20 bytes)
    coff_offset = pe_offset + 4
    # Machine type
    machine_map = {
        "x86": 0x014C,
        "x86_64": 0x8664,
        "aarch64": 0xAA64,
        "arm32": 0x01C2,
        "riscv32": 0x5032,
        "riscv64": 0x5064,
    }
    family = kwargs.get("family_name", "x86_64")
    machine = machine_map.get(family, 0x8664)
    struct.pack_into("<H", header, coff_offset, machine)
    struct.pack_into("<H", header, coff_offset + 2, 1)  # num sections
    struct.pack_into("<I", header, coff_offset + 4, int(time.time()) & 0xFFFFFFFF)
    struct.pack_into("<H", header, coff_offset + 16, 0xF0)  # size of optional header

    # Characteristics: executable, no relocations
    struct.pack_into("<H", header, coff_offset + 18, 0x0022)

    return HeaderResult(
        data=bytes(header),
        entry_point_offset=size,
        metadata={"header_type": "uefi_stub", "machine": machine},
    )


def opensbi_stub(
    endianness: str, rng: Random, code_offset: int = 0, **kwargs: Any
) -> HeaderResult:
    """
    RISC-V OpenSBI firmware header stub.
    48 bytes: jump instruction + magic + version + offsets.
    """
    header = bytearray(48)

    # RISC-V J-type jump instruction at offset 0 (jump past header)
    # JAL x0, 48 → encoded as J-immediate
    # Simplified: just use a plausible encoding
    jump_target = 48
    # J-type: imm[20|10:1|11|19:12] | rd=x0 | opcode=1101111
    imm = jump_target
    imm_20 = (imm >> 20) & 0x1
    imm_10_1 = (imm >> 1) & 0x3FF
    imm_11 = (imm >> 11) & 0x1
    imm_19_12 = (imm >> 12) & 0xFF
    jal = (imm_20 << 31) | (imm_10_1 << 21) | (imm_11 << 20) | (imm_19_12 << 12) | 0x6F
    struct.pack_into("<I", header, 0, jal)

    # OpenSBI magic at offset 4 (big-endian in spec, but we store LE for RISC-V)
    magic = 0x4F53424900000002  # "OSBI" + version 2
    struct.pack_into("<Q", header, 4, magic)

    # Size and offsets
    struct.pack_into("<I", header, 12, 48)  # header size
    struct.pack_into("<I", header, 16, kwargs.get("total_size", 65536))  # fw size

    return HeaderResult(
        data=bytes(header),
        entry_point_offset=48,
        metadata={"header_type": "opensbi_stub"},
    )


def bare(
    endianness: str, rng: Random, code_offset: int = 0, **kwargs: Any
) -> HeaderResult:
    """No header — raw flash image starting directly with code."""
    return HeaderResult(
        data=b"",
        entry_point_offset=0,
        metadata={"header_type": "bare"},
    )


# ---------------------------------------------------------------------------
# Trailer generators
# ---------------------------------------------------------------------------


def trailer_crc32(image_data: bytes, **kwargs: Any) -> TrailerResult:
    """4-byte CRC32 trailer."""
    crc = zlib.crc32(image_data) & 0xFFFFFFFF
    return TrailerResult(
        data=struct.pack("<I", crc),
        metadata={"checksum_type": "crc32", "value": f"{crc:08x}"},
    )


def trailer_md5(image_data: bytes, **kwargs: Any) -> TrailerResult:
    """16-byte MD5 trailer."""
    digest = hashlib.md5(image_data).digest()
    return TrailerResult(
        data=digest,
        metadata={"checksum_type": "md5", "value": hashlib.md5(image_data).hexdigest()},
    )


def trailer_sha256(image_data: bytes, **kwargs: Any) -> TrailerResult:
    """32-byte SHA256 trailer."""
    digest = hashlib.sha256(image_data).digest()
    return TrailerResult(
        data=digest,
        metadata={
            "checksum_type": "sha256",
            "value": hashlib.sha256(image_data).hexdigest(),
        },
    )


def trailer_none(image_data: bytes, **kwargs: Any) -> TrailerResult:
    """No trailer."""
    return TrailerResult(data=b"", metadata={"checksum_type": "none"})


# ---------------------------------------------------------------------------
# Registries
# ---------------------------------------------------------------------------

HEADER_REGISTRY: dict[str, type] = {
    "vector_table_cortexm": vector_table_cortexm,
    "vector_table_arm": vector_table_arm,
    "boot_vector_mips": boot_vector_mips,
    "avr_vector_table": avr_vector_table,
    "msp430_vector_table": msp430_vector_table,
    "uboot": uboot,
    "android_boot": android_boot,
    "tplink": tplink,
    "mediatek": mediatek,
    "qualcomm_mbn": qualcomm_mbn,
    "bios_boot": bios_boot,
    "uefi_stub": uefi_stub,
    "opensbi_stub": opensbi_stub,
    "bare": bare,
}

TRAILER_REGISTRY: dict[str, type] = {
    "crc32": trailer_crc32,
    "md5": trailer_md5,
    "sha256": trailer_sha256,
    "none": trailer_none,
}

# Trailer selection weights
TRAILER_WEIGHTS: dict[str, float] = {
    "crc32": 40.0,
    "md5": 20.0,
    "sha256": 10.0,
    "none": 30.0,
}


def generate_header(
    header_type: str,
    endianness: str,
    rng: Random,
    **kwargs: Any,
) -> HeaderResult:
    """Generate a header using the named generator."""
    if header_type not in HEADER_REGISTRY:
        raise ValueError(f"Unknown header type: {header_type}")
    return HEADER_REGISTRY[header_type](endianness, rng, **kwargs)


def generate_trailer(
    trailer_type: str,
    image_data: bytes,
    **kwargs: Any,
) -> TrailerResult:
    """Generate a trailer using the named generator."""
    if trailer_type not in TRAILER_REGISTRY:
        raise ValueError(f"Unknown trailer type: {trailer_type}")
    return TRAILER_REGISTRY[trailer_type](image_data, **kwargs)
