"""Layout engine: section ordering, sizing, alignment for synthetic firmware."""

import math
from dataclasses import dataclass, field
from enum import Enum
from random import Random
from typing import Any

from .config import (
    ISA_FAMILIES,
    MULTI_ISA_AFFINITY,
    FirmwareGenConfig,
    IsaFamily,
)
from .extractor import BlobIndex


class SectionType(Enum):
    HEADER = "header"
    CODE = "code"
    PADDING = "padding"
    STRING_TABLE = "string_table"
    FILESYSTEM = "filesystem"
    RANDOM = "random"
    RODATA = "rodata"
    TRAILER = "trailer"


@dataclass
class SectionSpec:
    """Specification for a single section in a firmware image."""

    offset: int
    size: int
    section_type: SectionType
    alignment: int = 1
    isa_family: str | None = None  # for CODE sections
    fill_params: dict[str, Any] = field(default_factory=dict)


@dataclass
class ImageLayout:
    """Complete layout specification for a firmware image."""

    image_id: str
    total_size: int
    primary_isa: str
    header_type: str
    trailer_type: str
    sections: list[SectionSpec]
    all_isa_families: list[str]
    seed: int

    @property
    def isa_label(self) -> str:
        """Directory label: sorted ISA families joined with '+'."""
        return "+".join(sorted(self.all_isa_families))

    @property
    def is_multi_isa(self) -> bool:
        return len(self.all_isa_families) > 1

    @property
    def code_sections(self) -> list[SectionSpec]:
        return [s for s in self.sections if s.section_type == SectionType.CODE]

    @property
    def code_bytes(self) -> int:
        return sum(s.size for s in self.code_sections)


# Non-code section type weights
_NON_CODE_WEIGHTS: dict[SectionType, float] = {
    SectionType.PADDING: 40.0,
    SectionType.STRING_TABLE: 15.0,
    SectionType.FILESYSTEM: 10.0,
    SectionType.RANDOM: 20.0,
    SectionType.RODATA: 15.0,
}

# Trailer weights
_TRAILER_WEIGHTS: list[tuple[str, float]] = [
    ("crc32", 40.0),
    ("md5", 20.0),
    ("sha256", 10.0),
    ("none", 30.0),
]

# Trailer sizes for layout calculation
_TRAILER_SIZES: dict[str, int] = {
    "crc32": 4,
    "md5": 16,
    "sha256": 32,
    "none": 0,
}


def _weighted_choice(rng: Random, options: list[tuple[Any, float]]) -> Any:
    """Pick from weighted options."""
    total = sum(w for _, w in options)
    r = rng.random() * total
    cumulative = 0.0
    for item, weight in options:
        cumulative += weight
        if r <= cumulative:
            return item
    return options[-1][0]


def _align_up(value: int, alignment: int) -> int:
    """Round up to next alignment boundary."""
    if alignment <= 1:
        return value
    return (value + alignment - 1) & ~(alignment - 1)


class LayoutEngine:
    """Generates firmware image layouts with realistic section arrangements."""

    def __init__(self, blob_index: BlobIndex, config: FirmwareGenConfig):
        self.blob_index = blob_index
        self.config = config

        # Build family weights from blob count
        self._family_weights: list[tuple[str, float]] = []
        for family in blob_index.families():
            if family in ISA_FAMILIES:
                count = blob_index.blob_count(family)
                if count > 0:
                    self._family_weights.append((family, float(count)))

        if not self._family_weights:
            raise ValueError("No blobs available for any ISA family")

    def _pick_primary_isa(self, rng: Random) -> str:
        """Select primary ISA family weighted by blob availability."""
        return _weighted_choice(rng, self._family_weights)

    def _pick_secondary_isas(
        self, primary: str, rng: Random
    ) -> list[str]:
        """Pick 1–2 secondary ISA families using affinity table."""
        affinity = MULTI_ISA_AFFINITY.get(primary, [])

        # Filter to families we actually have blobs for
        available = [
            (fam, w) for fam, w in affinity
            if self.blob_index.blob_count(fam) > 0
        ]

        if not available:
            # Fall back: pick any available family different from primary
            fallback = [
                (fam, 1.0) for fam, _ in self._family_weights
                if fam != primary
            ]
            if not fallback:
                return []
            available = fallback

        count = rng.choice([1, 1, 2])  # bias toward 1 secondary
        secondaries = []
        pool = list(available)
        for _ in range(min(count, len(pool))):
            pick = _weighted_choice(rng, pool)
            secondaries.append(pick)
            pool = [(f, w) for f, w in pool if f != pick]
            if not pool:
                break

        return secondaries

    def _pick_header_type(self, family: str, rng: Random) -> str:
        """Select header type from family's available types."""
        family_info = ISA_FAMILIES.get(family)
        if not family_info or not family_info.header_types:
            return "bare"
        return rng.choice(family_info.header_types)

    def _pick_trailer_type(self, rng: Random) -> str:
        """Select trailer type from weighted options."""
        return _weighted_choice(rng, _TRAILER_WEIGHTS)

    def _pick_total_size(self, rng: Random) -> int:
        """Pick total image size via log-uniform distribution."""
        log_min = math.log2(self.config.min_size)
        log_max = math.log2(self.config.max_size)
        log_size = rng.uniform(log_min, log_max)
        size = int(2 ** log_size)
        # Round to 256-byte boundary
        return _align_up(size, 256)

    def _pick_non_code_section(self, rng: Random, max_size: int) -> tuple[SectionType, int, dict]:
        """Pick a non-code section type, size, and fill params."""
        options = list(_NON_CODE_WEIGHTS.items())
        section_type = _weighted_choice(rng, [(t, w) for t, w in options])

        params: dict[str, Any] = {}

        if section_type == SectionType.PADDING:
            # Padding: 16 bytes to 10% of max_size
            pad_max = max(16, min(max_size, 65536, max(64, max_size // 10)))
            size = rng.randint(16, pad_max)
            pattern = rng.choice([0xFF, 0x00, 0xAA, 0xDE])
            params["pattern"] = f"0x{pattern:02X}"
            params["fill_byte"] = pattern

        elif section_type == SectionType.STRING_TABLE:
            hi = max(64, min(4096, max_size))
            size = rng.randint(64, hi)
            params["source"] = "generated"

        elif section_type == SectionType.FILESYSTEM:
            hi = max(512, min(65536, max_size))
            size = rng.randint(512, hi)
            fs_types = ["squashfs", "jffs2", "cramfs", "romfs"]
            params["fs_type"] = rng.choice(fs_types)

        elif section_type == SectionType.RANDOM:
            hi = max(32, min(8192, max_size))
            size = rng.randint(32, hi)
            params["source"] = "random"

        elif section_type == SectionType.RODATA:
            hi = max(64, min(16384, max_size))
            size = rng.randint(64, hi)
            params["source"] = "generated"

        else:
            hi = max(16, min(1024, max_size))
            size = rng.randint(16, hi)

        return section_type, size, params

    def generate_layout(
        self,
        rng: Random,
        seq: int = 0,
        primary_isa: str | None = None,
        forced_secondaries: list[str] | None = None,
    ) -> ImageLayout:
        """Generate a single firmware image layout.

        Args:
            primary_isa: Force this family as primary (None = random).
            forced_secondaries: Force exact secondary families.
                None  = random (may or may not add secondaries).
                []    = force single-ISA (no secondaries).
                [list]= use exactly these secondaries.
        """
        # 1. Pick primary ISA (or use provided one)
        if primary_isa is None:
            primary_isa = self._pick_primary_isa(rng)
        primary_family = ISA_FAMILIES[primary_isa]

        # 2. Decide multi-ISA
        all_families = [primary_isa]
        if forced_secondaries is not None:
            all_families.extend(forced_secondaries)
        elif rng.random() < self.config.multi_isa_probability:
            secondaries = self._pick_secondary_isas(primary_isa, rng)
            all_families.extend(secondaries)

        # 3. Pick header and trailer
        header_type = self._pick_header_type(primary_isa, rng)
        trailer_type = self._pick_trailer_type(rng)
        trailer_size = _TRAILER_SIZES[trailer_type]

        # 4. Determine total size
        total_size = self._pick_total_size(rng)

        # 5. Build section list
        sections: list[SectionSpec] = []
        cursor = 0

        # 5a. Header placeholder (actual size determined at generation time,
        #     but we estimate for layout)
        header_sizes = {
            "vector_table_cortexm": 64,
            "vector_table_arm": 32,
            "boot_vector_mips": 32,
            "avr_vector_table": 128,
            "msp430_vector_table": 32,
            "uboot": 64,
            "android_boot": 2048,
            "tplink": 512,
            "mediatek": 1024,
            "qualcomm_mbn": 40,
            "bios_boot": 512,
            "uefi_stub": 512,
            "opensbi_stub": 48,
            "bare": 0,
        }
        header_size = header_sizes.get(header_type, 64)
        if header_size > 0:
            sections.append(SectionSpec(
                offset=0,
                size=header_size,
                section_type=SectionType.HEADER,
                fill_params={"header_type": header_type},
            ))
            cursor = header_size

        # 5b. Budget code vs non-code
        usable_size = total_size - cursor - trailer_size
        if usable_size < 64:
            # Image too small for meaningful content, just make it bigger
            total_size = cursor + trailer_size + 256
            usable_size = 256

        code_fraction = rng.uniform(0.30, 0.70)
        code_budget = int(usable_size * code_fraction)
        noncode_budget = usable_size - code_budget

        # 5c. Generate code sections
        code_remaining = code_budget
        family_queue = list(all_families)  # cycle through families

        while code_remaining >= 64:
            # Pick which family for this code section
            fam = family_queue[0]
            family_queue.append(family_queue.pop(0))  # rotate

            fam_info = ISA_FAMILIES.get(fam)
            alignment = fam_info.alignment if fam_info else 4

            # Pick a blob to determine section size
            blob = self.blob_index.get_random_blob(fam, rng)
            if blob is None:
                # Skip this family if no blobs
                family_queue = [f for f in family_queue if f != fam]
                if not family_queue:
                    break
                continue

            # Section size: blob size, possibly repeated/truncated
            blob_size = blob.size_bytes
            # Sometimes use multiple copies or a fraction
            multiplier = rng.choice([1, 1, 1, 2, 3])
            section_size = min(blob_size * multiplier, code_remaining)
            section_size = max(section_size, min(blob_size, code_remaining))
            section_size = _align_up(section_size, alignment)

            if section_size > code_remaining:
                section_size = code_remaining

            if section_size < 4:
                break

            # Align cursor
            aligned_cursor = _align_up(cursor, alignment)
            if aligned_cursor > cursor:
                # Insert alignment padding
                pad_size = aligned_cursor - cursor
                sections.append(SectionSpec(
                    offset=cursor,
                    size=pad_size,
                    section_type=SectionType.PADDING,
                    fill_params={"pattern": "0xFF", "fill_byte": 0xFF},
                ))
                cursor = aligned_cursor

            sections.append(SectionSpec(
                offset=cursor,
                size=section_size,
                section_type=SectionType.CODE,
                alignment=alignment,
                isa_family=fam,
                fill_params={
                    "blob_family": fam,
                    "blob_triple": blob.triple,
                    "blob_program": blob.program,
                    "blob_config": blob.config,
                },
            ))
            cursor += section_size
            code_remaining -= section_size

            # Occasionally insert non-code between code sections
            if rng.random() < 0.3 and noncode_budget >= 64:
                nc_type, nc_size, nc_params = self._pick_non_code_section(rng, noncode_budget)
                nc_size = min(nc_size, noncode_budget)
                sections.append(SectionSpec(
                    offset=cursor,
                    size=nc_size,
                    section_type=nc_type,
                    fill_params=nc_params,
                ))
                cursor += nc_size
                noncode_budget -= nc_size

        # 5d. Fill remaining space with non-code sections
        while noncode_budget >= 32 and cursor < total_size - trailer_size:
            nc_type, nc_size, nc_params = self._pick_non_code_section(rng, noncode_budget)
            nc_size = min(nc_size, noncode_budget, total_size - trailer_size - cursor)
            if nc_size < 16:
                break
            sections.append(SectionSpec(
                offset=cursor,
                size=nc_size,
                section_type=nc_type,
                fill_params=nc_params,
            ))
            cursor += nc_size
            noncode_budget -= nc_size

        # 5e. Final padding to fill any gap before trailer
        gap = total_size - trailer_size - cursor
        if gap > 0:
            sections.append(SectionSpec(
                offset=cursor,
                size=gap,
                section_type=SectionType.PADDING,
                fill_params={"pattern": "0xFF", "fill_byte": 0xFF},
            ))
            cursor += gap

        # 5f. Trailer placeholder
        if trailer_size > 0:
            sections.append(SectionSpec(
                offset=cursor,
                size=trailer_size,
                section_type=SectionType.TRAILER,
                fill_params={"trailer_type": trailer_type},
            ))

        image_id = f"fw_{self.config.seed}_{seq:06d}"

        return ImageLayout(
            image_id=image_id,
            total_size=total_size,
            primary_isa=primary_isa,
            header_type=header_type,
            trailer_type=trailer_type,
            sections=sections,
            all_isa_families=all_families,
            seed=self.config.seed + seq,
        )

    def generate_batch(self, count: int, master_seed: int) -> list[ImageLayout]:
        """Generate a batch of layouts with per-combo minimums.

        Phase 1: Generate ``count`` layouts with per-family quotas so
        every available ISA family is represented.

        Phase 2: Any ISA *combination* (directory) that has fewer than
        ``config.min_images_per_combo`` images gets topped up with
        additional forced-combo layouts.

        The final list is deterministically shuffled.
        """
        families = [fam for fam, _ in self._family_weights]
        num_families = len(families)
        min_per_combo = self.config.min_images_per_combo

        # --- Phase 1: quota-based initial generation -----------------------
        # Give every family at least 1 image, distribute rest by blob weight
        base_per = max(1, count // num_families)
        quotas: dict[str, int] = {fam: base_per for fam in families}
        allocated = base_per * num_families

        remainder = count - allocated
        if remainder > 0:
            total_weight = sum(w for _, w in self._family_weights)
            for fam, weight in self._family_weights:
                extra = int(remainder * weight / total_weight)
                quotas[fam] += extra
                allocated += extra
            # rounding leftovers
            leftover = count - allocated
            sorted_fams = sorted(
                self._family_weights, key=lambda x: x[1], reverse=True,
            )
            for i in range(leftover):
                quotas[sorted_fams[i % len(sorted_fams)][0]] += 1

        layouts: list[ImageLayout] = []
        seq = 0
        for fam in families:
            for _ in range(quotas[fam]):
                rng = Random(master_seed + seq)
                layout = self.generate_layout(rng, seq=seq, primary_isa=fam)
                layouts.append(layout)
                seq += 1

        # --- Phase 2: fill under-represented combos ------------------------
        combo_counts: dict[str, int] = {}
        combo_primary: dict[str, str] = {}  # label → a known primary ISA
        for layout in layouts:
            label = layout.isa_label
            combo_counts[label] = combo_counts.get(label, 0) + 1
            combo_primary.setdefault(label, layout.primary_isa)

        for label in sorted(combo_counts):
            needed = min_per_combo - combo_counts[label]
            if needed <= 0:
                continue
            primary = combo_primary[label]
            combo_families = label.split("+")
            secondaries = [f for f in combo_families if f != primary]
            for _ in range(needed):
                rng = Random(master_seed + seq)
                layout = self.generate_layout(
                    rng, seq=seq,
                    primary_isa=primary,
                    forced_secondaries=secondaries,
                )
                layouts.append(layout)
                seq += 1

        # Deterministic shuffle so families are interleaved
        shuffle_rng = Random(master_seed)
        shuffle_rng.shuffle(layouts)

        return layouts
