"""Synthetic firmware image generator for ISA detection ML training."""

from .config import (
    FirmwareGenConfig,
    ISA_FAMILIES,
    IsaFamily,
    TRIPLE_TO_FAMILY,
    get_firmware_triples,
    get_family_for_triple,
    get_isa_family,
)
from .extractor import BlobExtractor, BlobIndex, BlobInfo
from .headers import (
    HeaderResult,
    TrailerResult,
    generate_header,
    generate_trailer,
    HEADER_REGISTRY,
    TRAILER_REGISTRY,
)
from .layout import (
    ImageLayout,
    LayoutEngine,
    SectionSpec,
    SectionType,
)

__all__ = [
    # Config
    "FirmwareGenConfig",
    "ISA_FAMILIES",
    "IsaFamily",
    "TRIPLE_TO_FAMILY",
    "get_firmware_triples",
    "get_family_for_triple",
    "get_isa_family",
    # Extractor
    "BlobExtractor",
    "BlobIndex",
    "BlobInfo",
    # Headers
    "HeaderResult",
    "TrailerResult",
    "generate_header",
    "generate_trailer",
    "HEADER_REGISTRY",
    "TRAILER_REGISTRY",
    # Layout
    "ImageLayout",
    "LayoutEngine",
    "SectionSpec",
    "SectionType",
]
