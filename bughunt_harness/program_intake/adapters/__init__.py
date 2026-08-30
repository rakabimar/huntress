"""Built-in read-only platform adapters."""

from .base import PlatformAdapter, adapter_for, detect_platform
from .bugcrowd import BugcrowdAdapter
from .generic import GenericAdapter
from .hackerone import HackerOneAdapter
from .intigriti import IntigritiAdapter
from .yeswehack import YesWeHackAdapter

__all__ = [
    "PlatformAdapter", "adapter_for", "detect_platform", "HackerOneAdapter",
    "BugcrowdAdapter", "IntigritiAdapter", "YesWeHackAdapter", "GenericAdapter",
]
