"""Dataset public API restored from the existing compatible bytecode modules."""

from encrypted_traffic_platform.dataset.manager import DatasetManager, SampleRecord
from encrypted_traffic_platform.dataset.index import build_index

__all__ = ["DatasetManager", "SampleRecord", "build_index"]
