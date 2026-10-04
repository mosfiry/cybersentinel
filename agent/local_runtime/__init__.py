"""Provider-neutral local model management and inference runtime."""

from .catalog import CATALOG_VERSION, MODEL_CATALOG, ModelSpec, get_model
from .manager import LocalModelManager

__all__ = ["CATALOG_VERSION", "MODEL_CATALOG", "ModelSpec", "get_model", "LocalModelManager"]
