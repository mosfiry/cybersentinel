from __future__ import annotations

from dataclasses import dataclass


CATALOG_VERSION = "2026-10-04.1"


@dataclass(frozen=True)
class ModelSpec:
    model_id: str
    family: str
    display_name: str
    parameter_size: str
    repository: str
    revision: str
    filename: str
    size_bytes: int
    sha256: str
    quantization: str
    license: str
    min_ram_gib: int
    recommended_ram_gib: int
    context_length: int = 4096

    @property
    def download_url(self) -> str:
        return (
            f"https://huggingface.co/{self.repository}/resolve/"
            f"{self.revision}/{self.filename}?download=true"
        )

    def public(self) -> dict[str, object]:
        return {
            "model_id": self.model_id,
            "family": self.family,
            "display_name": self.display_name,
            "parameter_size": self.parameter_size,
            "repository": self.repository,
            "revision": self.revision,
            "filename": self.filename,
            "size_bytes": self.size_bytes,
            "quantization": self.quantization,
            "license": self.license,
            "min_ram_gib": self.min_ram_gib,
            "recommended_ram_gib": self.recommended_ram_gib,
            "context_length": self.context_length,
        }


# The repository commit and Git-LFS SHA-256 are pinned from Hugging Face's
# public model metadata. Only these exact files can be fetched by the UI.
MODEL_CATALOG: tuple[ModelSpec, ...] = (
    ModelSpec(
        model_id="qwen3-4b-q4-k-m",
        family="Qwen3",
        display_name="Qwen3 4B",
        parameter_size="4B",
        repository="unsloth/Qwen3-4B-GGUF",
        revision="22c9fc8a8c7700b76a1789366280a6a5a1ad1120",
        filename="Qwen3-4B-Q4_K_M.gguf",
        size_bytes=2_497_281_312,
        sha256="f6f851777709861056efcdad3af01da38b31223a3ba26e61a4f8bf3a2195813a",
        quantization="Q4_K_M",
        license="Apache-2.0",
        min_ram_gib=8,
        recommended_ram_gib=12,
        context_length=4096,
    ),
    ModelSpec(
        model_id="qwen3-8b-q4-k-m",
        family="Qwen3",
        display_name="Qwen3 8B",
        parameter_size="8B",
        repository="Aldaris/Qwen3-8B-Q4_K_M-GGUF",
        revision="13bd893bea2d84ef95500851983ed8c4f24e70e3",
        filename="qwen3-8b-q4_k_m.gguf",
        size_bytes=5_027_783_872,
        sha256="609eb8a9fb256d0e2be8b8d252b00bae7c0496fac5e9ccca190206abbb24e2e5",
        quantization="Q4_K_M",
        license="Apache-2.0",
        min_ram_gib=16,
        recommended_ram_gib=24,
        context_length=4096,
    ),
    ModelSpec(
        model_id="deepseek-r1-distill-qwen-7b-q4-k-m",
        family="DeepSeek-R1-Distill-Qwen",
        display_name="DeepSeek R1 Distill Qwen 7B",
        parameter_size="7B",
        repository="unsloth/DeepSeek-R1-Distill-Qwen-7B-GGUF",
        revision="097680e4eed7a83b3df6b0bb5e5134099cadf1b0",
        filename="DeepSeek-R1-Distill-Qwen-7B-Q4_K_M.gguf",
        size_bytes=4_683_073_248,
        sha256="78272d8d32084548bd450394a560eb2d70de8232ab96a725769b1f9171235c1c",
        quantization="Q4_K_M",
        license="Apache-2.0",
        min_ram_gib=16,
        recommended_ram_gib=24,
        context_length=4096,
    ),
)

MODELS_BY_ID = {item.model_id: item for item in MODEL_CATALOG}


def get_model(model_id: str) -> ModelSpec:
    try:
        return MODELS_BY_ID[str(model_id)]
    except KeyError as exc:
        raise KeyError("unknown_model") from exc
