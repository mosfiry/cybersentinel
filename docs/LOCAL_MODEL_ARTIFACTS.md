# Pinned local model and runtime artifacts

Metadata checked from Hugging Face model cards, Hugging Face model/revision APIs, and the official `ggml-org/llama.cpp` GitHub Releases API on 2026-10-04. The catalog contains only the exact pinned GGUF files below; the model manager does not accept arbitrary repository/file URLs.

## Local GGUF catalog

| Catalog ID | Repository and immutable revision | File | Size (bytes) | SHA-256 | Quantization | License shown by model card |
| --- | --- | --- | ---: | --- | --- | --- |
| `qwen3-4b-q4-k-m` | [`unsloth/Qwen3-4B-GGUF`](https://huggingface.co/unsloth/Qwen3-4B-GGUF) · `22c9fc8a8c7700b76a1789366280a6a5a1ad1120` | `Qwen3-4B-Q4_K_M.gguf` | 2,497,281,312 | `f6f851777709861056efcdad3af01da38b31223a3ba26e61a4f8bf3a2195813a` | Q4_K_M | Apache-2.0 |
| `qwen3-8b-q4-k-m` | [`Aldaris/Qwen3-8B-Q4_K_M-GGUF`](https://huggingface.co/Aldaris/Qwen3-8B-Q4_K_M-GGUF) · `13bd893bea2d84ef95500851983ed8c4f24e70e3` | `qwen3-8b-q4_k_m.gguf` | 5,027,783,872 | `609eb8a9fb256d0e2be8b8d252b00bae7c0496fac5e9ccca190206abbb24e2e5` | Q4_K_M | Apache-2.0 |
| `deepseek-r1-distill-qwen-7b-q4-k-m` | [`unsloth/DeepSeek-R1-Distill-Qwen-7B-GGUF`](https://huggingface.co/unsloth/DeepSeek-R1-Distill-Qwen-7B-GGUF) · `097680e4eed7a83b3df6b0bb5e5134099cadf1b0` | `DeepSeek-R1-Distill-Qwen-7B-Q4_K_M.gguf` | 4,683,073,248 | `78272d8d32084548bd450394a560eb2d70de8232ab96a725769b1f9171235c1c` | Q4_K_M | Apache-2.0 |

These are third-party GGUF conversions. The upstream model authors' original repositories may publish different formats or terms; review the linked card and original model terms before distributing weights. We do not bundle model weights in the installer. Each user chooses and downloads a model from the in-app manager.

## Bundled llama.cpp CPU runtime

The latest stable release API returned [`llama.cpp v0.5.0`](https://github.com/ggml-org/llama.cpp/releases/tag/v0.5.0), published 2026-09-23. Its release notes point to binary build [`b11146`](https://github.com/ggml-org/llama.cpp/releases/tag/b11146); the binary build release itself is marked prerelease by GitHub. The Windows Installer pins this exact build and validates the GitHub API asset digest before extraction:

| Platform asset | Exact size | SHA-256 |
| --- | ---: | --- |
| [`llama-b11146-bin-win-cpu-x64.zip`](https://github.com/ggml-org/llama.cpp/releases/download/b11146/llama-b11146-bin-win-cpu-x64.zip) | 18,560,055 bytes | `14cf1303ca9ac3abd94816850532f9f9a69ac66fbaca3776fc6f9061c2fac1d1` |
| [`llama-b11146-bin-ubuntu-x64.tar.gz`](https://github.com/ggml-org/llama.cpp/releases/download/b11146/llama-b11146-bin-ubuntu-x64.tar.gz) | 16,998,357 bytes | `c150306eb16b5ab696f76a8bdf810c35fd98a24e82158742e6fa28f420ff8410` |

The second archive is used only for a Linux-hosted local-inference rehearsal; the Windows installer bundles the first archive's CPU runtime. Both archives are released by `ggml-org/llama.cpp` and fetched from HTTPS GitHub Releases URLs.
