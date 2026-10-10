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

The second archive is used for Linux-hosted local-inference acceptance; the Windows installer bundles the first archive's CPU runtime. Both archives are pinned by exact size and SHA-256 in `scripts/download_llama_runtime.py` and fetched from HTTPS GitHub Releases URLs. Extraction rejects archive path escapes, ZIP links, and unsafe TAR special files. The runtime-archive downloader refuses any existing output that does not match the verified manifest without deleting it and uses private unique temporary files before atomic replacement. The model-weight downloader uses a resumable `.part` file, rejects symlinked output/partial paths (and uses no-follow file opening where supported), verifies exact size and SHA-256, preserves an old target until verification succeeds, and atomically promotes only the verified artifact.

## Model-manager state contract

The `/api/public/desktop/models` catalog row distinguishes a saved preference from live runtime state:

- `selected` is the persisted model preference. It can remain true while the runtime is stopped or being restored; it does not imply readiness.
- `active` is true only when the manager runtime is `ready` and both the runtime model ID and active provider/model ID match that row's `model_id`. A persisted selection alone is insufficient; starting, stopping, stopped, failed, or mismatched runtime state is not active.
- `installed_sha256` is a display observation of the on-disk artifact digest, exposed only after the pinned manifest and expected size match and the actual file hash matches the catalog digest. A successful observation may be cached against the verified artifact fingerprint and pinned identity for status display; it is not authorization or inference authority. Install and activation perform their own fresh verification.
- Missing, partial, tampered, manifest-invalid, or failed-verification artifacts report `installed: false` and `installed_sha256: null`. Failed runtime verification/startup does not leave the model ready or active.

## Real local-model acceptance harness

`scripts/local_model_acceptance.py` uses an isolated temporary database/model root and a disposable Owner session. It requires the pinned llama.cpp `b11146` runtime manifest and verifies the runtime archive digest, server-binary digest, Qwen3 catalog file digest, real-inference marker, and exact `local_llama_cpp`/Qwen model identity. The Mission runs through AgentCore/MissionRuntime with a one-provider router, empty network/credential boundaries, and all registered tools except read-only `status` explicitly forbidden. AgentCore passes only canonical schemas named by the persisted Mission authorization snapshot to MissionRuntime; replanning remains restricted to that same authorized tool set. These are the schemas sent to the provider and counted in the token budget. Qwen3's bounded local inference smoke check disables reasoning mode so the short verification marker can complete within its fixed output cap; ordinary model generation settings are unchanged.

The harness requires a successful status-tool result, independently validated status evidence tied to that tool-call ID, provider-bound persisted turns, a nonempty bounded text-only final response from the same local provider after tool execution, and a valid Mission trajectory/event hash chain after reopening the Mission store. Its JSON report contains only digests, fixed status fields, numeric budget diagnostics, response byte length, and opaque evidence references; it never prints prompts, model response, or tool-result bodies. Successful temporary artifacts are removed by default; `--keep-artifacts` retains them for inspection. `--artifacts-dir` may resume only an existing real directory named with the harness's prefix under the OS temp directory; resumed artifacts are never deleted, and installed-model integrity is rechecked before use.

`scripts/windows_acceptance.ps1` remains the Windows-only package/runtime wrapper and invokes the shared harness. A Linux acceptance result validates only that tested Linux x64 CPU path; it does not establish Windows behavior, GPU backends, specialist-child real inference, product installation, or broader production acceptance.

On 2026-10-06, the shared harness completed a **real Linux x86_64 CPU acceptance** with `qwen3-4b-q4-k-m` (revision `22c9fc8a8c7700b76a1789366280a6a5a1ad1120`, SHA-256 `f6f851777709861056efcdad3af01da38b31223a3ba26e61a4f8bf3a2195813a`) and llama.cpp `b11146` (runtime asset SHA-256 `c150306eb16b5ab696f76a8bdf810c35fd98a24e82158742e6fa28f420ff8410`; server SHA-256 `22de090746c114569367998ec930b28f27f12e078e593ff21175a54b409d26fe`). It observed the fixed inference marker, then ran one Owner-authenticated Mission with two provider-bound turns: one successful `status` tool call and a 22-byte, text-only final response from the same local Qwen provider. The harness independently validated fenced status evidence, reopened and verified Mission/trajectory integrity, and confirmed runtime shutdown. The Mission reached `GOAL_COMPLETED`. This establishes the bounded Linux local-inference and Mission-to-final-response/evidence path only; it does not establish multi-agent real inference, Windows behavior, GPU backends, product installation, or broader production acceptance.
