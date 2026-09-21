# Model Integration Security

## Current Decision

No external model weights, serving framework, remote code, native extension, floating dependency, or model download was integrated in Phase 6K.5. The repository retains its existing provider boundary. This is an intentional security decision, not a failed integration.

## Required Pilot Record

Any future pilot must identify exactly one model, immutable model revision, repository revision, license, tokenizer revision, chat template, generation configuration, serving version, dependency lock, artifact hashes, download source, remote-code policy, native extensions, and container provenance. `trust_remote_code=True`, pickle or unsafe deserialization, `latest` tags, unverified downloads, and floating dependencies are prohibited.

## Candidate Research

The previous official-source research reviewed Qwen3/Qwen3-8B/Qwen3-Coder, Mistral Small, Devstral, llama.cpp, Transformers, vLLM, and Ollama. Qwen3-8B remains a possible future small local pilot, but its exact model-card revision, tokenizer revision, generation configuration, artifact hashes, and Arabic benchmark were not pinned in the repository. Therefore it was not integrated.

The serving options have different roles: llama.cpp for portable quantized local inference, vLLM for GPU/API serving, Ollama for low-friction local REST, and Transformers for flexible in-process execution. These are not model-quality claims. A model license is distinct from a framework license.

## Tool and Code Boundary

A model-generated tool call is untrusted input:

```text
MODEL
  ↓
UNTRUSTED PROPOSAL
  ↓
SCHEMA VALIDATION
  ↓
POLICY SNAPSHOT
  ↓
AUTHORIZATION
  ↓
SCOPE
  ↓
RISK CHECK
  ↓
TOOL
```

The model cannot write Owner Policy, Authorization, Scope, Tool Registry, Evidence, or Memory authority. Model-generated code is not executed. No arbitrary shell executor, exploit runner, recon runner, unrestricted MCP, credential harvesting, or automatic scope expansion is part of this foundation.

## Limitations

Arabic model quality, latency, memory use, long-horizon quality, structured-output reliability, and tool-call reliability are **UNKNOWN** until an exact pinned deployment is tested. No vendor benchmark is treated as production evidence.
