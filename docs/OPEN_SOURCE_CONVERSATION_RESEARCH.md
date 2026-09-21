# Open-Source Conversation Research Record

**Review date:** 2026-09-21  
**Status:** VERIFIED RESEARCH / NO DIRECT INTEGRATION

This record evaluates open-source model and serving options for a future CyberSentinel conversation layer. It does not treat model weights, chat frameworks, inference servers, or tool execution as interchangeable components. No external repository code, model weights, remote code, installation script, or dependency was added to CyberSentinel as part of this review.

## Decision Summary

The current repository keeps its deterministic provider boundary and does not add a new model dependency. The correct immediate decision is **not to integrate a model or framework solely from this comparison**. The next safe step would require selecting one exact checkpoint, reviewing its files and license, pinning an immutable revision, reviewing the serving source and dependency SBOM, then running the repository's policy, scope, provenance, prompt-injection, structured-output, and tool-call tests against that exact deployment.

At the capability level, vLLM is the strongest candidate for high-throughput GPU/API serving, llama.cpp is the strongest candidate for portable quantized local inference, Ollama is the lowest-friction local REST runner, Transformers is the most flexible Python in-process option, and Transformers.js is the browser/Node option. These are **capability distinctions, not model-quality rankings**.

## Model Options

| Option | Verified version/revision | License | Relevant capability | Decision |
|---|---|---|---|---|
| Qwen3-8B | Official Qwen repository main commit `7a2f61ffc7a20d47efcd2bf97f6f2bf52729042e`; Qwen3-8B model-card revision was not captured | Apache-2.0 for the weights | Multilingual instruction following, chat, documented tool calling, local routes through Transformers/vLLM/SGLang/llama.cpp/Ollama | **Candidate for later small local pilot**, after exact revision and Arabic benchmark are pinned |
| Qwen3-Coder 30B-A3B-Instruct | Repository main commit `33bc6aabd7791ad7b32f7e92104f11f2359ba890`; model revision not captured | Apache-2.0 for the weights | Agentic coding and specialized tool parser | **Not selected now**; higher parser, code-execution, and supply-chain risk |
| DeepSeek-V3 | Repository commit `9b4e9788e4a3a731f7567338ed15d3ec549ce03b` | Code repository MIT; weights use the separate DeepSeek Model License Agreement | 128K context and large MoE deployment; substantial infrastructure | **Not suitable for current local integration** |
| DeepSeek-R1 | Repository commit `0cf78561f1d51c84a21b2190626b21116d5c68bb` | MIT for R1 materials; distills retain upstream Qwen/Llama terms | Strong reasoning; native tool-call reliability remains unverified | **Not selected now**; long reasoning and resource cost require separate review |
| Meta Llama 3.1/3.3/4 | Llama model repository snapshot `0e0b8c519242d5833d8c11bffc1232b77ad7f301`; exact weights SHA not captured | Custom Llama Community Licenses, not OSI-open-source | Strong ecosystem, tool-use benchmarks, Llama 4 long context/multimodal options | **Not selected now**; custom license, gated artifacts, and hardware complexity |
| Devstral Small 1.1 | HF revision `bd165ab26cebbcc2eea2c4ecbfc07f3ac42b3c39` | Apache-2.0 | Agentic software engineering and explicit Mistral tool-call format | **Candidate for a separate code-agent study only**, never with ambient shell access |
| Devstral Small 2 | HF revision `55c5b41e98c2dbd21b0c8afffc540dcfc9eb5128` | Apache-2.0 | Tool loop and coding-agent behavior | **Rejected for new integration** because official Mistral documentation marks it deprecated |
| Mistral Small 3.2 | Model revision not captured | Apache-2.0 | Chat and improved function-call formatting | **Not selected now**; exact revision and local schema guarantees remain unverified |

Arabic quality is **UNKNOWN** for the candidate models unless an Arabic-specific benchmark is run. Vendor claims of multilingual support are not treated as Arabic-quality evidence.

## Serving and Library Options

| Project | Verified version | License | Use case | Key security findings |
|---|---|---|---|---|
| vLLM | v0.29.0, released 2026-09-09; exact release commit not exposed by reviewed response | Apache-2.0 | GPU/API serving, streaming, structured outputs, tool parsers | Internal distributed channels may be unauthenticated/unencrypted; API keys do not protect every endpoint; model downloads and custom code require review |
| llama.cpp | v0.4.1, release commit `391fac16460f15233a7740550d858ac96df3419d` | MIT for framework | Portable CPU/GPU/quantized local inference and llama-server | Official security guidance requires model isolation, artifact hash verification, network isolation, and warns against exposing RPC/server paths to untrusted networks |
| Ollama | v0.34.2, released 2026-09-15; exact release commit not exposed by reviewed response | MIT for framework | Lowest-friction local REST runner; streaming, JSON schema, and tool-call API | Local daemon becomes a network service when exposed; pulls/installers/manifests are supply-chain inputs; model license remains model-specific |
| Transformers | v5.17.0, released 2026-09-09; exact release commit not exposed by reviewed response | Apache-2.0 for library | Flexible Python model definition/in-process execution | Official security guidance recommends safetensors and warns that `trust_remote_code=True` executes repository-provided code |
| Transformers.js | v4.3.0, released 2026-09-16; exact release commit not exposed by reviewed response | Apache-2.0 for library | Browser/Node local inference; experimental structured output | Remote model downloads, npm/WASM/ONNX artifacts, browser storage, and WebGPU require allowlisting and supply-chain review |
| Qwen-Agent | v0.0.26 release; repository main commit `31a4d36d123688581a9e9744427272b33ce940e0` | Apache-2.0 | Qwen-oriented orchestration, RAG, function calling, MCP | Official README warns its Python executor is unsandboxed for local testing; MCP examples use floating `npx -y`/`uvx`; **not integrated** |
| mistral-inference | Repository main commit `9eaeb91c17450e09021b6065a1d5cc69876507c8` | Apache-2.0 | Historical Mistral inference library | Official repository is archived/no longer maintained; **not selected for new integration** |

## Reuse Decision

No external code was reused. No dependency was added. CyberSentinel's existing provider interface remains the integration seam. If a future provider is added, it must return typed, schema-validated data and must never be allowed to mutate Owner Policy, Authorization, Scope, Tool Registry, or Evidence state.

## Required Review Before Any Future Integration

The exact model revision, tokenizer, chat template, generation configuration, license files, model implementation, serving commit, container image, native kernels, quantization/conversion pipeline, and transitive dependency lockfile must be reviewed. Model artifacts should be downloaded offline or from an allowlisted immutable revision, verified with hashes where available, and loaded with safe formats such as safetensors. `trust_remote_code` must be rejected unless source-reviewed and isolated.

Generated tool calls are untrusted data. The application must independently validate tool name, JSON schema, argument values, Owner authentication, Authorization, Scope, rate limits, timeouts, filesystem/network capabilities, and evidence recording. Tool output, retrieved documents, memory, model reasoning, and expert advice remain non-authoritative.

## Evidence and Unknowns

No universal Arabic score, latency number, memory requirement, structured-output guarantee, streaming contract, or tool-call reliability score was invented. Where official sources did not establish a fact, it is recorded as **UNKNOWN**. Vendor benchmark numbers were not treated as production guarantees or security evidence.

## Sources Reviewed

Official project repositories, releases, model cards, licenses, security policies, and documentation were reviewed for Qwen, DeepSeek, Meta Llama, Mistral, vLLM, SGLang, llama.cpp, Ollama, Hugging Face Transformers, Transformers.js, and Qwen-Agent. The research workflow retained source URLs and exact revisions in its evidence record; this document records the decision-relevant subset.
