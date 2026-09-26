# CI run 20ac3f276cbd
result: SUCCESS

## compileall output (last 100 lines)

## pytest output (last 400 lines)
            if request.execution_class not in {ExecutionClass.MISSION_BOUND.value, ExecutionClass.OWNER_DIRECT.value}:
                raise ToolAdapterError(AdapterPhase.VALIDATE_INPUT, AdapterErrorCode.INPUT_INVALID, "unknown execution class: " + str(request.execution_class), tool=tool)
            spec = tools.registry.get_tool(tool)
            if spec is None:
                raise ToolAdapterError(AdapterPhase.VALIDATE_INPUT, AdapterErrorCode.TOOL_UNAVAILABLE, "tool is not registered in the runtime registry", tool=tool)
            valid, reason = spec.validate(request.argument)
            if not valid:
                raise ToolAdapterError(AdapterPhase.VALIDATE_INPUT, AdapterErrorCode.INPUT_INVALID, reason, tool=tool)
            if isinstance(request.argument, dict) and any(_is_authority_shaped_key(key) for key in request.argument):
                raise ToolAdapterError(AdapterPhase.VALIDATE_INPUT, AdapterErrorCode.INPUT_INVALID, "authority-shaped argument keys rejected", tool=tool)
            if request.execution_class == ExecutionClass.MISSION_BOUND.value:
                if request.mission is None:
                    raise ToolAdapterError(AdapterPhase.VALIDATE_INPUT, AdapterErrorCode.INPUT_INVALID, "mission-bound execution requires the live mission object", tool=tool)
                if not str(request.mission_id or ""):
                    raise ToolAdapterError(AdapterPhase.VALIDATE_INPUT, AdapterErrorCode.INPUT_INVALID, "mission-bound execution requires the mission identity", tool=tool)
            else:
                if request.mission is not None:
                    raise ToolAdapterError(AdapterPhase.VALIDATE_INPUT, AdapterErrorCode.INPUT_INVALID, "owner-direct execution must not carry mission bindings", tool=tool)
                if request.authorization_decision is None:
                    raise ToolAdapterError(AdapterPhase.VALIDATE_INPUT, AdapterErrorCode.INPUT_INVALID, "owner-direct execution requires the typed AuthorizationDecision that authorized it", tool=tool)
                if not str(request.request_id or ""):
                    raise ToolAdapterError(AdapterPhase.VALIDATE_INPUT, AdapterErrorCode.INPUT_INVALID, "owner-direct execution requires the request identity", tool=tool)
            self._validate_argument(request)
    
        def _validate_argument(self, request: ToolAdapterRequest) -> None:
            """Pure hook: additional tool-specific input checks. No side effects."""
    
        # -- Phase 2: authorization VERIFICATION (never creation) ---------------
    
        def authorize(self, request: ToolAdapterRequest) -> AdapterAuthorization:
            """Verify existing authority through the existing chain validators.
    
            INV-ADP-1: this method only calls ExecutionAuthorizationProof.verify
            and ExecutionAuthorizationProof.validate_against_mission — the same
            validators the registry and runtime use. It cannot mint, widen, or
            repair any authorization, and a missing/invalid proof fails closed.
            """
            proof = request.execution_proof
            if not isinstance(proof, ExecutionAuthorizationProof):
                code = RejectionCode.PROOF_REQUIRED.value if proof is None else RejectionCode.PROOF_INVALID.value
                raise ToolAdapterError(AdapterPhase.AUTHORIZE, _classify_rejection(code), "typed ExecutionAuthorizationProof required", tool=request.tool, rejection_code=code)
            if str(getattr(proof, "execution_class", "")) != str(request.execution_class):
                raise ToolAdapterError(
                    AdapterPhase.AUTHORIZE,
                    AdapterErrorCode.PROOF_FAILURE,
                    "proof execution class does not match the request execution class",
                    tool=request.tool,
                    rejection_code=RejectionCode.EXECUTION_CLASS_MISMATCH.value,
                )
            mission_bound = request.execution_class == ExecutionClass.MISSION_BOUND.value
            ok, reason, code = ExecutionAuthorizationProof.verify(
                proof,
                name=request.tool,
                argument=request.argument,
                mission_id=request.mission_id if mission_bound else None,
                request_id=request.request_id or None,
                run_id=request.run_id if mission_bound else None,
            )
            if not ok:
                raise ToolAdapterError(AdapterPhase.AUTHORIZE, _classify_rejection(code), reason, tool=request.tool, rejection_code=code)
            if mission_bound:
                ok, reason, code = ExecutionAuthorizationProof.validate_against_mission(proof, request.mission)
                if not ok:
                    raise ToolAdapterError(AdapterPhase.AUTHORIZE, _classify_rejection(code), reason, tool=request.tool, rejection_code=code)
            else:
                decision = request.authorization_decision
                if not isinstance(decision, AuthorizationDecision):
                    raise ToolAdapterError(AdapterPhase.AUTHORIZE, AdapterErrorCode.AUTHORIZATION_DENIED, "typed AuthorizationDecision required for owner-direct execution", tool=request.tool)
                if not decision.is_valid_for(request.tool, request.argument, request.request_id):
                    raise ToolAdapterError(AdapterPhase.AUTHORIZE, AdapterErrorCode.AUTHORIZATION_DENIED, "authorization decision does not match tool, argument, or request", tool=request.tool)
                if str(decision.decision_signature) != str(proof.decision_fingerprint):
                    raise ToolAdapterError(
                        AdapterPhase.AUTHORIZE,
                        AdapterErrorCode.PROOF_FAILURE,
                        "execution proof is not bound to the supplied AuthorizationDecision",
                        tool=request.tool,
                        rejection_code=RejectionCode.PROOF_BINDING_MISMATCH.value,
                    )
                if str(decision.policy_fingerprint) != str(proof.policy_fingerprint):
                    raise ToolAdapterError(
                        AdapterPhase.AUTHORIZE,
                        AdapterErrorCode.PROOF_FAILURE,
                        "execution proof policy binding does not match the authorization decision policy",
                        tool=request.tool,
                        rejection_code=RejectionCode.PROOF_BINDING_MISMATCH.value,
                    )
            return AdapterAuthorization(
                tool=request.tool,
                execution_class=str(request.execution_class),
                proof_fingerprint=str(proof.execution_binding_hash),
                snapshot_hash=str(proof.snapshot_hash),
                snapshot_version=int(proof.snapshot_version),
                decision_fingerprint=str(proof.decision_fingerprint),
            )
    
        # -- Phase 3: preparation and availability (fail closed, no fallback) ---
    
        def prepare(self, request: ToolAdapterRequest, authorization: AdapterAuthorization) -> PreparedExecution:
            spec = tools.registry.get_tool(request.tool)
            if spec is None:
                raise ToolAdapterError(AdapterPhase.PREPARE, AdapterErrorCode.TOOL_UNAVAILABLE, "tool is not registered in the runtime registry", tool=request.tool)
            if self.required_binary is not None and shutil.which(self.required_binary) is None:
                raise ToolAdapterError(
                    AdapterPhase.PREPARE,
                    AdapterErrorCode.TOOL_UNAVAILABLE,
                    "required runtime binary is unavailable: " + str(self.required_binary) + " (fail closed; no fallback execution)",
                    tool=request.tool,
                )
            timeout = int(self.timeout_seconds) if self.timeout_seconds is not None else int(spec.timeout)
            return PreparedExecution(tool=request.tool, timeout=timeout, required_binary=self.required_binary)
    
        # -- Phase 4: dry run (never executes anything) --------------------------
    
        def dry_run(self, request: ToolAdapterRequest, authorization: AdapterAuthorization, prepared: PreparedExecution) -> dict[str, Any]:
            plan = {
                "tool": request.tool,
                "argument_fingerprint": canonical_execution_fingerprint(request.argument),
                "execution_class": request.execution_class,
                "proof_fingerprint": authorization.proof_fingerprint,
                "timeout": prepared.timeout,
                "required_binary": prepared.required_binary,
                "handler_source": prepared.handler_source,
                "would_execute": True,
            }
            return plan
    
        # -- Phase 5: execution (ONLY through tools.registry.execute) -----------
    
        def execute(self, request: ToolAdapterRequest, authorization: AdapterAuthorization, prepared: PreparedExecution) -> Any:
            """Invoke the tool through the canonical registry boundary.
    
            INV-ADP-2: the only call path to a handler is tools.registry.execute
            with the full chain arguments. The adapter passes the typed proof, the
            live mission snapshot, the execution class, and the live run id; the
            registry remains the last line of defense and re-checks everything.
            """
            mission_bound = request.execution_class == ExecutionClass.MISSION_BOUND.value
            if mission_bound:
                try:
                    snapshot = MissionAuthorizationSnapshot.from_dict(dict(getattr(request.mission, "authorization_snapshot", None) or {}))
                except (MissionAuthorizationError, KeyError, TypeError, ValueError, PermissionError) as exc:
                    raise ToolAdapterError(
                        AdapterPhase.EXECUTE,
                        AdapterErrorCode.AUTHORIZATION_DENIED,
                        "live mission authorization snapshot is invalid: " + str(exc),
                        tool=request.tool,
                        rejection_code=RejectionCode.SNAPSHOT_INVALID.value,
                    ) from None
                try:
                    return tools.registry.execute(
                        request.tool,
                        request.argument,
                        mission_id=request.mission_id,
                        request_id=request.request_id,
                        mission_authorization=snapshot,
                        execution_proof=request.execution_proof,
                        execution_class=ExecutionClass.MISSION_BOUND.value,
                        execution_run_id=request.run_id,
                        timeout=prepared.timeout,
                    )
                except PermissionError as exc:
                    code = _rejection_code_from_message(str(exc))
                    raise ToolAdapterError(AdapterPhase.EXECUTE, _classify_rejection(code), str(exc), tool=request.tool, rejection_code=code) from None
                except TimeoutError as exc:
                    # The handler was submitted before the timeout fired.
                    raise ToolAdapterError(AdapterPhase.EXECUTE, AdapterErrorCode.TIMEOUT, str(exc), tool=request.tool) from None
                except ValueError as exc:
                    raise ToolAdapterError(AdapterPhase.EXECUTE, AdapterErrorCode.INPUT_INVALID, str(exc), tool=request.tool) from None
                except Exception as exc:  # handler-side failure after submission
                    raise ToolAdapterError(AdapterPhase.EXECUTE, AdapterErrorCode.EXECUTION_FAILED, str(exc), tool=request.tool) from None
            try:
                return tools.registry.execute(
                    request.tool,
                    request.argument,
                    request_id=request.request_id,
                    authorization_decision=request.authorization_decision,
                    execution_proof=request.execution_proof,
                    execution_class=ExecutionClass.OWNER_DIRECT.value,
                    timeout=prepared.timeout,
                )
            except PermissionError as exc:
                code = _rejection_code_from_message(str(exc))
                raise ToolAdapterError(AdapterPhase.EXECUTE, _classify_rejection(code), str(exc), tool=request.tool, rejection_code=code) from None
            except TimeoutError as exc:
                raise ToolAdapterError(AdapterPhase.EXECUTE, AdapterErrorCode.TIMEOUT, str(exc), tool=request.tool) from None
            except ValueError as exc:
                raise ToolAdapterError(AdapterPhase.EXECUTE, AdapterErrorCode.INPUT_INVALID, str(exc), tool=request.tool) from None
            except Exception as exc:  # handler-side failure after submission
                raise ToolAdapterError(AdapterPhase.EXECUTE, AdapterErrorCode.EXECUTION_FAILED, str(exc), tool=request.tool) from None
    
        # -- Phase 6: deterministic normalization (output is untrusted) ---------
    
        def normalize_output(self, raw: Any) -> dict[str, Any]:
            try:
                normalized = self._normalize(raw)
            except ToolAdapterError:
                raise
            except Exception as exc:
                raise ToolAdapterError(AdapterPhase.NORMALIZE_OUTPUT, AdapterErrorCode.NORMALIZATION_FAILED, "output normalization failed: " + str(exc), tool=self.tool_name) from None
            if not isinstance(normalized, dict):
                raise ToolAdapterError(AdapterPhase.NORMALIZE_OUTPUT, AdapterErrorCode.NORMALIZATION_FAILED, "normalized output must be a dict", tool=self.tool_name)
            for key in normalized:
                if _is_authority_shaped_key(key):
                    raise ToolAdapterError(
                        AdapterPhase.NORMALIZE_OUTPUT,
                        AdapterErrorCode.NORMALIZATION_FAILED,
                        "tool output attempted to carry an authority-shaped key (rejected as untrusted data): " + str(key),
                        tool=self.tool_name,
                    )
            return dict(normalized)
    
        def _normalize(self, raw: Any) -> dict[str, Any]:
            """Deterministic normalization hook. Output is UNTRUSTED DATA."""
            if isinstance(raw, dict):
                return dict(raw)
            if raw is None or isinstance(raw, (str, int, float, bool)):
                return {"value": raw}
            if isinstance(raw, (list, tuple)):
                return {"items": list(raw)}
            raise ToolAdapterError(AdapterPhase.NORMALIZE_OUTPUT, AdapterErrorCode.NORMALIZATION_FAILED, "tool output cannot be normalized deterministically", tool=self.tool_name)
    
        # -- Phase 7: structured evidence (bindings and hashes, never authority) -
    
        def collect_evidence(
            self,
            request: ToolAdapterRequest,
            authorization: AdapterAuthorization | None,
            raw: Any,
            normalized: dict[str, Any] | None,
            error: ToolAdapterError | None,
            *,
            status: str,
            executed: bool,
        ) -> dict[str, Any]:
            try:
                proof = request.execution_proof if isinstance(request.execution_proof, ExecutionAuthorizationProof) else None
                record: dict[str, Any] = {
                    "record_type": "TOOL_ADAPTER_EVIDENCE",
                    "provenance": "TOOL_ADAPTER",
                    "classification": "UNTRUSTED_TOOL_OUTPUT",
                    "tool": str(request.tool),
                    "execution_class": str(request.execution_class),
                    "status": str(status),
                    "executed": bool(executed),
                    "mission_id": str(getattr(proof, "mission_id", "") or "") if proof is not None else "",
                    "request_id": str(getattr(proof, "request_id", "") or "") if proof is not None else str(request.request_id or ""),
                    "run_id": str(getattr(proof, "run_id", "") or "") if proof is not None else str(request.run_id or ""),
                    "tool_call_id": str(getattr(proof, "tool_call_id", "") or "") if proof is not None else "",
                    "lifecycle_revision": int(getattr(proof, "lifecycle_revision", 0) or 0) if proof is not None else 0,
                    "proof_fingerprint": str(authorization.proof_fingerprint) if authorization is not None else "",
                    "snapshot_hash": str(authorization.snapshot_hash) if authorization is not None else "",
                    "snapshot_version": int(authorization.snapshot_version) if authorization is not None else 0,
                    "argument_fingerprint": canonical_execution_fingerprint(request.argument),
                    "raw_output_sha256": _sha256(raw),
                    "result_hash": _sha256(normalized),
                    "error_code": str(error.code.value) if error is not None else "",
                    "error_phase": str(error.phase.value) if error is not None else "",
                }
                return self._collect(request, record)
            except ToolAdapterError:
                raise
            except Exception as exc:
                raise ToolAdapterError(AdapterPhase.COLLECT_EVIDENCE, AdapterErrorCode.EVIDENCE_FAILED, "evidence collection failed: " + str(exc), tool=self.tool_name) from None
    
        def _collect(self, request: ToolAdapterRequest, record: dict[str, Any]) -> dict[str, Any]:
            """Pure evidence hook; subclasses may add descriptive fields only."""
            return dict(record)
    
        # -- Phase 8: cleanup (always runs; inert by contract) -------------------
    
        def cleanup(self, request: ToolAdapterRequest) -> None:
            """Inert cleanup hook. Runs exactly once per run() on every path.
    
            INV-ADP-7: cleanup receives no authorization, must never invoke the
            tool, the registry, or any handler, and must never repair a failure.
            """
    
        def _evidence_safe(
            self,
            request: ToolAdapterRequest,
            authorization: AdapterAuthorization | None,
            raw: Any,
            normalized: dict[str, Any] | None,
            error: ToolAdapterError | None,
            *,
            status: str,
            executed: bool,
        ) -> tuple[dict[str, Any], str]:
            """Collect evidence without ever raising (evidence failure is classified).
    
            A failing evidence hook must never crash the envelope, mask a primary
            error, or silently pass: on the success path the caller converts the
            returned error string into an EVIDENCE_FAILED result state.
            """
            try:
                return self.collect_evidence(request, authorization, raw, normalized, error, status=status, executed=executed), ""
            except ToolAdapterError as exc:
                return {}, str(exc)
            except Exception as exc:  # a misbehaving evidence hook is classified, never fatal
                return {}, str(ToolAdapterError(AdapterPhase.COLLECT_EVIDENCE, AdapterErrorCode.EVIDENCE_FAILED, str(exc), tool=str(request.tool or "")))
    
        # -- Orchestration -------------------------------------------------------
    
        def run(self, request: ToolAdapterRequest, *, dry_run: bool = False) -> AdapterResult:
            """Run the full contract in order. Returns a classified envelope.
    
            Every pre-execution rejection happens before tools.registry.execute;
            every failure is classified; cleanup always runs; no failure can be
            reported as success (INV-ADP-3, INV-ADP-7, INV-ADP-8).
            """
            authorization: AdapterAuthorization | None = None
            raw: Any = None
            normalized: dict[str, Any] | None = None
            executed = False
            error: ToolAdapterError | None = None
            evidence: dict[str, Any] = {}
            evidence_error = ""
            cleanup_ran = False
            cleanup_error = ""
            dry_run_plan: dict[str, Any] | None = None
            metadata: dict[str, Any] = {"adapter": type(self).__name__, "tool": str(request.tool or ""), "required_binary": self.required_binary}
            try:
                self.validate_input(request)
                authorization = self.authorize(request)
                prepared = self.prepare(request, authorization)
                if dry_run:
                    dry_run_plan = self.dry_run(request, authorization, prepared)
                    evidence, evidence_error = self._evidence_safe(request, authorization, None, None, None, status="DRY_RUN", executed=False)
                    if evidence_error and error is None:
                        error = ToolAdapterError(AdapterPhase.COLLECT_EVIDENCE, AdapterErrorCode.EVIDENCE_FAILED, evidence_error, tool=str(request.tool))
                        evidence_error = ""
                else:
                    try:
                        raw = self.execute(request, authorization, prepared)
                        executed = True
                    except ToolAdapterError as exc:
                        if exc.code is AdapterErrorCode.TIMEOUT or exc.code is AdapterErrorCode.EXECUTION_FAILED:
                            executed = True  # the handler was submitted before the failure
                        raise
                    normalized = self.normalize_output(raw)
                    evidence, evidence_error = self._evidence_safe(request, authorization, raw, normalized, None, status="SUCCESS", executed=executed)
                    if evidence_error and error is None:
                        error = ToolAdapterError(AdapterPhase.COLLECT_EVIDENCE, AdapterErrorCode.EVIDENCE_FAILED, evidence_error, tool=str(request.tool))
                        evidence_error = ""
            except ToolAdapterError as exc:
                error = exc
                evidence, evidence_retry_error = self._evidence_safe(request, authorization, raw, normalized, exc, status="ERROR", executed=executed)
                if evidence_retry_error:
                    evidence_error = (evidence_error + " | " if evidence_error else "") + evidence_retry_error
            finally:
                try:
                    self.cleanup(request)
                    cleanup_ran = True
                except ToolAdapterError as exc:
                    cleanup_error = str(exc)
                except Exception as exc:
                    cleanup_error = "CLEANUP_FAILED: " + str(exc)
            if error is None and cleanup_error:
                error = ToolAdapterError(AdapterPhase.CLEANUP, AdapterErrorCode.CLEANUP_FAILED, cleanup_error, tool=str(request.tool))
            if error is not None:
                status = "ERROR"
            elif dry_run:
                status = "DRY_RUN"
            else:
                status = "SUCCESS"
            return AdapterResult(
                tool=str(request.tool),
                execution_class=str(request.execution_class),
                status=status,
                dry_run=bool(dry_run),
                executed=executed,
                raw_output=raw,
                normalized_output=normalized,
                evidence=dict(evidence),
                metadata=dict(metadata, dry_run_plan=dict(dry_run_plan)) if dry_run_plan is not None else dict(metadata, evidence_error=evidence_error),
                error_state=dict(error.to_dict()) if error is not None else {},
                cleanup_ran=cleanup_ran,
                cleanup_error=cleanup_error,
            )
    
    
    def _sha256(value: Any) -> str:
        payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()
    
    
    class LocalSystemInfoAdapter(ToolAdapter):
        """First concrete adapter: the registered local_system_info tool.
    
        Local, informational, read-only, non-destructive. Pure local runtime
        (required_binary is None): the tool reads local system information through
        its existing registry handler. It reaches execution only through
        tools.registry.execute with a mission-bound or owner-direct proof.
        """
    
        tool_name = "local_system_info"
    
    
    LOCAL_SYSTEM_INFO_ADAPTER = LocalSystemInfoAdapter()
3 failed, 1133 passed, 1 skipped in 14.42s
