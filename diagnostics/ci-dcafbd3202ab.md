# CI run dcafbd3202ab
result: SUCCESS

## compileall output (last 100 lines)

## pytest output (last 400 lines)
    return _bootstrap._gcd_import(name[level:], package, level)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
tests/test_phase3_context.py:15: in <module>
    from agent.context import (
agent/context.py:33: in <module>
    from tools.registry import REGISTRY, get_tool
E   ImportError: cannot import name 'REGISTRY' from 'tools.registry' (/home/runner/work/cybersentinel/cybersentinel/tools/registry.py)
________________ ERROR collecting tests/test_phase5e_runtime.py ________________
ImportError while importing test module '/home/runner/work/cybersentinel/cybersentinel/tests/test_phase5e_runtime.py'.
Hint: make sure your test modules/packages have valid Python names.
Traceback:
/opt/hostedtoolcache/Python/3.13.18/x64/lib/python3.13/importlib/__init__.py:88: in import_module
    return _bootstrap._gcd_import(name[level:], package, level)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
tests/test_phase5e_runtime.py:13: in <module>
    from agent.task_runtime import AgentTaskRuntime
agent/task_runtime.py:10: in <module>
    from agent.context import ContextEngine, ExecutionState, RuntimeLimits
agent/context.py:33: in <module>
    from tools.registry import REGISTRY, get_tool
E   ImportError: cannot import name 'REGISTRY' from 'tools.registry' (/home/runner/work/cybersentinel/cybersentinel/tools/registry.py)
____________ ERROR collecting tests/test_phase6c_scope_firewall.py _____________
ImportError while importing test module '/home/runner/work/cybersentinel/cybersentinel/tests/test_phase6c_scope_firewall.py'.
Hint: make sure your test modules/packages have valid Python names.
Traceback:
/opt/hostedtoolcache/Python/3.13.18/x64/lib/python3.13/importlib/__init__.py:88: in import_module
    return _bootstrap._gcd_import(name[level:], package, level)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
tests/test_phase6c_scope_firewall.py:9: in <module>
    from agent.task_runtime import AgentTaskRuntime
agent/task_runtime.py:10: in <module>
    from agent.context import ContextEngine, ExecutionState, RuntimeLimits
agent/context.py:33: in <module>
    from tools.registry import REGISTRY, get_tool
E   ImportError: cannot import name 'REGISTRY' from 'tools.registry' (/home/runner/work/cybersentinel/cybersentinel/tools/registry.py)
_________________ ERROR collecting tests/test_phase6k5_core.py _________________
ImportError while importing test module '/home/runner/work/cybersentinel/cybersentinel/tests/test_phase6k5_core.py'.
Hint: make sure your test modules/packages have valid Python names.
Traceback:
/opt/hostedtoolcache/Python/3.13.18/x64/lib/python3.13/importlib/__init__.py:88: in import_module
    return _bootstrap._gcd_import(name[level:], package, level)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
tests/test_phase6k5_core.py:19: in <module>
    from security.authorization import authorize_plan
security/authorization.py:6: in <module>
    from tools.registry import KNOWN_TOOLS, MAX_ARG_LENGTH, get_tool
E   ImportError: cannot import name 'KNOWN_TOOLS' from 'tools.registry' (/home/runner/work/cybersentinel/cybersentinel/tools/registry.py)
_______________ ERROR collecting tests/test_phase6k6_unified.py ________________
ImportError while importing test module '/home/runner/work/cybersentinel/cybersentinel/tests/test_phase6k6_unified.py'.
Hint: make sure your test modules/packages have valid Python names.
Traceback:
/opt/hostedtoolcache/Python/3.13.18/x64/lib/python3.13/importlib/__init__.py:88: in import_module
    return _bootstrap._gcd_import(name[level:], package, level)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
tests/test_phase6k6_unified.py:13: in <module>
    from agent.task_runtime import AgentTaskRuntime
agent/task_runtime.py:10: in <module>
    from agent.context import ContextEngine, ExecutionState, RuntimeLimits
agent/context.py:33: in <module>
    from tools.registry import REGISTRY, get_tool
E   ImportError: cannot import name 'REGISTRY' from 'tools.registry' (/home/runner/work/cybersentinel/cybersentinel/tools/registry.py)
_______________ ERROR collecting tests/test_poisoning_battery.py _______________
ImportError while importing test module '/home/runner/work/cybersentinel/cybersentinel/tests/test_poisoning_battery.py'.
Hint: make sure your test modules/packages have valid Python names.
Traceback:
/opt/hostedtoolcache/Python/3.13.18/x64/lib/python3.13/importlib/__init__.py:88: in import_module
    return _bootstrap._gcd_import(name[level:], package, level)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
tests/test_poisoning_battery.py:21: in <module>
    from security.authorization import authorize_plan, authorize_tool
security/authorization.py:6: in <module>
    from tools.registry import KNOWN_TOOLS, MAX_ARG_LENGTH, get_tool
E   ImportError: cannot import name 'KNOWN_TOOLS' from 'tools.registry' (/home/runner/work/cybersentinel/cybersentinel/tools/registry.py)
______________ ERROR collecting tests/test_public_web_boundary.py ______________
ImportError while importing test module '/home/runner/work/cybersentinel/cybersentinel/tests/test_public_web_boundary.py'.
Hint: make sure your test modules/packages have valid Python names.
Traceback:
/opt/hostedtoolcache/Python/3.13.18/x64/lib/python3.13/importlib/__init__.py:88: in import_module
    return _bootstrap._gcd_import(name[level:], package, level)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
tests/test_public_web_boundary.py:11: in <module>
    import bridge
bridge.py:18: in <module>
    from core.engine import RUNTIME, status
core/engine.py:8: in <module>
    from agent.runtime import AgentRuntime
agent/runtime.py:7: in <module>
    from security.authorization import authorize_plan, public_plan
security/authorization.py:6: in <module>
    from tools.registry import KNOWN_TOOLS, MAX_ARG_LENGTH, get_tool
E   ImportError: cannot import name 'KNOWN_TOOLS' from 'tools.registry' (/home/runner/work/cybersentinel/cybersentinel/tools/registry.py)
__________ ERROR collecting tests/test_r1_closure_characterization.py __________
ImportError while importing test module '/home/runner/work/cybersentinel/cybersentinel/tests/test_r1_closure_characterization.py'.
Hint: make sure your test modules/packages have valid Python names.
Traceback:
/opt/hostedtoolcache/Python/3.13.18/x64/lib/python3.13/importlib/__init__.py:88: in import_module
    return _bootstrap._gcd_import(name[level:], package, level)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
tests/test_r1_closure_characterization.py:20: in <module>
    from agent.agent_core import AgentCore
agent/agent_core.py:9: in <module>
    from security.authorization import authorize_tool
security/authorization.py:6: in <module>
    from tools.registry import KNOWN_TOOLS, MAX_ARG_LENGTH, get_tool
E   ImportError: cannot import name 'KNOWN_TOOLS' from 'tools.registry' (/home/runner/work/cybersentinel/cybersentinel/tools/registry.py)
__________ ERROR collecting tests/test_r1_intent_characterization.py ___________
ImportError while importing test module '/home/runner/work/cybersentinel/cybersentinel/tests/test_r1_intent_characterization.py'.
Hint: make sure your test modules/packages have valid Python names.
Traceback:
/opt/hostedtoolcache/Python/3.13.18/x64/lib/python3.13/importlib/__init__.py:88: in import_module
    return _bootstrap._gcd_import(name[level:], package, level)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
tests/test_r1_intent_characterization.py:62: in <module>
    import tools.registry as registry_module
tools/__init__.py:1: in <module>
    from .registry import KNOWN_TOOLS, REGISTRY, ToolSpec, build_registry, execute, get_tool, tool_definitions
E   ImportError: cannot import name 'KNOWN_TOOLS' from 'tools.registry' (/home/runner/work/cybersentinel/cybersentinel/tools/registry.py)
_______________ ERROR collecting tests/test_r1_intent_engine.py ________________
ImportError while importing test module '/home/runner/work/cybersentinel/cybersentinel/tests/test_r1_intent_engine.py'.
Hint: make sure your test modules/packages have valid Python names.
Traceback:
/opt/hostedtoolcache/Python/3.13.18/x64/lib/python3.13/importlib/__init__.py:88: in import_module
    return _bootstrap._gcd_import(name[level:], package, level)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
tests/test_r1_intent_engine.py:23: in <module>
    from agent.agent_core import AgentCore
agent/agent_core.py:9: in <module>
    from security.authorization import authorize_tool
security/authorization.py:6: in <module>
    from tools.registry import KNOWN_TOOLS, MAX_ARG_LENGTH, get_tool
E   ImportError: cannot import name 'KNOWN_TOOLS' from 'tools.registry' (/home/runner/work/cybersentinel/cybersentinel/tools/registry.py)
_______________ ERROR collecting tests/test_scoped_dns_lookup.py _______________
ImportError while importing test module '/home/runner/work/cybersentinel/cybersentinel/tests/test_scoped_dns_lookup.py'.
Hint: make sure your test modules/packages have valid Python names.
Traceback:
/opt/hostedtoolcache/Python/3.13.18/x64/lib/python3.13/importlib/__init__.py:88: in import_module
    return _bootstrap._gcd_import(name[level:], package, level)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
tests/test_scoped_dns_lookup.py:34: in <module>
    import tools.registry
tools/__init__.py:1: in <module>
    from .registry import KNOWN_TOOLS, REGISTRY, ToolSpec, build_registry, execute, get_tool, tool_definitions
E   ImportError: cannot import name 'KNOWN_TOOLS' from 'tools.registry' (/home/runner/work/cybersentinel/cybersentinel/tools/registry.py)
_______________ ERROR collecting tests/test_scoped_http_probe.py _______________
ImportError while importing test module '/home/runner/work/cybersentinel/cybersentinel/tests/test_scoped_http_probe.py'.
Hint: make sure your test modules/packages have valid Python names.
Traceback:
/opt/hostedtoolcache/Python/3.13.18/x64/lib/python3.13/importlib/__init__.py:88: in import_module
    return _bootstrap._gcd_import(name[level:], package, level)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
tests/test_scoped_http_probe.py:20: in <module>
    import tools.registry
tools/__init__.py:1: in <module>
    from .registry import KNOWN_TOOLS, REGISTRY, ToolSpec, build_registry, execute, get_tool, tool_definitions
E   ImportError: cannot import name 'KNOWN_TOOLS' from 'tools.registry' (/home/runner/work/cybersentinel/cybersentinel/tools/registry.py)
____________ ERROR collecting tests/test_scoped_port_observation.py ____________
ImportError while importing test module '/home/runner/work/cybersentinel/cybersentinel/tests/test_scoped_port_observation.py'.
Hint: make sure your test modules/packages have valid Python names.
Traceback:
/opt/hostedtoolcache/Python/3.13.18/x64/lib/python3.13/importlib/__init__.py:88: in import_module
    return _bootstrap._gcd_import(name[level:], package, level)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
tests/test_scoped_port_observation.py:35: in <module>
    import tools.registry
tools/__init__.py:1: in <module>
    from .registry import KNOWN_TOOLS, REGISTRY, ToolSpec, build_registry, execute, get_tool, tool_definitions
E   ImportError: cannot import name 'KNOWN_TOOLS' from 'tools.registry' (/home/runner/work/cybersentinel/cybersentinel/tools/registry.py)
____________ ERROR collecting tests/test_scoped_tech_fingerprint.py ____________
ImportError while importing test module '/home/runner/work/cybersentinel/cybersentinel/tests/test_scoped_tech_fingerprint.py'.
Hint: make sure your test modules/packages have valid Python names.
Traceback:
/opt/hostedtoolcache/Python/3.13.18/x64/lib/python3.13/importlib/__init__.py:88: in import_module
    return _bootstrap._gcd_import(name[level:], package, level)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
tests/test_scoped_tech_fingerprint.py:37: in <module>
    import tools.registry
tools/__init__.py:1: in <module>
    from .registry import KNOWN_TOOLS, REGISTRY, ToolSpec, build_registry, execute, get_tool, tool_definitions
E   ImportError: cannot import name 'KNOWN_TOOLS' from 'tools.registry' (/home/runner/work/cybersentinel/cybersentinel/tools/registry.py)
____________ ERROR collecting tests/test_scoped_tls_observation.py _____________
ImportError while importing test module '/home/runner/work/cybersentinel/cybersentinel/tests/test_scoped_tls_observation.py'.
Hint: make sure your test modules/packages have valid Python names.
Traceback:
/opt/hostedtoolcache/Python/3.13.18/x64/lib/python3.13/importlib/__init__.py:88: in import_module
    return _bootstrap._gcd_import(name[level:], package, level)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
tests/test_scoped_tls_observation.py:37: in <module>
    import tools.registry
tools/__init__.py:1: in <module>
    from .registry import KNOWN_TOOLS, REGISTRY, ToolSpec, build_registry, execute, get_tool, tool_definitions
E   ImportError: cannot import name 'KNOWN_TOOLS' from 'tools.registry' (/home/runner/work/cybersentinel/cybersentinel/tools/registry.py)
_____________ ERROR collecting tests/test_security_and_runtime.py ______________
ImportError while importing test module '/home/runner/work/cybersentinel/cybersentinel/tests/test_security_and_runtime.py'.
Hint: make sure your test modules/packages have valid Python names.
Traceback:
/opt/hostedtoolcache/Python/3.13.18/x64/lib/python3.13/importlib/__init__.py:88: in import_module
    return _bootstrap._gcd_import(name[level:], package, level)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
tests/test_security_and_runtime.py:3: in <module>
    from agent.runtime import AgentRuntime
agent/runtime.py:7: in <module>
    from security.authorization import authorize_plan, public_plan
security/authorization.py:6: in <module>
    from tools.registry import KNOWN_TOOLS, MAX_ARG_LENGTH, get_tool
E   ImportError: cannot import name 'KNOWN_TOOLS' from 'tools.registry' (/home/runner/work/cybersentinel/cybersentinel/tools/registry.py)
___________ ERROR collecting tests/test_security_characterization.py ___________
ImportError while importing test module '/home/runner/work/cybersentinel/cybersentinel/tests/test_security_characterization.py'.
Hint: make sure your test modules/packages have valid Python names.
Traceback:
/opt/hostedtoolcache/Python/3.13.18/x64/lib/python3.13/importlib/__init__.py:88: in import_module
    return _bootstrap._gcd_import(name[level:], package, level)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
tests/test_security_characterization.py:44: in <module>
    from agent.agent_core import AgentCore
agent/agent_core.py:9: in <module>
    from security.authorization import authorize_tool
security/authorization.py:6: in <module>
    from tools.registry import KNOWN_TOOLS, MAX_ARG_LENGTH, get_tool
E   ImportError: cannot import name 'KNOWN_TOOLS' from 'tools.registry' (/home/runner/work/cybersentinel/cybersentinel/tools/registry.py)
________ ERROR collecting tests/test_security_integrity_adversarial.py _________
ImportError while importing test module '/home/runner/work/cybersentinel/cybersentinel/tests/test_security_integrity_adversarial.py'.
Hint: make sure your test modules/packages have valid Python names.
Traceback:
/opt/hostedtoolcache/Python/3.13.18/x64/lib/python3.13/importlib/__init__.py:88: in import_module
    return _bootstrap._gcd_import(name[level:], package, level)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
tests/test_security_integrity_adversarial.py:19: in <module>
    from tools.registry import execute
E   ImportError: cannot import name 'execute' from 'tools.registry' (/home/runner/work/cybersentinel/cybersentinel/tools/registry.py)
____________ ERROR collecting tests/test_security_tool_inventory.py ____________
ImportError while importing test module '/home/runner/work/cybersentinel/cybersentinel/tests/test_security_tool_inventory.py'.
Hint: make sure your test modules/packages have valid Python names.
Traceback:
/opt/hostedtoolcache/Python/3.13.18/x64/lib/python3.13/importlib/__init__.py:88: in import_module
    return _bootstrap._gcd_import(name[level:], package, level)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
tests/test_security_tool_inventory.py:47: in <module>
    import tools.registry
tools/__init__.py:1: in <module>
    from .registry import KNOWN_TOOLS, REGISTRY, ToolSpec, build_registry, execute, get_tool, tool_definitions
E   ImportError: cannot import name 'KNOWN_TOOLS' from 'tools.registry' (/home/runner/work/cybersentinel/cybersentinel/tools/registry.py)
___________ ERROR collecting tests/test_task_intent_authorization.py ___________
ImportError while importing test module '/home/runner/work/cybersentinel/cybersentinel/tests/test_task_intent_authorization.py'.
Hint: make sure your test modules/packages have valid Python names.
Traceback:
/opt/hostedtoolcache/Python/3.13.18/x64/lib/python3.13/importlib/__init__.py:88: in import_module
    return _bootstrap._gcd_import(name[level:], package, level)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
tests/test_task_intent_authorization.py:24: in <module>
    from security.owner_budget import OwnerAuthorizedToolBudget
security/owner_budget.py:20: in <module>
    from tools.registry import KNOWN_TOOLS
E   ImportError: cannot import name 'KNOWN_TOOLS' from 'tools.registry' (/home/runner/work/cybersentinel/cybersentinel/tools/registry.py)
_________________ ERROR collecting tests/test_tool_adapter.py __________________
ImportError while importing test module '/home/runner/work/cybersentinel/cybersentinel/tests/test_tool_adapter.py'.
Hint: make sure your test modules/packages have valid Python names.
Traceback:
/opt/hostedtoolcache/Python/3.13.18/x64/lib/python3.13/importlib/__init__.py:88: in import_module
    return _bootstrap._gcd_import(name[level:], package, level)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
tests/test_tool_adapter.py:39: in <module>
    import tools.registry
tools/__init__.py:1: in <module>
    from .registry import KNOWN_TOOLS, REGISTRY, ToolSpec, build_registry, execute, get_tool, tool_definitions
E   ImportError: cannot import name 'KNOWN_TOOLS' from 'tools.registry' (/home/runner/work/cybersentinel/cybersentinel/tools/registry.py)
_________ ERROR collecting tests/test_tool_adapter_resolved_binary.py __________
ImportError while importing test module '/home/runner/work/cybersentinel/cybersentinel/tests/test_tool_adapter_resolved_binary.py'.
Hint: make sure your test modules/packages have valid Python names.
Traceback:
/opt/hostedtoolcache/Python/3.13.18/x64/lib/python3.13/importlib/__init__.py:88: in import_module
    return _bootstrap._gcd_import(name[level:], package, level)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
tests/test_tool_adapter_resolved_binary.py:24: in <module>
    import tools.registry
tools/__init__.py:1: in <module>
    from .registry import KNOWN_TOOLS, REGISTRY, ToolSpec, build_registry, execute, get_tool, tool_definitions
E   ImportError: cannot import name 'KNOWN_TOOLS' from 'tools.registry' (/home/runner/work/cybersentinel/cybersentinel/tools/registry.py)
_____________ ERROR collecting tests/test_tool_adapter_stage_c.py ______________
ImportError while importing test module '/home/runner/work/cybersentinel/cybersentinel/tests/test_tool_adapter_stage_c.py'.
Hint: make sure your test modules/packages have valid Python names.
Traceback:
/opt/hostedtoolcache/Python/3.13.18/x64/lib/python3.13/importlib/__init__.py:88: in import_module
    return _bootstrap._gcd_import(name[level:], package, level)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
tests/test_tool_adapter_stage_c.py:42: in <module>
    import tools.registry
tools/__init__.py:1: in <module>
    from .registry import KNOWN_TOOLS, REGISTRY, ToolSpec, build_registry, execute, get_tool, tool_definitions
E   ImportError: cannot import name 'KNOWN_TOOLS' from 'tools.registry' (/home/runner/work/cybersentinel/cybersentinel/tools/registry.py)
_______________ ERROR collecting tests/test_v44_architecture.py ________________
ImportError while importing test module '/home/runner/work/cybersentinel/cybersentinel/tests/test_v44_architecture.py'.
Hint: make sure your test modules/packages have valid Python names.
Traceback:
/opt/hostedtoolcache/Python/3.13.18/x64/lib/python3.13/importlib/__init__.py:88: in import_module
    return _bootstrap._gcd_import(name[level:], package, level)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
tests/test_v44_architecture.py:4: in <module>
    from agent.runtime import AgentRuntime
agent/runtime.py:7: in <module>
    from security.authorization import authorize_plan, public_plan
security/authorization.py:6: in <module>
    from tools.registry import KNOWN_TOOLS, MAX_ARG_LENGTH, get_tool
E   ImportError: cannot import name 'KNOWN_TOOLS' from 'tools.registry' (/home/runner/work/cybersentinel/cybersentinel/tools/registry.py)
________________ ERROR collecting tests/test_v45_adversarial.py ________________
ImportError while importing test module '/home/runner/work/cybersentinel/cybersentinel/tests/test_v45_adversarial.py'.
Hint: make sure your test modules/packages have valid Python names.
Traceback:
/opt/hostedtoolcache/Python/3.13.18/x64/lib/python3.13/importlib/__init__.py:88: in import_module
    return _bootstrap._gcd_import(name[level:], package, level)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
tests/test_v45_adversarial.py:7: in <module>
    from agent.runtime import AgentRuntime
agent/runtime.py:7: in <module>
    from security.authorization import authorize_plan, public_plan
security/authorization.py:6: in <module>
    from tools.registry import KNOWN_TOOLS, MAX_ARG_LENGTH, get_tool
E   ImportError: cannot import name 'KNOWN_TOOLS' from 'tools.registry' (/home/runner/work/cybersentinel/cybersentinel/tools/registry.py)
_________________ ERROR collecting tests/test_v46_lifecycle.py _________________
ImportError while importing test module '/home/runner/work/cybersentinel/cybersentinel/tests/test_v46_lifecycle.py'.
Hint: make sure your test modules/packages have valid Python names.
Traceback:
/opt/hostedtoolcache/Python/3.13.18/x64/lib/python3.13/importlib/__init__.py:88: in import_module
    return _bootstrap._gcd_import(name[level:], package, level)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
tests/test_v46_lifecycle.py:5: in <module>
    from tools import registry
tools/__init__.py:1: in <module>
    from .registry import KNOWN_TOOLS, REGISTRY, ToolSpec, build_registry, execute, get_tool, tool_definitions
E   ImportError: cannot import name 'KNOWN_TOOLS' from 'tools.registry' (/home/runner/work/cybersentinel/cybersentinel/tools/registry.py)
_________________ ERROR collecting tests/test_v47_red_team.py __________________
ImportError while importing test module '/home/runner/work/cybersentinel/cybersentinel/tests/test_v47_red_team.py'.
Hint: make sure your test modules/packages have valid Python names.
Traceback:
/opt/hostedtoolcache/Python/3.13.18/x64/lib/python3.13/importlib/__init__.py:88: in import_module
    return _bootstrap._gcd_import(name[level:], package, level)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
tests/test_v47_red_team.py:3: in <module>
    from agent.runtime import AgentRuntime
agent/runtime.py:7: in <module>
    from security.authorization import authorize_plan, public_plan
security/authorization.py:6: in <module>
    from tools.registry import KNOWN_TOOLS, MAX_ARG_LENGTH, get_tool
E   ImportError: cannot import name 'KNOWN_TOOLS' from 'tools.registry' (/home/runner/work/cybersentinel/cybersentinel/tools/registry.py)
=========================== short test summary info ============================
ERROR tests/test_agent_adaptive_loop.py
ERROR tests/test_agent_core_integration.py
ERROR tests/test_agent_platform.py
ERROR tests/test_autonomous_foundation.py
ERROR tests/test_b3_c4b_execution_plan_runtime.py
ERROR tests/test_b3_c5_budget_intersection.py
ERROR tests/test_b3_c5_final_hardening.py
ERROR tests/test_b3_c5_owner_direct_binding.py
ERROR tests/test_b3_c5_run_binding.py
ERROR tests/test_b3_c5_second_pass_attacker_review.py
ERROR tests/test_b3_execution_plan_characterization.py
ERROR tests/test_b3_execution_plan_intersection.py
ERROR tests/test_b3_intent_ladder_characterization.py
ERROR tests/test_boolean_trust_battery.py
ERROR tests/test_directive_acceptance.py
ERROR tests/test_execution_proof_boundary.py
ERROR tests/test_governed_execution.py
ERROR tests/test_local_artifact_metadata.py
ERROR tests/test_local_binary_analysis.py
ERROR tests/test_local_string_extraction.py
ERROR tests/test_message0003_auth.py
ERROR tests/test_model_benchmark.py
ERROR tests/test_offensive_bridge.py
ERROR tests/test_owner_budget_authorization.py
ERROR tests/test_owner_master_invariants.py
ERROR tests/test_phase21_canonical_paths.py
ERROR tests/test_phase21_restart_authorization.py
ERROR tests/test_phase3_context.py
ERROR tests/test_phase5e_runtime.py
ERROR tests/test_phase6c_scope_firewall.py
ERROR tests/test_phase6k5_core.py
ERROR tests/test_phase6k6_unified.py
ERROR tests/test_poisoning_battery.py
ERROR tests/test_public_web_boundary.py
ERROR tests/test_r1_closure_characterization.py
ERROR tests/test_r1_intent_characterization.py
ERROR tests/test_r1_intent_engine.py
ERROR tests/test_scoped_dns_lookup.py
ERROR tests/test_scoped_http_probe.py
ERROR tests/test_scoped_port_observation.py
ERROR tests/test_scoped_tech_fingerprint.py
ERROR tests/test_scoped_tls_observation.py
ERROR tests/test_security_and_runtime.py
ERROR tests/test_security_characterization.py
ERROR tests/test_security_integrity_adversarial.py
ERROR tests/test_security_tool_inventory.py
ERROR tests/test_task_intent_authorization.py
ERROR tests/test_tool_adapter.py
ERROR tests/test_tool_adapter_resolved_binary.py
ERROR tests/test_tool_adapter_stage_c.py
ERROR tests/test_v44_architecture.py
ERROR tests/test_v45_adversarial.py
ERROR tests/test_v46_lifecycle.py
ERROR tests/test_v47_red_team.py
!!!!!!!!!!!!!!!!!!! Interrupted: 54 errors during collection !!!!!!!!!!!!!!!!!!!
54 errors in 3.75s
