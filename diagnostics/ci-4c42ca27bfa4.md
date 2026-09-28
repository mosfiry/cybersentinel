# CI run 4c42ca27bfa4
result: FAILURE

## pytest failed (exit 2)

==================================== ERRORS ====================================
__________ ERROR collecting tests/test_authority_no_platform_tier.py ___________
ImportError while importing test module '/home/runner/work/cybersentinel/cybersentinel/tests/test_authority_no_platform_tier.py'.
Hint: make sure your test modules/packages have valid Python names.
Traceback:
/opt/hostedtoolcache/Python/3.13.15/x64/lib/python3.13/importlib/__init__.py:88: in import_module
    return _bootstrap._gcd_import(name[level:], package, level)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
tests/test_authority_no_platform_tier.py:13: in <module>
    from security.authority import (
E   ImportError: cannot import name 'application_policy_order_guard' from 'security.authority' (/home/runner/work/cybersentinel/cybersentinel/security/authority.py)
=========================== short test summary info ============================
ERROR tests/test_authority_no_platform_tier.py
!!!!!!!!!!!!!!!!!!!! Interrupted: 1 error during collection !!!!!!!!!!!!!!!!!!!!
1 error in 1.99s
