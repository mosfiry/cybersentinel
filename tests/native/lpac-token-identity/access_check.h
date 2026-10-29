#ifndef CYBERSENTINEL_LPAC_TOKEN_IDENTITY_ACCESS_CHECK_H
#define CYBERSENTINEL_LPAC_TOKEN_IDENTITY_ACCESS_CHECK_H

#include <windows.h>
#include <sddl.h>

#define CS_LPAC_ACCESS_ALL_APPLICATION_PACKAGES 0x00000001UL
#define CS_LPAC_ACCESS_ALL_RESTRICTED_APPLICATION_PACKAGES 0x00000002UL
#define CS_LPAC_ACCESS_NORMAL_APPCONTAINER \
    (CS_LPAC_ACCESS_ALL_APPLICATION_PACKAGES | CS_LPAC_ACCESS_ALL_RESTRICTED_APPLICATION_PACKAGES)
#define CS_LPAC_ACCESS_LESS_PRIVILEGED \
    CS_LPAC_ACCESS_ALL_RESTRICTED_APPLICATION_PACKAGES
#define CS_LPAC_ACCESS_PRIVILEGE_BUFFER_INITIAL 4096UL
#define CS_LPAC_ACCESS_PRIVILEGE_BUFFER_MAX 65536UL

typedef struct CsLpacAccessCheckResult {
    BOOL api_succeeded;
    BOOL access_granted;
    DWORD granted_access;
    DWORD win32_error;
} CsLpacAccessCheckResult;

/*
 * This is a compositional diagnostic, not a Windows IsLPAC API. The caller
 * must first establish AppContainer identity and must compare the returned
 * access mask against known ordinary-AppContainer and LPAC controls on Windows.
 */
static BOOL cs_lpac_access_check(HANDLE primary_token, CsLpacAccessCheckResult *result)
{
    static const wchar_t security_descriptor_sddl[] =
        L"O:SYG:SYD:P"
        L"(A;;0x00000001;;;S-1-15-2-1)"
        L"(A;;0x00000002;;;S-1-15-2-2)";
    HANDLE impersonation_token = NULL;
    PSECURITY_DESCRIPTOR security_descriptor = NULL;
    BYTE *privilege_buffer = NULL;
    DWORD privilege_buffer_size = CS_LPAC_ACCESS_PRIVILEGE_BUFFER_INITIAL;
    DWORD error = ERROR_SUCCESS;
    BOOL completed = FALSE;
    BOOL return_value = FALSE;
    GENERIC_MAPPING generic_mapping = { 0, 0, 0, 0 };

    if (!result) return FALSE;
    ZeroMemory(result, sizeof(*result));
    result->win32_error = ERROR_INVALID_PARAMETER;
    if (!primary_token) return FALSE;

    if (!DuplicateToken(primary_token, SecurityImpersonation, &impersonation_token)) {
        error = GetLastError();
        goto done;
    }
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            security_descriptor_sddl, SDDL_REVISION_1, &security_descriptor, NULL)) {
        error = GetLastError();
        goto done;
    }
    privilege_buffer = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                          privilege_buffer_size);
    if (!privilege_buffer) {
        error = ERROR_NOT_ENOUGH_MEMORY;
        goto done;
    }

    for (;;) {
        DWORD privilege_set_length = privilege_buffer_size;
        DWORD granted_access = 0;
        BOOL access_granted = FALSE;
        BOOL ok;
        DWORD required_size;
        BYTE *larger_buffer;

        SetLastError(ERROR_SUCCESS);
        ok = AccessCheck(security_descriptor, impersonation_token, MAXIMUM_ALLOWED,
                         &generic_mapping, (PPRIVILEGE_SET)privilege_buffer,
                         &privilege_set_length, &granted_access, &access_granted);
        if (ok) {
            result->api_succeeded = TRUE;
            result->access_granted = access_granted;
            result->granted_access = granted_access;
            completed = TRUE;
            break;
        }

        error = GetLastError();
        required_size = privilege_set_length;
        if (error != ERROR_INSUFFICIENT_BUFFER || required_size <= privilege_buffer_size ||
            required_size > CS_LPAC_ACCESS_PRIVILEGE_BUFFER_MAX) {
            break;
        }
        larger_buffer = (BYTE *)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                             privilege_buffer, required_size);
        if (!larger_buffer) {
            error = ERROR_NOT_ENOUGH_MEMORY;
            break;
        }
        privilege_buffer = larger_buffer;
        privilege_buffer_size = required_size;
    }

done:
    if (privilege_buffer && !HeapFree(GetProcessHeap(), 0, privilege_buffer) &&
        error == ERROR_SUCCESS) {
        error = ERROR_NOT_ENOUGH_MEMORY;
        completed = FALSE;
    }
    if (security_descriptor && LocalFree(security_descriptor) != NULL &&
        error == ERROR_SUCCESS) {
        error = ERROR_INVALID_SECURITY_DESCR;
        completed = FALSE;
    }
    if (impersonation_token && !CloseHandle(impersonation_token) &&
        error == ERROR_SUCCESS) {
        error = GetLastError();
        completed = FALSE;
    }
    result->win32_error = completed ? ERROR_SUCCESS :
        (error ? error : ERROR_GEN_FAILURE);
    return_value = completed;
    return return_value;
}

#endif
