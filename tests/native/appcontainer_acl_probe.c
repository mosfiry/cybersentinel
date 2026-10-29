#define _WIN32_WINNT 0x0A00
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <userenv.h>
#include <sddl.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <stdint.h>
#include <string.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "userenv.lib")

#ifndef PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES
#define PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES 0x00020009
#endif
#ifndef PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY
#define PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY 0x0002000F
#endif
#ifndef PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT
#define PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT 0x00000001
#endif
#ifndef TokenIsLessPrivilegedAppContainer
#define TokenIsLessPrivilegedAppContainer ((TOKEN_INFORMATION_CLASS)46)
#endif

#define MAX_REPORT 2048
#define CHILD_TIMEOUT_MS 30000
#define TOKEN_INFO_MAX_BYTES 65536U

typedef struct ProbeResult {
    const wchar_t *name;
    BOOL ok;
    DWORD error;
} ProbeResult;

typedef struct TokenVerification {
    BOOL is_appcontainer;
    BOOL is_lpac;
    BOOL expected_sid_match;
    BOOL low_integrity;
    BOOL zero_capabilities;
    BOOL token_is_appcontainer_query_succeeded;
    BOOL token_is_lpac_query_succeeded;
    DWORD token_is_appcontainer_return_length;
    DWORD token_is_appcontainer_api_error;
    DWORD token_is_lpac_return_length;
    DWORD token_is_lpac_api_error;
    const wchar_t *failure_stage;
    DWORD api_error;
    DWORD return_length;
} TokenVerification;

typedef struct SecurityCapabilitiesCompat {
    PSID AppContainerSid;
    PSID *Capabilities;
    DWORD CapabilityCount;
    DWORD Reserved;
} SecurityCapabilitiesCompat;

typedef struct ProbeJobBasicLimitInformation {
    LARGE_INTEGER PerProcessUserTimeLimit;
    LARGE_INTEGER PerJobUserTimeLimit;
    DWORD LimitFlags;
    DWORD PaddingAfterLimitFlags;
    SIZE_T MinimumWorkingSetSize;
    SIZE_T MaximumWorkingSetSize;
    DWORD ActiveProcessLimit;
    DWORD PaddingAfterActiveProcessLimit;
    ULONG_PTR Affinity;
    DWORD PriorityClass;
    DWORD SchedulingClass;
} ProbeJobBasicLimitInformation;

typedef struct ProbeIoCounters {
    ULONGLONG ReadOperationCount, WriteOperationCount, OtherOperationCount;
    ULONGLONG ReadTransferCount, WriteTransferCount, OtherTransferCount;
} ProbeIoCounters;

typedef struct ProbeJobExtendedLimitInformation {
    ProbeJobBasicLimitInformation BasicLimitInformation;
    ProbeIoCounters IoInfo;
    SIZE_T ProcessMemoryLimit, JobMemoryLimit, PeakProcessMemoryUsed, PeakJobMemoryUsed;
} ProbeJobExtendedLimitInformation;

static int fail(const wchar_t *where, DWORD error) {
    fwprintf(stderr, L"probe failure: %ls (%lu)\n", where, (unsigned long)error);
    return 20;
}

static BOOL token_verification_fail(TokenVerification *verification,
                                    const wchar_t *stage, DWORD error, DWORD return_length) {
    verification->failure_stage = stage;
    verification->api_error = error ? error : ERROR_INVALID_DATA;
    verification->return_length = return_length;
    return FALSE;
}

static void report_token_diagnostic(BOOL verified, const TokenVerification *checks) {
    fwprintf(stderr,
        L"lpac_token_diagnostic: {\"version\":1,\"scope\":\"broker_only\",\"token_verified\":%ls,"
        L"\"is_appcontainer\":%ls,\"is_lpac\":%ls,\"low_integrity\":%ls,"
        L"\"expected_sid_match\":%ls,\"zero_capabilities\":%ls,"
        L"\"token_is_appcontainer_query_succeeded\":%ls,\"token_is_appcontainer_return_length\":%lu,"
        L"\"token_is_appcontainer_api_error\":%lu,\"token_is_lpac_query_succeeded\":%ls,"
        L"\"token_is_lpac_return_length\":%lu,\"token_is_lpac_api_error\":%lu,"
        L"\"token_failure_stage\":\"%ls\",\"token_api_error\":%lu,\"token_return_length\":%lu}\n",
        verified ? L"true" : L"false",
        checks->is_appcontainer ? L"true" : L"false",
        checks->is_lpac ? L"true" : L"false",
        checks->low_integrity ? L"true" : L"false",
        checks->expected_sid_match ? L"true" : L"false",
        checks->zero_capabilities ? L"true" : L"false",
        checks->token_is_appcontainer_query_succeeded ? L"true" : L"false",
        (unsigned long)checks->token_is_appcontainer_return_length,
        (unsigned long)checks->token_is_appcontainer_api_error,
        checks->token_is_lpac_query_succeeded ? L"true" : L"false",
        (unsigned long)checks->token_is_lpac_return_length,
        (unsigned long)checks->token_is_lpac_api_error,
        checks->failure_stage ? checks->failure_stage : L"not_run",
        (unsigned long)checks->api_error,
        (unsigned long)checks->return_length);
}

static BOOL verify_token(HANDLE token, PSID expected_sid, TokenVerification *verification) {
    DWORD value = 0, bytes = 0, needed = 0, error = ERROR_SUCCESS;
    BYTE *buffer = NULL, *integrity_buffer = NULL, *capabilities_buffer = NULL;
    BOOL size_query_succeeded;
    BOOL ok = FALSE;
    if (!verification) return FALSE;
    ZeroMemory(verification, sizeof(*verification));
    verification->failure_stage = L"not_run";
    if (!token || !expected_sid || !IsValidSid(expected_sid)) {
        token_verification_fail(verification, L"invalid_token_or_expected_sid", ERROR_INVALID_DATA, 0);
        return FALSE;
    }

#define TOKEN_VERIFY_FAIL(stage, code, length) \
    do { token_verification_fail(verification, (stage), (code), (length)); goto done; } while (0)

    if (!GetTokenInformation(token, TokenIsAppContainer, &value, sizeof(value), &bytes)) {
        error = GetLastError();
        verification->token_is_appcontainer_api_error = error;
        TOKEN_VERIFY_FAIL(L"TokenIsAppContainer_query", error, bytes);
    }
    verification->token_is_appcontainer_query_succeeded = TRUE;
    verification->token_is_appcontainer_return_length = bytes;
    verification->return_length = bytes;
    if (bytes != sizeof(value)) TOKEN_VERIFY_FAIL(L"TokenIsAppContainer_return_length", ERROR_INVALID_DATA, bytes);
    verification->is_appcontainer = value != 0;
    if (!verification->is_appcontainer)
        TOKEN_VERIFY_FAIL(L"TokenIsAppContainer_false", ERROR_INVALID_DATA, bytes);

    value = 0;
    bytes = 0;
    if (!GetTokenInformation(token, TokenIsLessPrivilegedAppContainer, &value, sizeof(value), &bytes)) {
        error = GetLastError();
        verification->token_is_lpac_api_error = error;
        TOKEN_VERIFY_FAIL(L"TokenIsLessPrivilegedAppContainer_query", error, bytes);
    }
    verification->token_is_lpac_query_succeeded = TRUE;
    verification->token_is_lpac_return_length = bytes;
    verification->return_length = bytes;
    if (bytes != sizeof(value))
        TOKEN_VERIFY_FAIL(L"TokenIsLessPrivilegedAppContainer_return_length", ERROR_INVALID_DATA, bytes);
    verification->is_lpac = value != 0;
    if (!verification->is_lpac)
        TOKEN_VERIFY_FAIL(L"TokenIsLessPrivilegedAppContainer_false", ERROR_INVALID_DATA, bytes);

    needed = 0;
    size_query_succeeded = GetTokenInformation(token, TokenAppContainerSid, NULL, 0, &needed);
    error = size_query_succeeded ? ERROR_SUCCESS : GetLastError();
    verification->return_length = needed;
    if (!size_query_succeeded && error != ERROR_INSUFFICIENT_BUFFER)
        TOKEN_VERIFY_FAIL(L"TokenAppContainerSid_size_query", error, needed);
    if (needed < sizeof(TOKEN_APPCONTAINER_INFORMATION) || needed > TOKEN_INFO_MAX_BYTES)
        TOKEN_VERIFY_FAIL(L"TokenAppContainerSid_size", needed > TOKEN_INFO_MAX_BYTES ? ERROR_BUFFER_OVERFLOW : ERROR_INVALID_DATA, needed);
    buffer = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, needed);
    if (!buffer) TOKEN_VERIFY_FAIL(L"TokenAppContainerSid_allocate", ERROR_NOT_ENOUGH_MEMORY, needed);
    bytes = needed;
    if (!GetTokenInformation(token, TokenAppContainerSid, buffer, bytes, &needed)) {
        error = GetLastError();
        TOKEN_VERIFY_FAIL(L"TokenAppContainerSid_query", error, needed);
    }
    verification->return_length = needed;
    if (needed < sizeof(TOKEN_APPCONTAINER_INFORMATION))
        TOKEN_VERIFY_FAIL(L"TokenAppContainerSid_return_length", ERROR_INVALID_DATA, needed);
    {
        TOKEN_APPCONTAINER_INFORMATION *container_info = (TOKEN_APPCONTAINER_INFORMATION *)buffer;
        if (!container_info->TokenAppContainer || !IsValidSid(container_info->TokenAppContainer) ||
            !EqualSid(container_info->TokenAppContainer, expected_sid))
            TOKEN_VERIFY_FAIL(L"expected_sid_mismatch", ERROR_INVALID_DATA, needed);
        verification->expected_sid_match = TRUE;
    }

    needed = 0;
    size_query_succeeded = GetTokenInformation(token, TokenIntegrityLevel, NULL, 0, &needed);
    error = size_query_succeeded ? ERROR_SUCCESS : GetLastError();
    verification->return_length = needed;
    if (!size_query_succeeded && error != ERROR_INSUFFICIENT_BUFFER)
        TOKEN_VERIFY_FAIL(L"TokenIntegrityLevel_size_query", error, needed);
    if (needed < sizeof(TOKEN_MANDATORY_LABEL) || needed > TOKEN_INFO_MAX_BYTES)
        TOKEN_VERIFY_FAIL(L"TokenIntegrityLevel_size", needed > TOKEN_INFO_MAX_BYTES ? ERROR_BUFFER_OVERFLOW : ERROR_INVALID_DATA, needed);
    integrity_buffer = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, needed);
    if (!integrity_buffer) TOKEN_VERIFY_FAIL(L"TokenIntegrityLevel_allocate", ERROR_NOT_ENOUGH_MEMORY, needed);
    bytes = needed;
    if (!GetTokenInformation(token, TokenIntegrityLevel, integrity_buffer, bytes, &needed)) {
        error = GetLastError();
        TOKEN_VERIFY_FAIL(L"TokenIntegrityLevel_query", error, needed);
    }
    verification->return_length = needed;
    if (needed < sizeof(TOKEN_MANDATORY_LABEL))
        TOKEN_VERIFY_FAIL(L"TokenIntegrityLevel_return_length", ERROR_INVALID_DATA, needed);
    {
        TOKEN_MANDATORY_LABEL *integrity = (TOKEN_MANDATORY_LABEL *)integrity_buffer;
        SID_IDENTIFIER_AUTHORITY mandatory_authority = SECURITY_MANDATORY_LABEL_AUTHORITY;
        PSID_IDENTIFIER_AUTHORITY observed_authority;
        PUCHAR subauthority_count;
        DWORD *integrity_rid;
        if (!integrity->Label.Sid || !IsValidSid(integrity->Label.Sid) ||
            !(subauthority_count = GetSidSubAuthorityCount(integrity->Label.Sid)) || *subauthority_count == 0)
            TOKEN_VERIFY_FAIL(L"TokenIntegrityLevel_sid_invalid", ERROR_INVALID_DATA, needed);
        observed_authority = GetSidIdentifierAuthority(integrity->Label.Sid);
        if (!observed_authority || *subauthority_count != 1 ||
            memcmp(observed_authority, &mandatory_authority, sizeof(mandatory_authority)) != 0)
            TOKEN_VERIFY_FAIL(L"TokenIntegrityLevel_authority_invalid", ERROR_INVALID_DATA, needed);
        integrity_rid = GetSidSubAuthority(integrity->Label.Sid, (DWORD)(*subauthority_count - 1));
        if (!integrity_rid) TOKEN_VERIFY_FAIL(L"TokenIntegrityLevel_sid_invalid", ERROR_INVALID_DATA, needed);
        verification->low_integrity = *integrity_rid == SECURITY_MANDATORY_LOW_RID;
        if (!verification->low_integrity)
            TOKEN_VERIFY_FAIL(L"integrity_not_low", ERROR_INVALID_DATA, needed);
    }

    needed = 0;
    size_query_succeeded = GetTokenInformation(token, TokenCapabilities, NULL, 0, &needed);
    error = size_query_succeeded ? ERROR_SUCCESS : GetLastError();
    verification->return_length = needed;
    if (!size_query_succeeded && error != ERROR_INSUFFICIENT_BUFFER)
        TOKEN_VERIFY_FAIL(L"TokenCapabilities_size_query", error, needed);
    if (needed > TOKEN_INFO_MAX_BYTES)
        TOKEN_VERIFY_FAIL(L"TokenCapabilities_size", ERROR_BUFFER_OVERFLOW, needed);
    if (needed < sizeof(TOKEN_GROUPS)) needed = sizeof(TOKEN_GROUPS);
    capabilities_buffer = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, needed);
    if (!capabilities_buffer) TOKEN_VERIFY_FAIL(L"TokenCapabilities_allocate", ERROR_NOT_ENOUGH_MEMORY, needed);
    bytes = needed;
    if (!GetTokenInformation(token, TokenCapabilities, capabilities_buffer, bytes, &needed)) {
        error = GetLastError();
        TOKEN_VERIFY_FAIL(L"TokenCapabilities_query", error, needed);
    }
    verification->return_length = needed;
    if (needed < sizeof(DWORD))
        TOKEN_VERIFY_FAIL(L"TokenCapabilities_return_length", ERROR_INVALID_DATA, needed);
    verification->zero_capabilities = ((TOKEN_GROUPS *)capabilities_buffer)->GroupCount == 0;
    if (!verification->zero_capabilities)
        TOKEN_VERIFY_FAIL(L"capabilities_nonzero", ERROR_INVALID_DATA, needed);

    verification->failure_stage = L"complete";
    verification->api_error = ERROR_SUCCESS;
    ok = TRUE;
done:
    if (capabilities_buffer) HeapFree(GetProcessHeap(), 0, capabilities_buffer);
    if (integrity_buffer) HeapFree(GetProcessHeap(), 0, integrity_buffer);
    if (buffer) HeapFree(GetProcessHeap(), 0, buffer);
#undef TOKEN_VERIFY_FAIL
    return ok;
}

static BOOL write_report(const wchar_t *path, const wchar_t *mode, BOOL token_ok,
                         const TokenVerification *token_checks,
                         const ProbeResult *results, DWORD count) {
    HANDLE file = INVALID_HANDLE_VALUE;
    wchar_t json[MAX_REPORT];
    DWORD used, i, written;
    int n;
    n = _snwprintf_s(json, MAX_REPORT, _TRUNCATE,
        L"{\"version\":3,\"mode\":\"%ls\",\"token_verified\":%ls,"
        L"\"is_appcontainer\":%ls,\"is_lpac\":%ls,\"low_integrity\":%ls,"
        L"\"expected_sid_match\":%ls,\"zero_capabilities\":%ls,"
        L"\"token_is_appcontainer_query_succeeded\":%ls,\"token_is_appcontainer_return_length\":%lu,"
        L"\"token_is_appcontainer_api_error\":%lu,\"token_is_lpac_query_succeeded\":%ls,"
        L"\"token_is_lpac_return_length\":%lu,\"token_is_lpac_api_error\":%lu,"
        L"\"token_failure_stage\":\"%ls\",\"token_api_error\":%lu,\"token_return_length\":%lu,\"checks\":[",
        mode, token_ok ? L"true" : L"false",
        token_checks->is_appcontainer ? L"true" : L"false",
        token_checks->is_lpac ? L"true" : L"false",
        token_checks->low_integrity ? L"true" : L"false",
        token_checks->expected_sid_match ? L"true" : L"false",
        token_checks->zero_capabilities ? L"true" : L"false",
        token_checks->token_is_appcontainer_query_succeeded ? L"true" : L"false",
        (unsigned long)token_checks->token_is_appcontainer_return_length,
        (unsigned long)token_checks->token_is_appcontainer_api_error,
        token_checks->token_is_lpac_query_succeeded ? L"true" : L"false",
        (unsigned long)token_checks->token_is_lpac_return_length,
        (unsigned long)token_checks->token_is_lpac_api_error,
        token_checks->failure_stage ? token_checks->failure_stage : L"not_run",
        (unsigned long)token_checks->api_error,
        (unsigned long)token_checks->return_length);
    if (n < 0) return FALSE;
    used = (DWORD)n;
    for (i = 0; i < count; ++i) {
        n = _snwprintf_s(json + used, MAX_REPORT - used, _TRUNCATE,
            L"%ls{\"name\":\"%ls\",\"ok\":%ls,\"error\":%lu}",
            i ? L"," : L"", results[i].name,
            results[i].ok ? L"true" : L"false", (unsigned long)results[i].error);
        if (n < 0) return FALSE;
        used += (DWORD)n;
    }
    n = _snwprintf_s(json + used, MAX_REPORT - used, _TRUNCATE, L"]}\n");
    if (n < 0) return FALSE;
    used += (DWORD)n;
    if (used >= (DWORD)MAX_REPORT) return FALSE;
    file = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return FALSE;
    {
        int bytes = WideCharToMultiByte(CP_UTF8, 0, json, (int)used, NULL, 0, NULL, NULL);
        char *utf8;
        BOOL ok = FALSE;
        if (bytes <= 0 || bytes > MAX_REPORT * 4) { CloseHandle(file); return FALSE; }
        utf8 = (char *)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)bytes);
        if (!utf8) { CloseHandle(file); return FALSE; }
        if (WideCharToMultiByte(CP_UTF8, 0, json, (int)used, utf8, bytes, NULL, NULL) == bytes &&
            WriteFile(file, utf8, (DWORD)bytes, &written, NULL) && written == (DWORD)bytes) ok = TRUE;
        HeapFree(GetProcessHeap(), 0, utf8);
        if (!CloseHandle(file)) ok = FALSE;
        return ok;
    }
}

static ProbeResult verify_minimal_environment(const wchar_t *workspace) {
    ProbeResult result = { L"environment_minimal", FALSE, ERROR_SUCCESS };
    LPWCH block = GetEnvironmentStringsW();
    LPWCH item;
    DWORD seen = 0;
    wchar_t temp[MAX_PATH * 4], tmp[MAX_PATH * 4];
    if (!block) { result.error = GetLastError(); return result; }
    for (item = block; *item; item += wcslen(item) + 1) {
        const wchar_t *equal = wcschr(item, L'=');
        size_t key_length;
        DWORD bit = 0;
        if (!equal) { result.error = ERROR_INVALID_DATA; goto done; }
        if (item[0] == L'=') {
            /* Windows may synthesize a drive-current-directory pseudo variable. */
            if (wcslen(item) < 5U || !((item[1] >= L'A' && item[1] <= L'Z') || (item[1] >= L'a' && item[1] <= L'z')) ||
                item[2] != L':' || item[3] != L'=' || _wcsicmp(item + 4, workspace) != 0) {
                result.error = ERROR_INVALID_DATA; goto done;
            }
            continue;
        }
        key_length = (size_t)(equal - item);
        if (key_length == 10U && _wcsnicmp(item, L"SystemRoot", key_length) == 0) bit = 1;
        else if (key_length == 6U && _wcsnicmp(item, L"windir", key_length) == 0) bit = 2;
        else if (key_length == 4U && _wcsnicmp(item, L"PATH", key_length) == 0) bit = 4;
        else if (key_length == 4U && _wcsnicmp(item, L"TEMP", key_length) == 0) bit = 8;
        else if (key_length == 3U && _wcsnicmp(item, L"TMP", key_length) == 0) bit = 16;
        if (!bit || (seen & bit)) { result.error = ERROR_INVALID_DATA; goto done; }
        seen |= bit;
    }
    if (seen != 31U) { result.error = ERROR_INVALID_DATA; goto done; }
    if (!GetEnvironmentVariableW(L"TEMP", temp, (DWORD)_countof(temp)) ||
        !GetEnvironmentVariableW(L"TMP", tmp, (DWORD)_countof(tmp)) ||
        _wcsicmp(temp, workspace) != 0 || _wcsicmp(tmp, workspace) != 0) {
        result.error = ERROR_INVALID_DATA;
        goto done;
    }
    result.ok = TRUE;
    result.error = ERROR_SUCCESS;
done:
    FreeEnvironmentStringsW(block);
    return result;
}

static ProbeResult verify_temp_api_path(const wchar_t *workspace) {
    ProbeResult result = { L"temp_api_points_to_workspace", FALSE, ERROR_SUCCESS };
    wchar_t temp_path[MAX_PATH * 4];
    DWORD length = GetTempPathW((DWORD)_countof(temp_path), temp_path);
    if (!length || length >= _countof(temp_path)) {
        result.error = length ? ERROR_INSUFFICIENT_BUFFER : GetLastError();
        return result;
    }
    while (length && (temp_path[length - 1] == L'\\' || temp_path[length - 1] == L'/'))
        temp_path[--length] = L'\0';
    result.ok = _wcsicmp(temp_path, workspace) == 0;
    if (!result.ok) result.error = ERROR_INVALID_DATA;
    return result;
}

static ProbeResult attempt_write(const wchar_t *name, const wchar_t *path, const char *payload, DWORD disposition) {
    ProbeResult result = { name, FALSE, ERROR_SUCCESS };
    HANDLE file = CreateFileW(path, GENERIC_WRITE, 0, NULL, disposition,
                              FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        result.error = GetLastError();
        return result;
    }
    {
        DWORD written = 0;
        DWORD length = (DWORD)strlen(payload);
        if (WriteFile(file, payload, length, &written, NULL) && written == length) {
            result.ok = TRUE;
            result.error = ERROR_SUCCESS;
        } else {
            result.error = GetLastError();
        }
    }
    CloseHandle(file);
    return result;
}

static ProbeResult attempt_read(const wchar_t *name, const wchar_t *path, const char *expected) {
    ProbeResult result = { name, FALSE, ERROR_SUCCESS };
    char buffer[128];
    DWORD read_bytes = 0;
    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                              FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) { result.error = GetLastError(); return result; }
    if (ReadFile(file, buffer, sizeof(buffer), &read_bytes, NULL) &&
        read_bytes == (DWORD)strlen(expected) && memcmp(buffer, expected, read_bytes) == 0) {
        result.ok = TRUE;
    } else {
        result.error = GetLastError();
        if (result.error == ERROR_SUCCESS) result.error = ERROR_INVALID_DATA;
    }
    CloseHandle(file);
    return result;
}

static ProbeResult attempt_mkdir(const wchar_t *name, const wchar_t *path) {
    ProbeResult result = { name, FALSE, ERROR_SUCCESS };
    if (CreateDirectoryW(path, NULL)) result.ok = TRUE;
    else result.error = GetLastError();
    return result;
}

static ProbeResult require_read_denied(const wchar_t *name, const wchar_t *path) {
    ProbeResult result = { name, FALSE, ERROR_SUCCESS };
    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                              FILE_ATTRIBUTE_NORMAL, NULL);
    if (file != INVALID_HANDLE_VALUE) {
        CloseHandle(file);
        return result;
    }
    result.error = GetLastError();
    result.ok = result.error == ERROR_ACCESS_DENIED;
    return result;
}

static ProbeResult require_denied(const wchar_t *name, const wchar_t *path, BOOL directory, BOOL existing_file) {
    ProbeResult result = { name, FALSE, ERROR_SUCCESS };
    if (directory) {
        if (CreateDirectoryW(path, NULL)) { result.error = ERROR_SUCCESS; return result; }
        result.error = GetLastError();
    } else {
        HANDLE file = CreateFileW(path, GENERIC_WRITE, 0, NULL,
                                  existing_file ? OPEN_EXISTING : CREATE_NEW,
                                  FILE_ATTRIBUTE_NORMAL, NULL);
        if (file != INVALID_HANDLE_VALUE) { CloseHandle(file); result.error = ERROR_SUCCESS; return result; }
        result.error = GetLastError();
    }
    result.ok = result.error == ERROR_ACCESS_DENIED;
    return result;
}

static ProbeResult require_dacl_tamper_denied(const wchar_t *name, const wchar_t *path) {
    ProbeResult result = { name, FALSE, ERROR_SUCCESS };
    PSECURITY_DESCRIPTOR descriptor = NULL;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"O:SYD:P(A;;FA;;;OW)", SDDL_REVISION_1, &descriptor, NULL)) {
        result.error = GetLastError();
        return result;
    }
    if (SetFileSecurityW(path, DACL_SECURITY_INFORMATION, descriptor)) {
        result.error = ERROR_SUCCESS;
    } else {
        result.error = GetLastError();
        result.ok = result.error == ERROR_ACCESS_DENIED;
    }
    LocalFree(descriptor);
    return result;
}

static ProbeResult require_owner_change_denied(const wchar_t *name, const wchar_t *path) {
    ProbeResult result = { name, FALSE, ERROR_SUCCESS };
    PSECURITY_DESCRIPTOR descriptor = NULL;
    HANDLE file;
    file = CreateFileW(path, WRITE_OWNER, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                       NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file != INVALID_HANDLE_VALUE) {
        CloseHandle(file);
        return result;
    }
    result.error = GetLastError();
    if (result.error != ERROR_ACCESS_DENIED) return result;
    file = CreateFileW(path, WRITE_DAC, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                       NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file != INVALID_HANDLE_VALUE) {
        CloseHandle(file);
        result.error = ERROR_SUCCESS;
        return result;
    }
    result.error = GetLastError();
    if (result.error != ERROR_ACCESS_DENIED) return result;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"O:SYD:P(A;;FA;;;SY)", SDDL_REVISION_1, &descriptor, NULL)) {
        result.error = GetLastError();
        return result;
    }
    if (!SetFileSecurityW(path, OWNER_SECURITY_INFORMATION, descriptor)) {
        result.error = GetLastError();
        result.ok = result.error == ERROR_ACCESS_DENIED;
    }
    LocalFree(descriptor);
    return result;
}

static ProbeResult require_security_open_denied(const wchar_t *name, const wchar_t *path, DWORD access) {
    ProbeResult result = { name, FALSE, ERROR_SUCCESS };
    HANDLE file = CreateFileW(path, access, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file != INVALID_HANDLE_VALUE) { CloseHandle(file); return result; }
    result.error = GetLastError();
    result.ok = result.error == ERROR_ACCESS_DENIED;
    return result;
}

static DWORD append_registered_registry_checks(ProbeResult *results, DWORD count) {
    static const wchar_t value_name[] = L"CyberSentinelRegisteredLPACProbe";
    static const BYTE payload[] = { 0x43, 0x53, 0x4C, 0x50, 0x41, 0x43, 0x01 };
    ProbeResult api = { L"registered_registry_api_available", FALSE, ERROR_SUCCESS };
    ProbeResult absent = { L"registered_registry_value_absent_before", FALSE, ERROR_SUCCESS };
    ProbeResult value_set = { L"registered_registry_value_set", FALSE, ERROR_SUCCESS };
    ProbeResult verified = { L"registered_registry_write_verified", FALSE, ERROR_SUCCESS };
    HKEY root = NULL;
    HRESULT hr;
    LONG status;
    DWORD old_size = 0, old_type = 0;
    hr = GetAppContainerRegistryLocation(KEY_READ | KEY_WRITE, &root);
    if (SUCCEEDED(hr) && root) {
        api.ok = TRUE;
    } else {
        api.error = FAILED(hr) ? (DWORD)HRESULT_CODE(hr) : ERROR_INVALID_HANDLE;
    }
    if (api.ok) {
        status = RegQueryValueExW(root, value_name, NULL, &old_type, NULL, &old_size);
        if (status == ERROR_FILE_NOT_FOUND) {
            absent.ok = TRUE;
        } else if (status == ERROR_SUCCESS) {
            absent.error = ERROR_ALREADY_EXISTS;
        } else {
            absent.error = (DWORD)status;
        }
    } else {
        absent.error = api.error;
    }
    if (api.ok && absent.ok) {
        status = RegSetValueExW(root, value_name, 0, REG_BINARY, payload, (DWORD)sizeof(payload));
        if (status != ERROR_SUCCESS) {
            value_set.error = verified.error = (DWORD)status;
        } else {
            value_set.ok = TRUE;
            BYTE observed[sizeof(payload)];
            DWORD observed_size = (DWORD)sizeof(observed), observed_type = 0;
            status = RegQueryValueExW(root, value_name, NULL, &observed_type, observed, &observed_size);
            if (status == ERROR_SUCCESS && observed_type == REG_BINARY &&
                observed_size == (DWORD)sizeof(payload) && memcmp(observed, payload, sizeof(payload)) == 0) {
                verified.ok = TRUE;
            } else {
                verified.error = status == ERROR_SUCCESS ? ERROR_INVALID_DATA : (DWORD)status;
            }
        }
    } else {
        value_set.error = verified.error = api.ok ? absent.error : api.error;
    }
    if (root) RegCloseKey(root);
    results[count++] = api;
    results[count++] = absent;
    results[count++] = value_set;
    results[count++] = verified;
    return count;
}

static int child_main(int argc, wchar_t **argv) {
    PSID sid = NULL;
    HANDLE token = NULL;
    TokenVerification token_checks;
    ProbeResult results[12];
    DWORD count = 0;
    BOOL token_ok = FALSE;
    const wchar_t *mode, *workspace, *arg1, *arg2, *report;
    if (argc != 8) return 21;
    if (!ConvertStringSidToSidW(argv[2], &sid)) return fail(L"parse child SID", GetLastError());
    mode = argv[3]; workspace = argv[4]; arg1 = argv[5]; arg2 = argv[6]; report = argv[7];
    ZeroMemory(&token_checks, sizeof(token_checks));
    token_checks.failure_stage = L"not_run";
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        DWORD error = GetLastError();
        token_verification_fail(&token_checks, L"OpenProcessToken", error, 0);
        report_token_diagnostic(FALSE, &token_checks);
        LocalFree(sid);
        return fail(L"open child token", error);
    }
    token_ok = verify_token(token, sid, &token_checks);
    CloseHandle(token);
    if (!token_ok) {
        DWORD error = token_checks.api_error;
        report_token_diagnostic(FALSE, &token_checks);
        LocalFree(sid);
        return fail(L"child LPAC token verification", error);
    }
    results[count++] = verify_minimal_environment(workspace);
    results[count++] = verify_temp_api_path(workspace);
    if (wcscmp(mode, L"rw") == 0) {
        wchar_t file[MAX_PATH * 4], nested[MAX_PATH * 4], nested_file[MAX_PATH * 4];
        if (swprintf_s(file, _countof(file), L"%ls\\probe.txt", workspace) < 0 ||
            swprintf_s(nested, _countof(nested), L"%ls\\nested", workspace) < 0 ||
            swprintf_s(nested_file, _countof(nested_file), L"%ls\\nested\\inner.txt", workspace) < 0) { LocalFree(sid); return 22; }
        results[count++] = attempt_write(L"workspace_write", file, "lpac-workspace-proof", CREATE_ALWAYS);
        results[count++] = attempt_read(L"workspace_read", file, "lpac-workspace-proof");
        results[count++] = attempt_mkdir(L"nested_directory_create", nested);
        results[count++] = attempt_write(L"nested_file_write", nested_file, "nested-proof", CREATE_ALWAYS);
        results[count++] = require_dacl_tamper_denied(L"workspace_file_dacl_tamper_denied", file);
        results[count++] = require_owner_change_denied(L"workspace_file_owner_change_denied", file);
    } else if (wcscmp(mode, L"outside") == 0 || wcscmp(mode, L"registered-storage") == 0) {
        wchar_t created[MAX_PATH * 4], subdir[MAX_PATH * 4];
        if (swprintf_s(created, _countof(created), L"%ls\\new.bin", arg2) < 0 ||
            swprintf_s(subdir, _countof(subdir), L"%ls\\newdir", arg2) < 0) { LocalFree(sid); return 23; }
        results[count++] = require_denied(L"outside_existing_file_write", arg1, FALSE, TRUE);
        results[count++] = require_denied(L"outside_new_file_create", created, FALSE, FALSE);
        results[count++] = require_denied(L"outside_directory_create", subdir, TRUE, FALSE);
        if (wcscmp(mode, L"registered-storage") == 0) {
            wchar_t temp_file[MAX_PATH * 4];
            ProbeResult temp_write = { L"temp_api_write_inside_workspace", FALSE, ERROR_SUCCESS };
            ProbeResult temp_read = { L"temp_api_read_inside_workspace", FALSE, ERROR_SUCCESS };
            ProbeResult temp_path_check = verify_temp_api_path(workspace);
            if (!temp_path_check.ok) {
                temp_write.error = temp_read.error = temp_path_check.error ? temp_path_check.error : ERROR_INVALID_DATA;
            } else if (swprintf_s(temp_file, _countof(temp_file), L"%ls\\CyberSentinel-temp-probe.bin", workspace) < 0) {
                temp_write.error = temp_read.error = ERROR_INSUFFICIENT_BUFFER;
            } else {
                temp_write = attempt_write(L"temp_api_write_inside_workspace", temp_file,
                                           "registered-lpac-temp-proof", CREATE_NEW);
                temp_read = attempt_read(L"temp_api_read_inside_workspace", temp_file,
                                         "registered-lpac-temp-proof");
            }
            results[count++] = temp_write;
            results[count++] = temp_read;
            count = append_registered_registry_checks(results, count);
        }
    } else if (wcscmp(mode, L"isolation") == 0 || wcscmp(mode, L"stale") == 0 || wcscmp(mode, L"revoked") == 0) {
        results[count++] = require_read_denied(L"other_workspace_read_denied", arg1);
        results[count++] = require_denied(L"other_workspace_write_denied", arg1, FALSE, TRUE);
        if (wcscmp(mode, L"revoked") == 0) {
            results[count++] = require_security_open_denied(L"revoked_write_dac_denied", arg1, WRITE_DAC);
            results[count++] = require_security_open_denied(L"revoked_write_owner_denied", arg1, WRITE_OWNER);
        }
    } else {
        LocalFree(sid);
        return 24;
    }
    if (!write_report(report, mode, token_ok, &token_checks, results, count)) { LocalFree(sid); return fail(L"write bounded evidence report", GetLastError()); }
    LocalFree(sid);
    for (DWORD i = 0; i < count; ++i) if (!results[i].ok) return 25;
    return 0;
}

static BOOL append_quoted(wchar_t *dst, size_t cap, size_t *used, const wchar_t *arg) {
    size_t i, slashes = 0;
    if (*used && *used + 1 >= cap) return FALSE;
    if (*used) dst[(*used)++] = L' ';
    if (*used + 1 >= cap) return FALSE;
    dst[(*used)++] = L'"';
    for (i = 0; arg[i]; ++i) {
        if (arg[i] == L'\\') { ++slashes; continue; }
        if (arg[i] == L'"') {
            size_t j;
            for (j = 0; j < slashes * 2 + 1; ++j) { if (*used + 2 >= cap) return FALSE; dst[(*used)++] = L'\\'; }
            if (*used + 2 >= cap) return FALSE;
            dst[(*used)++] = L'"';
            slashes = 0;
            continue;
        }
        while (slashes--) { if (*used + 2 >= cap) return FALSE; dst[(*used)++] = L'\\'; }
        slashes = 0;
        if (*used + 2 >= cap) return FALSE;
        dst[(*used)++] = arg[i];
    }
    while (slashes--) { if (*used + 2 >= cap) return FALSE; dst[(*used)++] = L'\\'; dst[(*used)++] = L'\\'; }
    if (*used + 2 >= cap) return FALSE;
    dst[(*used)++] = L'"'; dst[*used] = L'\0';
    return TRUE;
}

typedef LONG (WINAPI *LastNtStatusFn)(void);

typedef struct EnvironmentControlResult {
    BOOL diagnostic_only;
    BOOL parent_environment_filtered;
    BOOL lp_environment_null;
    DWORD parent_environment_entry_count;
    BOOL explicit_environment_snapshot_safe;
    DWORD explicit_environment_entry_count;
    BOOL main_environment_block;
    BOOL main_environment_block_safe;
    DWORD main_environment_entry_count;
    BOOL main_environment_variant;
    DWORD main_environment_variant_id;
    BOOL attempted;
    DWORD setup_error;
    BOOL create_succeeded;
    DWORD create_win32_error;
    BOOL create_ntstatus_available;
    LONG create_ntstatus;
    DWORD job_attribute_error;
    BOOL job_membership_verified;
    DWORD job_membership_error;
    BOOL token_verified;
    DWORD token_verification_error;
    TokenVerification token_details;
    BOOL terminated;
    DWORD job_active_processes;
    DWORD job_total_processes;
    BOOL job_empty;
    BOOL cleanup_confirmed;
    DWORD cleanup_error;
} EnvironmentControlResult;

static BOOL control_environment_block_is_filtered(const wchar_t *block, DWORD *entry_count_out) {
    static const wchar_t *safe_names[] = {
        L"ALLUSERSPROFILE", L"APPDATA", L"COMSPEC", L"HOMEDRIVE", L"HOMEPATH",
        L"LOCALAPPDATA", L"NUMBER_OF_PROCESSORS", L"OS", L"PATH", L"PATHEXT",
        L"PROCESSOR_ARCHITECTURE", L"PROCESSOR_IDENTIFIER", L"PROCESSOR_LEVEL",
        L"PROCESSOR_REVISION", L"PROGRAMDATA", L"PROGRAMFILES", L"PROGRAMFILES(X86)",
        L"PROGRAMW6432", L"PUBLIC", L"SYSTEMDRIVE", L"SYSTEMROOT", L"TEMP", L"TMP",
        L"USERDOMAIN", L"USERDOMAIN_ROAMINGPROFILE", L"USERNAME", L"USERPROFILE", L"WINDIR",
        L"CYBERSENTINEL_TEST_ENV_SANITIZED"
    };
    static const wchar_t *sensitive_markers[] = {
        L"TOKEN", L"SECRET", L"PASS", L"CREDENTIAL", L"KEY", L"AUTH", L"COOKIE", L"CERT"
    };
    const wchar_t *entry;
    BOOL safe = TRUE;
    DWORD entry_count = 0;
    size_t i;
    if (entry_count_out) *entry_count_out = 0;
    if (!block) return FALSE;
    for (entry = block; *entry; entry += wcslen(entry) + 1) {
        const wchar_t *separator = entry[0] == L'=' ? wcschr(entry + 1, L'=') : wcschr(entry, L'=');
        wchar_t name[256];
        size_t name_length;
        BOOL allowed = FALSE;
        if (!separator) { safe = FALSE; break; }
        name_length = (size_t)(separator - entry);
        if (!name_length || name_length >= _countof(name) ||
            wcsncpy_s(name, _countof(name), entry, name_length) != 0) {
            safe = FALSE;
            break;
        }
        for (i = 0; name[i]; ++i) {
            if (name[i] >= L'a' && name[i] <= L'z') name[i] = (wchar_t)(name[i] - L'a' + L'A');
        }
        for (i = 0; i < _countof(safe_names); ++i) {
            if (_wcsicmp(name, safe_names[i]) == 0) { allowed = TRUE; break; }
        }
        if (name[0] == L'=' && name[1] >= L'A' && name[1] <= L'Z' &&
            name[2] == L':' && name[3] == L'\0')
            allowed = TRUE;
        ++entry_count;
        if (!allowed && (!_wcsnicmp(name, L"ACTIONS_", 8) ||
                         !_wcsnicmp(name, L"GITHUB_", 7) ||
                         !_wcsnicmp(name, L"RUNNER_", 7))) {
            safe = FALSE;
            break;
        }
        for (i = 0; i < _countof(sensitive_markers); ++i) {
            if (wcsstr(name, sensitive_markers[i])) { safe = FALSE; break; }
        }
        if (!allowed) safe = FALSE;
        if (!safe) break;
    }
    if (entry_count_out) *entry_count_out = entry_count;
    return safe;
}

static BOOL build_environment_block_omitting_entry(
    const wchar_t *source, DWORD omit_index, wchar_t *destination,
    size_t destination_capacity, DWORD *entry_count_out) {
    const wchar_t *entry;
    size_t used = 0;
    DWORD source_index = 0, kept_count = 0;
    if (entry_count_out) *entry_count_out = 0;
    if (!source || !destination || !entry_count_out || destination_capacity < 2)
        return FALSE;
    for (entry = source; *entry; entry += wcslen(entry) + 1, ++source_index) {
        size_t entry_length = wcslen(entry);
        if (source_index != omit_index) {
            if (used + entry_length + 2 > destination_capacity) return FALSE;
            memcpy(destination + used, entry, (entry_length + 1) * sizeof(wchar_t));
            used += entry_length + 1;
            ++kept_count;
        }
    }
    if (omit_index >= source_index || kept_count == 0 || used >= destination_capacity)
        return FALSE;
    destination[used] = L'\0';
    *entry_count_out = kept_count;
    return kept_count + 1 == source_index;
}

static BOOL control_environment_is_filtered(DWORD *entry_count_out) {
    LPWCH block = GetEnvironmentStringsW();
    BOOL safe;
    if (entry_count_out) *entry_count_out = 0;
    if (!block) return FALSE;
    safe = control_environment_block_is_filtered(block, entry_count_out);
    return FreeEnvironmentStringsW(block) && safe;
}

static BOOL cleanup_control_attributes(LPPROC_THREAD_ATTRIBUTE_LIST *attrs,
                                       BOOL *attrs_initialized, DWORD *cleanup_error) {
    BOOL ok = TRUE;
    if (*attrs_initialized && *attrs) {
        DeleteProcThreadAttributeList(*attrs);
        *attrs_initialized = FALSE;
    }
    if (*attrs) {
        if (!HeapFree(GetProcessHeap(), 0, *attrs)) {
            if (*cleanup_error == ERROR_SUCCESS) *cleanup_error = GetLastError();
            ok = FALSE;
        } else {
            *attrs = NULL;
        }
    }
    return ok;
}

static BOOL close_control_job_handle(HANDLE *job, HANDLE *job_out, DWORD *cleanup_error) {
    if (!*job) return TRUE;
    if (CloseHandle(*job)) {
        *job = NULL;
        return TRUE;
    }
    if (*cleanup_error == ERROR_SUCCESS) *cleanup_error = GetLastError();
    *job_out = *job;
    *job = NULL;
    return FALSE;
}

static BOOL run_lp_environment_control(
    const wchar_t *image, const wchar_t *command, const wchar_t *cwd,
    const STARTUPINFOEXW *startup, const SECURITY_CAPABILITIES *caps,
    const DWORD *all_packages_policy, DWORD launch_flags, BOOL lp_environment_null,
    const wchar_t *main_environment_block, PSID expected_sid,
    LastNtStatusFn last_nt_status, EnvironmentControlResult *result,
    HANDLE *control_job_out, PROCESS_INFORMATION *control_process_out,
    HANDLE *control_token_out) {
    ProbeJobExtendedLimitInformation job_limits;
    wchar_t control_command[32768];
    HANDLE control_job = NULL, process_token = NULL;
    LPWCH explicit_environment = NULL;
    LPWCH environment_to_use = NULL;
    PROCESS_INFORMATION control_process;
    SIZE_T attr_size = 0;
    LPPROC_THREAD_ATTRIBUTE_LIST control_attrs = NULL;
    STARTUPINFOEXW control_startup;
    HANDLE control_job_list[1] = { NULL };
    BOOL attrs_initialized = FALSE, in_job = FALSE;
    DWORD wait_status, attr_error, create_error, cleanup_attempt;
    BOOL create_succeeded;
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounting;
    ZeroMemory(result, sizeof(*result));
    ZeroMemory(&control_process, sizeof(control_process));
    ZeroMemory(&accounting, sizeof(accounting));
    ZeroMemory(&control_startup, sizeof(control_startup));
    *control_job_out = NULL;
    ZeroMemory(control_process_out, sizeof(*control_process_out));
    *control_token_out = NULL;
    result->diagnostic_only = TRUE;
    result->lp_environment_null = lp_environment_null;
    result->main_environment_block = main_environment_block != NULL;
    result->token_details.failure_stage = L"not_run";
    {
        wchar_t marker[8];
        DWORD marker_length = GetEnvironmentVariableW(
            L"CYBERSENTINEL_TEST_ENV_SANITIZED", marker, (DWORD)_countof(marker));
        result->parent_environment_filtered =
            marker_length == 1 && marker[0] == L'1' &&
            control_environment_is_filtered(&result->parent_environment_entry_count);
    }
    if (!result->parent_environment_filtered) {
        result->setup_error = ERROR_ACCESS_DENIED;
        return TRUE;
    }
    if (wcscpy_s(control_command, _countof(control_command), command) != 0) {
        result->setup_error = ERROR_INSUFFICIENT_BUFFER;
        return TRUE;
    }
    ZeroMemory(&job_limits, sizeof(job_limits));
    job_limits.BasicLimitInformation.LimitFlags = 0x00002000; /* JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE */
    control_job = CreateJobObjectW(NULL, NULL);
    if (!control_job || !SetInformationJobObject(control_job, (JOBOBJECTINFOCLASS)9,
                                                  &job_limits, (DWORD)sizeof(job_limits))) {
        result->setup_error = GetLastError();
        result->cleanup_confirmed = close_control_job_handle(
            &control_job, control_job_out, &result->cleanup_error);
        return result->cleanup_confirmed;
    }
    if (InitializeProcThreadAttributeList(NULL, 3, 0, &attr_size)) {
        result->setup_error = ERROR_INVALID_DATA;
        result->cleanup_confirmed = close_control_job_handle(
            &control_job, control_job_out, &result->cleanup_error);
        return result->cleanup_confirmed;
    }
    attr_error = GetLastError();
    if (attr_error != ERROR_INSUFFICIENT_BUFFER || !attr_size) {
        result->setup_error = attr_error ? attr_error : ERROR_INVALID_DATA;
        result->cleanup_confirmed = close_control_job_handle(
            &control_job, control_job_out, &result->cleanup_error);
        return result->cleanup_confirmed;
    }
    control_attrs = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attr_size);
    if (!control_attrs) {
        result->setup_error = ERROR_NOT_ENOUGH_MEMORY;
        result->cleanup_confirmed = close_control_job_handle(
            &control_job, control_job_out, &result->cleanup_error);
        return result->cleanup_confirmed;
    }
    if (!InitializeProcThreadAttributeList(control_attrs, 3, 0, &attr_size)) {
        result->setup_error = GetLastError();
        cleanup_control_attributes(&control_attrs, &attrs_initialized, &result->cleanup_error);
        result->cleanup_confirmed = close_control_job_handle(
            &control_job, control_job_out, &result->cleanup_error) &&
            result->cleanup_error == ERROR_SUCCESS;
        return result->cleanup_confirmed;
    }
    attrs_initialized = TRUE;
    control_job_list[0] = control_job;
    if (!UpdateProcThreadAttribute(control_attrs, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                                   (PVOID)caps, sizeof(*caps), NULL, NULL) ||
        !UpdateProcThreadAttribute(control_attrs, 0, PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY,
                                   (PVOID)all_packages_policy, sizeof(*all_packages_policy), NULL, NULL)) {
        result->setup_error = GetLastError();
        goto control_setup_failed;
    }
    if (!UpdateProcThreadAttribute(control_attrs, 0, PROC_THREAD_ATTRIBUTE_JOB_LIST,
                                   control_job_list, sizeof(control_job_list), NULL, NULL)) {
        result->job_attribute_error = GetLastError();
        result->setup_error = result->job_attribute_error;
        goto control_setup_failed;
    }
    control_startup = *startup;
    control_startup.lpAttributeList = control_attrs;
    if (!lp_environment_null) {
        if (main_environment_block) {
            if (!control_environment_block_is_filtered(
                    main_environment_block, &result->main_environment_entry_count) ||
                result->main_environment_entry_count == 0) {
                result->setup_error = ERROR_ACCESS_DENIED;
                goto control_setup_failed;
            }
            result->main_environment_block_safe = TRUE;
            environment_to_use = (LPWCH)main_environment_block;
        } else {
            explicit_environment = GetEnvironmentStringsW();
            if (!explicit_environment) {
                result->setup_error = GetLastError();
                goto control_setup_failed;
            }
            if (!control_environment_block_is_filtered(
                    explicit_environment, &result->explicit_environment_entry_count)) {
                result->setup_error = ERROR_ACCESS_DENIED;
                goto control_setup_failed;
            }
            result->explicit_environment_snapshot_safe = TRUE;
            environment_to_use = explicit_environment;
        }
    }
    result->attempted = TRUE;
    create_succeeded = CreateProcessW(image, control_command, NULL, NULL, FALSE, launch_flags,
                        environment_to_use,
                        cwd, &control_startup.StartupInfo, &control_process);
    create_error = create_succeeded ? ERROR_SUCCESS : GetLastError();
    if (explicit_environment) {
        if (!FreeEnvironmentStringsW(explicit_environment) && result->cleanup_error == ERROR_SUCCESS)
            result->cleanup_error = GetLastError();
        explicit_environment = NULL;
    }
    if (!create_succeeded) {
        BOOL attributes_closed, job_closed;
        result->create_ntstatus_available = last_nt_status != NULL;
        result->create_ntstatus = last_nt_status ? last_nt_status() : 0;
        result->create_win32_error = create_error;
        attributes_closed = cleanup_control_attributes(
            &control_attrs, &attrs_initialized, &result->cleanup_error);
        job_closed = close_control_job_handle(
            &control_job, control_job_out, &result->cleanup_error);
        result->cleanup_confirmed = attributes_closed && job_closed &&
                                    result->cleanup_error == ERROR_SUCCESS;
        return result->cleanup_confirmed;
    }
    cleanup_control_attributes(&control_attrs, &attrs_initialized, &result->cleanup_error);
    result->create_succeeded = TRUE;
    *control_job_out = control_job;
    *control_process_out = control_process;
    if (!IsProcessInJob(control_process.hProcess, control_job, &in_job))
        result->job_membership_error = GetLastError();
    else if (in_job)
        result->job_membership_verified = TRUE;
    else
        result->job_membership_error = ERROR_INVALID_DATA;
    if (OpenProcessToken(control_process.hProcess, TOKEN_QUERY, &process_token)) {
        result->token_verified = verify_token(process_token, expected_sid, &result->token_details);
        result->token_verification_error = result->token_details.api_error;
        if (!CloseHandle(process_token)) {
            if (result->cleanup_error == ERROR_SUCCESS) result->cleanup_error = GetLastError();
            *control_token_out = process_token;
        }
        process_token = NULL;
    } else {
        DWORD error = GetLastError();
        token_verification_fail(&result->token_details, L"OpenProcessToken", error, 0);
        result->token_verification_error = error;
    }
    if (!TerminateProcess(control_process.hProcess, 0xE5)) {
        DWORD terminate_error = GetLastError();
        if (WaitForSingleObject(control_process.hProcess, 0) != WAIT_OBJECT_0 &&
            result->cleanup_error == ERROR_SUCCESS)
            result->cleanup_error = terminate_error;
    }
    wait_status = WaitForSingleObject(control_process.hProcess, 5000);
    if (wait_status != WAIT_OBJECT_0) {
        DWORD wait_error = wait_status == WAIT_TIMEOUT ? WAIT_TIMEOUT : GetLastError();
        if (result->cleanup_error == ERROR_SUCCESS) result->cleanup_error = wait_error;
        if (!TerminateJobObject(control_job, 0xE5) && result->cleanup_error == ERROR_SUCCESS)
            result->cleanup_error = GetLastError();
        if (!TerminateProcess(control_process.hProcess, 0xE5) && result->cleanup_error == ERROR_SUCCESS)
            result->cleanup_error = GetLastError();
        wait_status = WaitForSingleObject(control_process.hProcess, 5000);
    }
    result->terminated = wait_status == WAIT_OBJECT_0;
    if (!result->terminated && result->cleanup_error == ERROR_SUCCESS)
        result->cleanup_error = wait_status == WAIT_TIMEOUT ? WAIT_TIMEOUT : GetLastError();
    if (QueryInformationJobObject(control_job, JobObjectBasicAccountingInformation,
                                  &accounting, (DWORD)sizeof(accounting), NULL)) {
        result->job_active_processes = accounting.ActiveProcesses;
        result->job_total_processes = accounting.TotalProcesses;
        result->job_empty = accounting.ActiveProcesses == 0;
    } else if (result->cleanup_error == ERROR_SUCCESS) {
        result->cleanup_error = GetLastError();
    }
    if (!result->job_empty) {
        if (!TerminateJobObject(control_job, 0xE5) && result->cleanup_error == ERROR_SUCCESS)
            result->cleanup_error = GetLastError();
        for (cleanup_attempt = 0; cleanup_attempt < 100; ++cleanup_attempt) {
            if (QueryInformationJobObject(control_job, JobObjectBasicAccountingInformation,
                                          &accounting, (DWORD)sizeof(accounting), NULL)) {
                result->job_active_processes = accounting.ActiveProcesses;
                result->job_total_processes = accounting.TotalProcesses;
                result->job_empty = accounting.ActiveProcesses == 0;
            } else if (result->cleanup_error == ERROR_SUCCESS) {
                result->cleanup_error = GetLastError();
            }
            if (result->job_empty) break;
            Sleep(50);
        }
    }
    if (!(result->terminated && result->job_empty)) {
        if (result->cleanup_error == ERROR_SUCCESS) result->cleanup_error = ERROR_INVALID_DATA;
        return FALSE; /* Keep process and Job handles for the caller's final retry. */
    }
    if (!CloseHandle(control_process.hThread)) {
        result->cleanup_error = GetLastError();
    } else {
        control_process_out->hThread = NULL;
    }
    if (!CloseHandle(control_process.hProcess)) {
        if (result->cleanup_error == ERROR_SUCCESS) result->cleanup_error = GetLastError();
    } else {
        control_process_out->hProcess = NULL;
    }
    if (!CloseHandle(control_job)) {
        if (result->cleanup_error == ERROR_SUCCESS) result->cleanup_error = GetLastError();
    } else {
        *control_job_out = NULL;
    }
    result->cleanup_confirmed = result->terminated && result->job_empty &&
                                result->cleanup_error == ERROR_SUCCESS &&
                                !control_process_out->hThread && !control_process_out->hProcess &&
                                !*control_job_out;
    if (!result->cleanup_confirmed) return FALSE;
    ZeroMemory(control_process_out, sizeof(*control_process_out));
    return TRUE;

control_setup_failed:
    if (explicit_environment) {
        if (!FreeEnvironmentStringsW(explicit_environment) && result->cleanup_error == ERROR_SUCCESS)
            result->cleanup_error = GetLastError();
        explicit_environment = NULL;
    }
    {
        BOOL attributes_closed = cleanup_control_attributes(
            &control_attrs, &attrs_initialized, &result->cleanup_error);
        BOOL job_closed = close_control_job_handle(
            &control_job, control_job_out, &result->cleanup_error);
        result->cleanup_confirmed = attributes_closed && job_closed &&
                                    result->cleanup_error == ERROR_SUCCESS;
    }
    return result->cleanup_confirmed;
}

static void report_environment_control(const EnvironmentControlResult *result) {
    const wchar_t *prefix = result->main_environment_variant ?
        L"lpac_main_environment_variant_control" : result->lp_environment_null ?
        L"lpac_environment_control" : result->main_environment_block ?
        L"lpac_main_environment_block_control" : L"lpac_environment_snapshot_control";
    BOOL comparison_complete = result->diagnostic_only && result->lp_environment_null &&
        result->parent_environment_filtered &&
        result->attempted && result->create_succeeded && result->job_membership_verified &&
        result->token_verified && result->token_details.is_appcontainer && result->token_details.is_lpac &&
        result->token_details.expected_sid_match && result->token_details.low_integrity &&
        result->token_details.zero_capabilities &&
        result->token_details.token_is_appcontainer_query_succeeded &&
        result->token_details.token_is_lpac_query_succeeded &&
        result->token_details.token_is_appcontainer_return_length == sizeof(DWORD) &&
        result->token_details.token_is_lpac_return_length == sizeof(DWORD) &&
        result->token_details.token_is_appcontainer_api_error == ERROR_SUCCESS &&
        result->token_details.token_is_lpac_api_error == ERROR_SUCCESS &&
        result->token_details.failure_stage && wcscmp(result->token_details.failure_stage, L"complete") == 0 &&
        result->token_details.api_error == ERROR_SUCCESS &&
        result->terminated && result->job_empty && result->cleanup_confirmed &&
        result->setup_error == ERROR_SUCCESS && result->create_win32_error == ERROR_SUCCESS &&
        result->job_attribute_error == ERROR_SUCCESS && result->job_membership_error == ERROR_SUCCESS &&
        result->token_verification_error == ERROR_SUCCESS &&
        result->cleanup_error == ERROR_SUCCESS && result->job_active_processes == 0 &&
        result->job_total_processes == 1;
    fwprintf(stderr,
        L"%ls: {\"version\":1,\"scope\":\"broker_only\","
        L"\"diagnostic_only\":%ls,\"comparison_complete\":%ls,"
        L"\"lp_environment_null\":%ls,\"parent_environment_filtered\":%ls,"
        L"\"parent_environment_entry_count\":%lu,"
        L"\"explicit_environment_snapshot_safe\":%ls,\"explicit_environment_entry_count\":%lu,"
        L"\"main_environment_block\":%ls,\"main_environment_block_safe\":%ls,"
        L"\"main_environment_entry_count\":%lu,\"main_environment_variant\":%ls,"
        L"\"main_environment_variant_id\":%lu,"
        L"\"attempted\":%ls,\"setup_error\":%lu,"
        L"\"create_succeeded\":%ls,\"create_win32_error\":%lu,"
        L"\"create_ntstatus_available\":%ls,\"create_ntstatus_advisory\":\"0x%08lX\","
        L"\"job_attribute_error\":%lu,\"job_membership_verified\":%ls,\"job_membership_error\":%lu,"
        L"\"token_verified\":%ls,\"token_verification_error\":%lu,"
        L"\"is_appcontainer\":%ls,\"is_lpac\":%ls,\"low_integrity\":%ls,"
        L"\"expected_sid_match\":%ls,\"zero_capabilities\":%ls,"
        L"\"token_is_appcontainer_query_succeeded\":%ls,\"token_is_appcontainer_return_length\":%lu,"
        L"\"token_is_appcontainer_api_error\":%lu,\"token_is_lpac_query_succeeded\":%ls,"
        L"\"token_is_lpac_return_length\":%lu,\"token_is_lpac_api_error\":%lu,"
        L"\"token_failure_stage\":\"%ls\",\"token_api_error\":%lu,\"token_return_length\":%lu,"
        L"\"terminated\":%ls,\"job_active_processes\":%lu,\"job_total_processes\":%lu,"
        L"\"job_empty\":%ls,\"cleanup_confirmed\":%ls,\"cleanup_error\":%lu}\n",
        prefix,
        result->diagnostic_only ? L"true" : L"false",
        comparison_complete ? L"true" : L"false",
        result->lp_environment_null ? L"true" : L"false",
        result->parent_environment_filtered ? L"true" : L"false",
        (unsigned long)result->parent_environment_entry_count,
        result->explicit_environment_snapshot_safe ? L"true" : L"false",
        (unsigned long)result->explicit_environment_entry_count,
        result->main_environment_block ? L"true" : L"false",
        result->main_environment_block_safe ? L"true" : L"false",
        (unsigned long)result->main_environment_entry_count,
        result->main_environment_variant ? L"true" : L"false",
        (unsigned long)result->main_environment_variant_id,
        result->attempted ? L"true" : L"false", (unsigned long)result->setup_error,
        result->create_succeeded ? L"true" : L"false", (unsigned long)result->create_win32_error,
        result->create_ntstatus_available ? L"true" : L"false", (unsigned long)result->create_ntstatus,
        (unsigned long)result->job_attribute_error,
        result->job_membership_verified ? L"true" : L"false", (unsigned long)result->job_membership_error,
        result->token_verified ? L"true" : L"false", (unsigned long)result->token_verification_error,
        result->token_details.is_appcontainer ? L"true" : L"false",
        result->token_details.is_lpac ? L"true" : L"false",
        result->token_details.low_integrity ? L"true" : L"false",
        result->token_details.expected_sid_match ? L"true" : L"false",
        result->token_details.zero_capabilities ? L"true" : L"false",
        result->token_details.token_is_appcontainer_query_succeeded ? L"true" : L"false",
        (unsigned long)result->token_details.token_is_appcontainer_return_length,
        (unsigned long)result->token_details.token_is_appcontainer_api_error,
        result->token_details.token_is_lpac_query_succeeded ? L"true" : L"false",
        (unsigned long)result->token_details.token_is_lpac_return_length,
        (unsigned long)result->token_details.token_is_lpac_api_error,
        result->token_details.failure_stage ? result->token_details.failure_stage : L"not_run",
        (unsigned long)result->token_details.api_error,
        (unsigned long)result->token_details.return_length,
        result->terminated ? L"true" : L"false", (unsigned long)result->job_active_processes,
        (unsigned long)result->job_total_processes, result->job_empty ? L"true" : L"false",
        result->cleanup_confirmed ? L"true" : L"false", (unsigned long)result->cleanup_error);
}

static BOOL is_absolute_windows_path(const wchar_t *path) {
    BOOL drive_absolute = path &&
        (((path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z')) &&
         path[1] == L':' && (path[2] == L'\\' || path[2] == L'/'));
    BOOL unc_absolute = path && (path[0] == L'\\' || path[0] == L'/') &&
        (path[1] == L'\\' || path[1] == L'/') && path[2] &&
        path[2] != L'\\' && path[2] != L'/';
    return drive_absolute || unc_absolute;
}

/* Check only fixed, expected OS DLL names; never emit their containing path. */
static DWORD known_system_dependency_mask(DWORD *directory_error) {
    static const wchar_t *names[] = {
        L"kernel32.dll", L"kernelbase.dll", L"ntdll.dll", L"advapi32.dll"
    };
    wchar_t system_dir[MAX_PATH], dependency[MAX_PATH * 2];
    UINT length;
    DWORD mask = 0;
    size_t i;
    length = GetSystemDirectoryW(system_dir, (UINT)_countof(system_dir));
    if (!length || length >= _countof(system_dir)) {
        *directory_error = length ? ERROR_INSUFFICIENT_BUFFER : GetLastError();
        return 0;
    }
    *directory_error = ERROR_SUCCESS;
    for (i = 0; i < _countof(names); ++i) {
        DWORD attributes;
        if (_snwprintf_s(dependency, _countof(dependency), _TRUNCATE,
                         L"%ls\\%ls", system_dir, names[i]) < 0) continue;
        attributes = GetFileAttributesW(dependency);
        if (attributes != INVALID_FILE_ATTRIBUTES && !(attributes & FILE_ATTRIBUTE_DIRECTORY))
            mask |= (DWORD)1U << i;
    }
    return mask;
}

/* Broker-side observations only. Parent readability is not LPAC access, and
 * neither file presence nor NTSTATUS identifies the missing internal object.
 * Never log paths, SIDs, argv, or environment values. */
static void report_launch_failure(const wchar_t *image, const wchar_t *cwd,
                                  DWORD error, DWORD launch_flags,
                                  BOOL nt_available, LONG nt_status,
                                  BOOL drive_environment_present) {
    DWORD image_attrs, cwd_attrs, image_error, cwd_error, module_length;
    DWORD image_open_error = ERROR_SUCCESS, image_size_error = ERROR_SUCCESS;
    DWORD system_directory_error = ERROR_SUCCESS, dependency_mask;
    BOOL parent_can_read_image = FALSE, image_size_available = FALSE;
    LONGLONG image_size = 0;
    HANDLE image_handle;
    wchar_t module[32768], message[512];
    BOOL module_matches = FALSE;
    image_attrs = GetFileAttributesW(image);
    image_error = image_attrs == INVALID_FILE_ATTRIBUTES ? GetLastError() : ERROR_SUCCESS;
    cwd_attrs = GetFileAttributesW(cwd);
    cwd_error = cwd_attrs == INVALID_FILE_ATTRIBUTES ? GetLastError() : ERROR_SUCCESS;
    image_handle = CreateFileW(image, GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (image_handle == INVALID_HANDLE_VALUE) {
        image_open_error = GetLastError();
    } else {
        LARGE_INTEGER size;
        parent_can_read_image = GetFileType(image_handle) == FILE_TYPE_DISK;
        if (parent_can_read_image && GetFileSizeEx(image_handle, &size)) {
            image_size = size.QuadPart;
            image_size_available = TRUE;
        } else if (parent_can_read_image) {
            image_size_error = GetLastError();
        }
        CloseHandle(image_handle);
    }
    dependency_mask = known_system_dependency_mask(&system_directory_error);
    module_length = GetModuleFileNameW(NULL, module, (DWORD)_countof(module));
    if (module_length && module_length < (DWORD)_countof(module))
        module_matches = _wcsicmp(module, image) == 0;
    fwprintf(stderr,
        L"lpac_launch_diagnostic: {\"version\":2,\"scope\":\"broker_only\","
        L"\"drive_current_directory_env_present\":%ls,\"win32_error\":%lu,\"image_is_absolute\":%ls,"
        L"\"image_is_file\":%ls,\"image_attributes_error\":%lu,"
        L"\"parent_can_read_image\":%ls,\"image_open_error\":%lu,"
        L"\"image_size_available\":%ls,\"image_size_bytes\":%llu,"
        L"\"image_size_error\":%lu,\"cwd_is_absolute\":%ls,"
        L"\"cwd_is_directory\":%ls,\"cwd_attributes_error\":%lu,"
        L"\"module_matches_image\":%ls,\"known_dependency_mask\":%lu,"
        L"\"known_dependency_expected_mask\":15,\"system_directory_error\":%lu,"
        L"\"broker_pid\":%lu,\"broker_bitness\":%u,\"launch_flags\":%lu,"
        L"\"ntstatus_available\":%ls,"
        L"\"ntstatus_advisory\":\"0x%08lX\"}\n",
        drive_environment_present ? L"true" : L"false",
        (unsigned long)error,
        is_absolute_windows_path(image) ? L"true" : L"false",
        image_attrs != INVALID_FILE_ATTRIBUTES && !(image_attrs & FILE_ATTRIBUTE_DIRECTORY) ? L"true" : L"false",
        (unsigned long)image_error, parent_can_read_image ? L"true" : L"false",
        (unsigned long)image_open_error, image_size_available ? L"true" : L"false",
        (unsigned long long)image_size, (unsigned long)image_size_error,
        is_absolute_windows_path(cwd) ? L"true" : L"false",
        cwd_attrs != INVALID_FILE_ATTRIBUTES && (cwd_attrs & FILE_ATTRIBUTE_DIRECTORY) ? L"true" : L"false",
        (unsigned long)cwd_error, module_matches ? L"true" : L"false",
        (unsigned long)dependency_mask, (unsigned long)system_directory_error,
        (unsigned long)GetCurrentProcessId(), (unsigned)(sizeof(void *) * 8U),
        (unsigned long)launch_flags,
        nt_available ? L"true" : L"false", (unsigned long)nt_status);
    if (FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                       NULL, error, 0, message, (DWORD)_countof(message), NULL))
        fwprintf(stderr, L"lpac_launch_system_message: %ls\n", message);
}

static int launch_child(int argc, wchar_t **argv) {
    STARTUPINFOEXW startup;
    PROCESS_INFORMATION process;
    PROCESS_INFORMATION control_process;
    SIZE_T attr_size = 0;
    LPPROC_THREAD_ATTRIBUTE_LIST attrs = NULL;
    SECURITY_CAPABILITIES caps;
    DWORD all_packages_policy = PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT;
    PSID sid = NULL;
    HANDLE process_token = NULL;
    wchar_t command[32768];
    size_t used = 0;
    DWORD wait_status, child_exit = 0;
    BOOL initialized = FALSE;
    BOOL in_job = FALSE;
    BOOL job_query_ok = FALSE;
    BOOL parent_token_verified = FALSE;
    DWORD parent_token_error = ERROR_SUCCESS;
    TokenVerification parent_token_checks;
    HANDLE job = NULL;
    HANDLE job_list[1] = { NULL }; /* Referenced by the process attribute list until it is destroyed. */
    HANDLE control_job = NULL;
    wchar_t windows_dir[MAX_PATH], drive_env[MAX_PATH * 2];
    wchar_t path_env[MAX_PATH * 2], env_block[MAX_PATH * 6];
    wchar_t variant_env_block[MAX_PATH * 6];
    size_t env_used = 0;
    DWORD variant_index, variant_entry_count;
    BOOL drive_environment_present = FALSE;
    EnvironmentControlResult environment_control;
    EnvironmentControlResult explicit_environment_control;
    EnvironmentControlResult main_environment_block_control;
    EnvironmentControlResult variant_control;
    ProbeJobExtendedLimitInformation job_limits;
    int status = 20;
    LastNtStatusFn last_nt_status = NULL;
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll) {
        FARPROC address = GetProcAddress(ntdll, "RtlGetLastNtStatus");
        /* Both are function pointers under the Windows ABI. Diagnostic-only:
         * unavailable is explicitly reported; no launch decision uses it. */
        memcpy(&last_nt_status, &address, sizeof(last_nt_status));
    }
    if (argc != 8) return 21;
    if (!ConvertStringSidToSidW(argv[2], &sid)) return fail(L"parse launcher SID", GetLastError());
    memset(&startup, 0, sizeof(startup)); memset(&process, 0, sizeof(process));
    memset(&control_process, 0, sizeof(control_process));
    memset(&environment_control, 0, sizeof(environment_control));
    memset(&explicit_environment_control, 0, sizeof(explicit_environment_control));
    memset(&main_environment_block_control, 0, sizeof(main_environment_block_control));
    memset(&caps, 0, sizeof(caps));
    memset(&parent_token_checks, 0, sizeof(parent_token_checks));
    parent_token_checks.failure_stage = L"not_run";
    InitializeProcThreadAttributeList(NULL, 3, 0, &attr_size);
    attrs = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attr_size);
    if (!attrs || !InitializeProcThreadAttributeList(attrs, 3, 0, &attr_size)) { status = fail(L"allocate process attribute list", GetLastError()); goto done; }
    initialized = TRUE;
    caps.AppContainerSid = sid; caps.Capabilities = NULL; caps.CapabilityCount = 0; caps.Reserved = 0;
    if (!UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, &caps, sizeof(caps), NULL, NULL) ||
        !UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY, &all_packages_policy, sizeof(all_packages_policy), NULL, NULL)) {
        status = fail(L"set LPAC process attributes", GetLastError()); goto done;
    }
    startup.StartupInfo.cb = (DWORD)sizeof(startup); startup.lpAttributeList = attrs;
    if (!append_quoted(command, _countof(command), &used, argv[0]) ||
        !append_quoted(command, _countof(command), &used, L"--child") ||
        !append_quoted(command, _countof(command), &used, argv[2]) ||
        !append_quoted(command, _countof(command), &used, argv[3]) ||
        !append_quoted(command, _countof(command), &used, argv[4]) ||
        !append_quoted(command, _countof(command), &used, argv[5]) ||
        !append_quoted(command, _countof(command), &used, argv[6]) ||
        !append_quoted(command, _countof(command), &used, argv[7])) { status = fail(L"build child command line", ERROR_INSUFFICIENT_BUFFER); goto done; }
    if (!GetWindowsDirectoryW(windows_dir, (UINT)_countof(windows_dir)) ||
        _snwprintf_s(path_env, _countof(path_env), _TRUNCATE, L"PATH=%ls\\System32", windows_dir) < 0) {
        status = fail(L"build restricted child environment", GetLastError()); goto done;
    }
#define APPEND_ENV(value) do { size_t env_len = wcslen(value) + 1; if (env_used + env_len >= _countof(env_block)) { status = fail(L"child environment too large", ERROR_INSUFFICIENT_BUFFER); goto done; } memcpy(env_block + env_used, value, env_len * sizeof(wchar_t)); env_used += env_len; } while (0)
    {
        wchar_t system_root_env[MAX_PATH * 2], temp_env[MAX_PATH * 2];
        wchar_t tmp_env[MAX_PATH * 2], windir_env[MAX_PATH * 2];
        if (((argv[4][0] >= L'A' && argv[4][0] <= L'Z') ||
             (argv[4][0] >= L'a' && argv[4][0] <= L'z')) &&
            argv[4][1] == L':' && (argv[4][2] == L'\\' || argv[4][2] == L'/')) {
            if (_snwprintf_s(drive_env, _countof(drive_env), _TRUNCATE,
                             L"=%c:=%ls", (int)argv[4][0], argv[4]) < 0) {
                status = fail(L"build restricted child environment", ERROR_INSUFFICIENT_BUFFER); goto done;
            }
            drive_environment_present = TRUE;
        }
        if (_snwprintf_s(system_root_env, _countof(system_root_env), _TRUNCATE, L"SystemRoot=%ls", windows_dir) < 0 ||
            _snwprintf_s(temp_env, _countof(temp_env), _TRUNCATE, L"TEMP=%ls", argv[4]) < 0 ||
            _snwprintf_s(tmp_env, _countof(tmp_env), _TRUNCATE, L"TMP=%ls", argv[4]) < 0 ||
            _snwprintf_s(windir_env, _countof(windir_env), _TRUNCATE, L"windir=%ls", windows_dir) < 0) {
            status = fail(L"build restricted child environment", ERROR_INSUFFICIENT_BUFFER); goto done;
        }
        /* CreateProcess requires sorted entries; pass the per-drive CWD entry explicitly. */
        if (drive_environment_present) APPEND_ENV(drive_env);
        APPEND_ENV(path_env);
        APPEND_ENV(system_root_env);
        APPEND_ENV(temp_env);
        APPEND_ENV(tmp_env);
        APPEND_ENV(windir_env);
    }
    env_block[env_used] = L'\0';
#undef APPEND_ENV
    if (!run_lp_environment_control(
            argv[0], command, argv[4], &startup, &caps, &all_packages_policy,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
            TRUE, NULL,
            sid, last_nt_status, &environment_control, &control_job, &control_process,
            &process_token)) {
        report_environment_control(&environment_control);
        status = fail(L"environment control cleanup unconfirmed",
                      environment_control.cleanup_error ? environment_control.cleanup_error : ERROR_INVALID_DATA);
        goto done;
    }
    report_environment_control(&environment_control);
    if (!run_lp_environment_control(
            argv[0], command, argv[4], &startup, &caps, &all_packages_policy,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
            FALSE, NULL,
            sid, last_nt_status, &explicit_environment_control, &control_job, &control_process,
            &process_token)) {
        report_environment_control(&explicit_environment_control);
        status = fail(L"explicit environment control cleanup unconfirmed",
                      explicit_environment_control.cleanup_error ? explicit_environment_control.cleanup_error : ERROR_INVALID_DATA);
        goto done;
    }
    report_environment_control(&explicit_environment_control);
    if (!run_lp_environment_control(
            argv[0], command, argv[4], &startup, &caps, &all_packages_policy,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
            FALSE, env_block,
            sid, last_nt_status, &main_environment_block_control, &control_job, &control_process,
            &process_token)) {
        report_environment_control(&main_environment_block_control);
        status = fail(L"main environment block control cleanup unconfirmed",
                      main_environment_block_control.cleanup_error ?
                      main_environment_block_control.cleanup_error : ERROR_INVALID_DATA);
        goto done;
    }
    report_environment_control(&main_environment_block_control);
    if (wcscmp(argv[3], L"registered-storage") == 0 &&
        main_environment_block_control.main_environment_block_safe &&
        main_environment_block_control.main_environment_entry_count > 0) {
        for (variant_index = 0;
             variant_index < main_environment_block_control.main_environment_entry_count;
             ++variant_index) {
            if (!build_environment_block_omitting_entry(
                    env_block, variant_index, variant_env_block,
                    _countof(variant_env_block), &variant_entry_count)) {
                ZeroMemory(&variant_control, sizeof(variant_control));
                variant_control.diagnostic_only = TRUE;
                variant_control.parent_environment_filtered = main_environment_block_control.parent_environment_filtered;
                variant_control.lp_environment_null = FALSE;
                variant_control.main_environment_block = TRUE;
                variant_control.main_environment_block_safe = TRUE;
                variant_control.main_environment_entry_count = variant_entry_count;
                variant_control.main_environment_variant = TRUE;
                variant_control.main_environment_variant_id = variant_index + 1;
                variant_control.setup_error = ERROR_INVALID_DATA;
                variant_control.cleanup_confirmed = TRUE;
                variant_control.token_details.failure_stage = L"not_run";
                report_environment_control(&variant_control);
                status = fail(L"build main environment variant", ERROR_INVALID_DATA);
                goto done;
            }
            if (!run_lp_environment_control(
                    argv[0], command, argv[4], &startup, &caps, &all_packages_policy,
                    EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
                    FALSE, variant_env_block,
                    sid, last_nt_status, &variant_control, &control_job, &control_process,
                    &process_token)) {
                variant_control.main_environment_variant = TRUE;
                variant_control.main_environment_variant_id = variant_index + 1;
                report_environment_control(&variant_control);
                status = fail(L"main environment variant control cleanup unconfirmed",
                              variant_control.cleanup_error ? variant_control.cleanup_error : ERROR_INVALID_DATA);
                goto done;
            }
            variant_control.main_environment_variant = TRUE;
            variant_control.main_environment_variant_id = variant_index + 1;
            report_environment_control(&variant_control);
        }
    }
    ZeroMemory(&job_limits, sizeof(job_limits));
    job_limits.BasicLimitInformation.LimitFlags = 0x00002000; /* JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE */
    job = CreateJobObjectW(NULL, NULL);
    if (!job || !SetInformationJobObject(job, (JOBOBJECTINFOCLASS)9, &job_limits, (DWORD)sizeof(job_limits))) {
        status = fail(L"create bounded child job", GetLastError()); goto done;
    }
    job_list[0] = job;
    if (!UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_JOB_LIST,
                                   job_list, sizeof(HANDLE), NULL, NULL)) {
        status = fail(L"set LPAC child job attribute", GetLastError()); goto done;
    }
    if (!CreateProcessW(argv[0], command, NULL, NULL, FALSE,
                        EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
                        env_block, argv[4], &startup.StartupInfo, &process)) {
        DWORD launch_error = GetLastError();
        LONG nt_status = last_nt_status ? last_nt_status() : 0;
        report_launch_failure(argv[0], argv[4], launch_error,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
            last_nt_status != NULL, nt_status, drive_environment_present);
        status = fail(L"CreateProcessW LPAC", launch_error); goto done;
    }
    job_query_ok = IsProcessInJob(process.hProcess, job, &in_job);
    if (!job_query_ok || !in_job) {
        DWORD error = job_query_ok ? ERROR_INVALID_DATA : GetLastError();
        TerminateJobObject(job, 28);
        TerminateProcess(process.hProcess, 28); WaitForSingleObject(process.hProcess, 5000);
        status = fail(L"verify suspended LPAC child job membership", error); goto done;
    }
    if (!OpenProcessToken(process.hProcess, TOKEN_QUERY, &process_token)) {
        parent_token_error = GetLastError();
        token_verification_fail(&parent_token_checks, L"OpenProcessToken", parent_token_error, 0);
    } else {
        parent_token_verified = verify_token(process_token, sid, &parent_token_checks);
        parent_token_error = parent_token_checks.api_error;
        CloseHandle(process_token);
        process_token = NULL;
    }
    if (!parent_token_verified) {
        report_token_diagnostic(FALSE, &parent_token_checks);
        TerminateJobObject(job, 26);
        TerminateProcess(process.hProcess, 26); WaitForSingleObject(process.hProcess, 5000);
        status = fail(L"suspended LPAC child token verification",
                      parent_token_error ? parent_token_error : ERROR_INVALID_DATA); goto done;
    }
    fwprintf(stderr,
        L"pre_resume_attestation: {\"version\":1,\"token_verified\":true,"
        L"\"is_appcontainer\":true,\"is_lpac\":true,\"low_integrity\":true,"
        L"\"expected_sid_match\":true,\"zero_capabilities\":true,"
        L"\"job_membership_verified\":true}\n");
    if (ResumeThread(process.hThread) == (DWORD)-1) { status = fail(L"resume LPAC child", GetLastError()); TerminateJobObject(job, 26); TerminateProcess(process.hProcess, 26); WaitForSingleObject(process.hProcess, 5000); goto done; }
    wait_status = WaitForSingleObject(process.hProcess, CHILD_TIMEOUT_MS);
    if (wait_status != WAIT_OBJECT_0) {
        DWORD error = wait_status == WAIT_TIMEOUT ? WAIT_TIMEOUT : GetLastError();
        TerminateJobObject(job, 27);
        TerminateProcess(process.hProcess, 27); WaitForSingleObject(process.hProcess, 5000);
        status = fail(L"bounded LPAC child wait", error); goto done;
    }
    if (!GetExitCodeProcess(process.hProcess, &child_exit)) { status = fail(L"read child exit code", GetLastError()); goto done; }
    {
        JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounting;
        if (!QueryInformationJobObject(job, JobObjectBasicAccountingInformation,
                                       &accounting, (DWORD)sizeof(accounting), NULL)) {
            status = fail(L"query completed LPAC job accounting", GetLastError()); goto done;
        }
        fwprintf(stderr,
            L"post_exit_job_attestation: {\"version\":1,\"active_processes\":%llu,\"total_processes\":%llu}\n",
            (unsigned long long)accounting.ActiveProcesses,
            (unsigned long long)accounting.TotalProcesses);
        if (accounting.ActiveProcesses != 0 || accounting.TotalProcesses != 1) {
            status = fail(L"LPAC job did not become empty", ERROR_INVALID_DATA); goto done;
        }
    }
    status = child_exit == 0 ? 0 : (int)child_exit;
    CloseHandle(process.hThread); CloseHandle(process.hProcess); process.hThread = NULL; process.hProcess = NULL;
done:
    if (process_token) {
        if (!CloseHandle(process_token) && status == 0)
            status = fail(L"close token handle", GetLastError());
        process_token = NULL;
    }
    {
        DWORD cleanup_attempt;
        BOOL control_process_terminated = control_process.hProcess == NULL;
        BOOL control_job_empty = control_job == NULL;
        JOBOBJECT_BASIC_ACCOUNTING_INFORMATION control_accounting;
        if (control_process.hProcess) {
            if (!TerminateProcess(control_process.hProcess, 0xE6)) {
                DWORD terminate_error = GetLastError();
                if (WaitForSingleObject(control_process.hProcess, 0) != WAIT_OBJECT_0 && status == 0)
                    status = fail(L"retry diagnostic process termination", terminate_error);
            }
            wait_status = WaitForSingleObject(control_process.hProcess, 5000);
            if (wait_status != WAIT_OBJECT_0) {
                if (control_job && !TerminateJobObject(control_job, 0xE6) && status == 0)
                    status = fail(L"retry diagnostic Job termination", GetLastError());
                if (!TerminateProcess(control_process.hProcess, 0xE6) && status == 0)
                    status = fail(L"retry diagnostic process termination", GetLastError());
                wait_status = WaitForSingleObject(control_process.hProcess, 5000);
            }
            control_process_terminated = wait_status == WAIT_OBJECT_0;
        }
        if (control_job) {
            if (QueryInformationJobObject(control_job, JobObjectBasicAccountingInformation,
                                          &control_accounting, (DWORD)sizeof(control_accounting), NULL))
                control_job_empty = control_accounting.ActiveProcesses == 0;
            if (!control_job_empty) {
                if (!TerminateJobObject(control_job, 0xE6) && status == 0)
                    status = fail(L"retry diagnostic Job termination", GetLastError());
                for (cleanup_attempt = 0; cleanup_attempt < 100; ++cleanup_attempt) {
                    if (!QueryInformationJobObject(control_job, JobObjectBasicAccountingInformation,
                                                   &control_accounting, (DWORD)sizeof(control_accounting), NULL)) {
                        if (status == 0) status = fail(L"verify diagnostic Job cleanup", GetLastError());
                        break;
                    }
                    control_job_empty = control_accounting.ActiveProcesses == 0;
                    if (control_job_empty) break;
                    Sleep(50);
                }
            }
        }
        if (control_process_terminated && control_job_empty) {
            if (control_process.hThread) {
                if (!CloseHandle(control_process.hThread)) {
                    if (status == 0) status = fail(L"close diagnostic thread handle", GetLastError());
                } else control_process.hThread = NULL;
            }
            if (control_process.hProcess) {
                if (!CloseHandle(control_process.hProcess)) {
                    if (status == 0) status = fail(L"close diagnostic process handle", GetLastError());
                } else control_process.hProcess = NULL;
            }
            if (control_job) {
                if (!CloseHandle(control_job)) {
                    if (status == 0) status = fail(L"close diagnostic Job handle", GetLastError());
                } else control_job = NULL;
            }
        } else if (status == 0) {
            status = fail(L"diagnostic cleanup unconfirmed", ERROR_INVALID_DATA);
        }
    }
    if (process.hThread) CloseHandle(process.hThread);
    if (process.hProcess) CloseHandle(process.hProcess);
    if (initialized) DeleteProcThreadAttributeList(attrs);
    if (attrs) HeapFree(GetProcessHeap(), 0, attrs);
    /* An unconfirmed diagnostic Job handle is intentionally retained until process exit;
     * JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE then provides the final kernel cleanup. */
    if (job) CloseHandle(job); /* Kills any unexpected surviving child before the launcher exits. */
    if (sid) LocalFree(sid);
    return status;
}

int wmain(int argc, wchar_t **argv) {
    if (argc > 1 && wcscmp(argv[1], L"--child") == 0) return child_main(argc, argv);
    if (argc > 1 && wcscmp(argv[1], L"--launch") == 0) return launch_child(argc, argv);
    fwprintf(stderr, L"usage: appcontainer_acl_probe.exe --launch SID MODE WORKSPACE ARG1 ARG2 REPORT\n");
    return 2;
}
