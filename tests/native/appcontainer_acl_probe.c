#define _WIN32_WINNT 0x0A00
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <sddl.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <stdint.h>
#include <string.h>

#pragma comment(lib, "advapi32.lib")

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

typedef struct ProbeResult {
    const wchar_t *name;
    BOOL ok;
    DWORD error;
} ProbeResult;

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

static BOOL token_bool(HANDLE token, TOKEN_INFORMATION_CLASS cls, BOOL *value) {
    DWORD bytes = 0;
    DWORD result = 0;
    if (!GetTokenInformation(token, cls, &result, sizeof(result), &bytes)) return FALSE;
    *value = result != 0;
    return TRUE;
}

static BOOL verify_token(HANDLE token, PSID expected_sid) {
    BOOL is_container = FALSE, is_lpac = FALSE;
    DWORD needed = 0;
    BYTE *buffer = NULL;
    TOKEN_APPCONTAINER_INFORMATION *container_info;
    BOOL ok = FALSE;
    if (!token_bool(token, TokenIsAppContainer, &is_container) || !is_container) return FALSE;
    if (!token_bool(token, TokenIsLessPrivilegedAppContainer, &is_lpac) || !is_lpac) return FALSE;
    if (!GetTokenInformation(token, TokenAppContainerSid, NULL, 0, &needed) && GetLastError() != ERROR_INSUFFICIENT_BUFFER) return FALSE;
    if (needed < sizeof(*container_info)) return FALSE;
    buffer = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, needed);
    if (!buffer) return FALSE;
    if (!GetTokenInformation(token, TokenAppContainerSid, buffer, needed, &needed)) goto done;
    container_info = (TOKEN_APPCONTAINER_INFORMATION *)buffer;
    if (!container_info->TokenAppContainer || !EqualSid(container_info->TokenAppContainer, expected_sid)) goto done;
    needed = 0;
    SetLastError(ERROR_SUCCESS);
    if (GetTokenInformation(token, TokenCapabilities, NULL, 0, &needed)) goto done;
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || needed < sizeof(DWORD)) goto done;
    {
        BYTE *caps = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, needed);
        if (!caps) goto done;
        if (!GetTokenInformation(token, TokenCapabilities, caps, needed, &needed) ||
            ((TOKEN_GROUPS *)caps)->GroupCount != 0) {
            HeapFree(GetProcessHeap(), 0, caps);
            goto done;
        }
        HeapFree(GetProcessHeap(), 0, caps);
    }
    ok = TRUE;
done:
    HeapFree(GetProcessHeap(), 0, buffer);
    return ok;
}

static BOOL write_report(const wchar_t *path, const wchar_t *mode, BOOL token_ok,
                         const ProbeResult *results, DWORD count) {
    HANDLE file = INVALID_HANDLE_VALUE;
    wchar_t json[MAX_REPORT];
    DWORD used, i, written;
    int n;
    n = _snwprintf_s(json, MAX_REPORT, _TRUNCATE,
        L"{\"version\":1,\"mode\":\"%ls\",\"token_verified\":%ls,\"checks\":[",
        mode, token_ok ? L"true" : L"false");
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

static ProbeResult require_denied(const wchar_t *name, const wchar_t *path, BOOL directory) {
    ProbeResult result = { name, FALSE, ERROR_SUCCESS };
    if (directory) {
        if (CreateDirectoryW(path, NULL)) { result.error = ERROR_SUCCESS; return result; }
        result.error = GetLastError();
    } else {
        HANDLE file = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
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

static int child_main(int argc, wchar_t **argv) {
    PSID sid = NULL;
    HANDLE token = NULL;
    ProbeResult results[8];
    DWORD count = 0;
    BOOL token_ok = FALSE;
    const wchar_t *mode, *workspace, *arg1, *arg2, *report;
    if (argc != 8) return 21;
    if (!ConvertStringSidToSidW(argv[2], &sid)) return fail(L"parse child SID", GetLastError());
    mode = argv[3]; workspace = argv[4]; arg1 = argv[5]; arg2 = argv[6]; report = argv[7];
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) { LocalFree(sid); return fail(L"open child token", GetLastError()); }
    token_ok = verify_token(token, sid);
    CloseHandle(token);
    if (!token_ok) { LocalFree(sid); return fail(L"child LPAC token verification", ERROR_INVALID_TOKEN); }
    results[count++] = verify_minimal_environment(workspace);
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
    } else if (wcscmp(mode, L"outside") == 0) {
        wchar_t created[MAX_PATH * 4], subdir[MAX_PATH * 4];
        if (swprintf_s(created, _countof(created), L"%ls\\new.bin", arg2) < 0 ||
            swprintf_s(subdir, _countof(subdir), L"%ls\\newdir", arg2) < 0) { LocalFree(sid); return 23; }
        results[count++] = require_denied(L"outside_existing_file_write", arg1, FALSE);
        results[count++] = require_denied(L"outside_new_file_create", created, FALSE);
        results[count++] = require_denied(L"outside_directory_create", subdir, TRUE);
    } else if (wcscmp(mode, L"isolation") == 0 || wcscmp(mode, L"stale") == 0 || wcscmp(mode, L"revoked") == 0) {
        results[count++] = require_read_denied(L"other_workspace_read_denied", arg1);
        results[count++] = require_denied(L"other_workspace_write_denied", arg1, FALSE);
        if (wcscmp(mode, L"revoked") == 0) {
            results[count++] = require_security_open_denied(L"revoked_write_dac_denied", arg1, WRITE_DAC);
            results[count++] = require_security_open_denied(L"revoked_write_owner_denied", arg1, WRITE_OWNER);
        }
    } else {
        LocalFree(sid);
        return 24;
    }
    if (!write_report(report, mode, token_ok, results, count)) { LocalFree(sid); return fail(L"write bounded evidence report", GetLastError()); }
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
                                  BOOL nt_available, LONG nt_status) {
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
        L"\"win32_error\":%lu,\"image_is_absolute\":%ls,"
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
    HANDLE job = NULL;
    wchar_t windows_dir[MAX_PATH], path_env[MAX_PATH * 2], env_block[MAX_PATH * 6];
    size_t env_used = 0;
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
    memset(&startup, 0, sizeof(startup)); memset(&process, 0, sizeof(process)); memset(&caps, 0, sizeof(caps));
    InitializeProcThreadAttributeList(NULL, 2, 0, &attr_size);
    attrs = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attr_size);
    if (!attrs || !InitializeProcThreadAttributeList(attrs, 2, 0, &attr_size)) { status = fail(L"allocate process attribute list", GetLastError()); goto done; }
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
        wchar_t item[MAX_PATH * 2];
        _snwprintf_s(item, _countof(item), _TRUNCATE, L"SystemRoot=%ls", windows_dir); APPEND_ENV(item);
        _snwprintf_s(item, _countof(item), _TRUNCATE, L"windir=%ls", windows_dir); APPEND_ENV(item);
        APPEND_ENV(path_env);
        _snwprintf_s(item, _countof(item), _TRUNCATE, L"TEMP=%ls", argv[4]); APPEND_ENV(item);
        _snwprintf_s(item, _countof(item), _TRUNCATE, L"TMP=%ls", argv[4]); APPEND_ENV(item);
    }
    env_block[env_used] = L'\0';
#undef APPEND_ENV
    ZeroMemory(&job_limits, sizeof(job_limits));
    job_limits.BasicLimitInformation.LimitFlags = 0x00002000; /* JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE */
    job = CreateJobObjectW(NULL, NULL);
    if (!job || !SetInformationJobObject(job, (JOBOBJECTINFOCLASS)9, &job_limits, (DWORD)sizeof(job_limits))) {
        status = fail(L"create bounded child job", GetLastError()); goto done;
    }
    if (!CreateProcessW(argv[0], command, NULL, NULL, FALSE,
                        EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
                        env_block, argv[4], &startup.StartupInfo, &process)) {
        DWORD launch_error = GetLastError();
        LONG nt_status = last_nt_status ? last_nt_status() : 0;
        report_launch_failure(argv[0], argv[4], launch_error,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
            last_nt_status != NULL, nt_status);
        status = fail(L"CreateProcessW LPAC", launch_error); goto done;
    }
    if (!AssignProcessToJobObject(job, process.hProcess)) {
        DWORD error = GetLastError();
        TerminateProcess(process.hProcess, 28); WaitForSingleObject(process.hProcess, 5000);
        status = fail(L"assign LPAC child to kill-on-close job", error); goto done;
    }
    if (!OpenProcessToken(process.hProcess, TOKEN_QUERY, &process_token) || !verify_token(process_token, sid)) {
        DWORD error = GetLastError();
        if (process_token) { CloseHandle(process_token); process_token = NULL; }
        TerminateProcess(process.hProcess, 26); WaitForSingleObject(process.hProcess, 5000);
        status = fail(L"suspended LPAC child token verification", error ? error : ERROR_INVALID_TOKEN); goto done;
    }
    CloseHandle(process_token); process_token = NULL;
    if (ResumeThread(process.hThread) == (DWORD)-1) { status = fail(L"resume LPAC child", GetLastError()); TerminateProcess(process.hProcess, 26); WaitForSingleObject(process.hProcess, 5000); goto done; }
    wait_status = WaitForSingleObject(process.hProcess, CHILD_TIMEOUT_MS);
    if (wait_status != WAIT_OBJECT_0) {
        DWORD error = wait_status == WAIT_TIMEOUT ? WAIT_TIMEOUT : GetLastError();
        TerminateProcess(process.hProcess, 27); WaitForSingleObject(process.hProcess, 5000);
        status = fail(L"bounded LPAC child wait", error); goto done;
    }
    if (!GetExitCodeProcess(process.hProcess, &child_exit)) { status = fail(L"read child exit code", GetLastError()); goto done; }
    status = child_exit == 0 ? 0 : (int)child_exit;
    CloseHandle(process.hThread); CloseHandle(process.hProcess); process.hThread = NULL; process.hProcess = NULL;
done:
    if (process_token) CloseHandle(process_token);
    if (process.hThread) CloseHandle(process.hThread);
    if (process.hProcess) CloseHandle(process.hProcess);
    if (initialized) DeleteProcThreadAttributeList(attrs);
    if (attrs) HeapFree(GetProcessHeap(), 0, attrs);
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
