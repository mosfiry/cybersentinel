#define _WIN32_WINNT 0x0A00
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <userenv.h>
#include <sddl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stddef.h>
#include "access_check.h"

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "userenv.lib")

#ifndef PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES
#define PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES 0x00020009
#endif
#ifndef PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY
#define PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY 0x0002000F
#endif
#ifndef PROC_THREAD_ATTRIBUTE_JOB_LIST
#define PROC_THREAD_ATTRIBUTE_JOB_LIST 0x0002000D
#endif
#ifndef PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT
#define PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT 0x00000001
#endif

typedef char token_lpac_enum_must_be_46[
    TokenIsLessPrivilegedAppContainer == 46 ? 1 : -1];

#define TOKEN_INFO_MAX_BYTES 65536UL
#define TOKEN_CLASS_QUERY_COUNT 3
#define DIAGNOSTIC_TIMEOUT_MS 5000UL
#define LOW_INTEGRITY_RID 0x1000UL

typedef struct SecurityCapabilitiesCompat {
    PSID AppContainerSid;
    PSID *Capabilities;
    DWORD CapabilityCount;
    DWORD Reserved;
} SecurityCapabilitiesCompat;

typedef struct TokenQueryAttempt {
    DWORD buffer_size;
    DWORD return_length;
    DWORD win32_error;
    BOOL succeeded;
    DWORD raw_value_width_bits;
    ULONGLONG raw_value;
} TokenQueryAttempt;

typedef LONG (WINAPI *LastNtStatusFn)(void);

typedef struct TokenDiagnostic {
    const char *control;
    BOOL requested_lpac;
    BOOL process_created;
    DWORD create_error;
    DWORD create_win32_error;
    BOOL create_attempted;
    BOOL create_ntstatus_getter_available;
    BOOL create_ntstatus_sampled;
    LONG create_ntstatus;
    DWORD creation_flags;
    BOOL security_capabilities_attribute_set;
    BOOL job_list_attribute_set;
    BOOL all_packages_policy_attribute_set;
    const char *environment_block_mode;
    const char *application_path_redacted;
    const char *working_directory_redacted;
    const char *failure_stage_code;
    BOOL job_membership_verified;
    DWORD job_active_before;
    DWORD job_total_before;
    BOOL token_opened;
    DWORD token_open_error;
    BOOL appcontainer_query_succeeded;
    DWORD appcontainer_value;
    DWORD appcontainer_return_length;
    DWORD appcontainer_error;
    TokenQueryAttempt class46[TOKEN_CLASS_QUERY_COUNT];
    BOOL token_type_query_succeeded;
    DWORD token_type;
    DWORD token_type_return_length;
    DWORD token_type_error;
    BOOL sid_query_succeeded;
    BOOL expected_sid_match;
    DWORD sid_size_query_return_length;
    DWORD sid_size_query_error;
    DWORD sid_return_length;
    DWORD sid_query_error;
    BOOL integrity_query_succeeded;
    DWORD integrity_rid;
    DWORD integrity_return_length;
    DWORD integrity_error;
    BOOL capabilities_query_succeeded;
    DWORD capability_count;
    DWORD capabilities_return_length;
    DWORD capabilities_error;
    BOOL access_check_api_succeeded;
    BOOL access_check_granted;
    DWORD access_check_granted_access;
    DWORD access_check_error;
    BOOL process_signaled;
    BOOL job_query_after_succeeded;
    DWORD job_active_after;
    DWORD job_total_after;
    BOOL job_empty;
    BOOL process_handle_closed;
    BOOL thread_handle_closed;
    BOOL job_handle_closed;
    BOOL attributes_deleted;
    BOOL passed;
} TokenDiagnostic;

static BOOL append_environment(wchar_t *environment, size_t capacity,
                               size_t *used, const wchar_t *name,
                               const wchar_t *value)
{
    int written;
    size_t remaining;
    if (*used >= capacity) return FALSE;
    remaining = capacity - *used;
    written = _snwprintf_s(environment + *used, remaining, _TRUNCATE,
                           L"%ls=%ls", name, value);
    if (written < 0) return FALSE;
    *used += (size_t)written + 1;
    if (*used >= capacity) return FALSE;
    environment[*used] = L'\0';
    return TRUE;
}

static BOOL query_dword(HANDLE token, TOKEN_INFORMATION_CLASS info_class,
                        DWORD *value, DWORD *return_length, DWORD *error)
{
    BOOL ok;
    *value = 0;
    *return_length = 0;
    *error = ERROR_SUCCESS;
    SetLastError(ERROR_SUCCESS);
    ok = GetTokenInformation(token, info_class, value, sizeof(*value), return_length);
    if (!ok) *error = GetLastError();
    return ok;
}

static TokenQueryAttempt query_class46(HANDLE token, void *buffer, DWORD buffer_size)
{
    TokenQueryAttempt attempt;
    DWORD returned = 0;
    BOOL ok;
    ZeroMemory(&attempt, sizeof(attempt));
    attempt.buffer_size = buffer_size;
    SetLastError(ERROR_SUCCESS);
    ok = GetTokenInformation(token, TokenIsLessPrivilegedAppContainer,
                             buffer, buffer_size, &returned);
    attempt.succeeded = ok;
    attempt.return_length = returned;
    attempt.win32_error = ok ? ERROR_SUCCESS : GetLastError();
    if (ok && buffer && returned <= buffer_size) {
        if (returned == sizeof(DWORD)) {
            DWORD raw = 0;
            memcpy(&raw, buffer, sizeof(raw));
            attempt.raw_value = raw;
            attempt.raw_value_width_bits = 32;
        } else if (returned == sizeof(ULONGLONG)) {
            memcpy(&attempt.raw_value, buffer, sizeof(attempt.raw_value));
            attempt.raw_value_width_bits = 64;
        }
    }
    return attempt;
}

static BOOL pointer_within_buffer(const BYTE *buffer, DWORD length, PSID sid)
{
    ULONG_PTR start = (ULONG_PTR)buffer;
    ULONG_PTR address = (ULONG_PTR)sid;
    ULONG_PTR offset;
    const BYTE *sid_bytes;
    DWORD sid_length;
    if (!sid || address < start) return FALSE;
    offset = address - start;
    if (offset > length || length - (DWORD)offset < 8U) return FALSE;
    sid_bytes = buffer + offset;
    if (sid_bytes[1] > SID_MAX_SUB_AUTHORITIES) return FALSE;
    sid_length = 8U + (DWORD)sid_bytes[1] * (DWORD)sizeof(DWORD);
    return sid_length <= length - (DWORD)offset && IsValidSid(sid);
}

static void inspect_token(HANDLE token, PSID expected_sid, TokenDiagnostic *report)
{
    DWORD value = 0, returned = 0, error = ERROR_SUCCESS, needed = 0;
    TOKEN_TYPE token_type = TokenPrimary;
    BYTE *buffer = NULL;
    BOOL size_ok;

    report->appcontainer_query_succeeded = query_dword(
        token, TokenIsAppContainer, &value, &returned, &error);
    report->appcontainer_value = value;
    report->appcontainer_return_length = returned;
    report->appcontainer_error = error;

    {
        BYTE sized_storage[sizeof(ULONGLONG)] = { 0 };
        DWORD value4 = 0;
        report->class46[0] = query_class46(token, NULL, 0);
        report->class46[1] = query_class46(token, &value4, sizeof(value4));
        report->class46[2] = query_class46(token, sized_storage, sizeof(sized_storage));
    }

    report->token_type_return_length = sizeof(token_type);
    SetLastError(ERROR_SUCCESS);
    report->token_type_query_succeeded = GetTokenInformation(
        token, TokenType, &token_type, sizeof(token_type),
        &report->token_type_return_length);
    report->token_type_error = report->token_type_query_succeeded ? ERROR_SUCCESS : GetLastError();
    report->token_type = (DWORD)token_type;

    size_ok = GetTokenInformation(token, TokenAppContainerSid, NULL, 0, &needed);
    report->sid_size_query_return_length = needed;
    report->sid_size_query_error = size_ok ? ERROR_SUCCESS : GetLastError();
    if (!size_ok && report->sid_size_query_error == ERROR_INSUFFICIENT_BUFFER &&
        needed >= sizeof(TOKEN_APPCONTAINER_INFORMATION) && needed <= TOKEN_INFO_MAX_BYTES) {
        TOKEN_APPCONTAINER_INFORMATION *container_info;
        DWORD sid_returned = needed;
        buffer = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, needed);
        if (buffer) {
            SetLastError(ERROR_SUCCESS);
            report->sid_query_succeeded = GetTokenInformation(
                token, TokenAppContainerSid, buffer, needed, &sid_returned);
            report->sid_return_length = sid_returned;
            report->sid_query_error = report->sid_query_succeeded ? ERROR_SUCCESS : GetLastError();
            if (report->sid_query_succeeded && sid_returned <= needed &&
                sid_returned >= sizeof(TOKEN_APPCONTAINER_INFORMATION)) {
                container_info = (TOKEN_APPCONTAINER_INFORMATION *)buffer;
                if (pointer_within_buffer(buffer, sid_returned,
                                          container_info->TokenAppContainer))
                    report->expected_sid_match = EqualSid(
                        container_info->TokenAppContainer, expected_sid);
                else
                    report->sid_query_error = ERROR_INVALID_SID;
            } else if (report->sid_query_succeeded) {
                report->sid_query_error = ERROR_INVALID_DATA;
            }
            HeapFree(GetProcessHeap(), 0, buffer);
            buffer = NULL;
        } else {
            report->sid_query_error = ERROR_NOT_ENOUGH_MEMORY;
        }
    }

    needed = 0;
    size_ok = GetTokenInformation(token, TokenIntegrityLevel, NULL, 0, &needed);
    if (!size_ok && GetLastError() == ERROR_INSUFFICIENT_BUFFER &&
        needed >= sizeof(TOKEN_MANDATORY_LABEL) && needed <= TOKEN_INFO_MAX_BYTES) {
        DWORD integrity_returned = needed;
        buffer = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, needed);
        if (buffer) {
            TOKEN_MANDATORY_LABEL *label;
            BYTE *subauthority_count;
            SetLastError(ERROR_SUCCESS);
            report->integrity_query_succeeded = GetTokenInformation(
                token, TokenIntegrityLevel, buffer, needed, &integrity_returned);
            report->integrity_return_length = integrity_returned;
            report->integrity_error = report->integrity_query_succeeded ? ERROR_SUCCESS : GetLastError();
            if (report->integrity_query_succeeded && integrity_returned <= needed &&
                integrity_returned >= sizeof(TOKEN_MANDATORY_LABEL)) {
                label = (TOKEN_MANDATORY_LABEL *)buffer;
                subauthority_count = label->Label.Sid ?
                    GetSidSubAuthorityCount(label->Label.Sid) : NULL;
                if (label->Label.Sid && IsValidSid(label->Label.Sid) &&
                    subauthority_count && *subauthority_count == 1) {
                    DWORD *rid = GetSidSubAuthority(label->Label.Sid, 0);
                    if (rid) report->integrity_rid = *rid;
                    else report->integrity_error = ERROR_INVALID_SID;
                } else {
                    report->integrity_error = ERROR_INVALID_SID;
                }
            } else if (report->integrity_query_succeeded) {
                report->integrity_error = ERROR_INVALID_DATA;
            }
            HeapFree(GetProcessHeap(), 0, buffer);
            buffer = NULL;
        } else {
            report->integrity_error = ERROR_NOT_ENOUGH_MEMORY;
        }
    } else {
        report->integrity_error = size_ok ? ERROR_INVALID_DATA : GetLastError();
        report->integrity_return_length = needed;
    }

    needed = 0;
    size_ok = GetTokenInformation(token, TokenCapabilities, NULL, 0, &needed);
    if (!size_ok && GetLastError() == ERROR_INSUFFICIENT_BUFFER &&
        needed >= sizeof(DWORD) && needed <= TOKEN_INFO_MAX_BYTES) {
        DWORD capabilities_returned = needed;
        buffer = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, needed);
        if (buffer) {
            TOKEN_GROUPS *groups;
            SetLastError(ERROR_SUCCESS);
            report->capabilities_query_succeeded = GetTokenInformation(
                token, TokenCapabilities, buffer, needed, &capabilities_returned);
            report->capabilities_return_length = capabilities_returned;
            report->capabilities_error = report->capabilities_query_succeeded ? ERROR_SUCCESS : GetLastError();
            if (report->capabilities_query_succeeded && capabilities_returned <= needed &&
                capabilities_returned >= sizeof(DWORD)) {
                groups = (TOKEN_GROUPS *)buffer;
                report->capability_count = groups->GroupCount;
            } else if (report->capabilities_query_succeeded) {
                report->capabilities_error = ERROR_INVALID_DATA;
            }
            HeapFree(GetProcessHeap(), 0, buffer);
            buffer = NULL;
        } else {
            report->capabilities_error = ERROR_NOT_ENOUGH_MEMORY;
        }
    } else {
        report->capabilities_error = size_ok ? ERROR_INVALID_DATA : GetLastError();
        report->capabilities_return_length = needed;
    }
}

static BOOL run_control(PSID expected_sid, const wchar_t *sid_text,
                        BOOL request_lpac, TokenDiagnostic *report)
{
    STARTUPINFOEXW startup;
    PROCESS_INFORMATION process;
    SECURITY_CAPABILITIES security_capabilities;
    DWORD all_packages_policy = PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT;
    HANDLE job = NULL;
    HANDLE job_list[1] = { NULL };
    HANDLE token = NULL;
    SIZE_T attribute_bytes = 0;
    LPPROC_THREAD_ATTRIBUTE_LIST attributes = NULL;
    BOOL attributes_initialized = FALSE;
    BOOL in_job = FALSE;
    DWORD error = ERROR_SUCCESS;
    DWORD wait_result;
    const char *stage_code = "initialization";
    DWORD creation_attribute_count = request_lpac ? 3U : 2U;
    wchar_t image[MAX_PATH];
    wchar_t command[32768];
    wchar_t windows_directory[MAX_PATH];
    wchar_t current_directory[MAX_PATH];
    wchar_t path_directory[MAX_PATH * 2];
    wchar_t drive_environment_name[4] = { L'=', L'\0', L'\0', L'\0' };
    wchar_t environment[1024];
    size_t environment_used = 0;
    DWORD current_directory_length;
    DWORD creation_flags = EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED |
                           CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW;
    int command_length;
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION job_limits;
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounting;
    LastNtStatusFn last_nt_status = NULL;
    HMODULE ntdll = NULL;
    FARPROC ntstatus_address = NULL;
    BOOL ok = FALSE;

    ZeroMemory(report, sizeof(*report));
    report->control = request_lpac ? "lpac_candidate" : "ordinary_appcontainer";
    report->requested_lpac = request_lpac;
    report->environment_block_mode = "explicit_unicode_sorted";
    report->application_path_redacted =
        "<SYSTEM_DRIVE>:\\\\<SCRATCH>\\\\control\\\\lpac_token_identity_probe.exe";
    report->working_directory_redacted = "<SYSTEM_DRIVE>:\\\\<SCRATCH>\\\\control";
    report->process_handle_closed = TRUE;
    report->thread_handle_closed = TRUE;
    report->job_handle_closed = TRUE;
    report->attributes_deleted = TRUE;
    ZeroMemory(&startup, sizeof(startup));
    ZeroMemory(&process, sizeof(process));
    ZeroMemory(&security_capabilities, sizeof(security_capabilities));
    ZeroMemory(&job_limits, sizeof(job_limits));
    ZeroMemory(&accounting, sizeof(accounting));
    ZeroMemory(environment, sizeof(environment));

    stage_code = "module_path";
    if (!GetModuleFileNameW(NULL, image, (DWORD)_countof(image))) {
        error = GetLastError();
        goto cleanup;
    }
    stage_code = "windows_directory";
    if (!GetWindowsDirectoryW(windows_directory, (UINT)_countof(windows_directory))) {
        error = GetLastError();
        goto cleanup;
    }
    stage_code = "current_directory";
    current_directory_length = GetCurrentDirectoryW(
        (DWORD)_countof(current_directory), current_directory);
    if (!current_directory_length || current_directory_length >= _countof(current_directory)) {
        error = GetLastError();
        if (error == ERROR_SUCCESS) error = ERROR_INSUFFICIENT_BUFFER;
        goto cleanup;
    }
    stage_code = "validate_current_directory";
    if (current_directory_length < 3U || current_directory[1] != L':' ||
        (current_directory[2] != L'\\' && current_directory[2] != L'/')) {
        error = ERROR_INVALID_DATA;
        goto cleanup;
    }
    drive_environment_name[1] = current_directory[0];
    drive_environment_name[2] = L':';
    stage_code = "child_environment";
    if (_snwprintf_s(path_directory, _countof(path_directory), _TRUNCATE,
                     L"%ls\\System32", windows_directory) < 0) {
        error = ERROR_INSUFFICIENT_BUFFER;
        goto cleanup;
    }
    command_length = _snwprintf_s(command, _countof(command), _TRUNCATE,
                                  L"\"%ls\" --idle-child", image);
    if (command_length < 0 ||
        !append_environment(environment, _countof(environment), &environment_used,
                            drive_environment_name, current_directory) ||
        !append_environment(environment, _countof(environment), &environment_used,
                            L"PATH", path_directory) ||
        !append_environment(environment, _countof(environment), &environment_used,
                            L"SystemRoot", windows_directory) ||
        !append_environment(environment, _countof(environment), &environment_used,
                            L"TEMP", current_directory) ||
        !append_environment(environment, _countof(environment), &environment_used,
                            L"TMP", current_directory) ||
        !append_environment(environment, _countof(environment), &environment_used,
                            L"windir", windows_directory)) {
        error = ERROR_INSUFFICIENT_BUFFER;
        goto cleanup;
    }
    if (environment_used >= _countof(environment)) {
        error = ERROR_INSUFFICIENT_BUFFER;
        goto cleanup;
    }
    environment[environment_used] = L'\0';

    stage_code = "validate_appcontainer_sid";
    if (!ConvertStringSidToSidW(sid_text, &security_capabilities.AppContainerSid) ||
        !IsValidSid(security_capabilities.AppContainerSid) ||
        !EqualSid(security_capabilities.AppContainerSid, expected_sid)) {
        error = GetLastError() ? GetLastError() : ERROR_INVALID_SID;
        goto cleanup;
    }
    security_capabilities.Capabilities = NULL;
    security_capabilities.CapabilityCount = 0;
    security_capabilities.Reserved = 0;

    stage_code = "create_job";
    job = CreateJobObjectW(NULL, NULL);
    if (!job) {
        error = GetLastError();
        goto cleanup;
    }
    report->job_handle_closed = FALSE;
    job_limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    stage_code = "configure_job";
    if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation,
                                 &job_limits, sizeof(job_limits))) {
        error = GetLastError();
        goto cleanup;
    }

    stage_code = "query_attribute_list_size";
    if (InitializeProcThreadAttributeList(NULL, creation_attribute_count, 0,
                                          &attribute_bytes) ||
        GetLastError() != ERROR_INSUFFICIENT_BUFFER || !attribute_bytes) {
        error = GetLastError() ? GetLastError() : ERROR_INVALID_DATA;
        goto cleanup;
    }
    stage_code = "allocate_attribute_list";
    attributes = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, attribute_bytes);
    if (!attributes) {
        error = ERROR_NOT_ENOUGH_MEMORY;
        goto cleanup;
    }
    report->attributes_deleted = FALSE;
    stage_code = "initialize_attribute_list";
    if (!InitializeProcThreadAttributeList(attributes, creation_attribute_count,
                                           0, &attribute_bytes)) {
        error = GetLastError();
        goto cleanup;
    }
    attributes_initialized = TRUE;
    job_list[0] = job;
    stage_code = "set_security_capabilities";
    if (!UpdateProcThreadAttribute(attributes, 0,
                                   PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                                   &security_capabilities,
                                   sizeof(security_capabilities), NULL, NULL)) {
        error = GetLastError();
        goto cleanup;
    }
    report->security_capabilities_attribute_set = TRUE;
    stage_code = "set_job_list";
    if (!UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_JOB_LIST,
                                   job_list, sizeof(job_list), NULL, NULL)) {
        error = GetLastError();
        goto cleanup;
    }
    report->job_list_attribute_set = TRUE;
    stage_code = "set_lpac_policy";
    if (request_lpac && !UpdateProcThreadAttribute(
            attributes, 0, PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY,
            &all_packages_policy, sizeof(all_packages_policy), NULL, NULL)) {
        error = GetLastError();
        goto cleanup;
    }
    report->all_packages_policy_attribute_set = request_lpac;

    startup.StartupInfo.cb = (DWORD)sizeof(startup);
    startup.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
    startup.StartupInfo.wShowWindow = SW_HIDE;
    startup.lpAttributeList = attributes;
    ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll) {
        ntstatus_address = GetProcAddress(ntdll, "RtlGetLastNtStatus");
        if (ntstatus_address)
            memcpy(&last_nt_status, &ntstatus_address, sizeof(last_nt_status));
    }
    report->create_ntstatus_getter_available = last_nt_status != NULL;
    report->creation_flags = creation_flags;
    stage_code = "create_process";
    report->create_attempted = TRUE;
    if (!CreateProcessW(image, command, NULL, NULL, FALSE,
                        creation_flags,
                        environment, current_directory,
                        &startup.StartupInfo, &process)) {
        /* Snapshot thread NTSTATUS first, then the distinct Win32 last-error;
         * do not insert cleanup or other API calls between these reads. */
        if (last_nt_status) {
            report->create_ntstatus = last_nt_status();
            report->create_ntstatus_sampled = TRUE;
        }
        error = GetLastError();
        report->create_error = error;
        report->create_win32_error = error;
        goto cleanup;
    }
    report->process_created = TRUE;
    report->process_handle_closed = FALSE;
    report->thread_handle_closed = FALSE;
    stage_code = "verify_job_membership";
    if (!IsProcessInJob(process.hProcess, job, &in_job)) {
        error = GetLastError();
        report->create_error = error;
        goto cleanup;
    }
    if (!in_job) {
        error = ERROR_INVALID_DATA;
        report->create_error = error;
        goto cleanup;
    }
    report->job_membership_verified = TRUE;
    stage_code = "query_job_accounting";
    if (!QueryInformationJobObject(job, JobObjectBasicAccountingInformation,
                                   &accounting, sizeof(accounting), NULL)) {
        error = GetLastError();
        report->create_error = error;
        goto cleanup;
    }
    report->job_active_before = accounting.ActiveProcesses;
    report->job_total_before = accounting.TotalProcesses;
    stage_code = "verify_job_accounting";
    if (accounting.ActiveProcesses != 1 || accounting.TotalProcesses != 1) {
        error = ERROR_INVALID_DATA;
        report->create_error = error;
        goto cleanup;
    }

    stage_code = "open_process_token";
    if (!OpenProcessToken(process.hProcess, TOKEN_QUERY | TOKEN_DUPLICATE, &token)) {
        report->token_open_error = GetLastError();
        error = report->token_open_error;
        goto cleanup;
    }
    report->token_opened = TRUE;
    stage_code = "token_inspection";
    inspect_token(token, expected_sid, report);
    {
        CsLpacAccessCheckResult access_result;
        ZeroMemory(&access_result, sizeof(access_result));
        (void)cs_lpac_access_check(token, &access_result);
        report->access_check_api_succeeded = access_result.api_succeeded;
        report->access_check_granted = access_result.access_granted;
        report->access_check_granted_access = access_result.granted_access;
        report->access_check_error = access_result.win32_error;
    }

cleanup:
    if (error != ERROR_SUCCESS && !report->failure_stage_code)
        report->failure_stage_code = stage_code;
    stage_code = "cleanup";
    if (token && !CloseHandle(token) && error == ERROR_SUCCESS)
        error = GetLastError();
    if (security_capabilities.AppContainerSid &&
        LocalFree(security_capabilities.AppContainerSid) != NULL && error == ERROR_SUCCESS)
        error = ERROR_INVALID_SID;

    if (process.hProcess) {
        if (!TerminateProcess(process.hProcess, 0xE5) &&
            WaitForSingleObject(process.hProcess, 0) != WAIT_OBJECT_0 &&
            error == ERROR_SUCCESS)
            error = GetLastError();
        wait_result = WaitForSingleObject(process.hProcess, DIAGNOSTIC_TIMEOUT_MS);
        report->process_signaled = wait_result == WAIT_OBJECT_0;
        if (!report->process_signaled && error == ERROR_SUCCESS)
            error = wait_result == WAIT_TIMEOUT ? WAIT_TIMEOUT : GetLastError();
    }
    if (job) {
        DWORD attempt;
        for (attempt = 0; attempt < 100; ++attempt) {
            if (QueryInformationJobObject(job, JobObjectBasicAccountingInformation,
                                          &accounting, sizeof(accounting), NULL)) {
                report->job_query_after_succeeded = TRUE;
                report->job_active_after = accounting.ActiveProcesses;
                report->job_total_after = accounting.TotalProcesses;
                report->job_empty = accounting.ActiveProcesses == 0;
            } else if (error == ERROR_SUCCESS) {
                error = GetLastError();
            }
            if (report->job_empty) break;
            if (attempt == 0) (void)TerminateJobObject(job, 0xE5);
            Sleep(50);
        }
        if (!report->job_empty && error == ERROR_SUCCESS)
            error = ERROR_INVALID_DATA;
    }
    if (process.hThread) {
        report->thread_handle_closed = CloseHandle(process.hThread);
        if (!report->thread_handle_closed && error == ERROR_SUCCESS)
            error = GetLastError();
    }
    if (process.hProcess) {
        report->process_handle_closed = CloseHandle(process.hProcess);
        if (!report->process_handle_closed && error == ERROR_SUCCESS)
            error = GetLastError();
    }
    if (attributes) {
        if (attributes_initialized) DeleteProcThreadAttributeList(attributes);
        report->attributes_deleted = HeapFree(GetProcessHeap(), 0, attributes);
        if (!report->attributes_deleted && error == ERROR_SUCCESS)
            error = ERROR_NOT_ENOUGH_MEMORY;
    }
    if (job) {
        report->job_handle_closed = CloseHandle(job);
        if (!report->job_handle_closed && error == ERROR_SUCCESS)
            error = GetLastError();
    }

    report->passed = error == ERROR_SUCCESS && report->process_created &&
        report->job_membership_verified && report->job_active_before == 1 &&
        report->job_total_before == 1 && report->token_opened &&
        report->appcontainer_query_succeeded &&
        report->appcontainer_return_length == sizeof(DWORD) &&
        report->appcontainer_value != 0 && report->sid_query_succeeded &&
        report->expected_sid_match && report->token_type_query_succeeded &&
        report->token_type_return_length == sizeof(TOKEN_TYPE) &&
        report->token_type == TokenPrimary && report->integrity_query_succeeded &&
        report->integrity_rid == LOW_INTEGRITY_RID &&
        report->capabilities_query_succeeded && report->capability_count == 0 &&
        report->access_check_api_succeeded && report->access_check_granted &&
        report->access_check_granted_access == (request_lpac ?
            CS_LPAC_ACCESS_LESS_PRIVILEGED : CS_LPAC_ACCESS_NORMAL_APPCONTAINER) &&
        report->process_signaled && report->job_query_after_succeeded &&
        report->job_empty && report->job_total_after == 1 &&
        report->process_handle_closed && report->thread_handle_closed &&
        report->job_handle_closed && report->attributes_deleted;
    if (error != ERROR_SUCCESS) report->create_error = report->create_error ?
        report->create_error : error;
    if (error != ERROR_SUCCESS && !report->failure_stage_code)
        report->failure_stage_code = stage_code;
    if (!report->passed && !report->failure_stage_code)
        report->failure_stage_code = report->token_opened ?
            "token_inspection" : "result_validation";
    ok = report->passed;
    return ok;
}

static void emit_query(const TokenQueryAttempt *attempt)
{
    printf("{\"buffer_size\":%lu,\"return_length\":%lu,\"success\":%s,\"win32_error\":%lu,\"raw_value_width_bits\":%lu,\"raw_value\":",
           (unsigned long)attempt->buffer_size,
           (unsigned long)attempt->return_length,
           attempt->succeeded ? "true" : "false",
           (unsigned long)attempt->win32_error,
           (unsigned long)attempt->raw_value_width_bits);
    if (attempt->succeeded && attempt->raw_value_width_bits &&
        attempt->return_length <= attempt->buffer_size)
        printf("%llu", (unsigned long long)attempt->raw_value);
    else
        printf("null");
    putchar('}');
}

static void emit_control(const TokenDiagnostic *report)
{
    printf("{\"control\":\"%s\",\"requested_lpac\":%s,\"process_created\":%s,"
           "\"create_attempted\":%s,\"create_error\":%lu,\"create_win32_error\":%lu,"
           "\"create_ntstatus_getter_available\":%s,\"create_ntstatus_sampled\":%s,"
           "\"create_ntstatus_hex\":",
           report->control,
           report->requested_lpac ? "true" : "false",
           report->process_created ? "true" : "false",
           report->create_attempted ? "true" : "false",
           (unsigned long)report->create_error,
           (unsigned long)report->create_win32_error,
           report->create_ntstatus_getter_available ? "true" : "false",
           report->create_ntstatus_sampled ? "true" : "false");
    if (report->create_ntstatus_sampled)
        printf("\"0x%08lX\"", (unsigned long)(ULONG)report->create_ntstatus);
    else
        printf("null");
    printf(",\"failure_stage_code\":\"%s\",\"create_context\":{"
           "\"application_path_redacted\":\"%s\","
           "\"working_directory_redacted\":\"%s\","
           "\"environment_block_mode\":\"%s\","
           "\"creation_flags_hex\":\"0x%08lX\","
           "\"security_capabilities_attribute\":%s,"
           "\"job_list_attribute\":%s,"
           "\"all_application_packages_policy_attribute\":%s},"
           "\"job_membership_verified\":%s,\"job_active_before\":%lu,\"job_total_before\":%lu,"
           "\"token_opened\":%s,\"token_open_error\":%lu,"
           "\"appcontainer_query\":{\"class\":%u,\"buffer_size\":%lu,\"return_length\":%lu,\"success\":%s,\"win32_error\":%lu,\"value\":%lu},"
           "\"class46_queries\":[",
           report->failure_stage_code ? report->failure_stage_code : "none",
           report->application_path_redacted,
           report->working_directory_redacted,
           report->environment_block_mode,
           (unsigned long)report->creation_flags,
           report->security_capabilities_attribute_set ? "true" : "false",
           report->job_list_attribute_set ? "true" : "false",
           report->all_packages_policy_attribute_set ? "true" : "false",
           report->job_membership_verified ? "true" : "false",
           (unsigned long)report->job_active_before,
           (unsigned long)report->job_total_before,
           report->token_opened ? "true" : "false",
           (unsigned long)report->token_open_error,
           (unsigned)TokenIsAppContainer,
           (unsigned long)sizeof(DWORD),
           (unsigned long)report->appcontainer_return_length,
           report->appcontainer_query_succeeded ? "true" : "false",
           (unsigned long)report->appcontainer_error,
           (unsigned long)report->appcontainer_value);
    emit_query(&report->class46[0]); putchar(',');
    emit_query(&report->class46[1]); putchar(',');
    emit_query(&report->class46[2]);
    printf("],\"token_type\":{\"success\":%s,\"return_length\":%lu,\"win32_error\":%lu,\"value\":%lu},"
           "\"appcontainer_sid\":{\"size_query_return_length\":%lu,\"size_query_error\":%lu,\"return_length\":%lu,\"success\":%s,\"win32_error\":%lu,\"expected_sid_match\":%s},"
           "\"integrity\":{\"success\":%s,\"return_length\":%lu,\"win32_error\":%lu,\"rid\":%lu},"
           "\"capabilities\":{\"success\":%s,\"return_length\":%lu,\"win32_error\":%lu,\"count\":%lu},"
           "\"access_check\":{\"success\":%s,\"access_granted\":%s,\"granted_access\":%lu,\"expected_access\":%lu,\"win32_error\":%lu},"
           "\"cleanup\":{\"process_signaled\":%s,\"job_query_succeeded\":%s,\"job_active_processes\":%lu,\"job_total_processes\":%lu,\"job_empty\":%s,\"process_handle_closed\":%s,\"thread_handle_closed\":%s,\"job_handle_closed\":%s,\"attributes_deleted\":%s},\"passed\":%s}",
           report->token_type_query_succeeded ? "true" : "false",
           (unsigned long)report->token_type_return_length,
           (unsigned long)report->token_type_error,
           (unsigned long)report->token_type,
           (unsigned long)report->sid_size_query_return_length,
           (unsigned long)report->sid_size_query_error,
           (unsigned long)report->sid_return_length,
           report->sid_query_succeeded ? "true" : "false",
           (unsigned long)report->sid_query_error,
           report->expected_sid_match ? "true" : "false",
           report->integrity_query_succeeded ? "true" : "false",
           (unsigned long)report->integrity_return_length,
           (unsigned long)report->integrity_error,
           (unsigned long)report->integrity_rid,
           report->capabilities_query_succeeded ? "true" : "false",
           (unsigned long)report->capabilities_return_length,
           (unsigned long)report->capabilities_error,
           (unsigned long)report->capability_count,
           report->access_check_api_succeeded ? "true" : "false",
           report->access_check_granted ? "true" : "false",
           (unsigned long)report->access_check_granted_access,
           (unsigned long)(report->requested_lpac ?
               CS_LPAC_ACCESS_LESS_PRIVILEGED : CS_LPAC_ACCESS_NORMAL_APPCONTAINER),
           (unsigned long)report->access_check_error,
           report->process_signaled ? "true" : "false",
           report->job_query_after_succeeded ? "true" : "false",
           (unsigned long)report->job_active_after,
           (unsigned long)report->job_total_after,
           report->job_empty ? "true" : "false",
           report->process_handle_closed ? "true" : "false",
           report->thread_handle_closed ? "true" : "false",
           report->job_handle_closed ? "true" : "false",
           report->attributes_deleted ? "true" : "false",
           report->passed ? "true" : "false");
}

int wmain(int argc, wchar_t **argv)
{
    PSID expected_sid = NULL;
    TokenDiagnostic ordinary;
    TokenDiagnostic lpac;
    BOOL ordinary_ok, lpac_ok;
    int exit_code;

    if (argc > 1 && wcscmp(argv[1], L"--idle-child") == 0) return 0;
    if (argc != 3 || wcscmp(argv[1], L"--diagnostic") != 0) return 2;
    if (!ConvertStringSidToSidW(argv[2], &expected_sid) || !IsValidSid(expected_sid)) {
        DWORD error = GetLastError();
        printf("{\"schema\":\"lpac-token-identity-diagnostic-v1\",\"passed\":false,\"setup_error\":%lu}\n",
               (unsigned long)(error ? error : ERROR_INVALID_SID));
        if (expected_sid) LocalFree(expected_sid);
        return 20;
    }

    ordinary_ok = run_control(expected_sid, argv[2], FALSE, &ordinary);
    lpac_ok = run_control(expected_sid, argv[2], TRUE, &lpac);
    printf("{\"schema\":\"lpac-token-identity-diagnostic-v1\",\"token_information_class\":%u,"
           "\"resume_attempted\":false,\"mission_started\":false,"
           "\"network_tests_run\":false,\"storage_tests_run\":false,"
           "\"profile_registration_attempted\":false,\"ordinary_appcontainer\":",
           (unsigned)TokenIsLessPrivilegedAppContainer);
    emit_control(&ordinary);
    printf(",\"lpac_candidate\":");
    emit_control(&lpac);
    printf(",\"passed\":%s}\n", ordinary_ok && lpac_ok ? "true" : "false");
    exit_code = ordinary_ok && lpac_ok ? 0 : 20;
    if (LocalFree(expected_sid) != NULL) exit_code = 20;
    return exit_code;
}
