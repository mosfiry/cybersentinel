#define _WIN32_WINNT 0x0A00
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <sddl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <wchar.h>

#pragma comment(lib, "advapi32.lib")

#ifndef PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY
#define PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY 0x0002000F
#endif
#ifndef PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT
#define PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT 0x00000001
#endif
#ifndef PROC_THREAD_ATTRIBUTE_JOB_LIST
#define PROC_THREAD_ATTRIBUTE_JOB_LIST 0x0002000D
#endif
#ifndef TokenIsLessPrivilegedAppContainer
#define TokenIsLessPrivilegedAppContainer ((TOKEN_INFORMATION_CLASS)46)
#endif

#define PROBE_TIMEOUT_MS 5000U
#define LOWBOX_TOKEN_ACCESS (TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY)

typedef NTSTATUS (NTAPI *PFN_NT_CREATE_LOW_BOX_TOKEN)(
    PHANDLE, HANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PSID, ULONG,
    PSID_AND_ATTRIBUTES, ULONG, HANDLE *);
typedef ULONG (NTAPI *PFN_RTL_NT_STATUS_TO_DOS_ERROR)(NTSTATUS);

typedef struct TokenFacts {
    BOOL app_container;
    BOOL lpac;
    BOOL low_integrity;
    BOOL zero_capabilities;
    DWORD error;
} TokenFacts;

typedef struct ProbeReport {
    const char *stage;
    const char *classification;
    ULONG ntstatus;
    BOOL ntstatus_set;
    DWORD mapped_win32;
    DWORD win32_error;
    BOOL child_token_verified;
    BOOL resumed;
    BOOL child_exit_code_set;
    DWORD pretoken_win32;
    int pretoken_appcontainer;
    int pretoken_lpac;
    int pretoken_low_integrity;
    int pretoken_zero_capabilities;
    DWORD lowbox_win32;
    int lowbox_appcontainer;
    int lowbox_lpac;
    int lowbox_low_integrity;
    int lowbox_zero_capabilities;
    DWORD candidate_access_win32;
    DWORD launch_win32;
    DWORD child_verify_win32;
    DWORD resume_win32;
    DWORD wait_win32;
    DWORD child_exit_code;
    DWORD cleanup_error;
} ProbeReport;

static BOOL append_environment(wchar_t *buffer, size_t capacity, wchar_t **cursor,
                               const wchar_t *name, const wchar_t *value)
{
    size_t remaining = capacity - (size_t)(*cursor - buffer);
    int written;
    if (remaining < 2) return FALSE;
    written = _snwprintf_s(*cursor, remaining, _TRUNCATE, L"%ls=%ls", name, value);
    if (written < 0) return FALSE;
    *cursor += (size_t)written + 1;
    if ((size_t)(*cursor - buffer) >= capacity) return FALSE;
    **cursor = L'\0';
    return TRUE;
}

static void set_first_error(DWORD *target, DWORD error)
{
    if (*target == ERROR_SUCCESS && error != ERROR_SUCCESS) *target = error;
}

static BOOL read_token_bool(HANDLE token, TOKEN_INFORMATION_CLASS info_class, BOOL *value, DWORD *error)
{
    DWORD raw = 0;
    DWORD returned = 0;
    if (!GetTokenInformation(token, info_class, &raw, sizeof(raw), &returned)) {
        *error = GetLastError();
        return FALSE;
    }
    *value = raw != 0;
    return TRUE;
}

static BOOL read_integrity(HANDLE token, BOOL *is_low, DWORD *error)
{
    DWORD needed = 0;
    BYTE *buffer = NULL;
    TOKEN_MANDATORY_LABEL *label;
    SID_IDENTIFIER_AUTHORITY mandatory_authority = SECURITY_MANDATORY_LABEL_AUTHORITY;
    BOOL ok = FALSE;
    *is_low = FALSE;
    SetLastError(ERROR_SUCCESS);
    if (GetTokenInformation(token, TokenIntegrityLevel, NULL, 0, &needed)) {
        *error = ERROR_INVALID_DATA;
        return FALSE;
    }
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || needed < sizeof(TOKEN_MANDATORY_LABEL)) {
        *error = GetLastError();
        if (*error == ERROR_SUCCESS) *error = ERROR_INVALID_DATA;
        return FALSE;
    }
    buffer = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, needed);
    if (!buffer) {
        *error = ERROR_NOT_ENOUGH_MEMORY;
        return FALSE;
    }
    if (!GetTokenInformation(token, TokenIntegrityLevel, buffer, needed, &needed)) {
        *error = GetLastError();
        goto done;
    }
    label = (TOKEN_MANDATORY_LABEL *)buffer;
    if (!label->Label.Sid || !IsValidSid(label->Label.Sid) ||
        *GetSidSubAuthorityCount(label->Label.Sid) != 1 ||
        memcmp(GetSidIdentifierAuthority(label->Label.Sid), &mandatory_authority,
               sizeof(mandatory_authority)) != 0) {
        *error = ERROR_INVALID_DATA;
        goto done;
    }
    *is_low = *GetSidSubAuthority(label->Label.Sid,
        (DWORD)(*GetSidSubAuthorityCount(label->Label.Sid) - 1)) == SECURITY_MANDATORY_LOW_RID;
    ok = TRUE;
    *error = ERROR_SUCCESS;
done:
    HeapFree(GetProcessHeap(), 0, buffer);
    return ok;
}

static BOOL read_zero_capabilities(HANDLE token, BOOL *zero, DWORD *error)
{
    DWORD needed = 0;
    BYTE *buffer = NULL;
    TOKEN_GROUPS *groups;
    BOOL ok = FALSE;
    *zero = FALSE;
    SetLastError(ERROR_SUCCESS);
    if (GetTokenInformation(token, TokenCapabilities, NULL, 0, &needed)) {
        if (needed == 0) {
            *zero = TRUE;
            *error = ERROR_SUCCESS;
            return TRUE;
        }
        *error = ERROR_INVALID_DATA;
        return FALSE;
    }
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || needed < offsetof(TOKEN_GROUPS, Groups)) {
        *error = GetLastError();
        if (*error == ERROR_SUCCESS) *error = ERROR_INVALID_DATA;
        return FALSE;
    }
    buffer = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, needed);
    if (!buffer) {
        *error = ERROR_NOT_ENOUGH_MEMORY;
        return FALSE;
    }
    if (!GetTokenInformation(token, TokenCapabilities, buffer, needed, &needed)) {
        *error = GetLastError();
        goto done;
    }
    groups = (TOKEN_GROUPS *)buffer;
    if (needed < offsetof(TOKEN_GROUPS, Groups) ||
        groups->GroupCount > (needed - offsetof(TOKEN_GROUPS, Groups)) / sizeof(SID_AND_ATTRIBUTES)) {
        *error = ERROR_INVALID_DATA;
        goto done;
    }
    *zero = groups->GroupCount == 0;
    *error = *zero ? ERROR_SUCCESS : ERROR_INVALID_TOKEN;
    ok = TRUE;
done:
    HeapFree(GetProcessHeap(), 0, buffer);
    return ok;
}

static TokenFacts inspect_token(HANDLE token)
{
    TokenFacts facts;
    DWORD error = ERROR_SUCCESS;
    facts.app_container = FALSE;
    facts.lpac = FALSE;
    facts.low_integrity = FALSE;
    facts.zero_capabilities = FALSE;
    facts.error = ERROR_SUCCESS;
    if (!read_token_bool(token, TokenIsAppContainer, &facts.app_container, &error))
        set_first_error(&facts.error, error);
    if (!read_token_bool(token, TokenIsLessPrivilegedAppContainer, &facts.lpac, &error))
        set_first_error(&facts.error, error);
    if (!read_integrity(token, &facts.low_integrity, &error))
        set_first_error(&facts.error, error);
    if (!read_zero_capabilities(token, &facts.zero_capabilities, &error))
        set_first_error(&facts.error, error);
    return facts;
}

static int fact_json_value(int known, BOOL value)
{
    return known ? (value ? 1 : 0) : -1;
}

static DWORD verify_child_token(HANDLE process, PSID expected_sid)
{
    HANDLE token = NULL;
    DWORD error = ERROR_SUCCESS;
    DWORD needed = 0;
    BYTE *buffer = NULL;
    TokenFacts facts;
    TOKEN_APPCONTAINER_INFORMATION *container_info;
    if (!OpenProcessToken(process, TOKEN_QUERY, &token)) return GetLastError();
    facts = inspect_token(token);
    if (facts.error != ERROR_SUCCESS) {
        error = facts.error;
        goto done;
    }
    if (!facts.app_container || !facts.lpac || !facts.low_integrity || !facts.zero_capabilities) {
        error = ERROR_INVALID_TOKEN;
        goto done;
    }
    SetLastError(ERROR_SUCCESS);
    if (GetTokenInformation(token, TokenAppContainerSid, NULL, 0, &needed)) {
        error = ERROR_INVALID_DATA;
        goto done;
    }
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || needed < sizeof(*container_info)) {
        error = GetLastError();
        if (error == ERROR_SUCCESS) error = ERROR_INVALID_DATA;
        goto done;
    }
    buffer = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, needed);
    if (!buffer) {
        error = ERROR_NOT_ENOUGH_MEMORY;
        goto done;
    }
    if (!GetTokenInformation(token, TokenAppContainerSid, buffer, needed, &needed)) {
        error = GetLastError();
        goto done;
    }
    container_info = (TOKEN_APPCONTAINER_INFORMATION *)buffer;
    if (!container_info->TokenAppContainer || !IsValidSid(container_info->TokenAppContainer) ||
        !EqualSid(container_info->TokenAppContainer, expected_sid)) error = ERROR_INVALID_TOKEN;
done:
    if (buffer) HeapFree(GetProcessHeap(), 0, buffer);
    if (!CloseHandle(token)) set_first_error(&error, GetLastError());
    return error;
}

static DWORD candidate_read_execute(HANDLE lowbox_token, BOOL *revert_failed)
{
    HANDLE impersonation_token = NULL;
    HANDLE image = INVALID_HANDLE_VALUE;
    wchar_t image_path[32768];
    DWORD error = ERROR_SUCCESS;
    DWORD length;
    BOOL impersonating = FALSE;
    *revert_failed = FALSE;
    length = GetModuleFileNameW(NULL, image_path, (DWORD)_countof(image_path));
    if (length == 0 || length >= (DWORD)_countof(image_path)) return GetLastError() ? GetLastError() : ERROR_INSUFFICIENT_BUFFER;
    if (!DuplicateTokenEx(lowbox_token, TOKEN_QUERY | TOKEN_IMPERSONATE, NULL,
                          SecurityImpersonation, TokenImpersonation, &impersonation_token))
        return GetLastError();
    if (!ImpersonateLoggedOnUser(impersonation_token)) {
        error = GetLastError();
        goto done;
    }
    impersonating = TRUE;
    image = CreateFileW(image_path, GENERIC_READ | GENERIC_EXECUTE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (image == INVALID_HANDLE_VALUE) error = GetLastError();
    else if (!CloseHandle(image)) error = GetLastError();
    if (impersonating && !RevertToSelf()) {
        error = GetLastError();
        *revert_failed = TRUE;
        goto done;
    }
    impersonating = FALSE;
done:
    if (impersonating && !RevertToSelf()) {
        set_first_error(&error, GetLastError());
        *revert_failed = TRUE;
    }
    if (!CloseHandle(impersonation_token)) set_first_error(&error, GetLastError());
    return error;
}

static DWORD stop_child(PROCESS_INFORMATION *process)
{
    DWORD error = ERROR_SUCCESS;
    DWORD exit_code = STILL_ACTIVE;
    DWORD wait_result;
    if (!process->hProcess) return ERROR_SUCCESS;
    if (!GetExitCodeProcess(process->hProcess, &exit_code)) {
        set_first_error(&error, GetLastError());
    } else if (exit_code == STILL_ACTIVE && !TerminateProcess(process->hProcess, ERROR_PROCESS_ABORTED)) {
        set_first_error(&error, GetLastError());
    }
    wait_result = WaitForSingleObject(process->hProcess, PROBE_TIMEOUT_MS);
    if (wait_result == WAIT_TIMEOUT) {
        if (!TerminateProcess(process->hProcess, ERROR_PROCESS_ABORTED))
            set_first_error(&error, GetLastError());
        wait_result = WaitForSingleObject(process->hProcess, PROBE_TIMEOUT_MS);
    }
    if (wait_result != WAIT_OBJECT_0)
        set_first_error(&error, wait_result == WAIT_TIMEOUT ? ERROR_TIMEOUT :
                        (GetLastError() ? GetLastError() : ERROR_GEN_FAILURE));
    return error;
}

static void close_handle(HANDLE *handle, DWORD *cleanup_error)
{
    if (*handle && *handle != INVALID_HANDLE_VALUE) {
        if (!CloseHandle(*handle)) set_first_error(cleanup_error, GetLastError());
        *handle = NULL;
    }
}

static void emit_report(const ProbeReport *r)
{
    char ntstatus_text[16], exit_code_text[16];
    if (r->ntstatus_set) (void)sprintf_s(ntstatus_text, sizeof(ntstatus_text), "\"0x%08lX\"", (unsigned long)r->ntstatus);
    else (void)strcpy_s(ntstatus_text, sizeof(ntstatus_text), "null");
    if (r->child_exit_code_set) (void)sprintf_s(exit_code_text, sizeof(exit_code_text), "%lu", (unsigned long)r->child_exit_code);
    else (void)strcpy_s(exit_code_text, sizeof(exit_code_text), "null");
    (void)printf(
        "{\"stage\":\"%s\",\"classification\":\"%s\",\"child_token_verified\":%s,\"resumed\":%s,\"ntstatus\":%s,\"mapped_win32\":%lu,\"win32_error\":%lu,\"cleanup_error\":%lu,\"child_exit_code\":%s,\"pretoken_win32\":%lu,\"pretoken_appcontainer\":%d,\"pretoken_lpac\":%d,\"pretoken_low_integrity\":%d,\"pretoken_zero_capabilities\":%d,\"lowbox_win32\":%lu,\"lowbox_appcontainer\":%d,\"lowbox_lpac\":%d,\"lowbox_low_integrity\":%d,\"lowbox_zero_capabilities\":%d,\"candidate_access_win32\":%lu,\"launch_win32\":%lu,\"child_verify_win32\":%lu,\"resume_win32\":%lu,\"wait_win32\":%lu}\n",
        r->stage, r->classification, r->child_token_verified ? "true" : "false",
        r->resumed ? "true" : "false", ntstatus_text,
        (unsigned long)r->mapped_win32, (unsigned long)r->win32_error,
        (unsigned long)r->cleanup_error,
        exit_code_text,
        (unsigned long)r->pretoken_win32, r->pretoken_appcontainer, r->pretoken_lpac,
        r->pretoken_low_integrity, r->pretoken_zero_capabilities,
        (unsigned long)r->lowbox_win32, r->lowbox_appcontainer, r->lowbox_lpac,
        r->lowbox_low_integrity, r->lowbox_zero_capabilities,
        (unsigned long)r->candidate_access_win32, (unsigned long)r->launch_win32,
        (unsigned long)r->child_verify_win32, (unsigned long)r->resume_win32,
        (unsigned long)r->wait_win32);
    (void)fflush(stdout);
}

static int child_main(int argc, wchar_t **argv)
{
    (void)argc;
    (void)argv;
    return 0;
}

int wmain(int argc, wchar_t **argv)
{
    ProbeReport report;
    HMODULE ntdll = NULL;
    PFN_NT_CREATE_LOW_BOX_TOKEN nt_create_lowbox = NULL;
    PFN_RTL_NT_STATUS_TO_DOS_ERROR status_to_error = NULL;
    HANDLE base_token = NULL, lowbox_token = NULL, job = NULL;
    HANDLE attribute_list = NULL;
    PSID package_sid = NULL;
    SIZE_T attribute_bytes = 0;
    DWORD policy = PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT;
    DWORD cleanup_error = ERROR_SUCCESS;
    wchar_t executable[32768], command_line[32768];
    wchar_t system_dir[MAX_PATH * 4], windows_dir[MAX_PATH * 4];
    wchar_t environment[32768];
    wchar_t *env_cursor = environment;
    STARTUPINFOEXW startup;
    PROCESS_INFORMATION process;
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION job_limits;
    BOOL process_created = FALSE, attributes_initialized = FALSE;
    BOOL candidate_revert_failed = FALSE;
    HANDLE job_list[1];
    BOOL child_ok = FALSE;
    TokenFacts pretoken;

    ZeroMemory(&report, sizeof(report));
    report.stage = "input";
    report.classification = "inconclusive";
    report.pretoken_appcontainer = -1;
    report.pretoken_lpac = -1;
    report.pretoken_low_integrity = -1;
    report.pretoken_zero_capabilities = -1;
    report.lowbox_appcontainer = -1;
    report.lowbox_lpac = -1;
    report.lowbox_low_integrity = -1;
    report.lowbox_zero_capabilities = -1;
    if (argc == 2 && wcscmp(argv[1], L"--child") == 0) return child_main(argc, argv);
    if (argc != 3 || !argv[1][0] || !argv[2][0]) return 2;
    if (!ConvertStringSidToSidW(argv[1], &package_sid) || !IsValidSid(package_sid)) {
        if (package_sid) LocalFree(package_sid);
        return 2;
    }
    {
        DWORD attributes = GetFileAttributesW(argv[2]);
        if (attributes == INVALID_FILE_ATTRIBUTES || !(attributes & FILE_ATTRIBUTE_DIRECTORY)) {
            LocalFree(package_sid);
            return 2;
        }
    }

    ZeroMemory(&startup, sizeof(startup));
    ZeroMemory(&process, sizeof(process));
    ZeroMemory(&pretoken, sizeof(pretoken));
    startup.StartupInfo.cb = (DWORD)sizeof(startup);
    startup.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
    startup.StartupInfo.wShowWindow = SW_HIDE;

    report.stage = "pretoken";
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &base_token)) {
        report.win32_error = GetLastError();
        goto finish;
    }
    pretoken = inspect_token(base_token);
    report.pretoken_win32 = pretoken.error;
    report.pretoken_appcontainer = fact_json_value(pretoken.error == ERROR_SUCCESS, pretoken.app_container);
    report.pretoken_lpac = fact_json_value(pretoken.error == ERROR_SUCCESS, pretoken.lpac);
    report.pretoken_low_integrity = fact_json_value(pretoken.error == ERROR_SUCCESS, pretoken.low_integrity);
    report.pretoken_zero_capabilities = fact_json_value(pretoken.error == ERROR_SUCCESS, pretoken.zero_capabilities);

    report.stage = "nt_create_lowbox_token";
    ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll) {
        FARPROC address = GetProcAddress(ntdll, "NtCreateLowBoxToken");
        if (address && sizeof(address) == sizeof(nt_create_lowbox))
            memcpy(&nt_create_lowbox, &address, sizeof(nt_create_lowbox));
        address = GetProcAddress(ntdll, "RtlNtStatusToDosError");
        if (address && sizeof(address) == sizeof(status_to_error))
            memcpy(&status_to_error, &address, sizeof(status_to_error));
    }
    if (!nt_create_lowbox || !status_to_error) {
        report.win32_error = ERROR_PROC_NOT_FOUND;
        report.classification = "inconclusive";
        goto finish;
    }
    report.ntstatus = (ULONG)nt_create_lowbox(&lowbox_token, base_token, LOWBOX_TOKEN_ACCESS,
                                               NULL, package_sid, 0, NULL, 0, NULL);
    report.ntstatus_set = TRUE;
    report.mapped_win32 = status_to_error((NTSTATUS)report.ntstatus);
    if (report.ntstatus != 0 || !lowbox_token) {
        report.win32_error = report.ntstatus != 0 ? report.mapped_win32 : ERROR_INVALID_HANDLE;
        report.classification = "blocked";
        goto finish;
    }

    {
        TokenFacts lowbox_facts = inspect_token(lowbox_token);
        report.lowbox_win32 = lowbox_facts.error;
        report.lowbox_appcontainer = fact_json_value(lowbox_facts.error == ERROR_SUCCESS, lowbox_facts.app_container);
        report.lowbox_lpac = fact_json_value(lowbox_facts.error == ERROR_SUCCESS, lowbox_facts.lpac);
        report.lowbox_low_integrity = fact_json_value(lowbox_facts.error == ERROR_SUCCESS, lowbox_facts.low_integrity);
        report.lowbox_zero_capabilities = fact_json_value(lowbox_facts.error == ERROR_SUCCESS, lowbox_facts.zero_capabilities);
    }
    report.stage = "candidate_image_access";
    report.candidate_access_win32 = candidate_read_execute(lowbox_token, &candidate_revert_failed);
    if (candidate_revert_failed) {
        report.win32_error = report.candidate_access_win32;
        goto finish;
    }

    report.stage = "prepare_job_and_launch";
    if (!GetModuleFileNameW(NULL, executable, (DWORD)_countof(executable)) ||
        _snwprintf_s(command_line, _countof(command_line), _TRUNCATE, L"\"%ls\" --child", executable) < 0) {
        report.win32_error = GetLastError() ? GetLastError() : ERROR_INSUFFICIENT_BUFFER;
        goto finish;
    }
    if (!GetSystemDirectoryW(system_dir, (UINT)_countof(system_dir)) ||
        !GetWindowsDirectoryW(windows_dir, (UINT)_countof(windows_dir))) {
        report.win32_error = GetLastError();
        goto finish;
    }
    if (!append_environment(environment, _countof(environment), &env_cursor, L"PATH", system_dir) ||
        !append_environment(environment, _countof(environment), &env_cursor, L"SystemRoot", windows_dir) ||
        !append_environment(environment, _countof(environment), &env_cursor, L"TEMP", argv[2]) ||
        !append_environment(environment, _countof(environment), &env_cursor, L"TMP", argv[2]) ||
        !append_environment(environment, _countof(environment), &env_cursor, L"windir", windows_dir)) {
        report.win32_error = ERROR_INSUFFICIENT_BUFFER;
        goto finish;
    }
    job = CreateJobObjectW(NULL, NULL);
    if (!job) {
        report.win32_error = GetLastError();
        goto finish;
    }
    ZeroMemory(&job_limits, sizeof(job_limits));
    job_limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_ACTIVE_PROCESS |
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_PROCESS_TIME;
    job_limits.BasicLimitInformation.ActiveProcessLimit = 1;
    job_limits.BasicLimitInformation.PerProcessUserTimeLimit.QuadPart = (LONGLONG)PROBE_TIMEOUT_MS * 10000;
    if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &job_limits, (DWORD)sizeof(job_limits))) {
        report.win32_error = GetLastError();
        goto finish;
    }
    (void)InitializeProcThreadAttributeList(NULL, 2, 0, &attribute_bytes);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || attribute_bytes == 0) {
        report.win32_error = GetLastError() ? GetLastError() : ERROR_INVALID_DATA;
        goto finish;
    }
    attribute_list = (HANDLE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, attribute_bytes);
    if (!attribute_list) {
        report.win32_error = ERROR_NOT_ENOUGH_MEMORY;
        goto finish;
    }
    if (!InitializeProcThreadAttributeList((LPPROC_THREAD_ATTRIBUTE_LIST)attribute_list, 2, 0, &attribute_bytes)) {
        report.win32_error = GetLastError();
        goto finish;
    }
    attributes_initialized = TRUE;
    if (!UpdateProcThreadAttribute((LPPROC_THREAD_ATTRIBUTE_LIST)attribute_list, 0,
            PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY, &policy, sizeof(policy), NULL, NULL)) {
        report.win32_error = GetLastError();
        goto finish;
    }
    job_list[0] = job;
    if (!UpdateProcThreadAttribute((LPPROC_THREAD_ATTRIBUTE_LIST)attribute_list, 0,
            PROC_THREAD_ATTRIBUTE_JOB_LIST, job_list, sizeof(job_list), NULL, NULL)) {
        report.win32_error = GetLastError();
        goto finish;
    }
    startup.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)attribute_list;
    if (!CreateProcessAsUserW(lowbox_token, executable, command_line, NULL, NULL, FALSE,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
            environment, argv[2], &startup.StartupInfo, &process)) {
        report.launch_win32 = GetLastError();
        report.win32_error = report.launch_win32;
        report.classification = "blocked";
        goto finish;
    }
    process_created = TRUE;

    report.stage = "verify_suspended_child_token";
    report.child_verify_win32 = verify_child_token(process.hProcess, package_sid);
    if (report.child_verify_win32 != ERROR_SUCCESS) {
        report.win32_error = report.child_verify_win32;
        if (report.child_verify_win32 == ERROR_INVALID_TOKEN) report.classification = "blocked";
        goto finish;
    }
    report.child_token_verified = TRUE;

    report.stage = "resume_child";
    if (ResumeThread(process.hThread) == (DWORD)-1) {
        report.resume_win32 = GetLastError();
        report.win32_error = report.resume_win32;
        goto finish;
    }
    report.resumed = TRUE;
    report.stage = "wait_child";
    {
        DWORD wait_result = WaitForSingleObject(process.hProcess, PROBE_TIMEOUT_MS);
        if (wait_result != WAIT_OBJECT_0) {
            report.wait_win32 = (wait_result == WAIT_TIMEOUT) ? WAIT_TIMEOUT : GetLastError();
            if (report.wait_win32 == ERROR_SUCCESS) report.wait_win32 = ERROR_GEN_FAILURE;
            report.win32_error = report.wait_win32;
            goto finish;
        }
    }
    if (!GetExitCodeProcess(process.hProcess, &report.child_exit_code)) {
        report.wait_win32 = GetLastError();
        report.win32_error = report.wait_win32;
        goto finish;
    }
    report.child_exit_code_set = TRUE;
    if (report.child_exit_code != 0) {
        report.win32_error = ERROR_PROCESS_ABORTED;
        goto finish;
    }
    child_ok = TRUE;

finish:
    if (process_created && !child_ok) set_first_error(&cleanup_error, stop_child(&process));
    if (process.hThread) close_handle(&process.hThread, &cleanup_error);
    if (job) close_handle(&job, &cleanup_error);
    if (process_created && !child_ok && process.hProcess &&
        WaitForSingleObject(process.hProcess, PROBE_TIMEOUT_MS) != WAIT_OBJECT_0)
        set_first_error(&cleanup_error, ERROR_TIMEOUT);
    if (process.hProcess) close_handle(&process.hProcess, &cleanup_error);
    if (attributes_initialized) DeleteProcThreadAttributeList((LPPROC_THREAD_ATTRIBUTE_LIST)attribute_list);
    if (attribute_list) {
        if (!HeapFree(GetProcessHeap(), 0, attribute_list)) set_first_error(&cleanup_error, ERROR_NOT_ENOUGH_MEMORY);
        attribute_list = NULL;
    }
    close_handle(&lowbox_token, &cleanup_error);
    close_handle(&base_token, &cleanup_error);
    if (package_sid && LocalFree(package_sid) != NULL) set_first_error(&cleanup_error, ERROR_INVALID_HANDLE);
    report.cleanup_error = cleanup_error;
    if (cleanup_error != ERROR_SUCCESS) {
        report.classification = "inconclusive";
        if (report.win32_error == ERROR_SUCCESS) report.win32_error = cleanup_error;
        child_ok = FALSE;
    }
    if (child_ok && report.ntstatus_set && report.ntstatus == 0 && report.child_token_verified &&
        report.resumed && report.resume_win32 == ERROR_SUCCESS && report.wait_win32 == ERROR_SUCCESS &&
        report.child_exit_code_set && report.child_exit_code == 0) {
        report.stage = "complete";
        report.classification = "supported";
    } else if (strcmp(report.classification, "blocked") != 0) {
        report.classification = "inconclusive";
    }
    emit_report(&report);
    return 0;
}
