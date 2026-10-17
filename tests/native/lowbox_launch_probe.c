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
typedef NTSTATUS (NTAPI *PFN_NT_QUERY_OBJECT)(HANDLE, OBJECT_INFORMATION_CLASS, PVOID, ULONG, PULONG);

typedef struct ProbeObjectBasicInformation {
    ULONG Attributes;
    ACCESS_MASK GrantedAccess;
    ULONG HandleCount;
    ULONG PointerCount;
    ULONG Reserved[10];
} ProbeObjectBasicInformation;

#define MAX_QUERY_RECORDS 16
#define QUERY_VALUE_CAPACITY 4096

typedef struct QueryRecord {
    const char *name;
    ULONG info_class;
    DWORD buffer_size;
    DWORD win32_error;
    BOOL win32_error_set;
    ULONG ntstatus;
    BOOL ntstatus_set;
    DWORD returned_length;
    BOOL success;
    char validation[16];
    char value[QUERY_VALUE_CAPACITY];
} QueryRecord;

typedef struct TokenObservation {
    QueryRecord records[MAX_QUERY_RECORDS];
    DWORD count;
} TokenObservation;

typedef struct InputHandleObservation {
    ULONG info_class;
    ULONG buffer_size;
    ULONG returned_length;
    ULONG ntstatus;
    BOOL ntstatus_set;
    ACCESS_MASK granted_access;
    BOOL success;
    char validation[16];
} InputHandleObservation;

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
    TokenObservation pretoken_observation;
    TokenObservation lowbox_observation;
    TokenObservation child_observation;
    TokenObservation thread_token_observation;
    InputHandleObservation input_handle_observation;
    BOOL thread_token_checked;
    BOOL thread_token_present;
    DWORD thread_token_win32;
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

static QueryRecord *new_query_record(TokenObservation *observation, const char *name, ULONG info_class)
{
    QueryRecord *record;
    if (observation->count >= MAX_QUERY_RECORDS) return NULL;
    record = &observation->records[observation->count++];
    ZeroMemory(record, sizeof(*record));
    record->name = name;
    record->info_class = info_class;
    return record;
}

static void set_query_validation(QueryRecord *record, BOOL valid)
{
    if (record) (void)strcpy_s(record->validation, sizeof(record->validation), valid ? "valid" : "invalid");
}

static BOOL sid_within_buffer(const BYTE *buffer, DWORD returned, PSID sid)
{
    ULONG_PTR start = (ULONG_PTR)buffer, address = (ULONG_PTR)sid, offset;
    const BYTE *bytes;
    DWORD length;
    if (!sid || address < start) return FALSE;
    offset = address - start;
    if (offset > returned || returned - offset < 8U) return FALSE;
    bytes = buffer + offset;
    if (bytes[1] > SID_MAX_SUB_AUTHORITIES) return FALSE;
    length = 8U + (DWORD)bytes[1] * (DWORD)sizeof(DWORD);
    return length <= returned - offset && IsValidSid(sid);
}

static BOOL observed_get_token_information(HANDLE token, TokenObservation *observation,
        const char *name, TOKEN_INFORMATION_CLASS info_class, void *buffer, DWORD buffer_size,
        DWORD *returned, QueryRecord **record_out)
{
    QueryRecord *record = new_query_record(observation, name, (ULONG)info_class);
    BOOL ok;
    DWORD error = ERROR_SUCCESS;
    *returned = 0;
    SetLastError(ERROR_SUCCESS);
    ok = GetTokenInformation(token, info_class, buffer, buffer_size, returned);
    if (!ok) error = GetLastError();
    if (record) {
        record->buffer_size = buffer_size;
        record->returned_length = *returned;
        record->success = ok;
        record->win32_error = error;
        record->win32_error_set = !ok;
        if (!buffer) (void)strcpy_s(record->validation, sizeof(record->validation), "not_applicable");
        else if (ok) (void)strcpy_s(record->validation, sizeof(record->validation), "valid");
    }
    if (record_out) *record_out = record;
    return ok;
}

static BOOL read_token_bool(HANDLE token, TokenObservation *observation,
        TOKEN_INFORMATION_CLASS info_class, const char *name, BOOL *value, DWORD *error)
{
    DWORD raw = 0, returned = 0;
    QueryRecord *record = NULL;
    if (!observed_get_token_information(token, observation, name, info_class,
            &raw, sizeof(raw), &returned, &record)) {
        *error = record ? record->win32_error : ERROR_NOT_ENOUGH_MEMORY;
        return FALSE;
    }
    if (returned != sizeof(raw)) { set_query_validation(record, FALSE); *error = ERROR_INVALID_DATA; return FALSE; }
    *value = raw != 0;
    if (record) (void)sprintf_s(record->value, sizeof(record->value), "%s", raw ? "true" : "false");
    return TRUE;
}

static BOOL read_integrity(HANDLE token, TokenObservation *observation, BOOL *is_low, DWORD *error)
{
    DWORD needed = 0, returned = 0;
    BYTE *buffer = NULL;
    TOKEN_MANDATORY_LABEL *label;
    SID_IDENTIFIER_AUTHORITY mandatory_authority = SECURITY_MANDATORY_LABEL_AUTHORITY;
    QueryRecord *record = NULL;
    BOOL ok = FALSE;
    *is_low = FALSE;
    if (observed_get_token_information(token, observation, "TokenIntegrityLevel", TokenIntegrityLevel,
            NULL, 0, &needed, &record)) {
        *error = ERROR_INVALID_DATA;
        return FALSE;
    }
    if (!record || record->win32_error != ERROR_INSUFFICIENT_BUFFER) {
        *error = record ? record->win32_error : ERROR_NOT_ENOUGH_MEMORY;
        return FALSE;
    }
    if (needed < sizeof(TOKEN_MANDATORY_LABEL)) {
        *error = ERROR_INVALID_DATA;
        return FALSE;
    }
    buffer = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, needed);
    if (!buffer) { *error = ERROR_NOT_ENOUGH_MEMORY; return FALSE; }
    if (!observed_get_token_information(token, observation, "TokenIntegrityLevel", TokenIntegrityLevel,
            buffer, needed, &returned, &record)) {
        *error = record ? record->win32_error : ERROR_NOT_ENOUGH_MEMORY;
        goto done;
    }
    if (returned > needed || returned < sizeof(*label)) { set_query_validation(record, FALSE); *error = ERROR_INVALID_DATA; goto done; }
    label = (TOKEN_MANDATORY_LABEL *)buffer;
    if (!sid_within_buffer(buffer, returned, label->Label.Sid) ||
        *GetSidSubAuthorityCount(label->Label.Sid) != 1 ||
        memcmp(GetSidIdentifierAuthority(label->Label.Sid), &mandatory_authority,
               sizeof(mandatory_authority)) != 0) {
        set_query_validation(record, FALSE);
        *error = ERROR_INVALID_DATA;
        goto done;
    }
    {
        DWORD rid = *GetSidSubAuthority(label->Label.Sid, 0);
        *is_low = rid == SECURITY_MANDATORY_LOW_RID;
        if (record) (void)sprintf_s(record->value, sizeof(record->value), "%lu", (unsigned long)rid);
    }
    ok = TRUE;
    *error = ERROR_SUCCESS;
done:
    HeapFree(GetProcessHeap(), 0, buffer);
    return ok;
}

static BOOL append_sid_group_value(char *out, size_t capacity, size_t *used,
        PSID sid, DWORD attributes, BOOL first)
{
    LPSTR sid_text = NULL;
    int written;
    BOOL ok = FALSE;
    if (!ConvertSidToStringSidA(sid, &sid_text)) return FALSE;
    written = _snprintf_s(out + *used, capacity - *used, _TRUNCATE,
        "%s{\"sid\":\"%s\",\"attributes\":%lu}", first ? "" : ",",
        sid_text, (unsigned long)attributes);
    if (written >= 0) { *used += (size_t)written; ok = TRUE; }
    LocalFree(sid_text);
    return ok;
}

static BOOL read_zero_capabilities(HANDLE token, TokenObservation *observation,
        BOOL *zero, DWORD *error)
{
    DWORD needed = 0, returned = 0, i;
    BYTE *buffer = NULL;
    TOKEN_GROUPS *groups;
    QueryRecord *record = NULL;
    BOOL ok = FALSE;
    *zero = FALSE;
    if (observed_get_token_information(token, observation, "TokenCapabilities", TokenCapabilities,
            NULL, 0, &needed, &record)) {
        QueryRecord *empty_record = NULL;
        if (needed == 0) {
            if (!observed_get_token_information(token, observation, "TokenCapabilities", TokenCapabilities,
                    NULL, 0, &returned, &empty_record)) {
                *error = empty_record ? empty_record->win32_error : ERROR_NOT_ENOUGH_MEMORY;
                return FALSE;
            }
            if (returned != 0) { set_query_validation(empty_record, FALSE); *error = ERROR_INVALID_DATA; return FALSE; }
            if (empty_record) {
                (void)strcpy_s(empty_record->value, sizeof(empty_record->value), "[]");
                set_query_validation(empty_record, TRUE);
            }
            *zero = TRUE;
            *error = ERROR_SUCCESS;
            return TRUE;
        }
        *error = ERROR_INVALID_DATA;
        return FALSE;
    }
    if (!record || record->win32_error != ERROR_INSUFFICIENT_BUFFER) {
        *error = record ? record->win32_error : ERROR_NOT_ENOUGH_MEMORY;
        return FALSE;
    }
    if (needed < offsetof(TOKEN_GROUPS, Groups)) { *error = ERROR_INVALID_DATA; return FALSE; }
    buffer = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, needed);
    if (!buffer) { *error = ERROR_NOT_ENOUGH_MEMORY; return FALSE; }
    if (!observed_get_token_information(token, observation, "TokenCapabilities", TokenCapabilities,
            buffer, needed, &returned, &record)) {
        *error = record ? record->win32_error : ERROR_NOT_ENOUGH_MEMORY;
        goto done;
    }
    groups = (TOKEN_GROUPS *)buffer;
    if (returned > needed || returned < offsetof(TOKEN_GROUPS, Groups) ||
        groups->GroupCount > (returned - offsetof(TOKEN_GROUPS, Groups)) / sizeof(SID_AND_ATTRIBUTES)) {
        set_query_validation(record, FALSE);
        *error = ERROR_INVALID_DATA;
        goto done;
    }
    *zero = groups->GroupCount == 0;
    if (record) {
        size_t used = 1;
        record->value[0] = '[';
        record->value[1] = '\0';
        for (i = 0; i < groups->GroupCount; ++i) {
            if (!sid_within_buffer(buffer, returned, groups->Groups[i].Sid) ||
                !append_sid_group_value(record->value, sizeof(record->value), &used,
                    groups->Groups[i].Sid, groups->Groups[i].Attributes, i == 0)) {
                record->value[0] = '\0';
                set_query_validation(record, FALSE);
                *error = ERROR_INVALID_DATA;
                goto done;
            }
        }
        if (used + 2 > sizeof(record->value)) { set_query_validation(record, FALSE); *error = ERROR_INSUFFICIENT_BUFFER; goto done; }
        record->value[used++] = ']';
        record->value[used] = '\0';
    }
    *error = *zero ? ERROR_SUCCESS : ERROR_INVALID_TOKEN;
    ok = TRUE;
done:
    HeapFree(GetProcessHeap(), 0, buffer);
    return ok;
}

static BOOL read_token_type(HANDLE token, TokenObservation *observation, DWORD *type_out, DWORD *error)
{
    TOKEN_TYPE type = TokenPrimary;
    DWORD returned = 0;
    QueryRecord *record = NULL;
    if (!observed_get_token_information(token, observation, "TokenType", TokenType,
            &type, sizeof(type), &returned, &record)) {
        *error = record ? record->win32_error : ERROR_NOT_ENOUGH_MEMORY;
        return FALSE;
    }
    if (returned != sizeof(type) || (type != TokenPrimary && type != TokenImpersonation)) {
        set_query_validation(record, FALSE); *error = ERROR_INVALID_DATA; return FALSE;
    }
    *type_out = (DWORD)type;
    if (record) (void)sprintf_s(record->value, sizeof(record->value), "%lu", (unsigned long)*type_out);
    return TRUE;
}

static BOOL read_token_privileges(HANDLE token, TokenObservation *observation, DWORD *error)
{
    DWORD needed = 0, returned = 0, i;
    BYTE *buffer;
    TOKEN_PRIVILEGES *privileges;
    QueryRecord *record = NULL;
    size_t used = 1;
    if (observed_get_token_information(token, observation, "TokenPrivileges", TokenPrivileges,
            NULL, 0, &needed, &record)) { *error = ERROR_INVALID_DATA; return FALSE; }
    if (!record || record->win32_error != ERROR_INSUFFICIENT_BUFFER) {
        *error = record ? record->win32_error : ERROR_NOT_ENOUGH_MEMORY;
        return FALSE;
    }
    if (needed < sizeof(DWORD)) { *error = ERROR_INVALID_DATA; return FALSE; }
    buffer = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, needed);
    if (!buffer) { *error = ERROR_NOT_ENOUGH_MEMORY; return FALSE; }
    if (!observed_get_token_information(token, observation, "TokenPrivileges", TokenPrivileges,
            buffer, needed, &returned, &record)) {
        *error = record ? record->win32_error : ERROR_NOT_ENOUGH_MEMORY;
        HeapFree(GetProcessHeap(), 0, buffer);
        return FALSE;
    }
    privileges = (TOKEN_PRIVILEGES *)buffer;
    if (returned > needed || returned < sizeof(DWORD) || privileges->PrivilegeCount >
            (returned - sizeof(DWORD)) / sizeof(LUID_AND_ATTRIBUTES)) {
        set_query_validation(record, FALSE);
        *error = ERROR_INVALID_DATA;
        HeapFree(GetProcessHeap(), 0, buffer);
        return FALSE;
    }
    if (record) {
        record->value[0] = '[';
        record->value[1] = '\0';
        for (i = 0; i < privileges->PrivilegeCount; ++i) {
            int n = _snprintf_s(record->value + used, sizeof(record->value) - used, _TRUNCATE,
                "%s{\"luid_low\":%lu,\"luid_high\":%ld,\"attributes\":%lu}",
                i ? "," : "", (unsigned long)privileges->Privileges[i].Luid.LowPart,
                (long)privileges->Privileges[i].Luid.HighPart,
                (unsigned long)privileges->Privileges[i].Attributes);
            if (n < 0) { set_query_validation(record, FALSE); *error = ERROR_INSUFFICIENT_BUFFER; HeapFree(GetProcessHeap(), 0, buffer); return FALSE; }
            used += (size_t)n;
        }
        if (used + 2 > sizeof(record->value)) { set_query_validation(record, FALSE); *error = ERROR_INSUFFICIENT_BUFFER; HeapFree(GetProcessHeap(), 0, buffer); return FALSE; }
        record->value[used++] = ']';
        record->value[used] = '\0';
    }
    *error = ERROR_SUCCESS;
    HeapFree(GetProcessHeap(), 0, buffer);
    return TRUE;
}

static TokenFacts inspect_token(HANDLE token, TokenObservation *observation, BOOL extended_facts)
{
    TokenFacts facts;
    DWORD error = ERROR_SUCCESS, ignored = 0;
    facts.app_container = FALSE;
    facts.lpac = FALSE;
    facts.low_integrity = FALSE;
    facts.zero_capabilities = FALSE;
    facts.error = ERROR_SUCCESS;
    if (!read_token_bool(token, observation, TokenIsAppContainer, "TokenIsAppContainer", &facts.app_container, &error)) set_first_error(&facts.error, error);
    if (!read_token_bool(token, observation, TokenIsLessPrivilegedAppContainer, "TokenIsLessPrivilegedAppContainer", &facts.lpac, &error)) set_first_error(&facts.error, error);
    if (!read_integrity(token, observation, &facts.low_integrity, &error)) set_first_error(&facts.error, error);
    if (!read_zero_capabilities(token, observation, &facts.zero_capabilities, &error)) set_first_error(&facts.error, error);
    if (extended_facts) {
        if (!read_token_type(token, observation, &ignored, &error)) set_first_error(&facts.error, error);
        if (!read_token_privileges(token, observation, &error)) set_first_error(&facts.error, error);
    }
    return facts;
}

static BOOL facts_satisfy_requirements(const TokenFacts *facts)
{
    return facts->error == ERROR_SUCCESS && facts->app_container && facts->lpac &&
        facts->low_integrity && facts->zero_capabilities;
}

static BOOL read_impersonation_level(HANDLE token, TokenObservation *observation)
{
    SECURITY_IMPERSONATION_LEVEL level = SecurityAnonymous;
    DWORD returned = 0;
    QueryRecord *record = NULL;
    if (!observed_get_token_information(token, observation, "TokenImpersonationLevel",
            TokenImpersonationLevel, &level, sizeof(level), &returned, &record)) return FALSE;
    if (returned != sizeof(level) || level < SecurityAnonymous || level > SecurityDelegation) {
        set_query_validation(record, FALSE);
        return FALSE;
    }
    if (record) (void)sprintf_s(record->value, sizeof(record->value), "%lu", (unsigned long)level);
    return TRUE;
}

static void inspect_effective_thread_token(ProbeReport *report, DWORD *cleanup_error)
{
    HANDLE token = NULL;
    report->thread_token_checked = TRUE;
    if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &token)) {
        report->thread_token_win32 = GetLastError();
        return;
    }
    report->thread_token_present = TRUE;
    (void)inspect_token(token, &report->thread_token_observation, TRUE);
    (void)read_impersonation_level(token, &report->thread_token_observation);
    if (!CloseHandle(token)) set_first_error(cleanup_error, GetLastError());
}

static void inspect_input_handle(HANDLE handle, PFN_NT_QUERY_OBJECT query_object,
        InputHandleObservation *observation)
{
    ProbeObjectBasicInformation basic;
    ULONG returned = 0;
    NTSTATUS status;
    ZeroMemory(observation, sizeof(*observation));
    observation->info_class = 0; /* ObjectBasicInformation */
    observation->buffer_size = (ULONG)sizeof(basic);
    (void)strcpy_s(observation->validation, sizeof(observation->validation), "not_applicable");
    if (!query_object) return;
    ZeroMemory(&basic, sizeof(basic));
    status = query_object(handle, (OBJECT_INFORMATION_CLASS)observation->info_class,
        &basic, observation->buffer_size, &returned);
    observation->ntstatus = (ULONG)status;
    observation->ntstatus_set = TRUE;
    observation->returned_length = returned;
    if (status >= 0) {
        observation->success = TRUE;
        if (returned != sizeof(basic)) {
            (void)strcpy_s(observation->validation, sizeof(observation->validation), "invalid");
            return;
        }
        (void)strcpy_s(observation->validation, sizeof(observation->validation), "valid");
        observation->granted_access = basic.GrantedAccess;
    }
}

static const char *successful_query_value(const TokenObservation *observation, const char *name)
{
    DWORD i;
    for (i = 0; i < observation->count; ++i) {
        const QueryRecord *record = &observation->records[i];
        if (record->success && strcmp(record->validation, "valid") == 0 &&
            record->name && strcmp(record->name, name) == 0 && record->value[0])
            return record->value;
    }
    return NULL;
}

static int observed_fact(const TokenObservation *observation, const char *name)
{
    const char *value = successful_query_value(observation, name);
    if (!value) return -1;
    if (strcmp(name, "TokenIntegrityLevel") == 0)
        return strtoul(value, NULL, 10) == SECURITY_MANDATORY_LOW_RID ? 1 : 0;
    if (strcmp(name, "TokenCapabilities") == 0) return strcmp(value, "[]") == 0 ? 1 : 0;
    return strcmp(value, "true") == 0 ? 1 : 0;
}

static void emit_query_array(const TokenObservation *observation)
{
    DWORD i;
    putchar('[');
    for (i = 0; i < observation->count; ++i) {
        const QueryRecord *record = &observation->records[i];
        if (i) putchar(',');
        printf("{\"name\":\"%s\",\"class\":%lu,\"buffer_size\":%lu,\"win32_error\":",
            record->name ? record->name : "unknown", (unsigned long)record->info_class,
            (unsigned long)record->buffer_size);
        if (record->win32_error_set) printf("%lu", (unsigned long)record->win32_error);
        else printf("null");
        printf(",\"ntstatus\":");
        if (record->ntstatus_set) printf("\"0x%08lX\"", (unsigned long)record->ntstatus);
        else printf("null");
        printf(",\"returned_length\":%lu,\"success\":%s,\"validation\":",
            (unsigned long)record->returned_length, record->success ? "true" : "false");
        if (record->validation[0]) printf("\"%s\"", record->validation);
        else printf("null");
        printf(",\"value\":");
        if (record->success && strcmp(record->validation, "valid") == 0 && record->value[0]) printf("%s", record->value);
        else printf("null");
        putchar('}');
    }
    putchar(']');
}

static void emit_token_observation(const TokenObservation *observation, BOOL caller_facts)
{
    printf("{");
    if (caller_facts) {
        const char *token_type = successful_query_value(observation, "TokenType");
        const char *integrity_rid = successful_query_value(observation, "TokenIntegrityLevel");
        const char *privileges = successful_query_value(observation, "TokenPrivileges");
        printf("\"token_type\":%s,\"integrity_rid\":%s,\"privileges\":%s,",
            token_type ? token_type : "null", integrity_rid ? integrity_rid : "null",
            privileges ? privileges : "null");
    }
    printf("\"queries\":");
    emit_query_array(observation);
    putchar('}');
}

static void emit_observations(const ProbeReport *r)
{
    const InputHandleObservation *input = &r->input_handle_observation;
    printf(",\"observations\":{\"pretoken\":");
    emit_token_observation(&r->pretoken_observation, TRUE);
    printf(",\"lowbox\":");
    emit_token_observation(&r->lowbox_observation, FALSE);
    printf(",\"child\":");
    emit_token_observation(&r->child_observation, FALSE);
    printf(",\"thread_token\":{\"state\":\"%s\",\"win32_error\":",
        !r->thread_token_checked ? "not_checked" : r->thread_token_present ? "present" :
        r->thread_token_win32 == ERROR_NO_TOKEN ? "absent" : "query_error");
    if (r->thread_token_checked && !r->thread_token_present) printf("%lu", (unsigned long)r->thread_token_win32);
    else printf("null");
    printf(",\"queries\":");
    emit_query_array(&r->thread_token_observation);
    printf("},\"input_handle\":{\"class\":\"ObjectBasicInformation\",\"info_class\":%lu,\"buffer_size\":%lu,\"win32_error\":null,\"ntstatus\":",
        (unsigned long)input->info_class, (unsigned long)input->buffer_size);
    if (input->ntstatus_set) printf("\"0x%08lX\"", (unsigned long)input->ntstatus);
    else printf("null");
    printf(",\"returned_length\":%lu,\"success\":%s,\"validation\":",
        (unsigned long)input->returned_length, input->success ? "true" : "false");
    if (input->validation[0]) printf("\"%s\"", input->validation);
    else printf("null");
    printf(",\"value\":");
    if (input->success && strcmp(input->validation, "invalid") != 0)
        printf("%lu", (unsigned long)input->granted_access);
    else printf("null");
    printf("}}");
}

static DWORD query_appcontainer_sid(HANDLE token, TokenObservation *observation,
        PSID expected_sid, BOOL compare_sid)
{
    DWORD needed = 0, returned = 0, error = ERROR_SUCCESS;
    BYTE *buffer = NULL;
    TOKEN_APPCONTAINER_INFORMATION *container_info;
    QueryRecord *record = NULL;
    if (observed_get_token_information(token, observation, "TokenAppContainerSid", TokenAppContainerSid,
            NULL, 0, &needed, &record)) return ERROR_INVALID_DATA;
    if (!record || record->win32_error != ERROR_INSUFFICIENT_BUFFER)
        return record ? record->win32_error : ERROR_NOT_ENOUGH_MEMORY;
    if (needed < sizeof(*container_info)) return ERROR_INVALID_DATA;
    buffer = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, needed);
    if (!buffer) return ERROR_NOT_ENOUGH_MEMORY;
    if (!observed_get_token_information(token, observation, "TokenAppContainerSid", TokenAppContainerSid,
            buffer, needed, &returned, &record)) {
        error = record ? record->win32_error : ERROR_NOT_ENOUGH_MEMORY;
        goto done;
    }
    container_info = (TOKEN_APPCONTAINER_INFORMATION *)buffer;
    if (returned > needed || returned < sizeof(*container_info) || !container_info->TokenAppContainer ||
        !sid_within_buffer(buffer, returned, container_info->TokenAppContainer)) {
        set_query_validation(record, FALSE);
        error = ERROR_INVALID_TOKEN;
        goto done;
    }
    if (record) {
        LPSTR sid_text = NULL;
        if (!ConvertSidToStringSidA(container_info->TokenAppContainer, &sid_text)) {
            error = GetLastError();
            set_query_validation(record, FALSE);
            goto done;
        }
        if (sprintf_s(record->value, sizeof(record->value), "\"%s\"", sid_text) < 0)
            error = ERROR_INSUFFICIENT_BUFFER;
        LocalFree(sid_text);
        if (error != ERROR_SUCCESS) { set_query_validation(record, FALSE); goto done; }
    }
    if (compare_sid && !EqualSid(container_info->TokenAppContainer, expected_sid))
        error = ERROR_INVALID_TOKEN;
done:
    HeapFree(GetProcessHeap(), 0, buffer);
    return error;
}

static DWORD verify_child_token(HANDLE process, PSID expected_sid, TokenObservation *observation)
{
    HANDLE token = NULL;
    DWORD error = ERROR_SUCCESS;
    TokenFacts facts;
    if (!OpenProcessToken(process, TOKEN_QUERY, &token)) return GetLastError();
    facts = inspect_token(token, observation, FALSE);
    error = query_appcontainer_sid(token, observation, expected_sid, TRUE);
    if (facts.error != ERROR_SUCCESS) {
        set_first_error(&error, facts.error);
    } else if (!facts_satisfy_requirements(&facts)) {
        set_first_error(&error, ERROR_INVALID_TOKEN);
    }
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
        "{\"stage\":\"%s\",\"classification\":\"%s\",\"child_token_verified\":%s,\"resumed\":%s,\"ntstatus\":%s,\"mapped_win32\":%lu,\"win32_error\":%lu,\"cleanup_error\":%lu,\"child_exit_code\":%s,\"pretoken_win32\":%lu,\"pretoken_appcontainer\":%d,\"pretoken_lpac\":%d,\"pretoken_low_integrity\":%d,\"pretoken_zero_capabilities\":%d,\"lowbox_win32\":%lu,\"lowbox_appcontainer\":%d,\"lowbox_lpac\":%d,\"lowbox_low_integrity\":%d,\"lowbox_zero_capabilities\":%d,\"candidate_access_win32\":%lu,\"launch_win32\":%lu,\"child_verify_win32\":%lu,\"resume_win32\":%lu,\"wait_win32\":%lu",
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
    emit_observations(r);
    printf("}\n");
    (void)fflush(stdout);
}

static int child_main(int argc, wchar_t **argv)
{
    (void)argc;
    (void)argv;
    return 0;
}

static void set_self_test_query(TokenObservation *observation, const char *name,
        ULONG info_class, DWORD buffer_size, DWORD returned, BOOL success,
        DWORD win32_error, const char *value)
{
    QueryRecord *record = new_query_record(observation, name, info_class);
    if (!record) return;
    record->buffer_size = buffer_size;
    record->returned_length = returned;
    record->success = success;
    record->win32_error_set = !success;
    record->win32_error = win32_error;
    if (success) (void)strcpy_s(record->validation, sizeof(record->validation), "valid");
    else (void)strcpy_s(record->validation, sizeof(record->validation), "not_applicable");
    if (success && value) (void)strcpy_s(record->value, sizeof(record->value), value);
}

int wmain(int argc, wchar_t **argv)
{
    ProbeReport report;
    HMODULE ntdll = NULL;
    PFN_NT_CREATE_LOW_BOX_TOKEN nt_create_lowbox = NULL;
    PFN_RTL_NT_STATUS_TO_DOS_ERROR status_to_error = NULL;
    PFN_NT_QUERY_OBJECT nt_query_object = NULL;
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
    if (argc == 2 && wcscmp(argv[1], L"--serialization-self-test") == 0) {
        TokenFacts deliberately_invalid_facts;
        QueryRecord *invalid;
        SID bounded_sid;
        SID_IDENTIFIER_AUTHORITY mandatory_authority = SECURITY_MANDATORY_LABEL_AUTHORITY;
        ZeroMemory(&bounded_sid, sizeof(bounded_sid));
        bounded_sid.Revision = SID_REVISION;
        bounded_sid.SubAuthorityCount = 1;
        bounded_sid.IdentifierAuthority = mandatory_authority;
        bounded_sid.SubAuthority[0] = SECURITY_MANDATORY_LOW_RID;
        if (!sid_within_buffer((BYTE *)&bounded_sid, sizeof(bounded_sid), &bounded_sid) ||
            sid_within_buffer((BYTE *)&bounded_sid, sizeof(bounded_sid) - 1, &bounded_sid) ||
            sid_within_buffer((BYTE *)&bounded_sid, sizeof(bounded_sid),
                (PSID)((ULONG_PTR)&bounded_sid + sizeof(bounded_sid))) ||
            sid_within_buffer((BYTE *)&bounded_sid, sizeof(bounded_sid),
                (PSID)((ULONG_PTR)&bounded_sid - 1))) return 3;
        ZeroMemory(&deliberately_invalid_facts, sizeof(deliberately_invalid_facts));
        deliberately_invalid_facts.app_container = TRUE;
        deliberately_invalid_facts.lpac = TRUE;
        deliberately_invalid_facts.low_integrity = TRUE;
        deliberately_invalid_facts.zero_capabilities = TRUE;
        if (!facts_satisfy_requirements(&deliberately_invalid_facts)) return 3;
        deliberately_invalid_facts.error = ERROR_ACCESS_DENIED;
        if (facts_satisfy_requirements(&deliberately_invalid_facts)) return 3;
        deliberately_invalid_facts.error = ERROR_SUCCESS;
        deliberately_invalid_facts.lpac = FALSE;
        if (facts_satisfy_requirements(&deliberately_invalid_facts)) return 3;
        report.stage = "serialization_self_test";
        set_self_test_query(&report.pretoken_observation, "TokenIsAppContainer", TokenIsAppContainer,
            sizeof(DWORD), sizeof(DWORD), TRUE, ERROR_SUCCESS, "false");
        set_self_test_query(&report.pretoken_observation, "TokenIsLessPrivilegedAppContainer",
            TokenIsLessPrivilegedAppContainer, sizeof(DWORD), 0, FALSE, ERROR_INVALID_PARAMETER, NULL);
        set_self_test_query(&report.pretoken_observation, "TokenType", TokenType,
            sizeof(TOKEN_TYPE), sizeof(TOKEN_TYPE), TRUE, ERROR_SUCCESS, "1");
        set_self_test_query(&report.pretoken_observation, "TokenIntegrityLevel", TokenIntegrityLevel,
            0, sizeof(TOKEN_MANDATORY_LABEL), FALSE, ERROR_INSUFFICIENT_BUFFER, NULL);
        set_self_test_query(&report.pretoken_observation, "TokenPrivileges", TokenPrivileges,
            sizeof(DWORD), sizeof(DWORD), TRUE, ERROR_SUCCESS, "[]");
        set_self_test_query(&report.lowbox_observation, "TokenIsAppContainer", TokenIsAppContainer,
            sizeof(DWORD), sizeof(DWORD), TRUE, ERROR_SUCCESS, "true");
        set_self_test_query(&report.child_observation, "TokenAppContainerSid", TokenAppContainerSid,
            0, 0, FALSE, ERROR_ACCESS_DENIED, NULL);
        set_self_test_query(&report.child_observation, "TokenPrivileges", TokenPrivileges,
            sizeof(DWORD), sizeof(DWORD), TRUE, ERROR_SUCCESS, "[partial");
        invalid = &report.child_observation.records[report.child_observation.count - 1];
        set_query_validation(invalid, FALSE);
        if (successful_query_value(&report.child_observation, "TokenPrivileges")) return 3;
        report.thread_token_checked = TRUE;
        report.thread_token_win32 = ERROR_NO_TOKEN;
        report.input_handle_observation.info_class = 0;
        report.input_handle_observation.buffer_size = sizeof(ProbeObjectBasicInformation);
        report.input_handle_observation.ntstatus = 0xC0000022UL;
        report.input_handle_observation.ntstatus_set = TRUE;
        (void)strcpy_s(report.input_handle_observation.validation,
            sizeof(report.input_handle_observation.validation), "not_applicable");
        report.pretoken_win32 = ERROR_INVALID_PARAMETER;
        report.pretoken_appcontainer = observed_fact(&report.pretoken_observation, "TokenIsAppContainer");
        report.pretoken_lpac = observed_fact(&report.pretoken_observation, "TokenIsLessPrivilegedAppContainer");
        if (report.pretoken_appcontainer != 0 || report.pretoken_lpac != -1) return 3;
        report.child_token_verified = facts_satisfy_requirements(&deliberately_invalid_facts);
        emit_report(&report);
        return report.child_token_verified ? 3 : 0;
    }
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
    pretoken = inspect_token(base_token, &report.pretoken_observation, TRUE);
    report.pretoken_win32 = pretoken.error;
    report.pretoken_appcontainer = observed_fact(&report.pretoken_observation, "TokenIsAppContainer");
    report.pretoken_lpac = observed_fact(&report.pretoken_observation, "TokenIsLessPrivilegedAppContainer");
    report.pretoken_low_integrity = observed_fact(&report.pretoken_observation, "TokenIntegrityLevel");
    report.pretoken_zero_capabilities = observed_fact(&report.pretoken_observation, "TokenCapabilities");
    inspect_effective_thread_token(&report, &cleanup_error);

    report.stage = "nt_create_lowbox_token";
    ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll) {
        FARPROC address = GetProcAddress(ntdll, "NtCreateLowBoxToken");
        if (address && sizeof(address) == sizeof(nt_create_lowbox))
            memcpy(&nt_create_lowbox, &address, sizeof(nt_create_lowbox));
        address = GetProcAddress(ntdll, "NtQueryObject");
        if (address && sizeof(address) == sizeof(nt_query_object))
            memcpy(&nt_query_object, &address, sizeof(nt_query_object));
        address = GetProcAddress(ntdll, "RtlNtStatusToDosError");
        if (address && sizeof(address) == sizeof(status_to_error))
            memcpy(&status_to_error, &address, sizeof(status_to_error));
    }
    if (!nt_create_lowbox || !status_to_error) {
        report.win32_error = ERROR_PROC_NOT_FOUND;
        report.classification = "inconclusive";
        goto finish;
    }
    inspect_input_handle(base_token, nt_query_object, &report.input_handle_observation);
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
        TokenFacts lowbox_facts = inspect_token(lowbox_token, &report.lowbox_observation, FALSE);
        report.lowbox_win32 = lowbox_facts.error;
        report.lowbox_appcontainer = observed_fact(&report.lowbox_observation, "TokenIsAppContainer");
        report.lowbox_lpac = observed_fact(&report.lowbox_observation, "TokenIsLessPrivilegedAppContainer");
        report.lowbox_low_integrity = observed_fact(&report.lowbox_observation, "TokenIntegrityLevel");
        report.lowbox_zero_capabilities = observed_fact(&report.lowbox_observation, "TokenCapabilities");
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
    report.child_verify_win32 = verify_child_token(process.hProcess, package_sid,
        &report.child_observation);
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
