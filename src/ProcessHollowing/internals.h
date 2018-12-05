struct PROCESS_BASIC_INFORMATION {
	PVOID Reserved1;
	DWORD PebBaseAddress;
	PVOID Reserved2[2];
	DWORD UniqueProcessId;
	PVOID Reserved3;
};

typedef NTSTATUS (WINAPI* _NtUnmapViewOfSection)(
	HANDLE ProcessHandle,
	PVOID BaseAddress 
	);

typedef NTSTATUS (WINAPI* _NtQueryInformationProcess)(
	HANDLE ProcessHandle,
	DWORD ProcessInformationClass,
	PVOID ProcessInformation,
	DWORD ProcessInformationLength,
	PDWORD ReturnLength
	);

typedef NTSTATUS (WINAPI* _NtQuerySystemInformation)(
	DWORD SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);

typedef BOOL (WINAPI* _CreateProcessA)(
	_In_opt_ LPCSTR lpApplicationName,
	_Inout_opt_ LPSTR lpCommandLine,
	_In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
	_In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
	_In_ BOOL bInheritHandles,
	_In_ DWORD dwCreationFlags,
	_In_opt_ LPVOID lpEnvironment,
	_In_opt_ LPCSTR lpCurrentDirectory,
	_In_ LPSTARTUPINFOA lpStartupInfo,
	_Out_ LPPROCESS_INFORMATION lpProcessInformation
	);

typedef LPVOID (WINAPI* _VirtualAllocEx)(
	_In_ HANDLE hProcess,
	_In_opt_ LPVOID lpAddress,
	_In_ SIZE_T dwSize,
	_In_ DWORD flAllocationType,
	_In_ DWORD flProtect
	);

typedef BOOL (WINAPI* _WriteProcessMemory)(
	_In_ HANDLE hProcess,
	_In_ LPVOID lpBaseAddress,
	_In_reads_bytes_(nSize) LPCVOID lpBuffer,
	_In_ SIZE_T nSize,
	_Out_opt_ SIZE_T * lpNumberOfBytesWritten
	);

typedef BOOL (WINAPI* _ReadProcessMemory)(
	_In_ HANDLE hProcess,
	_In_ LPCVOID lpBaseAddress,
	_Out_writes_bytes_to_(nSize, *lpNumberOfBytesRead) LPVOID lpBuffer,
	_In_ SIZE_T nSize,
	_Out_opt_ SIZE_T * lpNumberOfBytesRead
	);

typedef BOOL (WINAPI* _GetThreadContext)(
	_In_ HANDLE hThread,
	_Inout_ LPCONTEXT lpContext
	);

typedef BOOL (WINAPI* _SetThreadContext)(
	_In_ HANDLE hThread,
	_In_ CONST CONTEXT * lpContext
	);

typedef DWORD (WINAPI* _ResumeThread)(
	_In_ HANDLE hThread
	);

typedef HGLOBAL (WINAPI* _LoadResource)(
	_In_opt_ HMODULE hModule,
	_In_ HRSRC hResInfo
	);