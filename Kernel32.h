#pragma once
#include "Imports.h"
#include "MyStructs.h"


HANDLE CreateThread (
	LPSECURITY_ATTRIBUTES   lpThreadAttributes,
	SIZE_T                  dwStackSize,
	LPTHREAD_START_ROUTINE  lpStartAddress,
	__drv_aliasesMem LPVOID lpParameter,
	DWORD                   dwCreationFlags,
	LPDWORD                 lpThreadId
	);

BOOL CheckRemoteDebuggerPresent (
	_In_    HANDLE hProcess,
	_Inout_ PBOOL  pbDebuggerPresent
	);

BOOL GetThreadContext (
	HANDLE    hThread,
	LPCONTEXT lpContext
	);
BOOL CreateProcessA (
	LPCSTR                lpApplicationName,
	LPSTR                 lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL                  bInheritHandles,
	DWORD                 dwCreationFlags,
	LPVOID                lpEnvironment,
	LPCSTR                lpCurrentDirectory,
	LPSTARTUPINFOA        lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
	);
DWORD GetModuleFileNameA (
	_In_opt_ HMODULE hModule,
	_Out_    LPTSTR  lpFilename,
	_In_     DWORD   nSize
	);
DWORD GetModuleFileNameExA (
	HANDLE  hProcess,
	HMODULE hModule,
	LPSTR   lpFilename,
	DWORD   nSize
	);
HMODULE GetModuleHandleA (
	LPCSTR lpModuleName
	);
FARPROC GetProcAddress (
	HMODULE hModule,
	LPCSTR  lpProcName
	);
void GetNativeSystemInfo (
	LPSYSTEM_INFO lpSystemInfo
	);
void OutputDebugStringA (
	_In_opt_ LPCTSTR lpOutputString
	);
BOOL SetFileAttributesA (
	LPCSTR lpFileName,
	DWORD  dwFileAttributes
	);
HANDLE FindFirstFileA (
	__in LPCSTR lpFileName,
	__out LPWIN32_FIND_DATAA lpFindFileData
	);
BOOL FindNextFileA (
	__in HANDLE hFindFile,
	__out LPWIN32_FIND_DATAA lpFindFileData
	);
BOOL TerminateThread (
	HANDLE hThread,
	DWORD  dwExitCode
	);
DWORD GetProcessId (
	HANDLE Process
	);
HANDLE GetCurrentProcess (
	void
	);
BOOL Process32Next (
	HANDLE           hSnapshot,
	LPPROCESSENTRY32 lppe
	);
HANDLE CreateToolhelp32Snapshot (
	DWORD dwFlags,
	DWORD th32ProcessID
	);
HANDLE OpenProcess (
	DWORD dwDesiredAccess,
	BOOL  bInheritHandle,
	DWORD dwProcessId
	);
BOOL TerminateProcess (
	HANDLE hProcess,
	UINT   uExitCode
	);
BOOL Process32First (
	HANDLE           hSnapshot,
	LPPROCESSENTRY32 lppe
	);
DWORD timeGetTime (
	void
	);
void  Sleep (
	DWORD dwMilliseconds
	);
BOOL CloseHandle (
	HANDLE hObject
	);
BOOL WriteFile (
	HANDLE       hFile,
	LPCVOID      lpBuffer,
	DWORD        nNumberOfBytesToWrite,
	LPDWORD      lpNumberOfBytesWritten,
	LPOVERLAPPED lpOverlapped
	);
BOOL CopyFileA (
	LPCSTR lpExistingFileName,
	LPCSTR lpNewFileName,
	BOOL   bFailIfExists
	);
DWORD GetLastError (
	void
	);
HANDLE CreateFileA (
	LPCSTR                lpFileName,
	DWORD                 dwDesiredAccess,
	DWORD                 dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD                 dwCreationDisposition,
	DWORD                 dwFlagsAndAttributes,
	HANDLE                hTemplateFile
	);
BOOL CreateDirectoryA (
	LPCSTR                lpPathName,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes
	);
HANDLE CreateMutexA (
	LPSECURITY_ATTRIBUTES lpMutexAttributes,
	BOOL                  bInitialOwner,
	LPCSTR                lpName
	);
DWORD WaitForSingleObject (
	HANDLE hHandle,
	DWORD  dwMilliseconds
	);
BOOL GetComputerNameW (
	_Out_writes_to_opt_(*nSize, *nSize + 1) LPWSTR lpBuffer,
	_Inout_ LPDWORD nSize
	);
BOOL ReleaseMutex (
	HANDLE hMutex
	);
HANDLE OpenMutexW (
	DWORD   dwDesiredAccess,
	BOOL    bInheritHandle,
	LPCWSTR lpName
	);
int  MultiByteToWideChar (
	UINT                              CodePage,
	DWORD                             dwFlags,
	_In_NLS_string_(cbMultiByte)LPCCH lpMultiByteStr,
	int                               cbMultiByte,
	LPWSTR                            lpWideCharStr,
	int                               cchWideChar
	);
BOOL SystemTimeToFileTime (
	const SYSTEMTIME *lpSystemTime,
	LPFILETIME       lpFileTime
	);
int  WideCharToMultiByte (
	UINT                               CodePage,
	DWORD                              dwFlags,
	_In_NLS_string_(cchWideChar)LPCWCH lpWideCharStr,
	int                                cchWideChar,
	LPSTR                              lpMultiByteStr,
	int                                cbMultiByte,
	LPCCH                              lpDefaultChar,
	LPBOOL                             lpUsedDefaultChar
	);
void  GetSystemTime (
	LPSYSTEMTIME lpSystemTime
	);

BOOL IsWow64Process (
	HANDLE hProcess,
	PBOOL  Wow64Process
	);

HMODULE LoadLibraryA (
	LPCSTR lpLibFileName
	);
BOOL FreeLibrary(
	HMODULE hLibModule
);

UINT GetWindowsDirectoryA(
	LPSTR lpBuffer,
	UINT  uSize
);

UINT GetPrivateProfileIntA(
	LPCSTR lpAppName,
	LPCSTR lpKeyName,
	INT    nDefault,
	LPCSTR lpFileName
);

DWORD GetPrivateProfileStringA(
	LPCSTR lpAppName,
	LPCSTR lpKeyName,
	LPCSTR lpDefault,
	LPSTR  lpReturnedString,
	DWORD  nSize,
	LPCSTR lpFileName
);


HANDLE GetProcessHeap(

);

DWORD GetPrivateProfileSectionNamesA(
	LPSTR  lpszReturnBuffer,
	DWORD   nSize,
	LPCSTR lpFileName
);