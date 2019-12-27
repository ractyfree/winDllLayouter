#include "Kernel32.h"
#include "DynImport.h"

#include "CRT.h"

HANDLE CreateThread(
	LPSECURITY_ATTRIBUTES   lpThreadAttributes,
	SIZE_T                  dwStackSize,
	LPTHREAD_START_ROUTINE  lpStartAddress,
	__drv_aliasesMem LPVOID lpParameter,
	DWORD                   dwCreationFlags,
	LPDWORD                 lpThreadId
){
#ifdef JUNKASM
#include "JunkASM.h"
#endif
	HANDLE(WINAPI *pCreateThread)(
		LPSECURITY_ATTRIBUTES   lpThreadAttributes,
		SIZE_T                  dwStackSize,
		LPTHREAD_START_ROUTINE  lpStartAddress,
		__drv_aliasesMem LPVOID lpParameter,
		DWORD                   dwCreationFlags,
		LPDWORD                 lpThreadId
		);
	*(DWORD_PTR*)&pCreateThread = get_proc_address(get_kernel32base(), 0x68a8c443);
	return pCreateThread(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);

};

BOOL CheckRemoteDebuggerPresent(
	_In_    HANDLE hProcess,
	_Inout_ PBOOL  pbDebuggerPresent
){
#ifdef JUNKASM
#include "JunkASM.h"
#endif
	BOOL(WINAPI *pCheckRemoteDebuggerPresent)(
		_In_    HANDLE hProcess,
		_Inout_ PBOOL  pbDebuggerPresent
		);
	*(DWORD_PTR*)&pCheckRemoteDebuggerPresent = get_proc_address(get_kernel32base(), 0xc63c0dc3);

	return pCheckRemoteDebuggerPresent(hProcess, pbDebuggerPresent);

};

BOOL GetThreadContext(
	HANDLE    hThread,
	LPCONTEXT lpContext
){
#ifdef JUNKASM
#include "JunkASM.h"
#endif
	BOOL(WINAPI *pGetThreadContext)(
		HANDLE    hThread,
		LPCONTEXT lpContext
		);
	*(DWORD_PTR*)&pGetThreadContext = get_proc_address(get_kernel32base(), 0xf7643b99);
	return pGetThreadContext(hThread, lpContext);



};


BOOL CreateProcessA(
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
){
#ifdef JUNKASM
#include "JunkASM.h"
#endif
	BOOL(WINAPI *pCreateProcessA)(
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

	*(DWORD_PTR*)&pCreateProcessA = get_proc_address(get_kernel32base(), 0xb4f0f459);
	return pCreateProcessA(lpApplicationName,
		lpCommandLine,
		lpProcessAttributes,
		lpThreadAttributes,
		bInheritHandles,
		dwCreationFlags,
		lpEnvironment,
		lpCurrentDirectory,
		lpStartupInfo,
		lpProcessInformation);



};
DWORD GetModuleFileNameA(
	_In_opt_ HMODULE hModule,
	_Out_    LPTSTR  lpFilename,
	_In_     DWORD   nSize
){
#ifdef JUNKASM
#include "JunkASM.h"
#endif
	DWORD(WINAPI *pGetModuleFileNameA)(
		_In_opt_ HMODULE hModule,
		_Out_    LPTSTR  lpFilename,
		_In_     DWORD   nSize
		);
	*(DWORD_PTR*)&pGetModuleFileNameA = get_proc_address(get_kernel32base(), 0xf3cf5f59);
	return pGetModuleFileNameA(hModule, lpFilename, nSize);


};
DWORD GetModuleFileNameExA(
	HANDLE  hProcess,
	HMODULE hModule,
	LPSTR   lpFilename,
	DWORD   nSize
){
#ifdef JUNKASM
#include "JunkASM.h"
#endif
	DWORD(WINAPI *pGetModuleFileNameExA)(
		HANDLE  hProcess,
		HMODULE hModule,
		LPSTR   lpFilename,
		DWORD   nSize
		);
	*(DWORD_PTR*)&pGetModuleFileNameExA = get_proc_address(get_kernel32base(), 0x16b158ed);
	return pGetModuleFileNameExA(hProcess, hModule, lpFilename, nSize);


};
HMODULE GetModuleHandleA(
	LPCSTR lpModuleName
){
#ifdef JUNKASM
#include "JunkASM.h"
#endif
	HMODULE(WINAPI *pGetModuleHandleA)(
		LPCSTR lpModuleName
		);
	*(DWORD_PTR*)&pGetModuleHandleA = get_proc_address(get_kernel32base(), 0x61eebcec);
	return pGetModuleHandleA(lpModuleName);



};
FARPROC GetProcAddress(
	HMODULE hModule,
	LPCSTR  lpProcName
){
#ifdef JUNKASM
#include "JunkASM.h"
#endif
	FARPROC(WINAPI *pGetProcAddress)(
		HMODULE hModule,
		LPCSTR  lpProcName
		);
	*(DWORD_PTR*)&pGetProcAddress = get_proc_address(get_kernel32base(), 0x1acaee7a);
	return pGetProcAddress(hModule, lpProcName);


};
void GetNativeSystemInfo(
	LPSYSTEM_INFO lpSystemInfo
){
#ifdef JUNKASM
#include "JunkASM.h"
#endif
	void(WINAPI *pGetNativeSystemInfo)(
		LPSYSTEM_INFO lpSystemInfo
		);
	*(DWORD_PTR*)&pGetNativeSystemInfo = get_proc_address(get_kernel32base(), 0xab489125);
	return pGetNativeSystemInfo(lpSystemInfo);


};
void OutputDebugStringA(
	_In_opt_ LPCTSTR lpOutputString
){
#ifdef JUNKASM
#include "JunkASM.h"
#endif
	void(WINAPI *pOutputDebugStringA)(
		_In_opt_ LPCTSTR lpOutputString
		);
	*(DWORD_PTR*)&pOutputDebugStringA = get_proc_address(get_kernel32base(), 0xd5e9949f);
	return pOutputDebugStringA(lpOutputString);



};
BOOL SetFileAttributesA(
	LPCSTR lpFileName,
	DWORD  dwFileAttributes
){
#ifdef JUNKASM
#include "JunkASM.h"
#endif
	BOOL(WINAPI *pSetFileAttributesA)(
		LPCSTR lpFileName,
		DWORD  dwFileAttributes
		);
	*(DWORD_PTR*)&pSetFileAttributesA = get_proc_address(get_kernel32base(), 0xe5142b55);
	return pSetFileAttributesA(lpFileName, dwFileAttributes);


};
HANDLE FindFirstFileA(
	__in LPCSTR lpFileName,
	__out LPWIN32_FIND_DATAA lpFindFileData
){

#ifdef JUNKASM
#include "JunkASM.h"
#endif
	HANDLE(WINAPI *pFindFirstFileA)(
		__in LPCSTR lpFileName,
		__out LPWIN32_FIND_DATAA lpFindFileData
		);
	*(DWORD_PTR*)&pFindFirstFileA = get_proc_address(get_kernel32base(), 0x216b24d);
	return pFindFirstFileA(lpFileName, lpFindFileData);

};

BOOL FindNextFileA(
	__in HANDLE hFindFile,
	__out LPWIN32_FIND_DATAA lpFindFileData
){
#ifdef JUNKASM
#include "JunkASM.h"
#endif
	BOOL(WINAPI *pFindNextFileA)(
		__in HANDLE hFindFile,
		__out LPWIN32_FIND_DATAA lpFindFileData
		);
	*(DWORD_PTR*)&pFindNextFileA = get_proc_address(get_kernel32base(), 0x6420a07f);
	return pFindNextFileA(hFindFile, lpFindFileData);

};

BOOL TerminateThread(
	HANDLE hThread,
	DWORD  dwExitCode
){
#ifdef JUNKASM
#include "JunkASM.h"
#endif
	BOOL(WINAPI *pTerminateThread)(
		HANDLE hThread,
		DWORD  dwExitCode
		);
	*(DWORD_PTR*)&pTerminateThread = get_proc_address(get_kernel32base(), 0x4b3e6161);
	return pTerminateThread(hThread, dwExitCode);



};

DWORD GetProcessId(
	HANDLE Process
){
#ifdef JUNKASM
#include "JunkASM.h"
#endif
	DWORD(WINAPI *pGetProcessId)(
		HANDLE Process
		);

	*(DWORD_PTR*)&pGetProcessId = get_proc_address(get_kernel32base(), 0xba190f77);
	return pGetProcessId(Process);


};

HANDLE GetCurrentProcess(
	void
){
#ifdef JUNKASM
#include "JunkASM.h"
#endif
	HANDLE(WINAPI *pGetCurrentProcess)(
		void
		);
	*(DWORD_PTR*)&pGetCurrentProcess = get_proc_address(get_kernel32base(), 0x1a4b89aa);
	return pGetCurrentProcess();

};



BOOL Process32Next(
	HANDLE           hSnapshot,
	LPPROCESSENTRY32 lppe
){
#ifdef JUNKASM
#include "JunkASM.h"
#endif
	BOOL(WINAPI *pProcess32Next)(
		HANDLE           hSnapshot,
		LPPROCESSENTRY32 lppe
		);
	*(DWORD_PTR*)&pProcess32Next = get_proc_address(get_kernel32base(), 0x25b55922);
	return pProcess32Next(hSnapshot, lppe);



};
HANDLE CreateToolhelp32Snapshot(
	DWORD dwFlags,
	DWORD th32ProcessID
){
#ifdef JUNKASM
#include "JunkASM.h"
#endif
	HANDLE(WINAPI *pCreateToolhelp32Snapshot)(
		DWORD dwFlags,
		DWORD th32ProcessID
		);
	*(DWORD_PTR*)&pCreateToolhelp32Snapshot = get_proc_address(get_kernel32base(), 0x8a62152f);
	return pCreateToolhelp32Snapshot(dwFlags, th32ProcessID);

};

HANDLE OpenProcess(
	DWORD dwDesiredAccess,
	BOOL  bInheritHandle,
	DWORD dwProcessId
){
#ifdef JUNKASM
#include "JunkASM.h"
#endif
	HANDLE(WINAPI *pOpenProcess)(
		DWORD dwDesiredAccess,
		BOOL  bInheritHandle,
		DWORD dwProcessId
		);
	*(DWORD_PTR*)&pOpenProcess = get_proc_address(get_kernel32base(), 0x8edf8b90);
	return pOpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);


};

BOOL TerminateProcess(
	HANDLE hProcess,
	UINT   uExitCode
){
#ifdef JUNKASM
#include "JunkASM.h"
#endif
	BOOL(WINAPI *pTerminateProcess)(
		HANDLE hProcess,
		UINT   uExitCode
		);
	*(DWORD_PTR*)&pTerminateProcess = get_proc_address(get_kernel32base(), 0x7722b4b);
	return pTerminateProcess(hProcess, uExitCode);

};

//#include <TlHelp32.h>
BOOL Process32First(
	HANDLE           hSnapshot,
	LPPROCESSENTRY32 lppe
){
#ifdef JUNKASM
#include "JunkASM.h"
#endif
	BOOL(WINAPI *pProcess32First)(
		HANDLE           hSnapshot,
		LPPROCESSENTRY32 lppe
		);

	*(DWORD_PTR*)&pProcess32First = get_proc_address(get_kernel32base(), 0xd108ac7e);
	return pProcess32First(hSnapshot, lppe);



};
DWORD timeGetTime(
	void
){
#ifdef JUNKASM
#include "JunkASM.h"
#endif
	DWORD(WINAPI* ptimeGetTime)(
		void
		);
	*(DWORD_PTR*)&ptimeGetTime = get_proc_address(get_kernel32base(), 0x788ba35d);
	return ptimeGetTime();

};

void  Sleep(
	DWORD dwMilliseconds
){
#ifdef JUNKASM
#include "JunkASM.h"
#endif
	void (WINAPI* pSleep)(
		DWORD dwMilliseconds
		);
	*(DWORD_PTR*)&pSleep = get_proc_address(get_kernel32base(), 0x9a2d4190);
	return pSleep(dwMilliseconds);

};

BOOL CloseHandle(
	HANDLE hObject
){
#ifdef JUNKASM
#include "JunkASM.h"
#endif
	BOOL(WINAPI* pCloseHandle)(
		HANDLE hObject
		);
	*(DWORD_PTR*)&pCloseHandle = get_proc_address(get_kernel32base(), 0xae7a8bda);
	return pCloseHandle(hObject);

};


BOOL WriteFile(
	HANDLE       hFile,
	LPCVOID      lpBuffer,
	DWORD        nNumberOfBytesToWrite,
	LPDWORD      lpNumberOfBytesWritten,
	LPOVERLAPPED lpOverlapped
){
#ifdef JUNKASM
#include "JunkASM.h"
#endif
	BOOL(WINAPI* pWriteFile)(
		HANDLE       hFile,
		LPCVOID      lpBuffer,
		DWORD        nNumberOfBytesToWrite,
		LPDWORD      lpNumberOfBytesWritten,
		LPOVERLAPPED lpOverlapped
		);
	*(DWORD_PTR*)&pWriteFile = get_proc_address(get_kernel32base(), 0xe6886cef);
	return pWriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);

};



BOOL CopyFileA(
	LPCSTR lpExistingFileName,
	LPCSTR lpNewFileName,
	BOOL   bFailIfExists
){
#ifdef JUNKASM
#include "JunkASM.h"
#endif
	BOOL(WINAPI* pCopyFileA)(
		LPCSTR lpExistingFileName,
		LPCSTR lpNewFileName,
		BOOL   bFailIfExists
		);
	*(DWORD_PTR*)&pCopyFileA = get_proc_address(get_kernel32base(), 0x586c7d4e);
	return pCopyFileA(lpExistingFileName, lpNewFileName, bFailIfExists);


};

DWORD GetLastError(
	void
){
#ifdef JUNKASM
#include "JunkASM.h"
#endif
	DWORD(WINAPI* pGetLastError)(
		void
		);
	*(DWORD_PTR*)&pGetLastError = get_proc_address(get_kernel32base(), 0x34590d2e);
	return pGetLastError();


};

HANDLE CreateFileA(
	LPCSTR                lpFileName,
	DWORD                 dwDesiredAccess,
	DWORD                 dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD                 dwCreationDisposition,
	DWORD                 dwFlagsAndAttributes,
	HANDLE                hTemplateFile
){
#ifdef JUNKASM
#include "JunkASM.h"
#endif
	HANDLE(WINAPI* pCreateFileA)(
		LPCSTR                lpFileName,
		DWORD                 dwDesiredAccess,
		DWORD                 dwShareMode,
		LPSECURITY_ATTRIBUTES lpSecurityAttributes,
		DWORD                 dwCreationDisposition,
		DWORD                 dwFlagsAndAttributes,
		HANDLE                hTemplateFile
		);
	*(DWORD_PTR*)&pCreateFileA = get_proc_address(get_kernel32base(), 0x1a7f0b95);
	return pCreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);




};

BOOL CreateDirectoryA(
	LPCSTR                lpPathName,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes
){
#ifdef JUNKASM
#include "JunkASM.h"
#endif
	BOOL(WINAPI* pCreateDirectoryA)(
		LPCSTR                lpPathName,
		LPSECURITY_ATTRIBUTES lpSecurityAttributes
		);
	*(DWORD_PTR*)&pCreateDirectoryA = get_proc_address(get_kernel32base(), 0x2e0ccb4d);
	return pCreateDirectoryA(lpPathName, lpSecurityAttributes);



};

HANDLE CreateMutexA(
	LPSECURITY_ATTRIBUTES lpMutexAttributes,
	BOOL                  bInitialOwner,
	LPCSTR                lpName
){	
#ifdef JUNKASM
#include "JunkASM.h"
#endif
	HANDLE(WINAPI* pCreateMutexA)(
		LPSECURITY_ATTRIBUTES lpMutexAttributes,
		BOOL                  bInitialOwner,
		LPCSTR                lpName
		);
	*(DWORD_PTR*)&pCreateMutexA = get_proc_address(get_kernel32base(), 0xed61943c);
	return pCreateMutexA(lpMutexAttributes, bInitialOwner, lpName);

};

DWORD WaitForSingleObject(
	HANDLE hHandle,
	DWORD  dwMilliseconds
){
#ifdef JUNKASM
#include "JunkASM.h"
#endif
	DWORD(WINAPI* pWaitForSingleObject)(
		HANDLE hHandle,
		DWORD  dwMilliseconds
		);
	*(DWORD_PTR*)&pWaitForSingleObject = get_proc_address(get_kernel32base(), 0x5c62ca81);
	return pWaitForSingleObject(hHandle, dwMilliseconds);

};

BOOL GetComputerNameW(
	_Out_writes_to_opt_(*nSize, *nSize + 1) LPWSTR lpBuffer,
	_Inout_ LPDWORD nSize
){
#ifdef JUNKASM
#include "JunkASM.h"
#endif
	BOOL(WINAPI* pGetComputerNameW)(
		_Out_writes_to_opt_(*nSize, *nSize + 1) LPWSTR lpBuffer,
		_Inout_ LPDWORD nSize
		);
	*(DWORD_PTR*)&pGetComputerNameW = get_proc_address(get_kernel32base(), 0x24e2968d);
	return pGetComputerNameW(lpBuffer, nSize);


};

BOOL ReleaseMutex(
	HANDLE hMutex
){
#ifdef JUNKASM
#include "JunkASM.h"
#endif
	BOOL(WINAPI* pReleaseMutex)(
		HANDLE hMutex
		);
	*(DWORD_PTR*)&pReleaseMutex = get_proc_address(get_kernel32base(), 0xb31f4dac);
	return pReleaseMutex(hMutex);
};

HANDLE OpenMutexW(
	DWORD   dwDesiredAccess,
	BOOL    bInheritHandle,
	LPCWSTR lpName
){
#ifdef JUNKASM
#include "JunkASM.h"
#endif
	HANDLE(WINAPI* pOpenMutexW)(
		DWORD   dwDesiredAccess,
		BOOL    bInheritHandle,
		LPCWSTR lpName
		);
	*(DWORD_PTR*)&pOpenMutexW = get_proc_address(get_kernel32base(), 0x7bffe25e);
	return pOpenMutexW(dwDesiredAccess, bInheritHandle, lpName);


};

int  MultiByteToWideChar(
	UINT                              CodePage,
	DWORD                             dwFlags,
	_In_NLS_string_(cbMultiByte)LPCCH lpMultiByteStr,
	int                               cbMultiByte,
	LPWSTR                            lpWideCharStr,
	int                               cchWideChar
){
#ifdef JUNKASM
#include "JunkASM.h"
#endif
	int (WINAPI* pMultiByteToWideChar)(
		UINT                              CodePage,
		DWORD                             dwFlags,
		_In_NLS_string_(cbMultiByte)LPCCH lpMultiByteStr,
		int                               cbMultiByte,
		LPWSTR                            lpWideCharStr,
		int                               cchWideChar
		);
	*(DWORD_PTR*)&pMultiByteToWideChar = get_proc_address(get_kernel32base(), 0xcd6839a8);
	return pMultiByteToWideChar(CodePage, dwFlags, lpMultiByteStr, cbMultiByte, lpWideCharStr, cchWideChar);


};

BOOL SystemTimeToFileTime(
	const SYSTEMTIME *lpSystemTime,
	LPFILETIME       lpFileTime
){
#ifdef JUNKASM
#include "JunkASM.h"
#endif
	BOOL(WINAPI* pSystemTimeToFileTime)(
		const SYSTEMTIME *lpSystemTime,
		LPFILETIME       lpFileTime
		);
	*(DWORD_PTR*)&pSystemTimeToFileTime = get_proc_address(get_kernel32base(), 0x1bc2ecae);
	return pSystemTimeToFileTime(lpSystemTime, lpFileTime);

};


int  WideCharToMultiByte(
	UINT                               CodePage,
	DWORD                              dwFlags,
	_In_NLS_string_(cchWideChar)LPCWCH lpWideCharStr,
	int                                cchWideChar,
	LPSTR                              lpMultiByteStr,
	int                                cbMultiByte,
	LPCCH                              lpDefaultChar,
	LPBOOL                             lpUsedDefaultChar
){
#ifdef JUNKASM
#include "JunkASM.h"
#endif
	int (WINAPI* pWideCharToMultiByte)(
		UINT                               CodePage,
		DWORD                              dwFlags,
		_In_NLS_string_(cchWideChar)LPCWCH lpWideCharStr,
		int                                cchWideChar,
		LPSTR                              lpMultiByteStr,
		int                                cbMultiByte,
		LPCCH                              lpDefaultChar,
		LPBOOL                             lpUsedDefaultChar
		);
	*(DWORD_PTR*)&pWideCharToMultiByte = get_proc_address(get_kernel32base(), 0xaf803bc5);
	return pWideCharToMultiByte(CodePage, dwFlags, lpWideCharStr, cchWideChar, lpMultiByteStr, cbMultiByte, lpDefaultChar, lpUsedDefaultChar);


};


void  GetSystemTime(
	LPSYSTEMTIME lpSystemTime
){
#ifdef JUNKASM
#include "JunkASM.h"
#endif
	void (WINAPI* pGetSystemTime)(
		LPSYSTEMTIME lpSystemTime
		);
	*(DWORD_PTR*)&pGetSystemTime = get_proc_address(get_kernel32base(), 0x8549898d);
	return pGetSystemTime(lpSystemTime);


};

BOOL IsWow64Process(
	HANDLE hProcess,
	PBOOL  Wow64Process
){
#ifdef JUNKASM
#include "JunkASM.h"
#endif
	BOOL(WINAPI* pIsWow64Process)(
		HANDLE hProcess,
		PBOOL  Wow64Process
		);
	*(DWORD_PTR*)&pIsWow64Process = get_proc_address(get_kernel32base(), 0xa50dc580);
	return IsWow64Process(hProcess, Wow64Process);

};

HMODULE LoadLibraryA(
	LPCSTR lpLibFileName
){
#ifdef JUNKASM
#include "JunkASM.h"
#endif
	HMODULE(WINAPI* pLoadLibraryA)(
		LPCSTR lpLibFileName
		);
	*(DWORD_PTR*)&pLoadLibraryA = get_proc_address(get_kernel32base(), 0x8a8b4676);
	return pLoadLibraryA(lpLibFileName);

};

BOOL FreeLibrary(
	HMODULE hLibModule
) {
#ifdef JUNKASM
#include "JunkASM.h"
#endif
	BOOL(WINAPI* pFreeLibrary)(HMODULE hLibModule);
	*(DWORD_PTR*)&pFreeLibrary = get_proc_address(get_kernel32base(), 0xecc6c96f);
	return pFreeLibrary(hLibModule);

};

UINT GetWindowsDirectoryA(
	LPSTR lpBuffer,
	UINT  uSize
) {

#ifdef JUNKASM
#include "JunkASM.h"
#endif

	UINT (WINAPI* pGetWindowsDirectoryA)(
		LPSTR lpBuffer,
		UINT  uSize);
	*(DWORD_PTR*)&pGetWindowsDirectoryA = get_proc_address(get_kernel32base(), 0x7f2a4cd1);
	return pGetWindowsDirectoryA(lpBuffer, uSize);

}

UINT GetPrivateProfileIntA(
	LPCSTR lpAppName,
	LPCSTR lpKeyName,
	INT    nDefault,
	LPCSTR lpFileName
) {
#ifdef JUNKASM
#include "JunkASM.h"
#endif


	UINT (WINAPI* pGetPrivateProfileIntA)(
		LPCSTR lpAppName,
		LPCSTR lpKeyName,
		INT    nDefault,
		LPCSTR lpFileName);
	*(DWORD_PTR*)&pGetPrivateProfileIntA = get_proc_address(get_kernel32base(), 0xab28e689);
	return pGetPrivateProfileIntA(lpAppName, lpKeyName, nDefault, lpFileName);

}

DWORD GetPrivateProfileStringA(
	LPCSTR lpAppName,
	LPCSTR lpKeyName,
	LPCSTR lpDefault,
	LPSTR  lpReturnedString,
	DWORD  nSize,
	LPCSTR lpFileName
) {

#ifdef JUNKASM
#include "JunkASM.h"
#endif

	DWORD (WINAPI* pGetPrivateProfileStringA)(
		LPCSTR lpAppName,
		LPCSTR lpKeyName,
		LPCSTR lpDefault,
		LPSTR  lpReturnedString,
		DWORD  nSize,
		LPCSTR lpFileName
	);
	*(DWORD_PTR*)&pGetPrivateProfileStringA = get_proc_address(get_kernel32base(), 0x25b64591);
	return pGetPrivateProfileStringA(lpAppName, lpKeyName, lpDefault, lpReturnedString, nSize, lpFileName);

}


HANDLE GetProcessHeap() {


#ifdef JUNKASM
#include "JunkASM.h"
#endif
	HANDLE (WINAPI* pGetProcessHeap)(void);
	*(DWORD_PTR*)&pGetProcessHeap = get_proc_address(get_kernel32base(), 0x864bde7e);
	return pGetProcessHeap();





}


DWORD GetPrivateProfileSectionNamesA(
	LPSTR  lpszReturnBuffer,
	DWORD   nSize,
	LPCSTR lpFileName
) {
#ifdef JUNKASM
#include "JunkASM.h"
#endif


	DWORD (WINAPI* pGetPrivateProfileSectionNamesA)(
		LPSTR  lpszReturnBuffer,
		DWORD   nSize,
		LPCSTR lpFileName);
	*(DWORD_PTR*)&pGetPrivateProfileSectionNamesA = get_proc_address(get_kernel32base(), 0xedf7117d);
	DWORD ret = pGetPrivateProfileSectionNamesA(lpszReturnBuffer, nSize, lpFileName);
	return pGetPrivateProfileSectionNamesA(lpszReturnBuffer, nSize, lpFileName);
}