#include "StdAfx.h"
#include "ThreadManage.h"
#include "Ntstatus.h "


extern "C" LONG (__stdcall *ZwQueryInformationThread)(
	IN  HANDLE  ThreadHandle,
	IN  THREADINFOCLASS   ThreadInformationClass,
	OUT PVOID   ThreadInformation,
	IN  ULONG   ThreadInformationLength,
	OUT PULONG  ReturnLength OPTIONAL
) = NULL;


tagTHREADINFO::tagTHREADINFO()
{
	dwThreadId = 0;
	dwProcessId = 0;
	lpStartAddr = NULL;
	memset(lpStartCode, 0, OPCODE_LENGTH);
	memset(wsModName, 0, MAX_NAME_PATH * sizeof(WCHAR));
	memset(wsProcName, 0, MAX_NAME_PATH * sizeof(WCHAR));
}

tagPROCESSINFO::tagPROCESSINFO()
{
	dwProcessId = 0;
	lpStartAddr = NULL;
	memset(lpStartCode, 0, OPCODE_LENGTH);
	memset(wsProcName, 0, MAX_NAME_PATH * sizeof(WCHAR));
}

CThreadManage::CThreadManage(void)
{
}

CThreadManage::~CThreadManage(void)
{
}

BOOL CThreadManage::EnablePrivilege(LPCTSTR lpszPrivilegeName, BOOL bEnable)
{
	HANDLE hToken = NULL;
	TOKEN_PRIVILEGES tp = {0};
	LUID luid = {0};
	BOOL bRet = FALSE;

	if(!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY|TOKEN_READ, &hToken))
	{
		fprintf(stderr, "[CThreadManage::EnablePrivilege] OpenProcessToken failed,%d\r\n", GetLastError());
		goto _exit;
	}

	if(!LookupPrivilegeValue(NULL, lpszPrivilegeName, &luid))
	{
		fprintf(stderr, "[CThreadManage::EnablePrivilege] LookupPrivilegeValue failed,%d\r\n", GetLastError());
		goto _exit;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = (bEnable) ? SE_PRIVILEGE_ENABLED : 0;
	bRet = AdjustTokenPrivileges(hToken, FALSE, &tp, NULL, NULL, NULL);
	

_exit:
	if (hToken != NULL)
	{
		CloseHandle(hToken);
	}
	return bRet;
}


BOOL CThreadManage::UpdateThreadList()
{
	EnablePrivilege(SE_DEBUG_NAME, TRUE);

	HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
	THREADENTRY32 te32;
	te32.dwSize = sizeof(THREADENTRY32);

	HINSTANCE hNTDLL = ::GetModuleHandleA("ntdll.dll");
	(FARPROC&)ZwQueryInformationThread = ::GetProcAddress(hNTDLL, "ZwQueryInformationThread");

	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if(hThreadSnap == INVALID_HANDLE_VALUE) 
	{
		fprintf(stderr, "[CThreadManage::UpdateThreadList] CreateToolhelp32Snapshot failed,%d\r\n", GetLastError());
		return FALSE;
	}

	if(!Thread32First(hThreadSnap, &te32))
	{
		fprintf(stderr, "[CThreadManage::UpdateThreadList] Thread32First failed,%d\r\n", GetLastError());
		CloseHandle(hThreadSnap);
		return FALSE;
	}

	do
	{
		tagTHREADINFO threadinfo;
		memset(&threadinfo, 0, sizeof(tagTHREADINFO));
		threadinfo.dwThreadId = te32.th32ThreadID;
		threadinfo.dwProcessId = te32.th32OwnerProcessID;
		GetThreadInfo(threadinfo);
		m_ThreadList.push_back(threadinfo);
	} while(Thread32Next(hThreadSnap, &te32));

	CloseHandle( hThreadSnap );
	return TRUE;
}


BOOL CThreadManage::GetThreadInfo(tagTHREADINFO &threadinfo)
{
	DWORD tid = threadinfo.dwThreadId;
	DWORD pid = threadinfo.dwProcessId;

	PVOID		lpStartAddr = NULL;
	NTSTATUS	status = 0;
	HANDLE		hThread = NULL;
	HANDLE		hProcess = NULL;
	DWORD		dwRetLenth = 0;
	
	hThread = ::OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid);
	if(hThread == NULL)
	{
		//ERROR_INVALID_PARAMETER (87)
		fprintf(stderr, "[CThreadManage::GetThreadInfo] OpenThread failed, %d, pid = %d, tid = %d\r\n", GetLastError(), pid, tid);
		return FALSE;
	}

	status = ZwQueryInformationThread(hThread, ThreadQuerySetWin32StartAddress, &lpStartAddr, sizeof(lpStartAddr), NULL);
	if(status != STATUS_SUCCESS)
	{
		fprintf(stderr, "[CThreadManage::GetThreadInfo] ZwQueryInformationThread failed, %d, 0x%08X\r\n", GetLastError(), status);
		CloseHandle(hThread);
		return FALSE;
	}

	//VirtualQueryEx
	threadinfo.lpStartAddr = lpStartAddr;

	hProcess = ::OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, FALSE, pid);
	if(hProcess == NULL) 
	{
		fprintf(stderr, "[CThreadManage::GetThreadInfo] OpenProcess failed, %d, pid = %d, tid = %d\r\n", GetLastError(), pid, tid);
		CloseHandle(hThread);
		return FALSE;
	}

	dwRetLenth = GetProcessImageFileNameW(hProcess, threadinfo.wsProcName, MAX_NAME_PATH);
	//dwRetLenth = GetModuleFileNameExW(hProcess, NULL, threadinfo.wsProcName, MAX_NAME_PATH);
	if (dwRetLenth == 0)
	{
		//ERROR_PARTIAL_COPY (299)
		fprintf(stderr, "[CThreadManage::GetThreadInfo] GetProcessImageFileNameW failed, %d, pid = %d, tid = %d\r\n", GetLastError(), pid, tid);
	}
	threadinfo.wsProcName[dwRetLenth] = L'\0';

	dwRetLenth = GetMappedFileNameW(hProcess, lpStartAddr, threadinfo.wsModName, MAX_NAME_PATH);
	if (dwRetLenth == 0)
	{
		//ERROR_UNEXP_NET_ERR (59)
		fprintf(stderr, "[CThreadManage::GetThreadInfo] GetMappedFileNameW failed, %d, pid = %d, tid = %d\r\n", GetLastError(), pid, tid);
	}
	threadinfo.wsModName[dwRetLenth] = L'\0';

	if (!ReadProcessMemory(hProcess, lpStartAddr, threadinfo.lpStartCode, OPCODE_LENGTH, NULL))
	{
		//ERROR_PARTIAL_COPY (299)
		//fprintf(stderr, "[CThreadManage::GetThreadInfo] ReadProcessMemory failed, %d, pid = %d, tid = %d\r\n", GetLastError(), pid, tid);
	}

	CloseHandle(hThread);
	CloseHandle(hProcess);
	return TRUE;
}



CProcessManage::CProcessManage(void)
{
}

CProcessManage::~CProcessManage(void)
{
}


BOOL CProcessManage::EnablePrivilege(LPCTSTR lpszPrivilegeName, BOOL bEnable)
{
	HANDLE hToken = NULL;
	TOKEN_PRIVILEGES tp = {0};
	LUID luid = {0};
	BOOL bRet = FALSE;

	if(!OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY|TOKEN_READ, &hToken))
	{
		fprintf(stderr, "[CProcessManage::EnablePrivilege] OpenProcessToken failed,%d\r\n", GetLastError());
		goto _exit;
	}

	if(!LookupPrivilegeValue(NULL, lpszPrivilegeName, &luid))
	{
		fprintf(stderr, "[CProcessManage::EnablePrivilege] LookupPrivilegeValue failed,%d\r\n", GetLastError());
		goto _exit;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = (bEnable) ? SE_PRIVILEGE_ENABLED : 0;
	bRet = AdjustTokenPrivileges(hToken, FALSE, &tp, NULL, NULL, NULL);

_exit:
	if (hToken != NULL)
	{
		CloseHandle(hToken);
	}
	return bRet;

}


BOOL CProcessManage::UpdateProcessList()
{
	EnablePrivilege(SE_DEBUG_NAME, TRUE);

	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(pe32);
	
	HANDLE hProcessSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if(hProcessSnap == INVALID_HANDLE_VALUE)
	{
		fprintf(stderr, "[CProcessManage::UpdateProcessList] CreateToolhelp32Snapshot failed,%d\r\n", GetLastError());
		return FALSE;
	}

	if(!Process32First(hProcessSnap, &pe32))
	{
		fprintf(stderr, "[CProcessManage::UpdateProcessList] Process32First failed,%d\r\n", GetLastError());
		CloseHandle(hProcessSnap);
		return FALSE;
	}

	do
	{
		tagPROCESSINFO processinfo;
		memset(&processinfo, 0, sizeof(tagPROCESSINFO));
		processinfo.dwProcessId = pe32.th32ProcessID;
		memcpy_s(processinfo.wsProcName, MAX_PATH, pe32.szExeFile, MAX_PATH);
		GetProcessInfo(processinfo);
		m_ProcessList.push_back(processinfo);
	} while(Process32Next(hProcessSnap, &pe32)); 

	CloseHandle(hProcessSnap);
	return TRUE;

}


BOOL CProcessManage::GetProcessInfo(tagPROCESSINFO &processinfo) 
{

	return TRUE;
}


