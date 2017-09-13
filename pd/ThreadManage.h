#pragma once

#include <list>
#include <windows.h>
#include <tlhelp32.h>
#include <Psapi.h>

using namespace std;

#pragma comment(lib, "psapi.lib")

#define OPCODE_LENGTH 64
#define MAX_NAME_PATH (MAX_PATH+1)*2

typedef enum _THREADINFOCLASS{
	ThreadBasicInformation, 
	ThreadTimes, 
	ThreadPriority, 
	ThreadBasePriority, 
	ThreadAffinityMask, 
	ThreadImpersonationToken, 
	ThreadDescriptorTableEntry, 
	ThreadEnableAlignmentFaultFixup, 
	ThreadEventPair_Reusable, 
	ThreadQuerySetWin32StartAddress, 
	ThreadZeroTlsCell, 
	ThreadPerformanceCount, 
	ThreadAmILastThread, 
	ThreadIdealProcessor, 
	ThreadPriorityBoost, 
	ThreadSetTlsArrayAddress, 
	ThreadIsIoPending, 
	ThreadHideFromDebugger, 
	ThreadBreakOnTermination, 
	MaxThreadInfoClass 
}THREADINFOCLASS;

typedef struct _CLIENT_ID_X
{
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID_X, *PCLIENT_ID_X;


typedef struct _THREAD_BASIC_INFORMATION
{
	LONG			ExitStatus; 
	PVOID			TebBaseAddress; 
	CLIENT_ID_X		ClientId; 
	LONG			AffinityMask; 
	LONG			Priority; 
	LONG			BasePriority; 
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION; 

struct tagTHREADINFO
{
	tagTHREADINFO();
	DWORD	dwThreadId;					// 线程ID
	DWORD	dwProcessId;				// 所属进程ID
	WCHAR	wsModName[MAX_NAME_PATH];	// 所属模块名
	WCHAR	wsProcName[MAX_NAME_PATH];	// 所属进程名
	PVOID	lpStartAddr;				// 入口地址
	BYTE	lpStartCode[OPCODE_LENGTH];	// 入口处代码
};

struct tagPROCESSINFO
{
	tagPROCESSINFO();
	DWORD	dwProcessId;				// 所属进程ID
	WCHAR	wsProcName[MAX_NAME_PATH];	// 所属进程名
	PVOID	lpStartAddr;				// 入口地址
	BYTE	lpStartCode[OPCODE_LENGTH];	// 入口处代码
};

typedef list<tagTHREADINFO> CThreadList;
typedef list<tagPROCESSINFO> CProcessList;



class CThreadManage
{
public:
	CThreadList		m_ThreadList;
public:
	BOOL UpdateThreadList();
	BOOL GetThreadInfo(tagTHREADINFO &);
	BOOL EnablePrivilege(LPCTSTR, BOOL);

public:
	CThreadManage(void);
	~CThreadManage(void);
};

class CProcessManage
{
public:
	CProcessList	m_ProcessList;
public:
	BOOL  UpdateProcessList();
	BOOL GetProcessInfo(tagPROCESSINFO &);
	static BOOL EnablePrivilege(LPCTSTR, BOOL);

public:
	CProcessManage(void);
	~CProcessManage(void);
};




