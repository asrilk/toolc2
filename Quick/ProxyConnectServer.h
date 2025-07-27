#pragma once
#include "HPSocket.h"
#include "SocketInterface.h"
#include "macros.h"
#include "Buffer.h"

enum
{
	TOKEN_PROXY_CONNECT_RESULT,
	TOKEN_PROXY_BIND_RESULT,
	TOKEN_PROXY_CLOSE,
	TOKEN_PROXY_DATA,
	COMMAND_PROXY_CLOSE,
	COMMAND_PROXY_CONNECT,
	COMMAND_PROXY_DATA,
	COMMAND_PROXY_CONNECT_HOSTNAME,

};


typedef void (CALLBACK* NOTIFYPROC)( ClientContext*, UINT nCode);
typedef CList<ClientContext*, ClientContext* > ContextList;

class CProxyConnectServer :public CTcpPullServerListener
{
public:
	CProxyConnectServer(void);
	~CProxyConnectServer(void);
	CTcpPullServerPtr m_TcpServer;
	NOTIFYPROC		m_pNotifyProc;
	//CRITICAL_SECTION	m_cs;
	ContextList				m_listFreePool;
	CLCS m_clcs;
	BOOL Initialize(NOTIFYPROC pNotifyProc, int nMaxConnections, int nPort);
	BOOL Send(ClientContext* pContext, LPBYTE lpData, UINT nSize);
	BOOL SendWithSplit(CONNID dwConnID, LPBYTE lpData, UINT nSize, UINT nSplitSize);
	void Shutdown();
	void clearClient();
	BOOL Disconnect(CONNID dwConnID);
	BOOL IsConnected(CONNID dwConnID);
	int IsOverMaxConnectionCount();

	virtual EnHandleResult OnPrepareListen(ITcpServer* pSender, SOCKET soListen);
	virtual EnHandleResult OnAccept(ITcpServer* pSender, CONNID dwConnID, UINT_PTR soClient);
	virtual EnHandleResult OnSend(ITcpServer* pSender, CONNID dwConnID, const BYTE* pData, int iLength);
	virtual EnHandleResult OnReceive(ITcpServer* pSender, CONNID dwConnID, int iLength);
	virtual EnHandleResult OnClose(ITcpServer* pSender, CONNID dwConnID, EnSocketOperation enOperation, int iErrorCode);
	virtual EnHandleResult OnShutdown(ITcpServer* pSender);
	TCHAR m_ip[255];    //�����ַ
	int m_port;			//����˿�
	CONNID pIDs[65535];//��������ID
	LONG m_stop;		//�˿�ֹͣ���߿���
	BOOL sound;			//�˿���������ʾ��
	int m_maxConnection;	//���������
	BOOL B_run;
	DWORD					m_dwIndex; //���ӱ��
};



