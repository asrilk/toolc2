#pragma once
#include "HPSocket.h"
#include "SocketInterface.h"
#include "macros.h"
#include "Buffer.h"



typedef void (CALLBACK* NOTIFYPROC)( ClientContext*, UINT nCode);
typedef CList<ClientContext*, ClientContext* > ContextList;

class CHpTcpServer :public CTcpPullServerListener
{
public:
	CHpTcpServer(void);
	~CHpTcpServer(void);
	CTcpPullServerPtr m_TcpServer;
	NOTIFYPROC		m_pNotifyProc;
	ContextList				m_listFreePool;
	// CRITICAL_SECTION	m_cs;
	CLCS m_clcs;
	BOOL Initialize(NOTIFYPROC pNotifyProc, int nMaxConnections, TCHAR* ip, int nPort);
	void Send(ClientContext* pContext, LPBYTE lpData, UINT nSize);
	BOOL SendWithSplit(CONNID dwConnID, LPBYTE lpData, UINT nSize, UINT nSplitSize);
	void Shutdown();
	BOOL Disconnect(CONNID dwConnID);
	BOOL IsConnected(CONNID dwConnID);
	int IsOverMaxConnectionCount();
	void MovetoFreePool(ClientContext* pContext);
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
	int m_headerlength;		//ͷ�������ܳ���֮��
	int m_maxConnection;	//���������
	BOOL B_run;
};



