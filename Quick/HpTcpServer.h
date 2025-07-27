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
	TCHAR m_ip[255];    //插件地址
	int m_port;			//插件端口
	CONNID pIDs[65535];//所有连接ID
	LONG m_stop;		//端口停止上线控制
	BOOL sound;			//端口上下线提示音
	int m_headerlength;		//头部数据总长度之和
	int m_maxConnection;	//最大连接数
	BOOL B_run;
};



