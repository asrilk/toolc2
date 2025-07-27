#pragma once


#include <winsock2.h>
#include <MSTcpIP.h>
#pragma comment(lib,"ws2_32.lib")
#include <process.h>
#include <afxtempl.h>

enum
{
	TOKEN_PROXY_CONNECT_RESULT,
	TOKEN_PROXY_BIND_RESULT,
	TOKEN_PROXY_CLOSE,
	TOKEN_PROXY_DATA,
	COMMAND_PROXY_CLOSE,
	COMMAND_PROXY_CONNECT,
	COMMAND_PROXY_DATA,

};


////////////////////////////////////////////////////////////////////


typedef void (CALLBACK* NOTIFYPROC)(LPVOID, ClientContext*, UINT nCode);

typedef CList<ClientContext*, ClientContext* > ContextList;



class CMainFrame;
class CIOCPServer
{
public:
	void DisconnectAll();
	CIOCPServer();
	virtual ~CIOCPServer();

	NOTIFYPROC					m_pNotifyProc;
	CMainFrame* m_pFrame;
	bool Initialize(NOTIFYPROC pNotifyProc, CMainFrame* pFrame, int nMaxConnections, int nPort);
	UINT                    m_nHeartBeatTime;


	static unsigned __stdcall ThreadHeartbeat(LPVOID WorkContext);
	static unsigned __stdcall ListenThreadProc(LPVOID lpVoid);
	static unsigned __stdcall ThreadPoolFunc(LPVOID WorkContext);
	CRITICAL_SECTION	m_cs;

	void PostRecv(ClientContext* pContext);
	void Send(ClientContext* pContext, LPBYTE lpData, UINT nSize);
	void PostSend(ClientContext* pContext);

	bool IsRunning();
	void Shutdown();
	void ResetConnection(ClientContext* pContext);


	UINT					m_nSendKbps; // 发送即时速度
	UINT					m_nRecvKbps; // 接受即时速度
	UINT					m_nMaxConnections; // 最大连接数

	SOCKET					m_socListen;
protected:
	BOOL AssociateSocketWithCompletionPort(SOCKET device, HANDLE hCompletionPort, DWORD dwCompletionKey);
	void RemoveStaleClient(ClientContext* pContext, BOOL bGraceful);
	void MoveToFreePool(ClientContext* pContext);
	ClientContext* AllocateContext(SOCKET clientSocket);
	LONG				m_nWorkerCnt;
	bool				m_bInit;
	bool				m_bDisconnectAll;
	void CloseCompletionPort();
	void OnAccept();
	bool InitializeIOCP(void);
	void Stop();
	// 设置保活机制 nKeepTime多长时间没有数据就开始发送心跳包,nKeepInterval每隔多长时间发送一个心跳包 (Vista之前默认5次 之后默认发10次)
	BOOL SetKeepAlive(SOCKET Socket, UINT nKeepTime = 10 * 1000, UINT nKeepInterval = 3000);
	ContextList				m_listContexts;
	ContextList				m_listFreePool;
	WSAEVENT				m_hEvent;
	HANDLE					m_hKillEvent;
	HANDLE					m_hThread;
	HANDLE					m_hCompletionPort;
	bool					m_bTimeToKill;
	LONG					m_nKeepLiveTime;    	// 多长时间没有数据
	UINT                 	m_nIntervalTime;		// 间隔多少时间发送
	DWORD					m_dwIndex;
	CString GetHostName(SOCKET socket);
	BEGIN_IO_MSG_MAP()
		IO_MESSAGE_HANDLER(IORead, OnClientReading)
		IO_MESSAGE_HANDLER(IOWrite, OnClientWriting)
		IO_MESSAGE_HANDLER(IOInitialize, OnClientInitializing)
	END_IO_MSG_MAP()

	bool OnClientInitializing(ClientContext* pContext, DWORD dwSize = 0);
	virtual bool OnClientReading(ClientContext* pContext, DWORD dwSize = 0);
	bool OnClientWriting(ClientContext* pContext, DWORD dwSize = 0);
};

