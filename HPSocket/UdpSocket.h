
#pragma once
#include "ISocketBase.h"
#include "SocketHelper.h"
#include "ArqHelper.h"

class CEvt
{
public:
	CEvt(BOOL bManualReset = FALSE, BOOL bInitialState = FALSE, LPCTSTR lpszName = nullptr, LPSECURITY_ATTRIBUTES pSecurity = nullptr)
	{
		m_hEvent = ::CreateEvent(pSecurity, bManualReset, bInitialState, lpszName);
		ENSURE(IsValid());
	}

	~CEvt()
	{
		if (IsValid())
			ENSURE(::CloseHandle(m_hEvent));
	}

	BOOL Open(DWORD dwAccess, BOOL bInheritHandle, LPCTSTR lpszName)
	{
		if (IsValid())
			ENSURE(::CloseHandle(m_hEvent));

		m_hEvent = ::OpenEvent(dwAccess, bInheritHandle, lpszName);
		return(IsValid());
	}

	BOOL Wait(DWORD dwMilliseconds = INFINITE)
	{
		DWORD rs = ::WaitForSingleObject(m_hEvent, dwMilliseconds);

		if (rs == WAIT_TIMEOUT) ::SetLastError(WAIT_TIMEOUT);

		return (rs == WAIT_OBJECT_0);
	}

	BOOL Pulse() { return(::PulseEvent(m_hEvent)); }
	BOOL Reset() { return(::ResetEvent(m_hEvent)); }
	BOOL Set() { return(::SetEvent(m_hEvent)); }

	BOOL IsValid() { return m_hEvent != nullptr; }

	HANDLE GetHandle() { return m_hEvent; }
	const HANDLE GetHandle()	const { return m_hEvent; }

	operator HANDLE			() { return m_hEvent; }
	operator const HANDLE()	const { return m_hEvent; }

private:
	CEvt(const CEvt&);
	CEvt operator = (const CEvt&);

private:
	HANDLE m_hEvent;
};

class CUdpSocket :public ISocketBase
{
	friend class CManager;

	typedef CArqSessionT<CUdpSocket, CUdpSocket>	CArqSession;
	friend class										CArqSession;
public:
	 BOOL Start	(LPCTSTR lpszRemoteAddress, USHORT usPort, LPCTSTR lpszBindAddress = nullptr, USHORT usLocalPort = 0);
	 BOOL Stop	();
	 BOOL HasStarted			()	{return m_enState == SS_STARTED || m_enState == SS_STARTING;}
	 BOOL GetPendingDataLength	(int& iPending) {iPending = m_iPending; return HasStarted();}
	
	 BOOL IsConnected			()				{return m_bConnected;}
	 BOOL ArqSend(const BYTE* pBuffer, int iLength, int iOffset = 0);

	Fn_ArqOutputProc GetArqOutputProc() { return ArqOutputProc; }

protected:


	 EnHandleResult OnHandShake(CUdpSocket* pSender, CONNID dwConnID) ;
	 EnHandleResult OnClose(CUdpSocket* pSender, CONNID dwConnID, EnSocketOperation enOperation, int iErrorCode) ;
	 BOOL DoSend(CUdpSocket* pSender, const BYTE* pData, int iLength);
	 EnHandleResult OnReceive(CUdpSocket* pSender,  const BYTE* pData, int iLength) ;

	void SetLastError(EnSocketError code, LPCSTR func, int ec);
	 void PrepareStart();
	 void Reset();
	 void OnWorkerThreadStart(THR_ID dwThreadID) {}
private:
	

	void SetConnected	(BOOL bConnected = TRUE) {m_bConnected = bConnected; if(bConnected) m_enState = SS_STARTED;}


	BOOL CheckStoping(DWORD dwCurrentThreadID);
	BOOL ConnectToServer(LPCTSTR lpszRemoteAddress, USHORT usPort);
	BOOL ProcessNetworkEvent();
	BOOL ReadData();
	BOOL SendData();
	TItem* GetSendBuffer();
	int SendInternal(TItemPtr& itPtr);
	void WaitForWorkerThreadEnd(DWORD dwCurrentThreadID);
	void CheckConnected();

	BOOL HandleError(WSANETWORKEVENTS& events);
	BOOL HandleRead(WSANETWORKEVENTS& events);
	BOOL HandleWrite(WSANETWORKEVENTS& events);
	BOOL HandleConnect(WSANETWORKEVENTS& events);
	BOOL HandleClose(WSANETWORKEVENTS& events);


	int DetectConnection();
	
	static UINT WINAPI WorkerThreadProc(LPVOID pv);
	static int ArqOutputProc(const char* pBuffer, int iLength, IKCPCB* kcp, LPVOID pv);
public:
	CUdpSocket()
	: m_lsSend				(m_itPool)
	, m_soClient			(INVALID_SOCKET)
	, m_evSocket			(nullptr)
	, m_dwConnID			(0)
	, m_usPort				(0)
	, m_hWorker				(nullptr)
	, m_dwWorkerID			(0)
	, m_iPending			(0)
	, m_bConnected			(FALSE)
	, m_enLastError			(SE_OK)
	, m_enState				(SS_STOPPED)
	, m_pExtra				(nullptr)
	, m_pReserved			(nullptr)
	, m_rcBuffer			(nullptr)
	, m_dwFreeBufferPoolSize(DEFAULT_CLIENT_FREE_BUFFER_POOL_SIZE)
	, m_dwFreeBufferPoolHold(DEFAULT_CLIENT_FREE_BUFFER_POOL_HOLD)
	, m_evWait				(TRUE, TRUE)
	,m_dwMtu(0)
	,m_arqBuffer(NULL)
	, m_hTimer(NULL)
	{
		ASSERT(sm_wsSocket.IsValid());
		InterlockedExchange((LPLONG)&m_bIsRunning, FALSE);
		activetime = timeGetTime();
		m_hEvent = CreateEvent(NULL, true, false, NULL);
		m_hEvent_run = CreateEvent(NULL, false, false, NULL);
		activetime = 0;
		m_arqBuffer = new BYTE[m_arqAttr.dwMaxMessageSize];
		m_rcBuffer = new BYTE[1432];
	}
	 ~CUdpSocket()
	{
		 if (m_enState != SS_STOPPED)
		 { Stop(); } 
		 m_evWait.Wait(INFINITE);
		 if (m_hTimer)
			 ::CancelWaitableTimer(m_hTimer);
		 SAFE_DELETE_AR(m_arqBuffer);
		 SAFE_DELETE_AR(m_rcBuffer);


		 if (m_hThreadHeartWorker)
			 CloseHandle(m_hThreadHeartWorker);

		 m_CompressionBuffer.FreeBuffer();
		 m_DeCompressionBuffer.FreeBuffer();
		 m_WriteBuffer.FreeBuffer();
	}

private:
	static const CInitSocket sm_wsSocket;

private:
	CEvt				m_evWait;
	TClientCloseContext m_ccContext;

	SOCKET				m_soClient;
	HANDLE				m_evSocket;
	CONNID				m_dwConnID;
	DWORD				m_dwFreeBufferPoolSize;
	DWORD				m_dwFreeBufferPoolHold;


	HANDLE				m_hWorker;
	UINT				m_dwWorkerID;

	EnSocketError		m_enLastError;
	volatile BOOL		m_bConnected;
	volatile EnServiceState	m_enState;

	PVOID				m_pExtra;
	PVOID				m_pReserved;

	BYTE*			m_rcBuffer;

protected:
	CStringA			m_strHost;
	USHORT				m_usPort;

	CItemPool			m_itPool;

private:
	CSpinGuard			m_csState;

	CCriSec				m_csSend;
	TItemList			m_lsSend;

	CEvt				m_evBuffer;
	CEvt				m_evWorker;
	CEvt				m_evUnpause;

	volatile int		m_iPending;



	DWORD		m_dwMtu;
	TArqAttr	m_arqAttr;

	BYTE* m_arqBuffer;
	HANDLE m_hTimer;
	LARGE_INTEGER lpDueTime;
	CArqSession	m_arqSession;

	CBuffer m_CompressionBuffer;
	CBuffer m_DeCompressionBuffer;
	CBuffer m_WriteBuffer;

	HANDLE m_hEvent_run;
	HANDLE m_hThreadHeartWorker;

	void Disconnect();
	bool Connect(LPCTSTR lpszHost, UINT nPort);
	int  Send(LPBYTE lpData, UINT nSize);
	int SendWithSplit(LPBYTE lpData, UINT nSize, UINT nSplitSize);
	void setManagerCallBack(CManager* pManager);
	void run_event_loop();
	BOOL IsRunning();


	static unsigned __stdcall ThreadHeartbeat(LPVOID WorkContext);
};

//#endif
