#include "stdafx.h"
#include "ProxyConnectServer.h"


CProxyConnectServer::CProxyConnectServer(void) :m_TcpServer(this)
{
	TRACE("CProxyConnectServer\r\n");
	B_run = TRUE;
	m_dwIndex = 0;
	//InitializeCriticalSection(&m_cs);
}


CProxyConnectServer::~CProxyConnectServer(void)
{
	if (m_TcpServer->GetState() != SS_STOPPED)
		m_TcpServer->Stop();
	while (m_TcpServer->GetState() != SS_STOPPED)
	{
		Sleep(300);
	}
	//DeleteCriticalSection(&m_cs);
}

BOOL CProxyConnectServer::Initialize(NOTIFYPROC pNotifyProc,  int nMaxConnections, int nPort)
{
	m_maxConnection = nMaxConnections;
	m_TcpServer->SetMaxConnectionCount(nMaxConnections);
	m_TcpServer->SetSendPolicy(SP_DIRECT);
	m_TcpServer->SetNoDelay(TRUE);
	m_pNotifyProc = pNotifyProc;
	m_port = nPort;
	m_stop = FALSE;
	return m_TcpServer->Start(_T("0.0.0.0"), nPort);

}

EnHandleResult CProxyConnectServer::OnPrepareListen(ITcpServer* pSender, SOCKET soListen)
{
	TRACE("%s  OnPrepareListenr\n", __FUNCTION__);
	SYS_SSO_SendBuffSize(soListen, MAX_SEND_BUFFER);
	SYS_SSO_RecvBuffSize(soListen, MAX_RECV_BUFFER);
	return HR_OK;
}

EnHandleResult CProxyConnectServer::OnAccept(ITcpServer* pSender, CONNID dwConnID, UINT_PTR soClient)
{
	
	if (!B_run)return HR_ERROR;

	ClientContext* pContext = NULL;
	{
	m_clcs.lock();
	if (!m_listFreePool.IsEmpty())
	{
		pContext = m_listFreePool.RemoveHead();
	}
	else
	{
		pContext = new(std::nothrow) ClientContext;
	}

	}
	m_clcs.unlock();
	if (pContext == NULL) 	return HR_ERROR;

	ZeroMemory(pContext, sizeof(ClientContext));
	pContext->m_bIsMainSocket = FALSE;
	memset(pContext->m_Dialog, 0, sizeof(pContext->m_Dialog));

	pContext->m_Socket = dwConnID;
	pContext->switchsocket = tcp;
	pContext->m_server = this;
	pContext->LoginInfo = NULL;
	int iAddressLen = sizeof(pContext->szAddress) / sizeof(TCHAR);
	pSender->GetRemoteAddress(dwConnID, pContext->szAddress, iAddressLen, pContext->usPort);
	pContext->m_port = m_port;
	pContext->dwID = dwConnID;
	
	TRACE("%s   OnAccept--%d---pContext->dwID %d    \r\n", __FUNCTION__, dwConnID, pContext->dwID);
	pContext->m_bProxyConnected = 0;
	m_TcpServer->SetConnectionExtra(dwConnID, pContext);
	m_pNotifyProc( pContext, NC_CLIENT_CONNECT);
	return HR_OK;
}

EnHandleResult CProxyConnectServer::OnSend(ITcpServer* pSender, CONNID dwConnID, const BYTE* pData, int iLength)
{
	TRACE("%s OnSend--%d\r\n", __FUNCTION__, dwConnID);

	return HR_OK;
}

EnHandleResult CProxyConnectServer::OnReceive(ITcpServer* pSender, CONNID dwConnID, int iLength)
{
	TRACE("%s OnReceive--%d\r\n", __FUNCTION__, dwConnID);

	ClientContext* pContext = NULL;
	if ((!m_TcpServer->GetConnectionExtra(dwConnID, (PVOID*)&pContext)) && (pContext != nullptr) && (iLength <= 0))
		return HR_ERROR;
	PBYTE pData = new BYTE[iLength];
	m_TcpServer->Fetch(dwConnID, pData, iLength);
	pContext->m_CompressionBuffer.ClearBuffer();
	BYTE bToken = COMMAND_PROXY_DATA;
	pContext->m_CompressionBuffer.Write(&bToken, sizeof(bToken));
	pContext->m_CompressionBuffer.Write((LPBYTE)&pContext->dwID, sizeof(DWORD));
	pContext->m_CompressionBuffer.Write((PBYTE)pData, iLength);
	SAFE_DELETE_AR(pData);
	m_pNotifyProc( pContext, NC_RECEIVE);
	return HR_OK;

}
EnHandleResult CProxyConnectServer::OnClose(ITcpServer* pSender, CONNID dwConnID, EnSocketOperation enOperation, int iErrorCode)
{
	TRACE("%s  %d---%d\r\n", __FUNCTION__, dwConnID, iErrorCode);
	ClientContext* pContext = NULL;
	if (m_TcpServer->GetConnectionExtra(dwConnID, (PVOID*)&pContext) && pContext != nullptr)
		m_TcpServer->SetConnectionExtra(dwConnID, NULL);
	if (!pContext)  return HR_OK;
	TRACE("%s                                 OnClose---%d\r\n", __FUNCTION__, pContext->dwID);
	m_pNotifyProc( pContext, NC_CLIENT_DISCONNECT);
	pContext->m_CompressionBuffer.ClearBuffer();
	pContext->m_WriteBuffer.ClearBuffer();
	pContext->m_DeCompressionBuffer.ClearBuffer();
	m_clcs.lock();
	m_listFreePool.AddTail(pContext);
	m_clcs.unlock();
	return HR_OK;
}

EnHandleResult CProxyConnectServer::OnShutdown(ITcpServer* pSender)
{
	TRACE("%s OnShutdown\r\n", __FUNCTION__);
	return HR_OK;
}




BOOL CProxyConnectServer::Send(ClientContext* pContext, LPBYTE lpData, UINT nSize)
{
	TRACE("%s Send  dwID  %d \r\n", __FUNCTION__, pContext->dwID);
	if (pContext == NULL) 	return FALSE;

	BOOL rt = FALSE;;
	if (nSize > 0 && B_run)
	{
		pContext->m_WriteBuffer.Write(lpData, nSize);
		 rt = SendWithSplit(pContext->m_Socket, pContext->m_WriteBuffer.GetBuffer(), pContext->m_WriteBuffer.GetBufferLen(), MAX_SEND_BUFFER);
		pContext->m_WriteBuffer.ClearBuffer();
	}
	return rt;
}


BOOL CProxyConnectServer::SendWithSplit(CONNID dwConnID, LPBYTE lpData, UINT nSize, UINT nSplitSize)
{
	int nSend = 0;
	UINT nSendRetry = 0;
	BOOL rt = TRUE;
	if (nSize >= nSplitSize)
	{
		UINT i = 0;
		nSendRetry = nSize / nSplitSize;
		for (i = 0; i < nSendRetry; i++)
		{
			rt = m_TcpServer->Send(dwConnID, lpData, nSplitSize);
			if (!rt)
				return rt;
			lpData += nSplitSize;
			nSend += nSplitSize;
		}
		if (nSize - nSend < nSplitSize)
		{
			if (nSize - nSend > 0)
			{
				 rt = m_TcpServer->Send(dwConnID, lpData, nSize - nSend);
				if (!rt)
					return rt;
			}
		}
	}
	else
	{
		 rt = m_TcpServer->Send(dwConnID, lpData, nSize);
		 if (!rt)
			 return rt;
	}
	return  TRUE;


}


void CProxyConnectServer::Shutdown()
{
	CONNID pIDs[65535] = { 0 };
	DWORD dwCount = 65535;
	BOOL status = m_TcpServer->GetAllConnectionIDs(pIDs, dwCount);
	if (status && (dwCount > 0))
	{
		for (DWORD i = 0; i < dwCount; i++)
		{
			Disconnect(pIDs[i]);
		}
	}
	m_TcpServer->Stop();
	B_run = FALSE;
	while (m_TcpServer->GetState() != SS_STOPPED)
		Sleep(10);
	m_clcs.lock();
	while (!m_listFreePool.IsEmpty())
		delete m_listFreePool.RemoveTail();
	m_clcs.unlock();
}

void CProxyConnectServer::clearClient()
{
	CONNID pIDs[65535] = { 0 };
	DWORD dwCount = 65535;

	BOOL status = m_TcpServer->GetAllConnectionIDs(pIDs, dwCount);
	if (status && (dwCount > 0))
	{
		for (DWORD i = 0; i < dwCount; i++)
		{
			m_TcpServer->Disconnect(pIDs[i]);
		}
	}
}

BOOL CProxyConnectServer::Disconnect(CONNID dwConnID)
{
	m_TcpServer->Disconnect(dwConnID);
	return 0;
}

BOOL CProxyConnectServer::IsConnected(CONNID dwConnID)
{
	return	m_TcpServer->IsConnected(dwConnID);
}

BOOL CProxyConnectServer::IsOverMaxConnectionCount()
{
	return (m_TcpServer->GetConnectionCount() > (DWORD)m_maxConnection) ? TRUE : FALSE;
}


