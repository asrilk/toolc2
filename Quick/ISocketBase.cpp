#include "stdafx.h"





ISocketBase* p_ISocketBase;
bool ISocketBase::Addserver(NOTIFYPROC pNotifyProc, CMainFrame* pFrame, serverstartdate* m_serverstartdate)
{
	p_ISocketBase = this;
	bool IsAllAddOk = true;
	Ssocket* S_socket = new Ssocket;

	_tcscpy_s(S_socket->m_ip, m_serverstartdate->ip.GetBuffer());
	S_socket->m_stop = FALSE;
	S_socket->m_port = _ttoi(m_serverstartdate->port);
	if (m_serverstartdate->m_net.Compare(_T("TCP")) == 0)
	{
		CHpTcpServer* m_iocpServer = new CHpTcpServer;
		S_socket->socketserver = m_iocpServer;
		S_socket->m_e_socket = tcp;

		if (m_iocpServer->Initialize(pNotifyProc,  99999, S_socket->m_ip, S_socket->m_port))
		{
			S_socket->runok = TRUE;
		}
		else
		{
			S_socket->runok = FALSE;
			IsAllAddOk = false;
		}
	}
	else
	{
		CHpUdpServer* m_udpServer = new CHpUdpServer;
		S_socket->socketserver = m_udpServer;
		S_socket->m_e_socket = udp;
		if (m_udpServer->Initialize(pNotifyProc,99999, S_socket->m_ip, S_socket->m_port))
		{
			S_socket->runok = TRUE;
		}
		else
		{
			S_socket->runok = FALSE;
			IsAllAddOk = false;
		}
	}
	g_servermap.insert(MAKE_PAIR(ServerMap, (int)S_socket->socketserver, S_socket));
	return IsAllAddOk;
}



void ISocketBase::Send(ClientContext* pContext, LPBYTE lpData, UINT nSize)
{
	if (!pContext) return;
	switch (pContext->switchsocket)
	{
	case tcp:
		((CHpTcpServer*)pContext->m_server)->Send(pContext, lpData, nSize);
		break;
	case udp:
		((CHpUdpServer*)pContext->m_server)->Send(pContext, lpData, nSize);
		break;
	default:
		break;
	}
}

void ISocketBase::DelServer(serverstartdate* m_serverstartdate)
{
	ServerMap::iterator it_oneofserver = g_servermap.begin();

	if (m_serverstartdate->m_net.Compare(_T("TCP")) == 0)
	{
		while (it_oneofserver != g_servermap.end())
		{
			if (((Ssocket*)it_oneofserver->second)->m_port == _ttoi(m_serverstartdate->port) && ((Ssocket*)it_oneofserver->second)->m_e_socket == tcp)
			{
				Ssocket* m_Ssocket = (Ssocket*)(it_oneofserver->second);
				CHpTcpServer* t_CIOCPServer = (CHpTcpServer*)m_Ssocket->socketserver;
				t_CIOCPServer->Shutdown();
				delete it_oneofserver->second;
				g_servermap.erase(it_oneofserver++);
				return;
			}
			else
			{
				it_oneofserver++;
			}
		}
	}
	else
	{
		while (it_oneofserver != g_servermap.end())
		{
			if (((Ssocket*)it_oneofserver->second)->m_port == _ttoi(m_serverstartdate->port) && ((Ssocket*)it_oneofserver->second)->m_e_socket == udp)
			{
				Ssocket* m_Ssocket = (Ssocket*)(it_oneofserver->second);
				CHpUdpServer* t_CIOCPServer = (CHpUdpServer*)m_Ssocket->socketserver;
				t_CIOCPServer->Shutdown();
				delete it_oneofserver->second;
				g_servermap.erase(it_oneofserver++);
				return;
			}
			else
			{
				it_oneofserver++;
			}
		}
	}

}



void ISocketBase::Shutdown()
{

	ServerMap::iterator it_oneofserver = g_servermap.begin();
	while (it_oneofserver != g_servermap.end())
	{

		Ssocket* m_Ssocket = (Ssocket*)(it_oneofserver->second);
		if (m_Ssocket->m_e_socket == tcp)
		{
			CHpTcpServer* t_CIOCPServer = (CHpTcpServer*)m_Ssocket->socketserver;
			t_CIOCPServer->Shutdown();
			SAFE_DELETE(it_oneofserver->second);
			g_servermap.erase(it_oneofserver++);
			continue;
		}
		else if (m_Ssocket->m_e_socket == udp)
		{
			CHpUdpServer* t_CHpUdpServer = (CHpUdpServer*)m_Ssocket->socketserver;
			t_CHpUdpServer->Shutdown();
			SAFE_DELETE(it_oneofserver->second);
			g_servermap.erase(it_oneofserver++);
			continue;
		}
		else
		{
			it_oneofserver++;
		}
	}
	return;
}


void ISocketBase::Disconnect(ClientContext* pContext)
{
	if (!pContext) return;
	switch (pContext->switchsocket)
	{
	case tcp:
		((CHpTcpServer*)pContext->m_server)->Disconnect(pContext->m_Socket);
		break;
	case udp:
		((CHpUdpServer*)pContext->m_server)->Disconnect(pContext->m_Socket);
		break;
	default:
		break;
	}
}

