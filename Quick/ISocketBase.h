#pragma once

#include "HpUdpServer.h"
#include "HpTcpServer.h"
#include <map>

#define MAKE_PAIR(_a,b,c) _a::value_type((b),(c))

class CMainFrame;

struct Ssocket
{
	PVOID socketserver;
	TCHAR m_ip[255];
	int m_port;
	e_socket m_e_socket;
	BOOL runok;
	BOOL m_stop;
};
typedef void (CALLBACK* NOTIFYPROC)( ClientContext*, UINT nCode);
typedef std::map<int, Ssocket*> ServerMap;  //��¼�˿� 2��ͨ��


class ISocketBase
{
public:
	ServerMap g_servermap;
public:
	bool Addserver(NOTIFYPROC pNotifyProc, CMainFrame* pFrame, serverstartdate* m_serverstartdate);   //��ʼ��

	virtual  void Send(ClientContext* pContext, LPBYTE lpData, UINT nSize);  //����

	void DelServer(serverstartdate* m_serverstartdate);     //ֹͣ����

	void Shutdown();     //�ر�

	void Disconnect(ClientContext* m_pContext);


};


