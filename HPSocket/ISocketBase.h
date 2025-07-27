#pragma once
#include "Manager.h"
#include "Buffer.h"




#define MAX_SEND_BUFFER		262144	// 最大发送数据长度 1024*256
#define	MAX_RECV_BUFFER		262144 // 最大接收数据长度

typedef struct _cl_cs {
	LONG bLock;
	DWORD ownerThreadId;
	LONG lockCounts;
	_cl_cs::_cl_cs()
	{
		bLock = FALSE;
		ownerThreadId = 0;
		lockCounts = 0;
	}
	void enter() {
		auto cid = GetCurrentThreadId();
		if (ownerThreadId != cid) {
			while (InterlockedExchange(&bLock, TRUE) == TRUE);
			//Sleep(0);
			ownerThreadId = cid;
		}
		++lockCounts;
	}
	void leave() {
		auto cid = GetCurrentThreadId();
		if (cid != ownerThreadId)
			return;
		--lockCounts;
		if (lockCounts == 0) {
			ownerThreadId = 0;
			bLock = FALSE;
		}
	}
	inline void lock() { enter(); }
	inline void unlock() { leave(); }
}CLCS, * PCLCS;


class ISocketBase
{
	friend class CManager;
public:
	virtual  void Disconnect()=0 ;
	virtual  BOOL IsRunning()=0 ;
	virtual int  Send(LPBYTE lpData, UINT nSize)=0 ;
	virtual  void setManagerCallBack(CManager* pManager)=0 ;
	virtual  bool Connect(LPCTSTR lpszHost, UINT nPort)=0;
	virtual void run_event_loop()=0;

	HANDLE m_hEvent;
	CLCS m_clcs;

	DWORD activetime;
	BOOL m_bIsRunning;
	CManager* m_pManager;
	byte m_password[10]; // 通信密码
};

