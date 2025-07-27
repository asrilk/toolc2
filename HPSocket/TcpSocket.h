#pragma once
#include "ISocketBase.h"




class CTcpSocket :public ISocketBase
{
	friend class CManager;
public:
	CTcpSocket(void);
	~CTcpSocket(void);



	CBuffer m_CompressionBuffer;
	CBuffer m_DeCompressionBuffer;
	CBuffer m_WriteBuffer;
	//CBuffer	m_ResendWriteBuffer;
	//double timeOfSecond;
	//LARGE_INTEGER freq;
	//LARGE_INTEGER beginTime;
	//LARGE_INTEGER endTime;



	HANDLE m_hWorkerThread;
	HANDLE m_hThreadHeartWorker;
	SOCKET m_Socket;
	static unsigned __stdcall WorkThread(LPVOID lparam);


	void Disconnect();
	bool Connect(LPCTSTR lpszHost, UINT nPort);
	int  Send(LPBYTE lpData, UINT nSize);
	int SendWithSplit(LPBYTE lpData, UINT nSize, UINT nSplitSize);
	void setManagerCallBack(CManager* pManager);
	void run_event_loop();
	BOOL IsRunning();
	bool OnReceive(const BYTE* pData, int iLength);
	static unsigned __stdcall ThreadHeartbeat(LPVOID WorkContext);
};



