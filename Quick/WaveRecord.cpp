// WaveRecord.cpp: implementation of the CWaveRecord class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
//#include "VoIP.h"
#include "WaveRecord.h"
//#include "defines.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#define new DEBUG_NEW
#endif

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

CWaveRecord::CWaveRecord(CAudioCode* pCode)
{
	m_bSend = TRUE;
	m_pACode = pCode;
	m_volmultiple = 1;
}

CWaveRecord::~CWaveRecord()
{

}

//////////////////////////////////////////////////////////////////////////
//
// 数据获取回调
//
void CWaveRecord::GetData(char* pBuffer, int iLen)
{

	int				iEncodeSize;

	m_soLock.Lock();
	if (m_bSend)
	{
		// 检查是否属于静音区间
//		if ( IsHaveWav(pBuffer, iLen) )
		{
			//			ioldSize	= iLen;
			//
			//			memcpy( oldAudio, pBuffer, ioldSize );
			//
			//			iEncodeSize = sizeof(m_AudioBuffer);
			//			memset( m_AudioBuffer, 0, iEncodeSize );
						//m_pACode->EncodeAudioData ( pBuffer, iLen, m_AudioBuffer, &iEncodeSize );

			//			m_pCommClient->SendPacket( pBuffer, iLen, PACKET_AUDIO );



						//LPBYTE	lpPacket = new BYTE[iEncodeSize + 1];
						//lpPacket[0] = COMMAND_SEND_DATE;
						//memcpy(lpPacket + 1, m_AudioBuffer, iEncodeSize);
						//::SendMessage(m_hwnd,WM_REMOVEFROMLIST, 0, (LPARAM)&iEncodeSize);
						//pIOCPServer->Send(m_pContext,lpPacket, iEncodeSize + 1);
						//SAFE_DELETE_AR(lpPacket);

			if (m_volmultiple == 1)
			{
				m_pACode->EncodeAudioData(pBuffer, iLen, m_AudioBuffer, &iEncodeSize);
				LPBYTE	lpPacket = new BYTE[iEncodeSize + 1];
				lpPacket[0] = COMMAND_SEND_DATE;
				memcpy(lpPacket + 1, m_AudioBuffer, iEncodeSize);
				((CDialog*)m_hwnd)->SendMessage(WM_OPENAUDIODIALOG, NULL, (LPARAM)&iEncodeSize);
				pIOCPServer->Send(m_pContext, lpPacket, iEncodeSize + 1);
				SAFE_DELETE_AR(lpPacket);
			}
			else
			{
				char* newdate = new char[iLen];
				memcpy(newdate, pBuffer, iLen);
				for (int i = 0; i < (iLen / 2); i++)
				{
					volume_adjust((short*)newdate, m_volmultiple);
					newdate += 2;
				}
				newdate = newdate - iLen;
				m_pACode->EncodeAudioData(newdate, iLen, m_AudioBuffer, &iEncodeSize);
				SAFE_DELETE_AR(newdate);
				LPBYTE	lpPacket = new BYTE[iEncodeSize + 1];
				lpPacket[0] = COMMAND_SEND_DATE;
				memcpy(lpPacket + 1, m_AudioBuffer, iEncodeSize);
				((CDialog*)m_hwnd)->SendMessage(WM_OPENAUDIODIALOG, NULL, (LPARAM)&iEncodeSize);
				pIOCPServer->Send(m_pContext, lpPacket, iEncodeSize + 1);
				SAFE_DELETE_AR(lpPacket);
			}


			////////fas //////////////m_pCommClient->SendPacket( m_AudioBuffer, iEncodeSize, PACKET_AUDIO );
		}
	}
	m_soLock.Unlock();

	CWaveIn::GetData(pBuffer, iLen);
}

//////////////////////////////////////////////////////////////////////////
//
// 初始化语音获取接口
//
BOOL CWaveRecord::Init()
{
	return TRUE;
}

void CWaveRecord::SetCommClient(ISocketBase* pClient, ClientContext* pContext, CDialog* i_hwnd)
{
	pIOCPServer = pClient;
	m_pContext = pContext;
	m_hwnd = i_hwnd;
}

//////////////////////////////////////////////////////////////////////////
//
// 检查是有语音数据
//
BOOL CWaveRecord::IsHaveWav(char* pBuffer, int iLen)
{
	int		iCount;
	UCHAR	uValue;

	iCount = 0;
	for (int i = 0; i < iLen; i++)
	{
		uValue = (UCHAR)pBuffer[i];
		if (uValue <= 125 || uValue >= 129)
		{
			iCount++;
		}
	}

	return iCount > 500;
}


int CWaveRecord::EnumerateInputLines(TCHAR* szPname, TCHAR* str)
{
	if (str == NULL || szPname == NULL)
		return -1;

	MIXERCAPS mxcaps = { 0 };
	HMIXER hMixer = NULL;
	int nRet = -1;

	for (UINT i = 0; i < mixerGetNumDevs(); i++)
	{
		if (MMSYSERR_NOERROR != mixerGetDevCaps(i, &mxcaps, sizeof(MIXERCAPS)))
			continue;
		if (MMSYSERR_NOERROR != mixerOpen(&hMixer, i, NULL, NULL, 0))
			continue;

		MIXERLINE mxl = { sizeof(MIXERLINE), 0, 0, 0, 0, 0, MIXERLINE_COMPONENTTYPE_DST_WAVEIN, 0 };
		if (MMSYSERR_NOERROR != mixerGetLineInfo((HMIXEROBJ)hMixer, &mxl, MIXER_GETLINEINFOF_COMPONENTTYPE))
		{
			mixerClose(hMixer);
			continue;
		}

		if (_tcscmp(mxcaps.szPname, szPname) != 0)
		{
			mixerClose(hMixer);
			continue;
		}

		MIXERCONTROL mxc = { sizeof(MIXERCONTROL), 0 };
		MIXERLINECONTROLS mxlc = { sizeof(MIXERLINECONTROLS), mxl.dwLineID, MIXERCONTROL_CONTROLTYPE_MIXER, 1, mxc.cbStruct, &mxc };
		if (MMSYSERR_NOERROR != mixerGetLineControls((HMIXEROBJ)hMixer, &mxlc, MIXER_GETLINECONTROLSF_ONEBYTYPE))
		{
			mxlc.dwControlType = MIXERCONTROL_CONTROLTYPE_MUX;
			if (MMSYSERR_NOERROR != mixerGetLineControls((HMIXEROBJ)hMixer, &mxlc, MIXER_GETLINECONTROLSF_ONEBYTYPE))
			{
				mixerClose(hMixer);
				continue;
			}
		}
		if (mxc.cMultipleItems == 0)
		{
			mixerClose(hMixer);
			continue;
		}

		MIXERCONTROLDETAILS mxcd = { sizeof(MIXERCONTROLDETAILS), mxc.dwControlID, 1, 0 };
		PMIXERCONTROLDETAILS_LISTTEXT mxcdlts = (PMIXERCONTROLDETAILS_LISTTEXT)malloc(sizeof(MIXERCONTROLDETAILS_LISTTEXT) * mxc.cMultipleItems);
		mxcd.cbDetails = sizeof(MIXERCONTROLDETAILS_LISTTEXT);
		mxcd.cMultipleItems = mxc.cMultipleItems;
		mxcd.paDetails = mxcdlts;
		if (MMSYSERR_NOERROR != mixerGetControlDetails((HMIXEROBJ)hMixer, &mxcd, MIXER_GETCONTROLDETAILSF_LISTTEXT))
		{
			free(mxcdlts);
			mixerClose(hMixer);
			continue;
		}

		PMIXERCONTROLDETAILS_BOOLEAN mxcdbls = (PMIXERCONTROLDETAILS_BOOLEAN)malloc(sizeof(MIXERCONTROLDETAILS_BOOLEAN) * mxc.cMultipleItems);
		mxcd.cbDetails = sizeof(MIXERCONTROLDETAILS_BOOLEAN);
		mxcd.cMultipleItems = mxc.cMultipleItems;
		mxcd.paDetails = mxcdbls;
		if (MMSYSERR_NOERROR != mixerGetControlDetails((HMIXEROBJ)hMixer, &mxcd, MIXER_GETCONTROLDETAILSF_VALUE))
		{
			free(mxcdbls);
			mixerClose(hMixer);
			continue;
		}

		DWORD dwConnections = mxl.cConnections;
		DWORD dwDestination = mxl.dwDestination;

		for (DWORD j = 0; j < dwConnections; j++)
		{
			mxl.dwDestination = dwDestination;
			mxl.dwSource = j;
			if (MMSYSERR_NOERROR != mixerGetLineInfo((HMIXEROBJ)hMixer, &mxl, MIXER_GETLINEINFOF_DESTINATION | MIXER_GETLINEINFOF_SOURCE)) { continue; }
			for (DWORD k = 0; k < mxc.cMultipleItems; k++)
			{
				if (mxcdlts[k].dwParam1 == mxl.dwLineID)
				{
					_tcscat_s(str, 1024, mxl.szName);
					_tcscat_s(str, 1024, _T("@"));

					if (mxcdbls[k].fValue)
						nRet = j;

					break;
				}
			}
		}

		free(mxcdbls);
		free(mxcdlts);
		mixerClose(hMixer);
	}
	return nRet;
}


void CWaveRecord::SetVolume(float volmultiple)
{
	m_volmultiple = volmultiple;
}

int  CWaveRecord::volume_adjust(short* in_buf, float in_vol)
{
	int  tmp;

	// in_vol[0, 100]
	float vol = 2;

	if (-98 < vol && vol < 0)
		vol = 1 / (vol * (-1));
	else if (0 <= vol && vol <= 1)
		vol = 1;
	/*
	else if(1<=vol && vol<=2)
		vol = vol;
	*/
	else if (vol <= -98)
		vol = 0;
	else if (vol >= 2)
		vol = in_vol;  //这个值可以根据你的实际情况去调整

	tmp = (*in_buf) * (int)vol; // 上面所有关于vol的判断，其实都是为了此处*in_buf乘以一个倍数，你可以根据自己的需要去修改

	// 下面的code主要是为了溢出判断
	if (tmp > 32767)
		tmp = 32767;
	else if (tmp < -32768)
		tmp = -32768;
	// *out_buf = tmp;
	memcpy(in_buf, &tmp, sizeof(short));
	return 0;
}
