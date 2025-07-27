#include "stdafx.h"
#include "WaveIn.h"
#include "math.h"
#pragma comment(lib,"Winmm")

DWORD CWaveIn::s_dwInstance = 0;

DWORD WINAPI CWaveIn::AudioInThreadProc(LPVOID lpParameter)
{
	Trace("AudioInThreadProc start.\n");
	CWaveIn *pWaveIn;
	pWaveIn = (CWaveIn *)lpParameter;

	char buffer[102400];
	MSG msg;
	while(GetMessage(&msg,0,0,0))
	{
		switch(msg.message )
		{
		case MM_WIM_OPEN:
			Trace("MM_WIM_OPEN \n");
			break;
		case MM_WIM_CLOSE:
			Trace("MM_WIM_CLOSE \n");
			break;
		case MM_WIM_DATA:
			WAVEHDR* pWH=(WAVEHDR*)msg.lParam;
			waveInUnprepareHeader((HWAVEIN)msg.wParam,pWH,sizeof(WAVEHDR));
			
			if(pWH->dwBytesRecorded!=SIZE_AUDIO_FRAME)
				break;

			memcpy(buffer,pWH->lpData,pWH->dwBytesRecorded);
			pWaveIn->GetData (buffer ,pWH->dwBytesRecorded );

			waveInPrepareHeader((HWAVEIN)msg.wParam,pWH,sizeof(WAVEHDR));
			waveInAddBuffer((HWAVEIN)msg.wParam,pWH,sizeof(WAVEHDR));

			break;
		}
	}
	Trace("AudioInThreadProc exit.\n");
	return (DWORD)msg.wParam;
}

CWaveIn::CWaveIn() :
	m_wChannel(1),
	m_dwSample (WISA_NORMAL),
	m_wBit(16)
{
	m_hIn=0;
	m_bThreadStart = FALSE;
	m_bDevOpen = FALSE;
	m_bAllocBuffer = FALSE;
	m_bRecord = FALSE;

	m_pHdr = NULL;
	m_dwAudioInId = 0;
	s_dwInstance ++;

}

CWaveIn::~CWaveIn()
{
}

BOOL CWaveIn::CloseDev()
{
	if (!m_bDevOpen)
	{
		Trace("CWaveIn::CloseDev: Device hasn't opened.\n");
		return FALSE;
	}

	if(!m_hIn)
	{
		Trace("CWaveIn::CloseDev: Device hasn't opened.\n");
		return FALSE;
	}

	m_mmr=waveInClose(m_hIn);
	if(m_mmr)
	{
	//	Trace("CWaveIn::CloseDev: waveInClose error %s.\n",GetLastErrorString());
		m_hIn=0;
		m_bDevOpen = FALSE;
		return FALSE;
	}
	m_hIn=0;
	m_bDevOpen = FALSE;
	return TRUE;
}
BOOL CWaveIn::OpenDev()
{
	if (m_bDevOpen)
	{
		Trace("CWaveIn::OpenDev: Device has open.\n");
		return FALSE;
	}
	WAVEFORMATEX wfx;
	wfx.wFormatTag = WAVE_FORMAT_PCM;
	wfx.nChannels = m_wChannel;
	wfx.nSamplesPerSec = m_dwSample;
	wfx.nAvgBytesPerSec = m_wChannel * m_dwSample * m_wBit / 8;
	wfx.nBlockAlign = m_wBit * m_wChannel / 8;
	wfx.wBitsPerSample = m_wBit;
	wfx.cbSize = 0;

	m_mmr=waveInOpen(0,WAVE_MAPPER,&wfx,0,0,WAVE_FORMAT_QUERY);
	if(m_mmr)
	{
		Trace("CWaveIn::OpenDev: waveInOpen error.\n");
		return FALSE;
	}

	m_mmr=waveInOpen(&m_hIn,WAVE_MAPPER,&wfx,m_dwAudioInId,s_dwInstance,CALLBACK_THREAD);
	if(m_mmr)
	{
		Trace("CWaveIn::OpenDev: waveInOpen error.\n");
		return FALSE;
	}
	m_bDevOpen = TRUE;
	return TRUE;
}

BOOL CWaveIn::StartThread()
{
	if (m_bThreadStart)
	{
		Trace("CWaveIn::StartThread: Wave in thread has run.\n");
		return FALSE;
	}

	m_hAudioIn=CreateThread(0,0,AudioInThreadProc,this,0,&m_dwAudioInId);
	if(!m_hAudioIn)
	{
		Trace("CWaveIn::StartThread: Strat wave in thread fail.\n");
		return FALSE;
	}
	m_bThreadStart = TRUE;
	return TRUE;
}

BOOL CWaveIn::StopThread()
{
	if (!m_bThreadStart)
	{
		Trace("CWaveIn::StopThread: Wave in thread hasn't run.\n");
		return FALSE;
	}

	if(m_hAudioIn)
	{
		int t=50;
		DWORD ExitCode;
		BOOL bEnd=FALSE;
		PostThreadMessage(m_dwAudioInId,WM_QUIT,0,0);
		while(t)
		{
			GetExitCodeThread(m_hAudioIn,&ExitCode);
			if(ExitCode!= STILL_ACTIVE)
			{
				bEnd=TRUE;
				break;
			}
			else
				Sleep(10);
			t--;
		}
		if(!bEnd)
		{
			TerminateThread(m_hAudioIn,0);
			Trace("CWaveIn::StopThread: TerminateThread wave in thread.\n");
		}
		m_hAudioIn=0;
	}
	m_bThreadStart = FALSE;
	return TRUE;
}

BOOL CWaveIn::StartRec()
{
	BOOL bRet=FALSE;
	if (!StartThread())           
	{
		goto Exit;
	};
	if (!OpenDev())
	{
		goto Exit1;
	};
	if (!PerPareBuffer())
	{
		goto Exit2;
	}
	if (!OpenRecord())
	{
		goto Exit3;
	}
	bRet = TRUE;
	goto Exit;
Exit3:
	FreeBuffer();
Exit2:
	CloseDev ();
Exit1:
	StopThread ();
Exit:
	return bRet;
}

BOOL CWaveIn::StopRec()
{
	CloseRecord ();	
	Sleep(1500);
	//notice delete
	FreeBuffer();
	if (CloseDev())
	{
		StopThread ();
	}

	return TRUE;
}

BOOL CWaveIn::PerPareBuffer()
{
	if (m_bAllocBuffer)
	{
		Trace("CWaveIn::PerPareBuffer: Buffer has been alloc.\n");
		return FALSE;
	}

	m_mmr=waveInReset(m_hIn);
	if(m_mmr)
	{
		Trace("CWaveIn::PerPareBuffer: waveInReset error.\n");
		return FALSE;
	}

	UINT i;
	m_pHdr=new WAVEHDR[NUM_BUF];
		
	for(i=0;i<NUM_BUF;i++)
	{
		ZeroMemory(&m_pHdr[i],sizeof(WAVEHDR));
		m_pHdr[i].lpData=new char[SIZE_AUDIO_FRAME];
		m_pHdr[i].dwBufferLength= SIZE_AUDIO_FRAME;
		m_mmr=waveInPrepareHeader(m_hIn,&m_pHdr[i],sizeof(WAVEHDR));
		if(m_mmr)
		{
			Trace("CWaveIn::PerPareBuffer: waveInPrepareHeader error.\n");
			return FALSE;
		}
		
		m_mmr=waveInAddBuffer(m_hIn,&m_pHdr[i],sizeof(WAVEHDR));
		if(m_mmr)
		{
			Trace("CWaveIn::PerPareBuffer: waveInAddBuffer error.\n");
			return FALSE;
		}
	}

	m_bAllocBuffer = TRUE;
	return TRUE;
}

BOOL CWaveIn::FreeBuffer()
{
	if (!m_bAllocBuffer)
	{
		Trace("CWaveIn::FreeBuffer: Buffer hasn't been alloc.\n");
		return FALSE;
	}
	
	UINT i;
	if(!m_pHdr)
	{
		Trace("CWaveIn::FreeBuffer: m_pHdr is NULL.\n");
		return FALSE;
	}

	for(i=0;i<NUM_BUF;i++)
	{
		m_mmr = waveInUnprepareHeader(m_hIn,&m_pHdr[i],sizeof(WAVEHDR));
		if(m_mmr)
		{
			Sleep(100);
			Trace("CWaveIn::FreeBuffer: waveInUnprepareHeader error.\n");
			continue;
		}
		Trace("CWaveIn::FreeBuffer: %d.\n",i);
		
		if(m_pHdr[i].lpData)
			delete []m_pHdr[i].lpData;
	
	}
	delete []m_pHdr;
	m_pHdr = NULL;

	m_bAllocBuffer = FALSE;
	return TRUE;
}

BOOL CWaveIn::OpenRecord()
{
	if (m_bRecord)
	{
		Trace("CWaveIn::OpenRecord: You may be has begun recored.\n");
		return FALSE;
	}

	if(!m_hIn)
	{
		Trace("CWaveIn::CloseDev: Device hasn't opened.\n");
		return FALSE;
	}

	m_mmr=waveInStart(m_hIn);
	if(m_mmr)
	{
		Trace("CWaveIn::OpenRecord: waveInStart error.\n");
		return FALSE;
	}

	m_bRecord = TRUE;
	return TRUE;
}

BOOL CWaveIn::CloseRecord()
{
	if (!m_bRecord)
	{
		Trace("CWaveIn::CloseRecord: You may be hasn't begun recored.\n");
		return FALSE;
	}

	if(!m_hIn)
	{
		Trace("CWaveIn::CloseRecord: Device hasn't opened.\n");
		return FALSE;
	}

/*	m_mmr=waveInStop(m_hIn);
	if(m_mmr)
	{
		Trace("CWaveIn::CloseRecord: waveInStop error.\n");
		return FALSE;
	}
 */	m_mmr=waveInReset(m_hIn);
	if(m_mmr)
	{
		Trace("CWaveIn::CloseRecord: waveInReset error.\n");
		return FALSE;
	}

	m_bRecord = FALSE;
	return TRUE;
}

void CWaveIn::GetData(char *pBuffer,int iLen)
{	
	static int i = 0;
	static SYSTEMTIME time,time1;
	static long l = 0;
	if (i == 0)
	{
		::GetLocalTime (&time);
	}
	::GetLocalTime (&time1);

	int j = time1.wSecond - time.wSecond;
	if (abs(j) >= 1 )
	{
		memcpy(&time,&time1,sizeof(time));
		Trace("Len / second %d \n",l);
		l = 0;
	}
	l = l + iLen;
	i++;
}


MMRESULT CWaveIn::GetLastMMError()
{
	return m_mmr;
}

TCHAR* CWaveIn::GetLastErrorString()
{
	TCHAR  *buffer=new TCHAR[256];
	memset(buffer,0,256*sizeof(TCHAR));
	waveInGetErrorText(m_mmr,buffer,256);
	return buffer;
}

void CWaveIn::SetChannel(WORD wChannel)
{
	m_wChannel = (m_wChannel == wChannel) ? 2:1;
}

void CWaveIn::SetSample(DWORD dwSample)
{
	m_dwSample = dwSample;
}

void CWaveIn::SetBit(WORD wBit)
{
	m_wBit = (wBit == 8) ? 8:16;
}

DWORD CWaveIn::GetInstance()
{
	return s_dwInstance;
}

WORD CWaveIn::GetBit()
{
	return m_wBit;
}

DWORD CWaveIn::GetSample()
{
	return m_dwSample;
}

WORD CWaveIn::GetChannel()
{
	return m_wChannel;
}

