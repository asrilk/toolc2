
#include "stdafx.h"
#include "MixOut.h"



#define	WND_CLASS_NAME	_T("Wave Output Volume Msg Wnd Class")
#define	WND_NAME		_T("Wave Output Volume Msg Wnd")
//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

static CMixOut *g_pThis = NULL;
LRESULT CALLBACK CMixOut::MixerWndProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam )
{
	if ( uMsg == MM_MIXM_CONTROL_CHANGE )
	{
		if ( g_pThis )
		{
			g_pThis->OnControlChanged( (DWORD)lParam );
		}	
	}
	return ::DefWindowProc( hwnd, uMsg, wParam, lParam);
}

MMRESULT CMixOut::GetLastMMError()
{
	return m_mmr;
}
//TCHAR* CMixOut::GetLastErrorString()
//{
//	TCHAR buffer[256];
//	memset(buffer,0,256);
//	switch(m_mmr)
//	{
//	case MMSYSERR_NOERROR:
//		_stprintf(buffer,_T("No error."));
//		break;
//	case MIXERR_INVALCONTROL:
//		_stprintf(buffer, _T("Specified device handle is invalid."));
//		break;
//	case MMSYSERR_BADDEVICEID:
//		_stprintf(buffer, _T("The hmxobj parameter specifies an invalid device identifier."));
//		break;
//	case MMSYSERR_INVALFLAG:
//		_stprintf(buffer, _T("One or more flags are invalid."));
//		break;
//	case MMSYSERR_INVALHANDLE:
//		_stprintf(buffer, _T("The hmxobj parameter specifies an invalid handle."));
//		break;
//	case MMSYSERR_INVALPARAM:
//		_stprintf(buffer, _T("One or more parameters are invalid."));
//		break;
//	case MMSYSERR_NODRIVER:
//		_stprintf(buffer, _T("No mixer device is available for the object specified by hmxobj."));
//		break;
//	case MIXERR_INVALLINE:
//		_stprintf(buffer, _T("The audio line reference is invalid.."));
//		break;
//	case MMSYSERR_NOTSUPPORTED:
//		_stprintf(buffer, _T("The mixer device did not process the message."));
//		break;
//	case MMSYSERR_ALLOCATED:
//		_stprintf(buffer, _T("The specified resource is already allocated by the maximum number of clients possible."));
//		break;
//	case MMSYSERR_NOMEM:
//		_stprintf(buffer, _T("Unable to allocate resources."));
//		break;
//	default:
//		_stprintf(buffer, _T("Unknow error,Error code %d"),m_mmr);
//		break;
//	}
//	return buffer;
//}

CMixOut::CMixOut():
	m_iDevNum(0),
	m_uiMixerId(0),
	m_hMixer(0),
	m_hWnd(NULL),
	m_bIni(FALSE),
	m_dwMinimalVolume(0),
	m_dwMaximalVolume(100)
{
	g_pThis = this;
}

CMixOut::~CMixOut()
{
}

BOOL CMixOut::Ini()
{
	if (m_bIni)
	{
		Trace("Mix in has alreadly ini.\n");		
		return FALSE;
	}
	if (!OpenMixer())
	{
	//	Trace("%s.\n",GetLastErrorString());
		return FALSE;
	};

	if (!Initialize())
	{
		//Trace("%s.\n",GetLastErrorString());
		return FALSE;
	}

	m_bIni = TRUE;
	return TRUE;
}

BOOL CMixOut::UnIni()
{
	if (!m_bIni)
	{
		Trace("Mix in hasn't ini.\n");
		return FALSE;
	}
	::DestroyWindow( m_hWnd );
	CloseMixer();

	m_iDevNum = 0;
	m_uiMixerId = 0;
	m_hMixer = 0;
	m_hWnd = NULL;
	m_bIni = FALSE;
	m_dwMinimalVolume = 0;
	m_dwMaximalVolume = 100;

	m_bIni = FALSE;
	return TRUE;
}

BOOL CMixOut::OpenMixer()
{
	m_iDevNum = mixerGetNumDevs();
	if (m_iDevNum == 0)
	{
		Trace("There (is) are no device mixer.\n");
		return FALSE;
	}

	WAVEFORMATEX wfx;
	memset( &wfx, 0, sizeof(WAVEFORMATEX) );
	wfx.wFormatTag = WAVE_FORMAT_PCM;
	wfx.nChannels = 1;
	wfx.nSamplesPerSec = 8000;
	wfx.nAvgBytesPerSec = 1 * 8000 * 16 / 8;
	wfx.nBlockAlign = 16 * 1 / 8;
	wfx.wBitsPerSample = 16;
	wfx.cbSize = 0;

	HWAVEOUT hwaveOut;
	m_mmr = waveOutOpen( &hwaveOut, WAVE_MAPPER, &wfx, 0L, 0L, CALLBACK_NULL );
	if ( m_mmr != MMSYSERR_NOERROR )
	{
		return false;
	}
	else
	{
		m_mmr = mixerGetID( (HMIXEROBJ)hwaveOut, &m_uiMixerId, MIXER_OBJECTF_HWAVEOUT );
		waveOutClose( hwaveOut );
		if (m_mmr != MMSYSERR_NOERROR )
		{
			return false;
		}
	}

	WNDCLASSEX wcx;
	memset( &wcx, 0, sizeof(WNDCLASSEX) );	
	wcx.cbSize = sizeof(WNDCLASSEX);
	wcx.lpszClassName = WND_CLASS_NAME;
	wcx.lpfnWndProc = (WNDPROC)MixerWndProc;
	::RegisterClassEx(&wcx);
	m_hWnd = CreateWindow(	WND_CLASS_NAME,
							WND_NAME,
							WS_POPUP | WS_DISABLED,
							0, 0, 0, 0,
							NULL, NULL, NULL, NULL );
	if ( !m_hWnd )
	{
	
		return false;
	}
	::ShowWindow(m_hWnd, SW_HIDE);
	m_mmr = mixerOpen( (LPHMIXER)&m_hMixer, m_uiMixerId, (DWORD)m_hWnd, 0L, CALLBACK_WINDOW );
	if (m_mmr != MMSYSERR_NOERROR )
	{
		::DestroyWindow( m_hWnd );
		return false;
	}
	return true;
}

BOOL CMixOut::CloseMixer()
{
	if (m_hMixer)
	{
		m_mmr = mixerClose((HMIXER)m_hMixer);
		if (m_mmr != MMSYSERR_NOERROR )
		{
			return false;
		}
	}
	return TRUE;
}

void CMixOut::OnControlChanged(int iValue)
{
}

BOOL CMixOut::Initialize()
{
	if (m_hMixer)
	{
		Trace("You haven't open the mixer.\n");
		return FALSE;
	}
	
	MIXERLINE MixerLine;
	memset( &MixerLine, 0, sizeof(MIXERLINE) );
	MixerLine.cbStruct = sizeof(MIXERLINE);
	MixerLine.dwComponentType = MIXERLINE_COMPONENTTYPE_SRC_WAVEOUT;
	m_mmr = mixerGetLineInfo( (HMIXEROBJ)m_hMixer, &MixerLine, MIXER_GETLINEINFOF_COMPONENTTYPE );
	if ( m_mmr != MMSYSERR_NOERROR )
	{
		return false;
	}

	MIXERCONTROL Control;
	memset( &Control, 0, sizeof(MIXERCONTROL) );
	Control.cbStruct = sizeof(MIXERCONTROL);

	MIXERLINECONTROLS LineControls;
	memset( &LineControls, 0, sizeof(MIXERLINECONTROLS) );
	LineControls.cbStruct = sizeof(MIXERLINECONTROLS);

	LineControls.dwControlType = MIXERCONTROL_CONTROLTYPE_VOLUME;
	LineControls.dwLineID = MixerLine.dwLineID;
	LineControls.cControls = 1;
	LineControls.cbmxctrl = sizeof(MIXERCONTROL);
	LineControls.pamxctrl = &Control;
	m_mmr = mixerGetLineControls( (HMIXEROBJ)m_hMixer, &LineControls, MIXER_GETLINECONTROLSF_ONEBYTYPE );
	if ( m_mmr == MMSYSERR_NOERROR )
	{
		if ((Control.fdwControl & MIXERCONTROL_CONTROLF_DISABLED) )
		{
			return FALSE;
		} 
	} 
	else 
	{
		return FALSE;
	}

	m_dwMinimalVolume = Control.Bounds.dwMinimum;
	m_dwMaximalVolume = Control.Bounds.dwMaximum;

	return TRUE;
}

DWORD CMixOut::GetMinimalVolume()
{
	if (!m_bIni)
	{
		Trace("Mix in hasn't ini.\n");
		return 0;
	}
	return this->m_dwMinimalVolume ;
}

DWORD CMixOut::GetMaximalVolume()
{
	if (!m_bIni)
	{
		Trace("Mix in hasn't ini.\n");
		return 100;
	}
	return this->m_dwMaximalVolume ;
}

DWORD CMixOut::GetCurrentVolume()
{
	if (!m_bIni)
	{
		Trace("Mix in hasn't ini.\n");
		return 0;
	}
	return 0;
}

void CMixOut::SetCurrentVolume(DWORD dwValue)
{
}

