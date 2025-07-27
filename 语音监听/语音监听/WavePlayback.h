// WavePlayback.h: interface for the CWavePlayback class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_WAVEPLAYBACK_H__592109B9_0102_4857_B5CB_58B445201331__INCLUDED_)
#define AFX_WAVEPLAYBACK_H__592109B9_0102_4857_B5CB_58B445201331__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include "WaveOut.h"
#include "AudioCode.h"


class CWavePlayback : public CWaveOut  
{
public:
	BOOL Playback(char* pBuffer,UINT uiSize);
	CWavePlayback(CAudioCode* pCode);
	virtual ~CWavePlayback();
	void SetVolume(float volmultiple);
	int  volume_adjust(short* in_buf, float in_vol);
protected:
	// ±àÂëÊý¾Ý
	char				m_AudioBuffer[102400];
	// ±àÂëÆ÷
	CAudioCode*			m_pACode;
	
	float m_volmultiple;
};

#endif // !defined(AFX_WAVEPLAYBACK_H__592109B9_0102_4857_B5CB_58B445201331__INCLUDED_)
