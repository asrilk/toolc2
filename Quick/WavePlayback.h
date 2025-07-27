// WavePlayback.h: interface for the CWavePlayback class.
//
//////////////////////////////////////////////////////////////////////

#pragma once

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
