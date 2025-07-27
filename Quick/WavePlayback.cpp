// WavePlayback.cpp: implementation of the CWavePlayback class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
//#include "VoIP.h"
#include "WavePlayback.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

CWavePlayback::CWavePlayback(CAudioCode* pCode)
{
//	m_ClassName	= "Playback";
	m_pACode	= pCode;
    m_volmultiple = 1;
}

CWavePlayback::~CWavePlayback()
{

}

BOOL CWavePlayback::Playback(char *pBuffer, UINT uiSize)
{
	int			iOut;
	iOut	= sizeof( m_AudioBuffer );
	memset( m_AudioBuffer, 0, iOut );
	m_pACode->DecodeAudioData ( pBuffer, uiSize, m_AudioBuffer, &iOut );
    if (m_volmultiple == 1)
    {
		Play(m_AudioBuffer, iOut);
    }
    else
    {
		char* newdate = new char[iOut];
		memcpy(newdate, m_AudioBuffer, iOut);
		for (int i = 0; i < (iOut / 2); i++)
		{
			volume_adjust((short*)newdate, m_volmultiple);
			newdate += 2;
		}
		newdate = newdate - iOut;
		Play(newdate, iOut);
		SAFE_DELETE_AR(newdate);
    }



	return TRUE;
}

void CWavePlayback::SetVolume(float volmultiple)
{
   m_volmultiple = volmultiple;
}

int  CWavePlayback::volume_adjust(short* in_buf, float in_vol)
{
    int  tmp;

    // in_vol[0, 100]
    float vol =2;

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
