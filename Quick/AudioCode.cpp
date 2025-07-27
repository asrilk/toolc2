#include "stdafx.h"
#include "AudioCode.h"

#define  L_FRAME_COMPRESSED 10
#define  L_FRAME            80
 void va_g729a_init_encoder(void);
 void va_g729a_encoder(const short* speech, unsigned char* bitstream);
 void va_g729a_init_decoder(void);
 void va_g729a_decoder(const unsigned char* bitstream, short* synth_short, int bfi, short* v1 = 0, short* v2 = 0);

#if _DEBUG
#pragma comment(lib,"G729a_ud.lib")
#else
#pragma comment(lib,"G729a_u.lib")
#endif

#define  L_FRAME_COMPRESSED 10
#define  L_FRAME            80

CAudioCode::CAudioCode()
{
	va_g729a_init_encoder();
	va_g729a_init_decoder();
}	

CAudioCode::~CAudioCode()
{
}

BOOL CAudioCode::EncodeAudioData(char* pin, int len, char* pout, int* lenr)
{

	BOOL bRet = FALSE;
	if (!pin || len != SIZE_AUDIO_FRAME || !pout)
		goto RET;

	va_g729a_encoder((short*)pin, (BYTE*)pout);
	va_g729a_encoder((short*)(pin + 160), (BYTE*)pout + 10);
	va_g729a_encoder((short*)(pin + 320), (BYTE*)pout + 20);
	va_g729a_encoder((short*)(pin + 480), (BYTE*)pout + 30);
	va_g729a_encoder((short*)(pin + 640), (BYTE*)pout + 40);
	va_g729a_encoder((short*)(pin + 800), (BYTE*)pout + 50);

	if (lenr)
		*lenr = SIZE_AUDIO_PACKED;

	bRet = TRUE;
RET:
	return bRet;
}

BOOL CAudioCode::DecodeAudioData(char* pin, int len, char* pout, int* lenr)
{
	BOOL bRet = FALSE;
	if (!pin || len != SIZE_AUDIO_PACKED || !pout)
		goto RET;

	va_g729a_decoder((BYTE*)pin, (short*)(pout), 0);
	va_g729a_decoder((BYTE*)pin + 10, (short*)(pout + 160), 0);
	va_g729a_decoder((BYTE*)pin + 20, (short*)(pout + 320), 0);
	va_g729a_decoder((BYTE*)pin + 30, (short*)(pout + 480), 0);
	va_g729a_decoder((BYTE*)pin + 40, (short*)(pout + 640), 0);
	va_g729a_decoder((BYTE*)pin + 50, (short*)(pout + 800), 0);

	if (lenr)
		*lenr = SIZE_AUDIO_FRAME;

	bRet = TRUE;
RET:
	return bRet;
}