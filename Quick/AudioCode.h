#pragma once

#ifndef SIZE_AUDIO_FRAME
#define SIZE_AUDIO_FRAME 960
#endif
#ifndef SIZE_AUDIO_PACKED
#define SIZE_AUDIO_PACKED 60
#endif

class CAudioCode
{
public:
	virtual  ~CAudioCode();
	CAudioCode();

	BOOL EncodeAudioData(char *pin,int len,char* pout,int* lenr);
	BOOL DecodeAudioData(char *pin,int len,char* pout,int* lenr);
};


