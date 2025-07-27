#pragma once

// Windows ͷ�ļ�:
#include <windows.h>

// C ����ʱͷ�ļ�
#include <stdlib.h>
#include <malloc.h>
#include <memory.h>
#include <tchar.h>



#include <mmdeviceapi.h>
#include <Audioclient.h>
#include <process.h>
#include <avrt.h>
#include<iostream>
#include<fstream>
#define AUDIO_CAPTURE_CLASS _T("audio_cpature_message_class")
using namespace std;
#include <mmreg.h>
#pragma comment(lib, "Avrt.lib")


class CAudioCapture
{
public:
	CAudioCapture();
	~CAudioCapture();

	BOOL Initialize(void*);
	BOOL Start();
	void Stop();
	void Destroy();
	BOOL IsInited() const;
	BOOL IsCapturing() const;
	IMMDevice* m_pDevice;
	BOOL m_bInited;

	void* pSpeakerManager;
	HANDLE m_hThreadCapture;
	HANDLE m_hEventStop;

};

