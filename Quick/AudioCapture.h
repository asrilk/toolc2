
#pragma once


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

typedef   void (CALLBACK* SendData)(byte* senddata, int datasize);
class CAudioCapture
{
public:
	CAudioCapture();
	~CAudioCapture();

	BOOL Initialize(SendData pSendData);
	BOOL Start();
	void Stop();
	void Destroy();
	BOOL IsInited() const;
	BOOL IsCapturing() const;
	IMMDevice* m_pDevice;
	BOOL m_bInited;

	SendData pSendData;
	HANDLE m_hThreadCapture;
	HANDLE m_hEventStop;

};

