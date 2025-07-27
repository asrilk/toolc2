#pragma once
#include "Buffer.h"
#include <mmdeviceapi.h>
#include <Audioclient.h>
#include <process.h>
#include <avrt.h>
#include<iostream>
#include<fstream>
using namespace std;
#define AUDIO_RENDER_CLASS _T("audio_render_message_class")
#include <mmreg.h>
#pragma comment(lib, "Avrt.lib")


class CAudioRenderImpl
{
public:
	CAudioRenderImpl();
	~CAudioRenderImpl();
	BOOL Initialize();
	VOID Destroy();
	BOOL Start();
	VOID Stop();
	BOOL IsInited() const;
	BOOL IsRendering() const;
	BOOL PlayBuffer(LPBYTE szBuffer, DWORD dwBufferSize);

	CRITICAL_SECTION cs;// 临界区的声明
	CBuffer	m_WriteBuffer;
	HANDLE m_hEventStop;
	IMMDevice* m_pDevice;
	HANDLE m_hThreadRender;
	BOOL m_bInited;
};