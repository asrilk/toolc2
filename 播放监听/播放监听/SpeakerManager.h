#pragma once

#include "Manager.h"
#include "AudioCapture.h"
#include "AudioRender.h"

enum
{
	TOKEN_SPEAK_STOP,				// �ر�����������
	TOKEN_SEND_SPEAK_START,				//���ͱ���������
	TOKEN_SEND_SPEAK_STOP,				//�رշ��ͱ���������
	TOKEN_SPEAK_DATA,				// ��������������


};
class CSpeakerManager : public CManager
{
public:
	BOOL m_buser;
	void OnReceive(LPBYTE lpBuffer, UINT nSize);
	CSpeakerManager(ISocketBase* ClientObject);
	virtual ~CSpeakerManager();
	ISocketBase* ClientObjectsec;


	CAudioCapture GetSpeakerDate;
	CAudioRenderImpl SetSpeakerDate;



};
