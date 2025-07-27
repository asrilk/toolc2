#pragma once

#include "Manager.h"
#include "AudioCapture.h"
#include "AudioRender.h"

enum
{
	TOKEN_SPEAK_STOP,				// 关闭扬声器监听
	TOKEN_SEND_SPEAK_START,				//发送本地扬声器
	TOKEN_SEND_SPEAK_STOP,				//关闭发送本地扬声器
	TOKEN_SPEAK_DATA,				// 接收扬声器数据


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
