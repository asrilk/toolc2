// WaveRecord.h: interface for the CWaveRecord class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_WAVERECORD_H__02D23E96_405A_46D9_918B_9A6BEEC228B9__INCLUDED_)
#define AFX_WAVERECORD_H__02D23E96_405A_46D9_918B_9A6BEEC228B9__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include <afxmt.h>
#include "WaveIn.h"
#include "AudioCode.h"

enum
{
	TOKEN_SEND_DATE,
	COMMAND_SEND_START,
	COMMAND_SEND_STOP,
	COMMAND_SEND_DATE,
	TOKEN_START_OK,
	TOKEN_STOP_OK,
	TOKEN_STOP_ERROR,
	COMMAND_AUDIO_CHANGER,
	COMMAND_AUDIO_CHANGER_LINES,
	COMMAND_SET_IN,
	COMMAND_SET_OUT,

};


class CWaveRecord : public CWaveIn  
{
public:
	void SetCommClient(ISocketBase* pClient, ClientContext* pContext, CDialog* i_hwnd);
	CWaveRecord(CAudioCode* pCode);
	virtual ~CWaveRecord();
	int EnumerateInputLines(TCHAR* szPname, TCHAR* str);

	void SetVolume(float volmultiple);
	int  volume_adjust(short* in_buf, float in_vol);
	//////////////////////////////////////////////////////////////////////////
	//
	// 数据获取回调
	//
	virtual void GetData(char *pBuffer,int iLen);

	//////////////////////////////////////////////////////////////////////////
	//
	// 初始化语音获取接口
	//
	BOOL Init();
protected:
	BOOL IsHaveWav(char* pBuffer, int iLen);
	// 是否发送语音数据
	BOOL				m_bSend;
	// 语音资源锁
	CCriticalSection	m_soLock;
	// 编码数据
	char				m_AudioBuffer[102400];
	// 编码器
	CAudioCode*			m_pACode;
	// 数据通信接口
	ISocketBase* pIOCPServer;
	ClientContext* m_pContext;
	CDialog* m_hwnd;
	float m_volmultiple;
};

#endif // !defined(AFX_WAVERECORD_H__02D23E96_405A_46D9_918B_9A6BEEC228B9__INCLUDED_)
