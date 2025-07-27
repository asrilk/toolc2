// WaveRecord.h: interface for the CWaveRecord class.
//
//////////////////////////////////////////////////////////////////////

#pragma once

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
	void SetCommClient(ISocketBase* pClient);
	CWaveRecord(CAudioCode* pCode);
	virtual ~CWaveRecord();
	int EnumerateInputLines(TCHAR* szPname, TCHAR* str);

	void SetVolume(float volmultiple);
	int  volume_adjust(short* in_buf, float in_vol);
	//////////////////////////////////////////////////////////////////////////
	//
	// ���ݻ�ȡ�ص�
	//
	virtual void GetData(char *pBuffer,int iLen);

	//////////////////////////////////////////////////////////////////////////
	//
	// ��ʼ��������ȡ�ӿ�
	//
	BOOL Init();
protected:
	BOOL IsHaveWav(char* pBuffer, int iLen);
	// �Ƿ�����������
	BOOL				m_bSend;
	// ������Դ��
	//CCriticalSection	m_soLock;
	// ��������
	char				m_AudioBuffer[102400];
	// ������
	CAudioCode*			m_pACode;
	// ����ͨ�Žӿ�
	ISocketBase*		m_pCommClient;

	CRITICAL_SECTION cs;// �ٽ���������

	float m_volmultiple;
};

