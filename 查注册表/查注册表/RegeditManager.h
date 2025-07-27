#include "Manager.h"

#pragma once

enum
{

	TOKEN_REG_INFO,
	TOKEN_REG_KEY,
	TOKEN_REG_ERROR,
	TOKEN_REG_SUCCEED,

	COMMAND_REG_ENUM,
	COMMAND_REG_CREATEKEY,
	COMMAND_REG_DELKEY,
	COMMAND_REG_CREATKEY,
	COMMAND_REG_DELVAL,
	COMMAND_REG_RENAME
};



struct REGMSG
{
	int count;         //名字个数
	DWORD size;        //名字大小
	DWORD valsize;     //值大小 
};

class CRegeditManager : public CManager
{
public:
	BOOL m_buser;
	CRegeditManager(ISocketBase* pClient);
	virtual ~CRegeditManager();
	void OnReceive(LPBYTE lpBuffer, UINT nSize);


private:
	void EnumReg(BYTE bToken, LPBYTE lpBuffer);
	LPBYTE GetRegInfo();
	LPBYTE GetRegKey();

	void  CreateKey(LPBYTE lpBuffer);
	BOOL  MyCreateKey(LPCTSTR lpSubKey);

	void  DeleteVal(char* buf);
	void  DeleteKey(LPBYTE lpBuffer);
	BOOL  MyDeleteKey(LPCTSTR lpSubKey);

	BOOL  DeleteValue(LPCTSTR lpValueName);

	void  ParseKey(BYTE bType);
	BOOL  OpenKey(LPCTSTR lpSubKey);
	BOOL  WriteValue(LPCTSTR lpSubKey, LPCTSTR lpVal);
	BOOL  WriteValue(LPCTSTR lpSubKey, DWORD dwVal);
	BOOL  WriteBuf(LPCTSTR lpValueName, LPCTSTR lpValue);

	void SendSucceed();
	void SendError();
	LONG IsHaveSubkeys(DWORD& dwRet);
	void Rename(char* buf);
	void CreateKeyEx(char* buf);
	void CreatSTR(char* buf);
	void CreatDWORD(char* buf);
	void CreatEXSTR(char* buf);
	HKEY        m_hKey;
	HKEY        m_hKey_n;

	HKEY		MKEY;
	TCHAR       KeyPath[MAX_PATH];
};

