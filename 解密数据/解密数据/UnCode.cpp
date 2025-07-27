#include "stdafx.h"
#include "UnCode.h"



BOOL AesGcmDecrypt(DATA_BLOB cipher, DATA_BLOB key, DATA_BLOB iv, PDATA_BLOB decrypted)
{
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		return FALSE;

	if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
		return FALSE;

	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.cbData, NULL))
		return FALSE;

	if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key.pbData, iv.pbData))
		return FALSE;

	int bufLen;
	int sumLen = 0;

	if (!EVP_DecryptUpdate(ctx, decrypted->pbData + sumLen, &bufLen, cipher.pbData + sumLen, cipher.cbData))
		return FALSE;
	sumLen += bufLen;

	int ret = EVP_DecryptFinal_ex(ctx, decrypted->pbData + sumLen, &bufLen);
	sumLen += bufLen;

	EVP_CIPHER_CTX_free(ctx);

	decrypted->cbData = sumLen;

	//return ret > 0;
	return TRUE;
}


int aes_decrypt(char* in, int in_len, char* key, char* out)
{
	if (NULL == in || NULL == key || NULL == out)
		return -1;

	AES_KEY aes;
	if (AES_set_decrypt_key((unsigned char*)key, 128, &aes) < 0)
	{
		return -2;
	}

	int en_len = 0;
	while (en_len < in_len)
	{
		AES_decrypt((unsigned char*)in, (unsigned char*)out, &aes);
		in += AES_BLOCK_SIZE;
		out += AES_BLOCK_SIZE;
		en_len += AES_BLOCK_SIZE;
	}

	return 0;
}

std::string DecryptAes(std::string text, char* key)
{

	size_t encryptedKeyLength = Base64decode_len(text.c_str());
	LPSTR encryptedKey = (LPSTR)malloc(encryptedKeyLength);
	Base64decode(encryptedKey, text.c_str());
	char aes_en[1024] = { 0 };
	aes_decrypt(encryptedKey, (int)encryptedKeyLength, key, aes_en);

	return aes_en;
}

//此函数用于调用Windows的内部函数对信息进行解密，返回值为报错信息或解密后的信息
BYTE* Decrypt(BYTE* enPassword, int len) {
	DATA_BLOB temp, out;
	temp.pbData = enPassword;
	temp.cbData = len;
	if (CryptUnprotectData(&temp, NULL, NULL, NULL, NULL, 0, &out)) {

		return out.pbData;
	}
	else {
		return NULL;
	}
}

int DecryptPassword(const DATA_BLOB encryptedPassword, const DATA_BLOB masterKey, PDATA_BLOB decryptedPassword)
{
	const DATA_BLOB iv = { 15 - 3, encryptedPassword.pbData + 3 };
	const DATA_BLOB payload = { encryptedPassword.cbData - 15, encryptedPassword.pbData + 15 };

	int ret = AesGcmDecrypt(payload, masterKey, iv, decryptedPassword);
	decryptedPassword->cbData -= 16;
	decryptedPassword->pbData[decryptedPassword->cbData] = '\0';
	return ret;
}

//基于不可见字符进行去除，需改的可能性不高
bool _getPwd(BYTE* enPassword, int len, std::string& getPwd) {

	std::string DecryptPassword;
	BYTE* temp = Decrypt(enPassword, len);

	if (temp != NULL) {
		DecryptPassword = (char*)temp;
		int length =(int)( DecryptPassword.size());
		int flag = 0;

		for (int i = 0; i < length; i++) {
			if (DecryptPassword[i] > 31 && DecryptPassword[i] < 127) {
				continue;
			}
			else {
				flag = i;
				break;
			}

		}
		getPwd = DecryptPassword.substr(0, flag);

		return true;
	}
	else
	{
		getPwd = "err : uncode failed!";
		return false;
	}
}


long FileSize(FILE* f)
{
	fseek(f, 0L, SEEK_END);
	long res = ftell(f);
	rewind(f);
	return res;
}


char* U2G(const char* utf8)
{
	int len = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, NULL, 0);
	wchar_t* wstr = new wchar_t[len + (INT64)1];
	memset(wstr, 0, len + (INT64)1);
	MultiByteToWideChar(CP_UTF8, 0, utf8, -1, wstr, len);
	len = WideCharToMultiByte(CP_ACP, 0, wstr, -1, NULL, 0, NULL, NULL);
	char* str = new char[len + (INT64)1];
	memset(str, 0, len + (INT64)1);
	WideCharToMultiByte(CP_ACP, 0, wstr, -1, str, len, NULL, NULL);
	if (wstr) delete[] wstr;
	return str;
}


// 1601-1-1 时间间隔计算创建时间 纳秒计算差值
std::string int64timeToStr(__time64_t broTime)
{
	// -11644502743 == 1601-01-01 00:00:00
	long long _1601time = -11644502743;
	long long  all_sec = broTime / 1000000;
	// 13,261,062,631

	//获取64位时间    
	__time64_t t64Time = all_sec + _1601time;

	tm tmThatTime={};

	errno_t err = _localtime64_s(&tmThatTime,&t64Time);

	if (err != 0)
	{
		return "unknow";
	}

	char cThatTime[30];
	memset(cThatTime, 0, 30);
	sprintf_s(cThatTime, "%04d/%02d/%02d %02d:%02d:%02d", tmThatTime.tm_year + 1900, tmThatTime.tm_mon + 1,
		tmThatTime.tm_mday, tmThatTime.tm_hour, tmThatTime.tm_min, tmThatTime.tm_sec);

	return cThatTime;
}


#define MAX_REG_NAME 255
std::shared_ptr<BYTE> MyGetRegValueA(HKEY hKey, const char* lpValueName, const char* lpVal)
{

	if (RegOpenKeyExA(hKey, lpValueName, 0, KEY_READ | KEY_WOW64_64KEY, &hKey) != ERROR_SUCCESS)
		return nullptr;

	DWORD dwType;
	DWORD dwSize = MAX_REG_NAME * 2;
	const std::shared_ptr<BYTE> lpData(new BYTE[dwSize]);

	const auto lReturn = RegQueryValueExA(hKey, lpVal, nullptr, &dwType, lpData.get(), &dwSize);

	if (lReturn == ERROR_SUCCESS)
	{
		return lpData;  // NOLINT(performance-no-automatic-move)
	}
	return nullptr;
}

//替换指定的子串
//src:原字符串 target:待被替换的子串 subs:替换的子串
std::string replaceALL(const char* src, const std::string& target, const std::string& subs)
{
	std::string tmp(src);
	std::string::size_type pos = tmp.find(target), targetSize = target.size(), resSize = subs.size();
	while (pos != std::string::npos)//found  
	{
		tmp.replace(pos, targetSize, subs);
		pos = tmp.find(target, pos + resSize);
	}
	return tmp;
}

bool Calcsha256(unsigned char * src, unsigned int src_len, unsigned char * buffer) {

	SHA256_CTX c;

	int r = SHA256_Init(&c);

	if (r != 1) return false;

	r = SHA256_Update(&c, src, src_len);

	if (r != 1) return false;

	r = SHA256_Final(buffer, &c);

	if (r != 1) return false;

	return true;
}

bool CalcMd5(unsigned char *data, unsigned int src_len, unsigned char * buffer)
{
	MD5_CTX c;
	//char *data = "hoge";
	//unsigned char md[MD5_DIGEST_LENGTH];
	//char mdString[33];
	int r;

	r = MD5_Init(&c);
	if (r != 1) return false;

	r = MD5_Update(&c, data, src_len);
	if (r != 1)return false;

	r = MD5_Final(buffer, &c);
	if (r != 1) return false;

	return true;
}