#pragma once
#include "ntdef.h"

BOOL SetPrivilege(HANDLE hToken, wchar_t* lpszPrivilege, BOOL bEnablePrivilege);
void EnableDebugPrivilege(BOOL enforceCheck);
BOOL EnableImpersonatePrivilege();
void SpoofPidTeb(DWORD spoofedPid, PDWORD originalPid, PDWORD originalTid);
void RestoreOriginalPidTeb(DWORD originalPid, DWORD originalTid);
void FindProcessHandlesInTargetProcess(DWORD lsassPid, HANDLE* handlesToLeak, PDWORD handlesToLeakCount);
void FindTokenHandlesInProcess(DWORD targetPid, HANDLE* tokenHandles, PDWORD tokenHandlesLen);
void MalSeclogonPPIDSpoofing(int lsassPid, wchar_t* cmdline);
void ReplaceNtOpenProcess(HANDLE leakedHandle, char* oldCode, int* oldCodeSize);
void RestoreNtOpenProcess(char* oldCode, int oldCodeSize);
void MalSeclogonLeakHandles(int lsassPid, wchar_t* dumpPath);
void LeakLsassHandleInSeclogonWithRaceCondition(DWORD lsassPid);
void CreateFileLock(HANDLE hFile, LPOVERLAPPED overlapped);
DWORD WINAPI ThreadSeclogonLock(LPVOID lpParam);
NTSTATUS QueryObjectTypesInfo(__out POBJECT_TYPES_INFORMATION* TypesInfo);
NTSTATUS GetTypeIndexByName(__in PCUNICODE_STRING TypeName, __out PULONG TypeIndex);
BOOL FileExists(LPCTSTR szPath);
DWORD GetPidUsingFilePath(wchar_t* processBinaryPath);