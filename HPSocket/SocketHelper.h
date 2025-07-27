/*
 * Copyright: JessMA Open Source (ldcsaa@gmail.com)
 *
 * Author	: Bruce Liang
 * Website	: https://github.com/ldcsaa
 * Project	: https://github.com/ldcsaa/HP-Socket
 * Blog		: http://www.cnblogs.com/ldcsaa
 * Wiki		: http://www.oschina.net/p/hp-socket
 * QQ Group	: 44636872, 75375912
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
 
#pragma once

#include <ws2tcpip.h>
#include <mswsock.h>
#include <malloc.h>

#include <atlfile.h>

#include "SysHelper.h"
#include "BufferPool.h"
DWORD GetTimeGap32(DWORD dwOriginal, DWORD dwCurrent = 0);
BOOL PeekMessageLoop(BOOL bDispatchQuitMsg = TRUE);
DWORD WaitForMultipleObjectsWithMessageLoop(DWORD dwHandles, HANDLE szHandles[], DWORD dwMilliseconds = INFINITE, BOOL bWaitAll = FALSE, DWORD dwWakeMask = QS_ALLINPUT);
BOOL MsgWaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds = INFINITE, BOOL bWaitAll = FALSE, DWORD dwWakeMask = QS_ALLINPUT);


typedef const BYTE* LPCBYTE, PCBYTE;
typedef ULONG_PTR		TID, THR_ID, NTHR_ID, PID, PRO_ID;
typedef ULONG_PTR		CONNID, HP_CONNID;

typedef enum EnServiceState
{
	SS_STARTING = 0,	// 正在启动
	SS_STARTED = 1,	// 已经启动
	SS_STOPPING = 2,	// 正在停止
	SS_STOPPED = 3,	// 已经停止
} En_HP_ServiceState;

typedef enum EnHandleResult
{
	HR_OK = 0,	// 成功
	HR_IGNORE = 1,	// 忽略
	HR_ERROR = 2,	// 错误
} En_HP_HandleResult;


typedef enum EnSocketOperation
{
	SO_UNKNOWN = 0,	// Unknown
	SO_ACCEPT = 1,	// Acccept
	SO_CONNECT = 2,	// Connect
	SO_SEND = 3,	// Send
	SO_RECEIVE = 4,	// Receive
	SO_CLOSE = 5,	// Close
} En_HP_SocketOperation;


typedef enum EnSocketError
{
	SE_OK = 0,	// 成功
	SE_ILLEGAL_STATE = 1,		// 当前状态不允许操作
	SE_INVALID_PARAM = 2,		// 非法参数
	SE_SOCKET_CREATE = 3,		// 创建 SOCKET 失败
	SE_SOCKET_BIND = 4,		// 绑定 SOCKET 失败
	SE_SOCKET_PREPARE = 5,		// 设置 SOCKET 失败
	SE_SOCKET_LISTEN = 6,		// 监听 SOCKET 失败
	SE_CP_CREATE = 7,		// 创建完成端口失败
	SE_WORKER_THREAD_CREATE = 8,		// 创建工作线程失败
	SE_DETECT_THREAD_CREATE = 9,		// 创建监测线程失败
	SE_SOCKE_ATTACH_TO_CP = 10,		// 绑定完成端口失败
	SE_CONNECT_SERVER = 11,		// 连接服务器失败
	SE_NETWORK = 12,		// 网络错误
	SE_DATA_PROC = 13,		// 数据处理错误
	SE_DATA_SEND = 14,		// 数据发送失败

	/***** SSL Socket 扩展操作结果代码 *****/
	SE_SSL_ENV_NOT_READY = 101,		// SSL 环境未就绪
} En_HP_SocketError;
 /************************************************************************
 名称：全局常量
 描述：声明组件的公共全局常量
 ************************************************************************/

inline int ENSURE_ERROR(int def_code) { int __le_ = ::GetLastError(); if (__le_ == 0) __le_ = (def_code);  return __le_; }
#define ENSURE_ERROR_CANCELLED	

inline BOOL IsStrEmptyW(LPCWSTR lpsz) { return (lpsz == nullptr || lpsz[0] == 0); }
//inline BOOL IsStrNotEmptyA(LPCSTR lpsz) { return !IsStrEmptyA(lpsz); }
inline BOOL IsStrNotEmptyW(LPCWSTR lpsz) { return !IsStrEmptyW(lpsz); }
//inline LPCSTR SafeStrA(LPCSTR lpsz) { return (lpsz != nullptr) ? lpsz : ""; }
inline LPCWSTR SafeStrW(LPCWSTR lpsz) { return (lpsz != nullptr) ? lpsz : L""; }
//

#define IsStrEmpty(lpsz)			IsStrEmptyW(lpsz)
#define IsStrNotEmpty(lpsz)			IsStrNotEmptyW(lpsz)
#define SafeStr(lpsz)				SafeStrW(lpsz)

#define EXECUTE_RESET_ERROR(expr)		(::SetLastError(0), (expr))
#define TRIGGER(expr)					EXECUTE_RESET_ERROR((expr))

 /* IOCP Socket 缓冲区最小值 */
#define MIN_SOCKET_BUFFER_SIZE					88
/* 小文件最大字节数 */
#define MAX_SMALL_FILE_SIZE						0x3FFFFF
/* 最大连接时长 */
#define MAX_CONNECTION_PERIOD					(MAXLONG / 2)
/* IOCP 处理接收事件时最大额外读取次数 */
#define MAX_IOCP_CONTINUE_RECEIVE				30

/* Server/Agent 最大连接数 */
#define MAX_CONNECTION_COUNT					(5 * 1000 * 1000)
/* Server/Agent 默认最大连接数 */
#define DEFAULT_CONNECTION_COUNT				10000
/* Server/Agent 默认 Socket 对象缓存锁定时间 */
#define DEFAULT_FREE_SOCKETOBJ_LOCK_TIME		(30 * 1000)
/* Server/Agent 默认 Socket 缓存池大小 */
#define DEFAULT_FREE_SOCKETOBJ_POOL				600
/* Server/Agent 默认 Socket 缓存池回收阀值 */
#define DEFAULT_FREE_SOCKETOBJ_HOLD				600
/* Server/Agent 默认内存块缓存池大小 */
#define DEFAULT_FREE_BUFFEROBJ_POOL				1024
/* Server/Agent 默认内存块缓存池回收阀值 */
#define DEFAULT_FREE_BUFFEROBJ_HOLD				1024
/* Client 默认内存块缓存池大小 */
#define DEFAULT_CLIENT_FREE_BUFFER_POOL_SIZE	60
/* Client 默认内存块缓存池回收阀值 */
#define DEFAULT_CLIENT_FREE_BUFFER_POOL_HOLD	60
/* IPv4 默认绑定地址 */
#define  DEFAULT_IPV4_BIND_ADDRESS				_T("0.0.0.0")
/* IPv6 默认绑定地址 */
#define  DEFAULT_IPV6_BIND_ADDRESS				_T("::")
/* IPv4 广播地址 */
#define DEFAULT_IPV4_BROAD_CAST_ADDRESS			_T("255.255.255.255")

/* SOCKET 默认发送缓冲区大小 */
#define DEFAULT_SOCKET_SNDBUFF_SIZE				(16 * 1024)

/* TCP 默认通信数据缓冲区大小 */
#define DEFAULT_TCP_SOCKET_BUFFER_SIZE			4096
/* TCP 默认心跳包间隔 */
#define DEFALUT_TCP_KEEPALIVE_TIME				(60 * 1000)
/* TCP 默认心跳确认包检测间隔 */
#define DEFALUT_TCP_KEEPALIVE_INTERVAL			(20 * 1000)
/* TCP Server 默认 Listen 队列大小 */
#define DEFAULT_TCP_SERVER_SOCKET_LISTEN_QUEUE	SOMAXCONN
/* TCP Server 默认预投递 Accept 数量 */
#define DEFAULT_TCP_SERVER_ACCEPT_SOCKET_COUNT	300

/* UDP 最大数据报文最大长度 */
#define MAXIMUM_UDP_MAX_DATAGRAM_SIZE			(16 * 4096)
/* UDP 默认数据报文最大长度 */
#define DEFAULT_UDP_MAX_DATAGRAM_SIZE			1432
/* UDP 默认 Receive 预投递数量 */
#define DEFAULT_UDP_POST_RECEIVE_COUNT			300


/* TCP Pack 包长度位数 */
#define TCP_PACK_LENGTH_BITS					22
/* TCP Pack 包长度掩码 */
#define TCP_PACK_LENGTH_MASK					0x3FFFFF
/* TCP Pack 包最大长度硬限制 */
#define TCP_PACK_MAX_SIZE_LIMIT					0x3FFFFF
/* TCP Pack 包默认最大长度 */
#define TCP_PACK_DEFAULT_MAX_SIZE				0x040000
/* TCP Pack 包头标识值硬限制 */
#define TCP_PACK_HEADER_FLAG_LIMIT				0x0003FF
/* TCP Pack 包头默认标识值 */
#define TCP_PACK_DEFAULT_HEADER_FLAG			0x000000

/* 压缩/解压数据缓冲器长度 */
#define COMPRESS_BUFFER_SIZE					(16 * 1024)

#define HOST_SEPARATOR_CHAR						'^'
#define PORT_SEPARATOR_CHAR						':'
#define IPV6_ADDR_BEGIN_CHAR					'['
#define IPV6_ADDR_END_CHAR						']'
#define IPV4_ADDR_SEPARATOR_CHAR				'.'
#define IPV6_ADDR_SEPARATOR_CHAR				':'
#define IPV6_ZONE_INDEX_CHAR					'%'


//#define ENSURE_HAS_STOPPED()					{ASSERT(GetState() == SS_STOPPED); if(GetState() != SS_STOPPED) return;}



/************************************************************************
名称：Windows Socket 组件初始化类
描述：自动加载和卸载 Windows Socket 组件
************************************************************************/
class CInitSocket
{
public:
	CInitSocket(LPWSADATA lpWSAData = nullptr, BYTE minorVersion = 2, BYTE majorVersion = 2)
	{
		LPWSADATA lpTemp = lpWSAData;

		if(!lpTemp)
			lpTemp	= (WSADATA*)alloca(sizeof(WSADATA) * (1));

		m_iResult	= ::WSAStartup(MAKEWORD(majorVersion, minorVersion), lpTemp);
	}

	~CInitSocket()
	{
		if(IsValid())
			::WSACleanup();
	}

	int	 GetResult() const {return m_iResult;}
	BOOL IsValid()	 const {return m_iResult == 0;}

private:
	int m_iResult;
};

typedef struct hp_addr
{
	ADDRESS_FAMILY family;

	union
	{
		ULONG_PTR	addr;
		IN_ADDR		addr4;
		IN6_ADDR	addr6;
	};

	static const hp_addr ANY_ADDR4;
	static const hp_addr ANY_ADDR6;

	inline int AddrSize() const
	{
		return AddrSize(family);
	}

	inline static int AddrSize(ADDRESS_FAMILY f)
	{
		if(f == AF_INET)
			return sizeof(IN_ADDR);

		return sizeof(IN6_ADDR);
	}

	inline static const hp_addr& AnyAddr(ADDRESS_FAMILY f)
	{
		if(f == AF_INET)
			return ANY_ADDR4;

		return ANY_ADDR6;
	}

	inline const ULONG_PTR* Addr()	const	{return &addr;}
	inline ULONG_PTR* Addr()				{return &addr;}

	inline BOOL IsIPv4()			const	{return family == AF_INET;}
	inline BOOL IsIPv6()			const	{return family == AF_INET6;}
	inline BOOL IsSpecified()		const	{return IsIPv4() || IsIPv6();}
	inline void ZeroAddr()					{::ZeroMemory(&addr6, sizeof(addr6));}
	inline void Reset()						{::ZeroMemory(this, sizeof(*this));}

	inline hp_addr& Copy(hp_addr& other) const
	{
		if(this != &other)
			memcpy(&other, this, offsetof(hp_addr, addr) + AddrSize());

		return other;
	}

	hp_addr(ADDRESS_FAMILY f = AF_UNSPEC, BOOL bZeroAddr = FALSE)
	{
		family = f;

		if(bZeroAddr) ZeroAddr();
	}

} HP_ADDR, *HP_PADDR;

typedef struct hp_sockaddr
{
	union
	{
		ADDRESS_FAMILY	family;
		SOCKADDR		addr;
		SOCKADDR_IN		addr4;
		SOCKADDR_IN6	addr6;
	};

	inline int AddrSize() const
	{
		return AddrSize(family);
	}

	inline static int AddrSize(ADDRESS_FAMILY f)
	{
		if(f == AF_INET)
			return sizeof(SOCKADDR_IN);

		return sizeof(SOCKADDR_IN6);
	}

	inline int EffectAddrSize() const
	{
		return EffectAddrSize(family);
	}

	inline static int EffectAddrSize(ADDRESS_FAMILY f)
	{
		return (f == AF_INET) ? offsetof(SOCKADDR_IN, sin_zero) : sizeof(SOCKADDR_IN6);
	}

	inline static const hp_sockaddr& AnyAddr(ADDRESS_FAMILY f)
	{
		static const hp_sockaddr s_any_addr4(AF_INET, TRUE);
		static const hp_sockaddr s_any_addr6(AF_INET6, TRUE);

		if(f == AF_INET)
			return s_any_addr4;

		return s_any_addr6;
	}

	inline static int AddrMinStrLength(ADDRESS_FAMILY f)
	{
		if(f == AF_INET)
			return 16;

		return 46;
	}

	inline BOOL IsIPv4()			const	{return family == AF_INET;}
	inline BOOL IsIPv6()			const	{return family == AF_INET6;}
	inline BOOL IsSpecified()		const	{return IsIPv4() || IsIPv6();}
	inline USHORT Port()			const	{return ntohs(addr4.sin_port);}
	inline void SetPort(USHORT usPort)		{addr4.sin_port = htons(usPort);}
	inline void* SinAddr()			const	{return IsIPv4() ? (void*)&addr4.sin_addr : (void*)&addr6.sin6_addr;}
	inline void* SinAddr()					{return IsIPv4() ? (void*)&addr4.sin_addr : (void*)&addr6.sin6_addr;}

	inline const SOCKADDR* Addr()	const	{return &addr;}
	inline SOCKADDR* Addr()					{return &addr;}
	inline void ZeroAddr()					{::ZeroMemory(((char*)this) + sizeof(family), sizeof(*this) - sizeof(family));}
	inline void Reset()						{::ZeroMemory(this, sizeof(*this));}

	inline hp_sockaddr& Copy(hp_sockaddr& other) const
	{
		if(this != &other)
			memcpy(&other, this, AddrSize());

		return other;
	}

	size_t Hash() const
	{
		ASSERT(IsSpecified());

		size_t _Val		  = 2166136261U;
		const int size	  = EffectAddrSize();
		const BYTE* pAddr = (const BYTE*)Addr();

		for(int i = 0; i < size; i++)
			_Val = 16777619U * _Val ^ (size_t)pAddr[i];

		return (_Val);
	}

	bool EqualTo(const hp_sockaddr& other) const
	{
		ASSERT(IsSpecified() && other.IsSpecified());

		return 	!memcmp((this), (&other), (EffectAddrSize()));
	}

	hp_sockaddr(ADDRESS_FAMILY f = AF_UNSPEC, BOOL bZeroAddr = FALSE)
	{
		family = f;

		if(bZeroAddr) ZeroAddr();
	}

} HP_SOCKADDR, *HP_PSOCKADDR;

typedef struct hp_scope_host
{
	LPCTSTR addr;
	LPCTSTR name;

	BOOL bNeedFree;

	hp_scope_host(LPCTSTR lpszOriginAddress)
	{
		ASSERT(lpszOriginAddress != nullptr);

		LPCTSTR lpszFind = ::StrChr(lpszOriginAddress, HOST_SEPARATOR_CHAR);

		if(lpszFind == nullptr)
		{
			addr		= lpszOriginAddress;
			name		= lpszOriginAddress;
			bNeedFree	= FALSE;
		}
		else
		{
			int i			= (int)(lpszFind - lpszOriginAddress);
			int iSize		= (int)lstrlen(lpszOriginAddress) + 1;
			LPTSTR lpszCopy	= new TCHAR[iSize];

			::memcpy((PVOID)lpszCopy, (PVOID)lpszOriginAddress, iSize * sizeof(TCHAR));

			lpszCopy[i]	= 0;
			addr		= lpszCopy;
			name		= lpszCopy + i + 1;
			bNeedFree	= TRUE;

			if(::IsStrEmpty(name))
				name = addr;
		}
	}

	~hp_scope_host()
	{
		if(bNeedFree)
			delete[] addr;
	}

} HP_SCOPE_HOST, *HP_PSCOPE_HOST;

/* Server 组件和 Agent 组件内部使用的事件处理结果常量 */

// 连接已关闭
#define HR_CLOSED	0xFF

/* 关闭连接标识 */
enum EnSocketCloseFlag
{
	SCF_NONE		= 0,	// 不触发事件
	SCF_CLOSE		= 1,	// 触发 正常关闭 OnClose 事件
	SCF_ERROR		= 2		// 触发 异常关闭 OnClose 事件
};

/* 数据缓冲区基础结构 */
template<class T> struct TBufferObjBase
{
	WSAOVERLAPPED		ov;
	CPrivateHeap&		heap;

	EnSocketOperation	operation;
	WSABUF				buff;

	int					capacity;
	volatile LONG		sndCounter;

	T* next;
	T* last;

	static T* Construct(CPrivateHeap& heap, DWORD dwCapacity)
	{
		T* pBufferObj = (T*)heap.Alloc(sizeof(T) + dwCapacity);
		ASSERT(pBufferObj);

		pBufferObj->TBufferObjBase::TBufferObjBase(heap, dwCapacity);
		pBufferObj->buff.buf = ((char*)pBufferObj) + sizeof(T);

		return pBufferObj;
	}

	static void Destruct(T* pBufferObj)
	{
		ASSERT(pBufferObj);
		pBufferObj->heap.Free(pBufferObj);
	}

	void ResetSendCounter()
	{
		sndCounter = 2;
	}

	LONG ReleaseSendCounter()
	{
		return ::InterlockedDecrement(&sndCounter);
	}

	TBufferObjBase(CPrivateHeap& hp, DWORD dwCapacity)
	: heap(hp)
	, capacity((int)dwCapacity)
	{
		ASSERT(capacity > 0);
	}

	int Cat(const BYTE* pData, int length)
	{
		ASSERT(pData != nullptr && length >= 0);

		int cat = min(Remain(), length);

		if(cat > 0)
		{
			memcpy(buff.buf + buff.len, pData, cat);
			buff.len += cat;
		}

		return cat;
	}

	void ResetOV()	{::ZeroMemory(&ov, sizeof(ov));}
	void Reset()	{ResetOV(); buff.len = 0;}
	int Remain()	{return capacity - buff.len;}
	BOOL IsFull()	{return Remain() == 0;}
};

/* 数据缓冲区结构 */
struct TBufferObj : public TBufferObjBase<TBufferObj>
{
	SOCKET client;
};

/* UDP 数据缓冲区结构 */
struct TUdpBufferObj : public TBufferObjBase<TUdpBufferObj>
{
	HP_SOCKADDR	remoteAddr;
	int			addrLen;
};

/* 数据缓冲区链表模板 */
template<class T> struct TBufferObjListT : public TSimpleList<T>
{
public:
	int Cat(const BYTE* pData, int length)
	{
		ASSERT(pData != nullptr && length >= 0);

		int remain = length;

		while(remain > 0)
		{
			T* pItem = Back();

			if(pItem == nullptr || pItem->IsFull())
				pItem = PushBack(bfPool.PickFreeItem());

			int cat  = pItem->Cat(pData, remain);

			pData	+= cat;
			remain	-= cat;
		}

		return length;
	}

	T* PushTail(const BYTE* pData, int length)
	{
		ASSERT(pData != nullptr && length >= 0 && length <= (int)bfPool.GetItemCapacity());

		T* pItem = PushBack(bfPool.PickFreeItem());
		pItem->Cat(pData, length);

		return pItem;
	}

	void Release()
	{
		bfPool.PutFreeItem(*this);
	}

public:
	TBufferObjListT(CNodePoolT<T>& pool) : bfPool(pool)
	{
	}

private:
	CNodePoolT<T>& bfPool;
};

/* 数据缓冲区对象池 */
typedef CNodePoolT<TBufferObj>			CBufferObjPool;
/* UDP 数据缓冲区对象池 */
typedef CNodePoolT<TUdpBufferObj>		CUdpBufferObjPool;
/* 数据缓冲区链表模板 */
typedef TBufferObjListT<TBufferObj>		TBufferObjList;
/* UDP 数据缓冲区链表模板 */
typedef TBufferObjListT<TUdpBufferObj>	TUdpBufferObjList;

/* TBufferObj 智能指针 */
typedef TItemPtrT<TBufferObj>			TBufferObjPtr;
/* TUdpBufferObj 智能指针 */
typedef TItemPtrT<TUdpBufferObj>		TUdpBufferObjPtr;

/* Socket 缓冲区基础结构 */
struct TSocketObjBase : public CSafeCounter
{
	CPrivateHeap& heap;

	CONNID		connID;
	HP_SOCKADDR	remoteAddr;
	PVOID		extra;
	PVOID		reserved;
	PVOID		reserved2;

	union
	{
		DWORD	freeTime;
		DWORD	connTime;
	};

	DWORD		activeTime;

	volatile BOOL	valid;
	volatile BOOL	smooth;
	volatile long	pending;
	volatile long	sndCount;

	volatile BOOL	connected;
	volatile BOOL	paused;
	volatile BOOL	recving;

	TSocketObjBase(CPrivateHeap& hp) : heap(hp) {}

	static BOOL IsExist(TSocketObjBase* pSocketObj)
		{return pSocketObj != nullptr;}

	static BOOL IsValid(TSocketObjBase* pSocketObj)
		{return (IsExist(pSocketObj) && pSocketObj->valid == TRUE);}

	static void Invalid(TSocketObjBase* pSocketObj)
		{ASSERT(IsExist(pSocketObj)); pSocketObj->valid = FALSE;}

	static void Release(TSocketObjBase* pSocketObj)
	{
		ASSERT(IsExist(pSocketObj)); pSocketObj->freeTime = ::timeGetTime();
	}

	DWORD GetConnTime	()	const	{return connTime;}
	DWORD GetFreeTime	()	const	{return freeTime;}
	DWORD GetActiveTime	()	const	{return activeTime;}
	BOOL IsPaused		()	const	{return paused;}

	long Pending()		{return pending;}
	BOOL IsPending()	{return pending > 0;}
	BOOL IsSmooth()		{return smooth;}
	void TurnOnSmooth()	{smooth = TRUE;}

	BOOL TurnOffSmooth()
		{return ::InterlockedCompareExchange((volatile long*)&smooth, FALSE, TRUE) == TRUE;}
	
	BOOL HasConnected()							{return connected;}
	void SetConnected(BOOL bConnected = TRUE)	{connected = bConnected;}

	void Reset(CONNID dwConnID)
	{
		ResetCount();

		connID		= dwConnID;
		connected	= FALSE;
		valid		= TRUE;
		smooth		= TRUE;
		paused		= FALSE;
		recving		= FALSE;
		pending		= 0;
		sndCount	= 0;
		extra		= nullptr;
		reserved	= nullptr;
		reserved2	= nullptr;
	}
};

/* 数据缓冲区结构 */
struct TSocketObj : public TSocketObjBase
{
	CCriSec			csRecv;
	CCriSec			csSend;
	CSpinGuard		sgPause;

	SOCKET			socket;
	CStringA		host;
	TBufferObjList	sndBuff;

	BOOL IsCanSend() {return sndCount <= GetSendBufferSize();}

	long GetSendBufferSize()
	{
		long lSize;
		int len	= (int)(sizeof(lSize));
		int rs	= getsockopt(socket, SOL_SOCKET, SO_SNDBUF, (CHAR*)&lSize, &len);

		if(rs == SOCKET_ERROR || lSize <= 0)
			lSize = DEFAULT_SOCKET_SNDBUFF_SIZE;

		return lSize;
	}

	static TSocketObj* Construct(CPrivateHeap& hp, CBufferObjPool& bfPool)
	{
		TSocketObj* pSocketObj = (TSocketObj*)hp.Alloc(sizeof(TSocketObj));
		ASSERT(pSocketObj);

		pSocketObj->TSocketObj::TSocketObj(hp, bfPool);

		return pSocketObj;
	}

	static void Destruct(TSocketObj* pSocketObj)
	{
		ASSERT(pSocketObj);

		CPrivateHeap& heap = pSocketObj->heap;
		pSocketObj->TSocketObj::~TSocketObj();
		heap.Free(pSocketObj);
	}
	
	TSocketObj(CPrivateHeap& hp, CBufferObjPool& bfPool)
	: TSocketObjBase(hp), sndBuff(bfPool)
	{

	}

	static BOOL InvalidSocketObj(TSocketObj* pSocketObj)
	{
		BOOL bDone = FALSE;

		if(TSocketObj::IsValid(pSocketObj))
		{
			pSocketObj->SetConnected(FALSE);

			CCriSecLock locallock(pSocketObj->csRecv);
			CCriSecLock locallock2(pSocketObj->csSend);

			if(TSocketObjBase::IsValid(pSocketObj))
			{
				TSocketObjBase::Invalid(pSocketObj);
				bDone = TRUE;
			}
		}

		return bDone;
	}

	static void Release(TSocketObj* pSocketObj)
	{
		__super::Release(pSocketObj);

		pSocketObj->sndBuff.Release();
	}

	void Reset(CONNID dwConnID, SOCKET soClient)
	{
		__super::Reset(dwConnID);
		
		host.Empty();

		socket = soClient;
	}

	BOOL GetRemoteHost(LPCSTR* lpszHost, USHORT* pusPort = nullptr)
	{
		*lpszHost = host;

		if(pusPort)
			*pusPort = remoteAddr.Port();

		return (*lpszHost != nullptr && (*lpszHost)[0] != 0);
	}
};

/* UDP 数据缓冲区结构 */
struct TUdpSocketObj : public TSocketObjBase
{
	PVOID				pHolder;
	HANDLE				hTimer;

	CRWLock				csRecv;
	CCriSec				csSend;

	TUdpBufferObjList	sndBuff;
	volatile DWORD		detectFails;

	BOOL IsCanSend			() {return sndCount <= GetSendBufferSize();}
	long GetSendBufferSize	() {return (4 * DEFAULT_SOCKET_SNDBUFF_SIZE);}

	static TUdpSocketObj* Construct(CPrivateHeap& hp, CUdpBufferObjPool& bfPool)
	{
		TUdpSocketObj* pSocketObj = (TUdpSocketObj*)hp.Alloc(sizeof(TUdpSocketObj));
		ASSERT(pSocketObj);

		pSocketObj->TUdpSocketObj::TUdpSocketObj(hp, bfPool);

		return pSocketObj;
	}

	static void Destruct(TUdpSocketObj* pSocketObj)
	{
		ASSERT(pSocketObj);

		CPrivateHeap& heap = pSocketObj->heap;
		pSocketObj->TUdpSocketObj::~TUdpSocketObj();
		heap.Free(pSocketObj);
	}
	
	TUdpSocketObj(CPrivateHeap& hp, CUdpBufferObjPool& bfPool)
	: TSocketObjBase(hp), sndBuff(bfPool)
	{

	}

	static BOOL InvalidSocketObj(TUdpSocketObj* pSocketObj)
	{
		BOOL bDone = FALSE;

		if(TUdpSocketObj::IsValid(pSocketObj))
		{
			pSocketObj->SetConnected(FALSE);

			CReentrantWriteLock	locallock(pSocketObj->csRecv);
			CCriSecLock			locallock2(pSocketObj->csSend);

			if(TSocketObjBase::IsValid(pSocketObj))
			{
				TSocketObjBase::Invalid(pSocketObj);
				bDone = TRUE;
			}
		}

		return bDone;
	}

	static void Release(TUdpSocketObj* pSocketObj)
	{
		__super::Release(pSocketObj);

		pSocketObj->sndBuff.Release();
	}

	void Reset(CONNID dwConnID)
	{
		__super::Reset(dwConnID);

		pHolder		= nullptr;
		hTimer		= nullptr;
		detectFails	= 0;
	}
};

/* 有效 TSocketObj 缓存 */
typedef CRingCache2<TSocketObj, CONNID, true>		TSocketObjPtrPool;
/* 失效 TSocketObj 缓存 */
typedef CRingPool<TSocketObj>						TSocketObjPtrList;
/* 失效 TSocketObj 垃圾回收结构链表 */
typedef CCASQueue<TSocketObj>						TSocketObjPtrQueue;

/* 有效 TUdpSocketObj 缓存 */
typedef CRingCache2<TUdpSocketObj, CONNID, true>	TUdpSocketObjPtrPool;
/* 失效 TUdpSocketObj 缓存 */
typedef CRingPool<TUdpSocketObj>					TUdpSocketObjPtrList;
/* 失效 TUdpSocketObj 垃圾回收结构链表 */
typedef CCASQueue<TUdpSocketObj>					TUdpSocketObjPtrQueue;

/* HP_SOCKADDR 比较器 */
struct hp_sockaddr_func
{
	struct hash
	{
		size_t operator() (const HP_SOCKADDR* pA) const
		{
			return pA->Hash();
		}
	};

	struct equal_to
	{
		bool operator () (const HP_SOCKADDR* pA, const HP_SOCKADDR* pB) const
		{
			return pA->EqualTo(*pB);
		}
	};

};

/* 地址-连接 ID 哈希表 */
typedef unordered_map<const HP_SOCKADDR*, CONNID, hp_sockaddr_func::hash, hp_sockaddr_func::equal_to>
										TSockAddrMap;
/* 地址-连接 ID 哈希表迭代器 */
typedef TSockAddrMap::iterator			TSockAddrMapI;
/* 地址-连接 ID 哈希表 const 迭代器 */
typedef TSockAddrMap::const_iterator	TSockAddrMapCI;

/* IClient 组件关闭上下文 */
struct TClientCloseContext
{
	BOOL bFireOnClose;
	EnSocketOperation enOperation;
	int iErrorCode;
	BOOL bNotify;

	TClientCloseContext(BOOL bFire = TRUE, EnSocketOperation enOp = SO_CLOSE, int iCode = SE_OK, BOOL bNtf = TRUE)
	{
		Reset(bFire, enOp, iCode, bNtf);
	}

	void Reset(BOOL bFire = TRUE, EnSocketOperation enOp = SO_CLOSE, int iCode = SE_OK, BOOL bNtf = TRUE)
	{
		bFireOnClose = bFire;
		enOperation	 = enOp;
		iErrorCode	 = iCode;
		bNotify		 = bNtf;
	}

};
