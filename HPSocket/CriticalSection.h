﻿
#pragma once

#include <intrin.h>
#include "GeneralHelper.h"
#pragma intrinsic(_ReadBarrier)
#pragma intrinsic(_WriteBarrier)
#pragma intrinsic(_ReadWriteBarrier)

#define DEFAULT_CRISEC_SPIN_COUNT	0
#define THREAD_YIELD_CYCLE			63
#define THREAD_SWITCH_CYCLE			4095

#ifndef YieldProcessor
	#pragma intrinsic(_mm_pause)
	#define YieldProcessor _mm_pause
#endif


inline void YieldThread(UINT i = THREAD_YIELD_CYCLE)
{
	if((i & THREAD_SWITCH_CYCLE) == THREAD_SWITCH_CYCLE)
		::SwitchToThread();
	else if((i & THREAD_YIELD_CYCLE) == THREAD_YIELD_CYCLE)
		::YieldProcessor();
}

class CInterCriSec
{
public:
	CInterCriSec(DWORD dwSpinCount = DEFAULT_CRISEC_SPIN_COUNT)
		{ENSURE(::InitializeCriticalSectionAndSpinCount(&m_crisec, dwSpinCount));}
	~CInterCriSec()
		{::DeleteCriticalSection(&m_crisec);}

	void Lock()								{::EnterCriticalSection(&m_crisec);}
	void Unlock()							{::LeaveCriticalSection(&m_crisec);}
	BOOL TryLock()							{return ::TryEnterCriticalSection(&m_crisec);}
	DWORD SetSpinCount(DWORD dwSpinCount)	{return ::SetCriticalSectionSpinCount(&m_crisec, dwSpinCount);}

	CRITICAL_SECTION* GetObject()			{return &m_crisec;}

private:
	CInterCriSec(const CInterCriSec& cs);
	CInterCriSec operator = (const CInterCriSec& cs);

private:
	CRITICAL_SECTION m_crisec;
};

class CInterCriSec2
{
public:
	CInterCriSec2(DWORD dwSpinCount = DEFAULT_CRISEC_SPIN_COUNT, BOOL bInitialize = TRUE)
	{
		if(bInitialize)
		{
			m_pcrisec = new CRITICAL_SECTION;
			ENSURE(::InitializeCriticalSectionAndSpinCount(m_pcrisec, dwSpinCount));
		}
		else
			m_pcrisec = nullptr;
	}

	~CInterCriSec2() {Reset();}

	void Attach(CRITICAL_SECTION* pcrisec)
	{
		Reset();
		m_pcrisec = pcrisec;
	}

	CRITICAL_SECTION* Detach()
	{
		CRITICAL_SECTION* pcrisec = m_pcrisec;
		m_pcrisec = nullptr;
		return pcrisec;
	}

	void Lock()								{::EnterCriticalSection(m_pcrisec);}
	void Unlock()							{::LeaveCriticalSection(m_pcrisec);}
	BOOL TryLock()							{return ::TryEnterCriticalSection(m_pcrisec);}
	DWORD SetSpinCount(DWORD dwSpinCount)	{return ::SetCriticalSectionSpinCount(m_pcrisec, dwSpinCount);}

	CRITICAL_SECTION* GetObject()			{return m_pcrisec;}

private:
	CInterCriSec2(const CInterCriSec2& cs);
	CInterCriSec2 operator = (const CInterCriSec2& cs);

	void Reset()
	{
		if(m_pcrisec)
		{
			::DeleteCriticalSection(m_pcrisec);
			delete m_pcrisec;
			m_pcrisec = nullptr;
		}
	}

private:
	CRITICAL_SECTION* m_pcrisec;
};

class CMTX
{
public:
	CMTX(BOOL bInitialOwner = FALSE, LPCTSTR pszName = nullptr, LPSECURITY_ATTRIBUTES pSecurity = nullptr)	
	{
		m_hMutex = ::CreateMutex(pSecurity, bInitialOwner, pszName);
		ASSERT(IsValid());
	}

	~CMTX()
	{
		if(IsValid())
			::CloseHandle(m_hMutex);
	}

	BOOL Open(DWORD dwAccess, BOOL bInheritHandle, LPCTSTR pszName)
	{
		if(IsValid())
			ENSURE(::CloseHandle(m_hMutex));

		m_hMutex = ::OpenMutex(dwAccess, bInheritHandle, pszName);
		return(IsValid());
	}

	void Lock(DWORD dwMilliseconds = INFINITE)	{::WaitForSingleObject(m_hMutex, dwMilliseconds);}
	void Unlock()								{::ReleaseMutex(m_hMutex);}

	HANDLE& GetHandle	() 	{return m_hMutex;}
	operator HANDLE		()	{return m_hMutex;}
	BOOL IsValid		()	{return m_hMutex != nullptr;}

private:
	CMTX(const CMTX& mtx);
	CMTX operator = (const CMTX& mtx);

private:
	HANDLE m_hMutex;
};

class CSpinGuard
{
public:
	CSpinGuard() : m_lFlag(0)
	{

	}

	~CSpinGuard()
	{
		ASSERT(m_lFlag == 0);
	}

	void Lock()
	{
		for(UINT i = 0; !TryLock(); ++i)
			YieldThread(i);
	}

	BOOL TryLock()
	{
		if(::InterlockedCompareExchange(&m_lFlag, 1, 0) == 0)
		{
			::_ReadWriteBarrier();
			return TRUE;
		}

		return FALSE;
	}

	void Unlock()
	{
		ASSERT(m_lFlag == 1);
		m_lFlag = 0;
	}

private:
	CSpinGuard(const CSpinGuard& cs);
	CSpinGuard operator = (const CSpinGuard& cs);

private:
	volatile LONG m_lFlag;
};

class CReentrantSpinGuard
{
public:
	CReentrantSpinGuard()
	: m_dwThreadID	(0)
	, m_iCount		(0)
	{

	}

	~CReentrantSpinGuard()
	{
		ASSERT(m_dwThreadID	== 0);
		ASSERT(m_iCount		== 0);
	}

	void Lock()
	{
		for(UINT i = 0; !_TryLock(i == 0); ++i)
			YieldThread(i);
	}

	BOOL TryLock()
	{
		return _TryLock(TRUE);
	}

	void Unlock()
	{
		ASSERT(m_dwThreadID == ::GetCurrentThreadId());

		if((--m_iCount) == 0)
			m_dwThreadID = 0;
	}

private:
	CReentrantSpinGuard(const CReentrantSpinGuard& cs);
	CReentrantSpinGuard operator = (const CReentrantSpinGuard& cs);

	BOOL _TryLock(BOOL bFirst)
	{
		DWORD dwCurrentThreadID = ::GetCurrentThreadId();

		if(bFirst && m_dwThreadID == dwCurrentThreadID)
		{
			++m_iCount;
			return TRUE;
		}

		if(::InterlockedCompareExchange(&m_dwThreadID, dwCurrentThreadID, 0) == 0)
		{
			::_ReadWriteBarrier();
			ASSERT(m_iCount == 0);

			m_iCount = 1;

			return TRUE;
		}

		return FALSE;
	}

private:
	volatile DWORD	m_dwThreadID;
	int				m_iCount;
};

class CFakeGuard
{
public:
	void Lock()		{}
	void Unlock()	{}
	BOOL TryLock()	{return TRUE;}
};



template<class CLockObj> class CLocalLock
{
public:
	CLocalLock(CLockObj& obj) : m_lock(obj) {m_lock.Lock();}
	~CLocalLock() {m_lock.Unlock();}
private:
	CLockObj& m_lock;
};

template<class CLockObj> class CLocalTryLock
{
public:
	CLocalTryLock(CLockObj& obj) : m_lock(obj) {m_bValid = m_lock.TryLock();}
	~CLocalTryLock() {if(m_bValid) m_lock.Unlock();}

	BOOL IsValid() {return m_bValid;}

private:
	CLockObj&	m_lock;
	BOOL		m_bValid;
};

typedef CInterCriSec						CCriSec;

typedef CLocalLock<CCriSec>					CCriSecLock;
typedef CLocalLock<CInterCriSec>			CInterCriSecLock;
typedef CLocalLock<CInterCriSec2>			CInterCriSecLock2;
typedef CLocalLock<CMTX>					CMutexLock;
typedef CLocalLock<CSpinGuard>				CSpinLock;
typedef CLocalLock<CReentrantSpinGuard>		CReentrantSpinLock;
typedef	CLocalLock<CFakeGuard>				CFakeLock;

typedef CLocalTryLock<CCriSec>				CCriSecTryLock;
typedef CLocalTryLock<CInterCriSec>			CInterCriSecTryLock;
typedef CLocalTryLock<CInterCriSec2>		CInterCriSecTryLock2;
typedef CLocalTryLock<CMTX>					CMutexTryLock;
typedef CLocalTryLock<CSpinGuard>			CSpinTryLock;
typedef CLocalTryLock<CReentrantSpinGuard>	CReentrantSpinTryLock;
typedef	CLocalTryLock<CFakeGuard>			CFakeTryLock;

template<typename T> class CSafeCounterT
{
public:
	T Increment()				{return IncrementImpl<sizeof(T)>();}
	T Decrement()				{return DecrementImpl<sizeof(T)>();}
	T FetchAdd(T iCount)		{return FetchAddImpl<sizeof(T)>(iCount);}
	T FetchSub(T iCount)		{return FetchSubImpl<sizeof(T)>(iCount);}
	T AddFetch(T iCount)		{return FetchAdd(iCount) + iCount;}
	T SubFetch(T iCount)		{return FetchSub(iCount) - iCount;}

	T SetCount(T iCount)		{return (m_iCount = iCount);}
	T ResetCount()				{return SetCount(0);}
	T GetCount()				{return m_iCount;}

	T operator ++ ()			{return Increment();}
	T operator -- ()			{return Decrement();}
	T operator ++ (int)			{return FetchAdd(1);}
	T operator -- (int)			{return FetchSub(1);}
	T operator += (T iCount)	{return AddFetch(iCount);}
	T operator -= (T iCount)	{return SubFetch(iCount);}
	T operator  = (T iCount)	{return SetCount(iCount);}
	operator T	  ()			{return GetCount();}

public:
	CSafeCounterT(T iCount = 0) : m_iCount(iCount) {}

private:
	template<SIZE_T> T IncrementImpl()			{return (T)::InterlockedIncrement((volatile LONG*)&m_iCount);}
	template<SIZE_T> T DecrementImpl()			{return (T)::InterlockedDecrement((volatile LONG*)&m_iCount);}
	template<SIZE_T> T FetchAddImpl(T iCount)	{return (T)::InterlockedExchangeAdd((volatile LONG*)&m_iCount, iCount);}
	template<SIZE_T> T FetchSubImpl(T iCount)	{return (T)::InterlockedExchangeAdd((volatile LONG*)&m_iCount, -iCount);}

//#if _WIN32_WINNT >= _WIN32_WINNT_VISTA
//	template<> T IncrementImpl<8>()				{return (T)::InterlockedIncrement64((volatile LONGLONG*)&m_iCount);}
//	template<> T DecrementImpl<8>()				{return (T)::InterlockedDecrement64((volatile LONGLONG*)&m_iCount);}
//	template<> T FetchAddImpl<8>(T iCount)		{return (T)::InterlockedExchangeAdd64((volatile LONGLONG*)&m_iCount, iCount);}
//	template<> T FetchSubImpl<8>(T iCount)		{return (T)::InterlockedExchangeAdd64((volatile LONGLONG*)&m_iCount, -iCount);}
//#endif

protected:
	volatile T m_iCount;
};

template<typename T> class CUnsafeCounterT
{
public:
	T Increment()				{return ++m_iCount;}
	T Decrement()				{return --m_iCount;}
	T AddFetch(T iCount)		{return m_iCount += iCount;}
	T SubFetch(T iCount)		{return m_iCount -= iCount;}
	T FetchAdd(T iCount)		{T rs = m_iCount; m_iCount += iCount; return rs;}
	T FetchSub(T iCount)		{T rs = m_iCount; m_iCount -= iCount; return rs;}

	T SetCount(T iCount)		{return (m_iCount = iCount);}
	T ResetCount()				{return SetCount(0);}
	T GetCount()				{return m_iCount;}

	T operator ++ ()			{return Increment();}
	T operator -- ()			{return Decrement();}
	T operator ++ (int)			{return FetchAdd(1);}
	T operator -- (int)			{return FetchSub(1);}
	T operator += (T iCount)	{return AddFetch(iCount);}
	T operator -= (T iCount)	{return SubFetch(iCount);}
	T operator  = (T iCount)	{return SetCount(iCount);}
	operator T	  ()			{return GetCount();}

public:
	CUnsafeCounterT(T iCount = 0) : m_iCount(iCount) {}

protected:
	T m_iCount;
};

template<class CCounter> class CLocalCounter
{
public:
	CLocalCounter(CCounter& obj) : m_counter(obj) {m_counter.Increment();}
	~CLocalCounter() {m_counter.Decrement();}
private:
	CCounter& m_counter;
};

typedef CSafeCounterT<INT>					CSafeCounter;
typedef CSafeCounterT<LONGLONG>				CSafeBigCounter;
typedef CUnsafeCounterT<INT>				CUnsafeCounter;
typedef CUnsafeCounterT<LONGLONG>			CUnsafeBigCounter;

typedef CLocalCounter<CSafeCounter>			CLocalSafeCounter;
typedef CLocalCounter<CSafeBigCounter>		CLocalSafeBigCounter;
typedef CLocalCounter<CUnsafeCounter>		CLocalUnsafeCounter;
typedef CLocalCounter<CUnsafeBigCounter>	CLocalUnsafeBigCounter;
