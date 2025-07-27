
#pragma once

//#include "CriticalSection.h"
#include "Semaphore.h"

class CSWMR
{
public:
	VOID WaitToRead();
	VOID WaitToWrite();
	VOID ReadDone()  {Done();}
	VOID WriteDone() {Done();}

private:
	VOID Done();

public:
	CSWMR();
	~CSWMR();

private:
	CSWMR(const CSWMR&);
	CSWMR operator = (const CSWMR&);

private:
	int m_nWaitingReaders;
	int m_nWaitingWriters;
	int m_nActive;

	CSpinGuard	m_cs;
	CSEM		m_smRead;
	CSEM		m_smWrite;
};

class CSEMRWLock
{
public:
	VOID WaitToRead();
	VOID WaitToWrite();
	VOID ReadDone();
	VOID WriteDone();

private:
	VOID Done			(CSEM** ppSem, LONG& lCount);
	BOOL IsOwner()		{return m_dwWriterTID == ::GetCurrentThreadId();}
	VOID SetOwner()		{m_dwWriterTID = ::GetCurrentThreadId();}
	VOID DetachOwner()	{m_dwWriterTID = 0;}

public:
	CSEMRWLock();
	~CSEMRWLock();

private:
	CSEMRWLock(const CSEMRWLock&);
	CSEMRWLock operator = (const CSEMRWLock&);

private:
	int m_nWaitingReaders;
	int m_nWaitingWriters;
	int m_nActive;
	DWORD m_dwWriterTID;

	CSpinGuard	m_cs;
	CSEM		m_smRead;
	CSEM		m_smWrite;
};

template<class CLockObj> class CLocalReadLock
{
public:
	CLocalReadLock(CLockObj& obj) : m_wait(obj) {m_wait.WaitToRead();}
	~CLocalReadLock() {m_wait.ReadDone();}
private:
	CLocalReadLock(const CLocalReadLock&);
	CLocalReadLock operator = (const CLocalReadLock&);
private:
	CLockObj& m_wait;
};

template<class CLockObj> class CLocalWriteLock
{
public:
	CLocalWriteLock(CLockObj& obj) : m_wait(obj) {m_wait.WaitToWrite();}
	~CLocalWriteLock() {m_wait.WriteDone();}
private:
	CLocalWriteLock(const CLocalWriteLock&);
	CLocalWriteLock operator = (const CLocalWriteLock&);
private:
	CLockObj& m_wait;
};


	typedef CSWMR		CSimpleRWLock;
typedef CLocalReadLock<CSimpleRWLock>	CReadLock;
typedef CLocalWriteLock<CSimpleRWLock>	CWriteLock;

typedef CSEMRWLock						CRWLock;
typedef CLocalReadLock<CRWLock>			CReentrantReadLock;
typedef CLocalWriteLock<CRWLock>		CReentrantWriteLock;
