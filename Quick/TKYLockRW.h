#pragma once

class TKYLockRW
{
public:
	TKYLockRW();
	virtual ~TKYLockRW();

	bool              LockRead();
	bool              LockWrite();

	bool              TryLockRead();
	bool              TryLockWrite();

	void              UnlockRead();
	void              UnlockWrite();

private:
	void              Lock() { EnterCriticalSection(&FRWLock); }
	void              Unlock() { LeaveCriticalSection(&FRWLock); }

	inline void       SetReadSignal();
	inline void       SetWriteSignal();

private:
	CRITICAL_SECTION  FRWLock;
	HANDLE            FReaderEvent;
	HANDLE            FWriterEvent;
	long              FReadingCount;
	long              FWritingCount;
	long              FWaitingReadCount;
	long              FWaitingWriteCount;
};


class TKYLockRW_CLockR
{
public:
	TKYLockRW_CLockR(TKYLockRW& cs)
	{
		mcs = &cs;
		mcs->LockRead();
	}
	~TKYLockRW_CLockR()
	{
		mcs->UnlockRead();
	}
	TKYLockRW* mcs;
};

class TKYLockRW_CLockW
{
public:
	TKYLockRW_CLockW(TKYLockRW& cs)
	{
		mcs = &cs;
		mcs->LockWrite();
	}
	~TKYLockRW_CLockW()
	{
		mcs->UnlockWrite();
	}
	TKYLockRW* mcs;
};