#include "stdafx.h"
#include "TKYLockRW.h"



/* TKYLockRW - 多读单写锁类 */

 // ---------------- 构造函数和析构函数 ----------------
 // 构造函数
TKYLockRW::TKYLockRW()
{
	// 初始化
	FReadingCount = 0;
	FWritingCount = 0;
	FWaitingReadCount = 0;
	FWaitingWriteCount = 0;

	// 创建临界区和读写者事件
	InitializeCriticalSection(&FRWLock);
	FReaderEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	FWriterEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
}

// 析构函数
TKYLockRW::~TKYLockRW()
{
	// 置释放标志
	Lock();
	bool bWaiting = (FReadingCount > 0) || (FWritingCount == 1)
		|| (FWaitingReadCount > 0)
		|| (FWaitingWriteCount > 0);
	FReadingCount = -1;
	Unlock();

	// 等待一会儿
	if (bWaiting)
		Sleep(10);

	// 释放临界区和读写者事件
	CloseHandle(FReaderEvent);
	CloseHandle(FWriterEvent);
	DeleteCriticalSection(&FRWLock);
}

// ---------------- 私有方法 ----------------
// 设置读信号
inline void TKYLockRW::SetReadSignal()
{
	// FWritingCount 作为读信号广播的个数
	if (FWritingCount == 0)
		FWritingCount = -FWaitingReadCount;

	// 是否需要继续广播
	if (FWritingCount < 0)
	{
		FWritingCount++;
		FReadingCount++;
		FWaitingReadCount--;

		SetEvent(FReaderEvent);
	}
}

// 设置写信号
inline void TKYLockRW::SetWriteSignal()
{
	FWritingCount = 1;
	FWaitingWriteCount--;

	SetEvent(FWriterEvent);
}

// ---------------- 公有方法 ----------------
// 读加锁
bool TKYLockRW::LockRead()
{
	bool result = true;
	bool bWaiting = false;

	// 读数加 1
	Lock();
	if (FReadingCount == -1)      // 释放标志
		result = false;
	else if ((FWritingCount == 1) || (FWaitingWriteCount > 0))
	{
		FWaitingReadCount++;
		bWaiting = true;
	}
	else
		FReadingCount++;
	Unlock();

	// 判断是否等待读信号
	if (bWaiting)
	{
		// 等待读信号
		result = (WaitForSingleObject(FReaderEvent, INFINITE) == WAIT_OBJECT_0);

		if (result)
		{
			// 若广播个数不为零则继续置信号
			Lock();
			if (FWritingCount < 0)
				SetReadSignal();
			Unlock();
		}
	}

	// 返回结果
	return result;
}

// 写加锁
bool TKYLockRW::LockWrite()
{
	bool result = true;
	bool bWaiting = false;

	// 写数置 1
	Lock();
	if (FReadingCount == -1)      // 释放标志
		result = false;
	else if ((FWritingCount == 1) || (FReadingCount > 0))
	{
		FWaitingWriteCount++;
		bWaiting = true;
	}
	else
		FWritingCount = 1;
	Unlock();

	// 判断是否等待写信号
	if (bWaiting)
		result = (WaitForSingleObject(FWriterEvent, INFINITE) == WAIT_OBJECT_0);

	// 返回结果
	return result;
}

// 读试着加锁
bool TKYLockRW::TryLockRead()
{
	bool result = true;

	// 读数加 1
	Lock();
	if ((FReadingCount == -1) || (FWritingCount == 1)
		|| (FWaitingWriteCount > 0))
		result = false;
	else
		FReadingCount++;
	Unlock();

	// 返回结果
	return result;
}

// 写试着加锁
bool TKYLockRW::TryLockWrite()
{
	bool result = true;

	// 写数置 1
	Lock();
	if ((FReadingCount == -1) || (FWritingCount == 1)
		|| (FReadingCount > 0))
		result = false;
	else
		FWritingCount = 1;
	Unlock();

	// 返回结果
	return result;
}

// 读解锁
void TKYLockRW::UnlockRead()
{
	Lock();
	if (FReadingCount > 0)
	{
		// 读数减 1
		FReadingCount--;

		// 置读/写信号
		if (FReadingCount == 0)
		{
			if (FWaitingWriteCount > 0)
				SetWriteSignal();
			else
				SetReadSignal();
		}
	}
	Unlock();
}

// 写解锁
void TKYLockRW::UnlockWrite()
{
	Lock();
	if (FWritingCount == 1)
	{
		// 写数置 0
		FWritingCount = 0;

		// 置读/写信号
		if (FWaitingWriteCount > FWaitingReadCount)
			SetWriteSignal();
		else
			SetReadSignal();
	}
	Unlock();
}