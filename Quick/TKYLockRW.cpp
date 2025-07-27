#include "stdafx.h"
#include "TKYLockRW.h"



/* TKYLockRW - �����д���� */

 // ---------------- ���캯������������ ----------------
 // ���캯��
TKYLockRW::TKYLockRW()
{
	// ��ʼ��
	FReadingCount = 0;
	FWritingCount = 0;
	FWaitingReadCount = 0;
	FWaitingWriteCount = 0;

	// �����ٽ����Ͷ�д���¼�
	InitializeCriticalSection(&FRWLock);
	FReaderEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	FWriterEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
}

// ��������
TKYLockRW::~TKYLockRW()
{
	// ���ͷű�־
	Lock();
	bool bWaiting = (FReadingCount > 0) || (FWritingCount == 1)
		|| (FWaitingReadCount > 0)
		|| (FWaitingWriteCount > 0);
	FReadingCount = -1;
	Unlock();

	// �ȴ�һ���
	if (bWaiting)
		Sleep(10);

	// �ͷ��ٽ����Ͷ�д���¼�
	CloseHandle(FReaderEvent);
	CloseHandle(FWriterEvent);
	DeleteCriticalSection(&FRWLock);
}

// ---------------- ˽�з��� ----------------
// ���ö��ź�
inline void TKYLockRW::SetReadSignal()
{
	// FWritingCount ��Ϊ���źŹ㲥�ĸ���
	if (FWritingCount == 0)
		FWritingCount = -FWaitingReadCount;

	// �Ƿ���Ҫ�����㲥
	if (FWritingCount < 0)
	{
		FWritingCount++;
		FReadingCount++;
		FWaitingReadCount--;

		SetEvent(FReaderEvent);
	}
}

// ����д�ź�
inline void TKYLockRW::SetWriteSignal()
{
	FWritingCount = 1;
	FWaitingWriteCount--;

	SetEvent(FWriterEvent);
}

// ---------------- ���з��� ----------------
// ������
bool TKYLockRW::LockRead()
{
	bool result = true;
	bool bWaiting = false;

	// ������ 1
	Lock();
	if (FReadingCount == -1)      // �ͷű�־
		result = false;
	else if ((FWritingCount == 1) || (FWaitingWriteCount > 0))
	{
		FWaitingReadCount++;
		bWaiting = true;
	}
	else
		FReadingCount++;
	Unlock();

	// �ж��Ƿ�ȴ����ź�
	if (bWaiting)
	{
		// �ȴ����ź�
		result = (WaitForSingleObject(FReaderEvent, INFINITE) == WAIT_OBJECT_0);

		if (result)
		{
			// ���㲥������Ϊ����������ź�
			Lock();
			if (FWritingCount < 0)
				SetReadSignal();
			Unlock();
		}
	}

	// ���ؽ��
	return result;
}

// д����
bool TKYLockRW::LockWrite()
{
	bool result = true;
	bool bWaiting = false;

	// д���� 1
	Lock();
	if (FReadingCount == -1)      // �ͷű�־
		result = false;
	else if ((FWritingCount == 1) || (FReadingCount > 0))
	{
		FWaitingWriteCount++;
		bWaiting = true;
	}
	else
		FWritingCount = 1;
	Unlock();

	// �ж��Ƿ�ȴ�д�ź�
	if (bWaiting)
		result = (WaitForSingleObject(FWriterEvent, INFINITE) == WAIT_OBJECT_0);

	// ���ؽ��
	return result;
}

// �����ż���
bool TKYLockRW::TryLockRead()
{
	bool result = true;

	// ������ 1
	Lock();
	if ((FReadingCount == -1) || (FWritingCount == 1)
		|| (FWaitingWriteCount > 0))
		result = false;
	else
		FReadingCount++;
	Unlock();

	// ���ؽ��
	return result;
}

// д���ż���
bool TKYLockRW::TryLockWrite()
{
	bool result = true;

	// д���� 1
	Lock();
	if ((FReadingCount == -1) || (FWritingCount == 1)
		|| (FReadingCount > 0))
		result = false;
	else
		FWritingCount = 1;
	Unlock();

	// ���ؽ��
	return result;
}

// ������
void TKYLockRW::UnlockRead()
{
	Lock();
	if (FReadingCount > 0)
	{
		// ������ 1
		FReadingCount--;

		// �ö�/д�ź�
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

// д����
void TKYLockRW::UnlockWrite()
{
	Lock();
	if (FWritingCount == 1)
	{
		// д���� 0
		FWritingCount = 0;

		// �ö�/д�ź�
		if (FWaitingWriteCount > FWaitingReadCount)
			SetWriteSignal();
		else
			SetReadSignal();
	}
	Unlock();
}