
#pragma once

class CPrivateHeapImpl
{
public:
	PVOID Alloc(SIZE_T dwSize, DWORD dwFlags = 0)
		{return ::HeapAlloc(m_hHeap, dwFlags, dwSize);}

	PVOID ReAlloc(PVOID pvMemory, SIZE_T dwSize, DWORD dwFlags = 0)
		{return ::HeapReAlloc(m_hHeap, dwFlags, pvMemory, dwSize);}

	SIZE_T Size(PVOID pvMemory, DWORD dwFlags = 0)
		{return ::HeapSize(m_hHeap, dwFlags, pvMemory);}

	BOOL Free(PVOID pvMemory, DWORD dwFlags = 0)
		{return ::HeapFree(m_hHeap, dwFlags, pvMemory);}

	SIZE_T Compact(DWORD dwFlags = 0)
		{return ::HeapCompact(m_hHeap, dwFlags);}

	BOOL IsValid() {return m_hHeap != nullptr;}

	BOOL Reset()
	{
		if(IsValid()) ::HeapDestroy(m_hHeap);
		m_hHeap = ::HeapCreate(m_dwOptions, m_dwInitSize, m_dwMaxSize);

		return IsValid();
	}

public:
	CPrivateHeapImpl(DWORD dwOptions = 0, SIZE_T dwInitSize = 0, SIZE_T dwMaxSize = 0)
	: m_dwOptions(dwOptions | HEAP_GENERATE_EXCEPTIONS), m_dwInitSize(dwInitSize), m_dwMaxSize(dwMaxSize)
	{
		m_hHeap = ::HeapCreate(m_dwOptions, m_dwInitSize, m_dwMaxSize);
		ENSURE(IsValid());
	}

	~CPrivateHeapImpl	()	{if(IsValid()) ::HeapDestroy(m_hHeap);}

	operator HANDLE	()	{return m_hHeap;}

private:
	CPrivateHeapImpl(const CPrivateHeapImpl&);
	CPrivateHeapImpl operator = (const CPrivateHeapImpl&);

private:
	HANDLE	m_hHeap;
	DWORD	m_dwOptions;
	SIZE_T	m_dwInitSize;
	SIZE_T	m_dwMaxSize;
};

#ifndef _NOT_USE_PRIVATE_HEAP
	typedef CPrivateHeapImpl	CPrivateHeap;
#else
	typedef CGlobalHeapImpl		CPrivateHeap;
#endif

template<class T> class CPrivateHeapBuffer
{
public:
	CPrivateHeapBuffer(CPrivateHeap& hpPrivate, SIZE_T dwSize = 0)
	: m_hpPrivate	(hpPrivate)
	, m_pvMemory	(nullptr)
	{
		ASSERT(m_hpPrivate.IsValid());
		Alloc(dwSize);
	}

	~CPrivateHeapBuffer() {Free();}

public:
	T* Alloc(SIZE_T dwSize, DWORD dwFlags = 0)
	{
		if(IsValid())
			Free();

		if(dwSize > 0)
			m_pvMemory = (T*)m_hpPrivate.Alloc(dwSize * sizeof(T), dwFlags);

		return m_pvMemory;
	}

	T* ReAlloc(SIZE_T dwSize, DWORD dwFlags = 0)
		{return m_pvMemory = (T*)m_hpPrivate.ReAlloc(m_pvMemory, dwSize * sizeof(T), dwFlags);}

	SIZE_T Size(DWORD dwFlags = 0)
		{return m_hpPrivate.Size(m_pvMemory, dwFlags) / sizeof(T);}

	BOOL Free(DWORD dwFlags = 0)
	{
		BOOL isOK = TRUE;

		if(IsValid())
		{
			isOK		= m_hpPrivate.Free(m_pvMemory, dwFlags);
			m_pvMemory	= nullptr;
		}

		return isOK;
	}

	BOOL IsValid()					{return m_pvMemory != nullptr;}
	operator T* ()			const	{return m_pvMemory;}
	T& operator [] (int i)	const	{return *(m_pvMemory + i);}

private:
	CPrivateHeapBuffer(const CPrivateHeapBuffer&);
	CPrivateHeapBuffer operator = (const CPrivateHeapBuffer&);

private:
	CPrivateHeap&	m_hpPrivate;
	T*				m_pvMemory;
};

typedef CPrivateHeapBuffer<BYTE>	CPrivateHeapByteBuffer;
typedef CPrivateHeapBuffer<TCHAR>	CPrivateHeapStrBuffer;
