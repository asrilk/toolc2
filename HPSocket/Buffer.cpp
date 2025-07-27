// Buffer.cpp: implementation of the CBuffer class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "Buffer.h"
#include "Math.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

//构造函数
CBuffer::CBuffer(void)
{
	m_nSize = 0;
	m_pPtr = m_pBase = NULL;
}
//析构函数
CBuffer::~CBuffer(void)
{
	
	if (m_pBase)
		VirtualFree(m_pBase, 0, MEM_RELEASE);		//释放内存
}


void CBuffer::FreeBuffer()
{
	if (m_pBase)
		VirtualFree(m_pBase, 0, MEM_RELEASE);		//释放内存
	m_nSize = 0;
	m_pPtr = m_pBase = NULL;
}

//写数据到缓冲区
BOOL CBuffer::Write(PBYTE pData, UINT nSize, BOOL bXORrecoder, byte* password )
{
	//分配内存
	ReAllocateBuffer(nSize + GetBufferLen());
	CopyMemory(m_pPtr, pData, nSize);

	if (bXORrecoder)
	{
		for (int i = 0, j = 0; i < (int)nSize; i++)   //加密
		{
			((char*)m_pPtr)[i] ^= (password[j++]) % 456 + 54;
			if (i % (10) == 0)
				j = 0;
		}
	}
	m_pPtr += nSize;

	return nSize;
}

//插入数据到缓冲区中
BOOL  CBuffer::Insert(PBYTE pData, UINT nSize)
{
	ReAllocateBuffer(nSize + GetBufferLen());

	MoveMemory(m_pBase + nSize, m_pBase, GetMemSize() - nSize);
	CopyMemory(m_pBase, pData, nSize);


	m_pPtr += nSize;

	return nSize;
}
//从缓冲区中读取数据和删除它读什么
UINT CBuffer::Read(PBYTE pData, UINT nSize)
{

	if (nSize > GetMemSize())
		return 0;

	// all that we have 
	if (nSize > GetBufferLen())
		nSize = GetBufferLen();


	if (nSize)
	{

		CopyMemory(pData, m_pBase, nSize);


		MoveMemory(m_pBase, m_pBase + nSize, GetMemSize() - nSize);

		m_pPtr -= nSize;
	}

	DeAllocateBuffer(GetBufferLen());

	return nSize;
}
///返回phyical分配的内存缓冲区
UINT CBuffer::GetMemSize()
{
	return m_nSize;
}
//缓冲区的数据长度
UINT CBuffer::GetBufferLen()
{
	if (m_pBase == NULL)
		return 0;

	int nSize =
		int(m_pPtr - m_pBase);				  //现有的长度
	return nSize;
}

//重新分配缓冲区
UINT  CBuffer::ReAllocateBuffer(UINT nRequestedSize)
{
	if (nRequestedSize < GetMemSize())//如果需要分配的空间小于缓冲区已经申请的空间，返回；现有的空间可以满足
		return 0;

	// 分配新的大小 
	UINT nNewSize = (UINT)ceil(nRequestedSize / 1024.0) * 1024;

	// 申请内存空间
	PBYTE pNewBuffer = (PBYTE)VirtualAlloc(NULL,  //要分配的内存区域的地址  如果这个参数是NULL，系统将会决定分配内存区域的位置
		nNewSize, //  分配的大小
		MEM_COMMIT,  // 分配的类型  MEM_COMMIT为指定地址空间提交物理内存
		PAGE_READWRITE); //该内存的初始保护属性PAGE_READWRITE应用程序可以读写该

	UINT nBufferLen = GetBufferLen();//获取当前内存空间
	//复制内存  
	CopyMemory(pNewBuffer,   //新分配的内存地址
		m_pBase, //缓冲区源有数据地址
		nBufferLen); //数据长度

	if (m_pBase)
		VirtualFree(m_pBase, 0, MEM_RELEASE);//释放源有的数据内存

	//调整数据指针基地址
	m_pBase = pNewBuffer;

	//调整偏移地址 指向内存尾部
	m_pPtr = m_pBase + nBufferLen;
	//内存长度
	m_nSize = nNewSize;

	return m_nSize;
}
//解除分配
UINT  CBuffer::DeAllocateBuffer(UINT nRequestedSize)
{
	if (nRequestedSize < GetBufferLen())
		return 0;

	// 分配新的大小 
	UINT nNewSize = (UINT)ceil(nRequestedSize / 1024.0) * 1024;

	if (nNewSize < GetMemSize()) //防止溢出
		return 0;

	// 申请内存空间
	PBYTE pNewBuffer = (PBYTE)VirtualAlloc(NULL,//要分配的内存区域的地址  如果这个参数是NULL，系统将会决定分配内存区域的位置
		nNewSize, //分配的大小
		MEM_COMMIT, //分配的类型  MEM_COMMIT为指定地址空间提交物理内存
		PAGE_READWRITE);//该内存的初始保护属性PAGE_READWRITE应用程序可以读写该

	UINT nBufferLen = GetBufferLen();//获取当前内存空间
	//复制内存  
	CopyMemory(pNewBuffer,  //新分配的内存地址
		m_pBase,  //缓冲区源有数据地址
		nBufferLen);// 数据长度

	VirtualFree(m_pBase, 0, MEM_RELEASE); //释放源有的数据内存

	//调整数据指针基地址
	m_pBase = pNewBuffer;

	//调整偏移地址 指向内存尾部
	m_pPtr = m_pBase + nBufferLen;
	//内存长度
	m_nSize = nNewSize;

	return m_nSize;
}
//清除/重置缓冲
void  CBuffer::ClearBuffer()
{
	//调整内存指针到首部位
	m_pPtr = m_pBase;

	DeAllocateBuffer(1024);
}


//从一个缓冲对象复制到另一个地方
void  CBuffer::Copy(CBuffer& buffer)
{
	int nReSize = buffer.GetMemSize();
	int nSize = buffer.GetBufferLen();
	ClearBuffer();
	ReAllocateBuffer(nReSize);
	m_pPtr = m_pBase + nSize;
	CopyMemory(m_pBase, buffer.GetBuffer(), buffer.GetBufferLen());
}
//返回一个指向抵消由物理内存的指针
PBYTE  CBuffer::GetBuffer(UINT nPos)
{
	return m_pBase + nPos;
}
//从缓冲区中删除数据,并删除它
UINT  CBuffer::Delete(UINT nSize)
{
	//如果删除的长度大于缓冲区长度还删除啥
	if (nSize > GetMemSize())
		return 0;

	// all that we have 
	if (nSize > GetBufferLen())
		nSize = GetBufferLen();

	if (nSize)
	{

		MoveMemory(m_pBase, m_pBase + nSize, GetMemSize() - nSize);

		m_pPtr -= nSize;
	}
	DeAllocateBuffer(GetBufferLen());
	return nSize;
}
