// Buffer.cpp: implementation of the CBuffer class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "Buffer.h"
#include "Math.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

//���캯��
CBuffer::CBuffer(void)
{
	m_nSize = 0;
	m_pPtr = m_pBase = NULL;
}
//��������
CBuffer::~CBuffer(void)
{
	
	if (m_pBase)
		VirtualFree(m_pBase, 0, MEM_RELEASE);		//�ͷ��ڴ�
}


void CBuffer::FreeBuffer()
{
	if (m_pBase)
		VirtualFree(m_pBase, 0, MEM_RELEASE);		//�ͷ��ڴ�
	m_nSize = 0;
	m_pPtr = m_pBase = NULL;
}

//д���ݵ�������
BOOL CBuffer::Write(PBYTE pData, UINT nSize, BOOL bXORrecoder, byte* password )
{
	//�����ڴ�
	ReAllocateBuffer(nSize + GetBufferLen());
	CopyMemory(m_pPtr, pData, nSize);

	if (bXORrecoder)
	{
		for (int i = 0, j = 0; i < (int)nSize; i++)   //����
		{
			((char*)m_pPtr)[i] ^= (password[j++]) % 456 + 54;
			if (i % (10) == 0)
				j = 0;
		}
	}
	m_pPtr += nSize;

	return nSize;
}

//�������ݵ���������
BOOL  CBuffer::Insert(PBYTE pData, UINT nSize)
{
	ReAllocateBuffer(nSize + GetBufferLen());

	MoveMemory(m_pBase + nSize, m_pBase, GetMemSize() - nSize);
	CopyMemory(m_pBase, pData, nSize);


	m_pPtr += nSize;

	return nSize;
}
//�ӻ������ж�ȡ���ݺ�ɾ������ʲô
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
///����phyical������ڴ滺����
UINT CBuffer::GetMemSize()
{
	return m_nSize;
}
//�����������ݳ���
UINT CBuffer::GetBufferLen()
{
	if (m_pBase == NULL)
		return 0;

	int nSize =
		int(m_pPtr - m_pBase);				  //���еĳ���
	return nSize;
}

//���·��仺����
UINT  CBuffer::ReAllocateBuffer(UINT nRequestedSize)
{
	if (nRequestedSize < GetMemSize())//�����Ҫ����Ŀռ�С�ڻ������Ѿ�����Ŀռ䣬���أ����еĿռ��������
		return 0;

	// �����µĴ�С 
	UINT nNewSize = (UINT)ceil(nRequestedSize / 1024.0) * 1024;

	// �����ڴ�ռ�
	PBYTE pNewBuffer = (PBYTE)VirtualAlloc(NULL,  //Ҫ������ڴ�����ĵ�ַ  ������������NULL��ϵͳ������������ڴ������λ��
		nNewSize, //  ����Ĵ�С
		MEM_COMMIT,  // ���������  MEM_COMMITΪָ����ַ�ռ��ύ�����ڴ�
		PAGE_READWRITE); //���ڴ�ĳ�ʼ��������PAGE_READWRITEӦ�ó�����Զ�д��

	UINT nBufferLen = GetBufferLen();//��ȡ��ǰ�ڴ�ռ�
	//�����ڴ�  
	CopyMemory(pNewBuffer,   //�·�����ڴ��ַ
		m_pBase, //������Դ�����ݵ�ַ
		nBufferLen); //���ݳ���

	if (m_pBase)
		VirtualFree(m_pBase, 0, MEM_RELEASE);//�ͷ�Դ�е������ڴ�

	//��������ָ�����ַ
	m_pBase = pNewBuffer;

	//����ƫ�Ƶ�ַ ָ���ڴ�β��
	m_pPtr = m_pBase + nBufferLen;
	//�ڴ泤��
	m_nSize = nNewSize;

	return m_nSize;
}
//�������
UINT  CBuffer::DeAllocateBuffer(UINT nRequestedSize)
{
	if (nRequestedSize < GetBufferLen())
		return 0;

	// �����µĴ�С 
	UINT nNewSize = (UINT)ceil(nRequestedSize / 1024.0) * 1024;

	if (nNewSize < GetMemSize()) //��ֹ���
		return 0;

	// �����ڴ�ռ�
	PBYTE pNewBuffer = (PBYTE)VirtualAlloc(NULL,//Ҫ������ڴ�����ĵ�ַ  ������������NULL��ϵͳ������������ڴ������λ��
		nNewSize, //����Ĵ�С
		MEM_COMMIT, //���������  MEM_COMMITΪָ����ַ�ռ��ύ�����ڴ�
		PAGE_READWRITE);//���ڴ�ĳ�ʼ��������PAGE_READWRITEӦ�ó�����Զ�д��

	UINT nBufferLen = GetBufferLen();//��ȡ��ǰ�ڴ�ռ�
	//�����ڴ�  
	CopyMemory(pNewBuffer,  //�·�����ڴ��ַ
		m_pBase,  //������Դ�����ݵ�ַ
		nBufferLen);// ���ݳ���

	VirtualFree(m_pBase, 0, MEM_RELEASE); //�ͷ�Դ�е������ڴ�

	//��������ָ�����ַ
	m_pBase = pNewBuffer;

	//����ƫ�Ƶ�ַ ָ���ڴ�β��
	m_pPtr = m_pBase + nBufferLen;
	//�ڴ泤��
	m_nSize = nNewSize;

	return m_nSize;
}
//���/���û���
void  CBuffer::ClearBuffer()
{
	//�����ڴ�ָ�뵽�ײ�λ
	m_pPtr = m_pBase;

	DeAllocateBuffer(1024);
}


//��һ����������Ƶ���һ���ط�
void  CBuffer::Copy(CBuffer& buffer)
{
	int nReSize = buffer.GetMemSize();
	int nSize = buffer.GetBufferLen();
	ClearBuffer();
	ReAllocateBuffer(nReSize);
	m_pPtr = m_pBase + nSize;
	CopyMemory(m_pBase, buffer.GetBuffer(), buffer.GetBufferLen());
}
//����һ��ָ������������ڴ��ָ��
PBYTE  CBuffer::GetBuffer(UINT nPos)
{
	return m_pBase + nPos;
}
//�ӻ�������ɾ������,��ɾ����
UINT  CBuffer::Delete(UINT nSize)
{
	//���ɾ���ĳ��ȴ��ڻ��������Ȼ�ɾ��ɶ
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
