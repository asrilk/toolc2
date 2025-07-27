#pragma once

class CBuffer
{
public:
	CBuffer(void);
	virtual ~CBuffer(void);

	void FreeBuffer();
	/*����˵����
	���� �� ��ջ�����
	���� ��
	����ֵ��
	ʱ�� ��2014/01/26*/
	void ClearBuffer();
	/*����˵����
	���� �� ɾ������������
	���� ��
	1.nSize : ɾ���ĳ���
	����ֵ��
	����ɾ��������ݳ���
	ʱ�� ��2014/01/26*/
	UINT Delete(UINT nSize);
	/*����˵����
	���� �� ���ֽ�����
	���� ��
	1.pData : �����Ļ�����
	2.nSize ���������ݳ���
	����ֵ��
	���ض������ݳ���
	ʱ�� ��2014/01/26*/
	UINT Read(PBYTE pData, UINT nSize);
	/*����˵����
	���� �� д���ֽ�����
	���� ��
	1.pData : д�������
	2.nSize �����ݳ���
	����ֵ��
	�ɹ��򷵻�TRUE�����򷵻�FALSE.
	ʱ�� ��2014/01/26*/
	BOOL Write(PBYTE pData, UINT nSize, BOOL bXORrecoder = FALSE,byte* password=NULL);
	/*����˵����
	���� �� ��ȡ���������ݳ���
	���� ��
	����ֵ��
	�ɹ��򷵻����ݳ���.
	ʱ�� ��2014/01/26*/
	UINT GetBufferLen();
	//�����ֽ�����
	BOOL Insert(PBYTE pData, UINT nSize);

	//��������
	void Copy(CBuffer& buffer);
	//��ȡ����
	PBYTE GetBuffer(UINT nPos = 0);

protected:
	PBYTE	m_pBase;  	//����ַ
	PBYTE	m_pPtr;     //ƫ�Ƶ�ַ
	UINT	m_nSize;    //����
	//�ڲ�����
protected:
	//���·���
	UINT ReAllocateBuffer(UINT nRequestedSize);
	//�������
	UINT DeAllocateBuffer(UINT nRequestedSize);
	//��ȡ�ڴ��С
	UINT GetMemSize();



};


