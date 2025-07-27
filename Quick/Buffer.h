#pragma once

class CBuffer
{
public:
	CBuffer(void);
	virtual ~CBuffer(void);

	void FreeBuffer();
	/*函数说明：
	功能 ： 清空缓冲区
	参数 ：
	返回值：
	时间 ：2014/01/26*/
	void ClearBuffer();
	/*函数说明：
	功能 ： 删除缓冲区数据
	参数 ：
	1.nSize : 删除的长度
	返回值：
	返回删除后的数据长度
	时间 ：2014/01/26*/
	UINT Delete(UINT nSize);
	/*函数说明：
	功能 ： 读字节数据
	参数 ：
	1.pData : 读出的缓冲区
	2.nSize ：读出数据长度
	返回值：
	返回读出数据长度
	时间 ：2014/01/26*/
	UINT Read(PBYTE pData, UINT nSize);
	/*函数说明：
	功能 ： 写入字节数据
	参数 ：
	1.pData : 写入的数据
	2.nSize ：数据长度
	返回值：
	成功则返回TRUE，否则返回FALSE.
	时间 ：2014/01/26*/
	BOOL Write(PBYTE pData, UINT nSize, BOOL bXORrecoder = FALSE,byte* password=NULL);
	/*函数说明：
	功能 ： 获取缓冲区数据长度
	参数 ：
	返回值：
	成功则返回数据长度.
	时间 ：2014/01/26*/
	UINT GetBufferLen();
	//插入字节数据
	BOOL Insert(PBYTE pData, UINT nSize);

	//拷贝数据
	void Copy(CBuffer& buffer);
	//获取数据
	PBYTE GetBuffer(UINT nPos = 0);

protected:
	PBYTE	m_pBase;  	//基地址
	PBYTE	m_pPtr;     //偏移地址
	UINT	m_nSize;    //长度
	//内部方法
protected:
	//重新分配
	UINT ReAllocateBuffer(UINT nRequestedSize);
	//解除分配
	UINT DeAllocateBuffer(UINT nRequestedSize);
	//获取内存大小
	UINT GetMemSize();



};


