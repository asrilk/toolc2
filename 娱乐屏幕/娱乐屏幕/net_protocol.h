#pragma once

#include  <stdint.h>
#include <winsock2.h>

//�̶���ʼ����
#define PACKET_START_SING  (0xffffffff)


//��Ļ����
#define PACKET_TYPE_SCREEN  0x001

//���
#define PACKET_TYPE_MOUSE_EVENT  0x02

//����
#define PACKET_TYPE_KEY_EVENT  0x03

//READY �ź�
#define PACKET_TYPE_READY  0x100

//READY �ź� �ظ�
#define PACKET_TYPE_READY_PEPLY  0x101


#pragma pack(push, 4)

//��ʼ��־+������+����+���ĳ�������  ����
struct PacketHead
{
	//0xffffffff  uint32 max
	uint32_t start_sign;

	//����
	uint32_t type;

	//���ĳ���
	uint32_t len;
};


//�����¼�������
struct KeybdEventData
{
	int VK;
	bool down;
};

//��������
struct MouseEventData
{
	 int dx;
	 int dy;

	unsigned int action;
	//����
	int wheel;
};

//Ready ���ģ��ɱ����ƶ˷������ƶˣ������� ��Ƶ�߿�
struct ReadyData
{
	unsigned int video_L;
	unsigned int video_T;

	unsigned int video_w;
	unsigned int video_h;
};


#pragma pack(pop)

