#pragma once
#include "AudioRender.h"
#include "AudioCapture.h"

// CSpeakerDlg 对话框

enum
{
	TOKEN_SPEAK_STOP,				// 关闭扬声器监听
	TOKEN_SEND_SPEAK_START,				//发送本地扬声器
	TOKEN_SEND_SPEAK_STOP,				//关闭发送本地扬声器
	TOKEN_SPEAK_DATA,				// 接收扬声器数据
};

class CSpeakerDlg : public CDialog
{
public:
	CSpeakerDlg(CWnd* pParent = NULL, ISocketBase* IOCPServer = NULL, ClientContext* ContextObject = NULL);   // 标准构造函数
	//virtual ~CSpeakerDlg();
	enum {IDD = IDD_SPEAKER};

	ClientContext* m_pContext;
	ISocketBase* m_iocpServer;
	HICON          m_hIcon;
	long long         m_nTotalRecvBytes;
	DWORD         m_nTotalSendBytes;
	CAudioRenderImpl SetSpeakerDate;
	CAudioCapture GetSpeakerDate;

	static void CALLBACK SendData(byte* senddata, int datasize);
	void CSpeakerDlg::OnReceiveComplete(void);
	void OnReceive();

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持
	virtual void PostNcDestroy();
	virtual void OnCancel();
	DECLARE_MESSAGE_MAP()
public:
	BOOL m_bOnClose;
	BOOL m_bSend; // 是否发送本地语音到远程
	virtual BOOL OnInitDialog();

	afx_msg void OnBnClickedRrmoteOn();
	afx_msg void OnBnClickedRrmoteOff();
	afx_msg void OnBnClickedSendOn();
	afx_msg void OnBnClickedSendOff();
};
