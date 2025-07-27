#pragma once
#include "AudioRender.h"
#include "AudioCapture.h"

// CSpeakerDlg �Ի���

enum
{
	TOKEN_SPEAK_STOP,				// �ر�����������
	TOKEN_SEND_SPEAK_START,				//���ͱ���������
	TOKEN_SEND_SPEAK_STOP,				//�رշ��ͱ���������
	TOKEN_SPEAK_DATA,				// ��������������
};

class CSpeakerDlg : public CDialog
{
public:
	CSpeakerDlg(CWnd* pParent = NULL, ISocketBase* IOCPServer = NULL, ClientContext* ContextObject = NULL);   // ��׼���캯��
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
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��
	virtual void PostNcDestroy();
	virtual void OnCancel();
	DECLARE_MESSAGE_MAP()
public:
	BOOL m_bOnClose;
	BOOL m_bSend; // �Ƿ��ͱ���������Զ��
	virtual BOOL OnInitDialog();

	afx_msg void OnBnClickedRrmoteOn();
	afx_msg void OnBnClickedRrmoteOff();
	afx_msg void OnBnClickedSendOn();
	afx_msg void OnBnClickedSendOff();
};
