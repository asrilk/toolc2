
#pragma once


/////////////////////////////////////////////////////////////////////////////
// CDDOSAttackDlg dialog

#include "WebAttackDlg.h"
#include "FlowAttackDlg.h"


enum
{
	COMMAND_NEXT_DDOS,
	COMMAND_DDOS_ATTACK,
	COMMAND_DDOS_STOP,
};








class CDDOSAttackDlg : public CXTPResizeFormView
{
	DECLARE_DYNCREATE(CDDOSAttackDlg)
	// Construction
public:
#ifdef AFX_DESIGN_TIME
	enum {
		IDD = IDD_ATTACK_DIALOG
};
#endif
#ifdef _DEBUG
	virtual void AssertValid() const;
#ifndef _WIN32_WCE
	virtual void Dump(CDumpContext& dc) const;
#endif
#endif


	CDDOSAttackDlg();   // standard constructor
	virtual ~CDDOSAttackDlg();
	virtual void OnInitialUpdate();
	WORD SendDDosAttackCommand(LPATTACK m_Attack, INT HostNums, WORD iTaskID);
	WORD SendDDostStopCommand(WORD iTaskID);

	void StatusTextOut(int iPane, LPCTSTR ptzFormat, ...);
	VOID InitailizeStatus();
	VOID SetSocketPoint(ISocketBase* pIOCPServer = NULL);
	VOID AddClient(ClientContext* pContext);
	VOID DelClient(ClientContext* pContext);


	// Dialog Data
		//{{AFX_DATA(CDDOSAttackDlg)

	CTabCtrl	m_TabCtrl;
	CXTPListCtrl	m_ClientList;
	CXTHeaderCtrl   m_heades;
	ISocketBase* m_iocpServer;

	//}}AFX_DATA

	int             m_nSortedCol;
	bool            m_bAscending;
// Overrides
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CDDOSAttackDlg)
protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	virtual BOOL OnNotify(WPARAM wParam, LPARAM lParam, LRESULT* pResult);
	void SortColumn(int iCol, bool bAsc);
	//}}AFX_VIRTUAL

// Implementation
protected:

	// Generated message map functions
	//{{AFX_MSG(CDDOSAttackDlg)

	

	afx_msg void OnSize(UINT nType, int cx, int cy);
	afx_msg void OnSelchangeDdosAttack(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg LRESULT OnDDOSMessage(WPARAM wParam, LPARAM lParam);
	afx_msg void OnRclickList(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnDblclkList(NMHDR* pNMHDR, LRESULT* pResult);
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
private:
	CWebAttackDlg m_WebAttack;
	CFlowAttackDlg m_FlowAttack;
	CStatusBarCtrl m_wndStatusBar;

};

