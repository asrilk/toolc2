// LogView.cpp : implementation file
//

#include "stdafx.h"
#include "Quick.h"

#include "QuickDoc.h"
#include "QuickView.h"
#include "LogView.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

CLogView* g_pLogView;

typedef struct
{
	TCHAR* title;
	int		nWidth;
}COLUMNSTRUCT;

COLUMNSTRUCT g_Log_Data[] =
{
	{_T("发生时间"),		150	},
	{_T("事件"),			50	},
	{_T("IP"),				150	},
	{_T("定位"),			150	},
	{_T("计算机名"),		80	},
	{_T("系统"),			150	},
	{_T("分组"),			80	},
	{_T("备注"),			80	},
	{_T("杀软"),			150	}
};



/////////////////////////////////////////////////////////////////////////////
// CLogView

IMPLEMENT_DYNCREATE(CLogView, CListView)

CLogView::CLogView()
{
	gLogUpdate = FALSE;
	g_pLogView = this;

	g_Log_Width = 0;
	g_Log_Count = (sizeof(g_Log_Data) / sizeof(COLUMNSTRUCT));
}

CLogView::~CLogView()
{
}


BEGIN_MESSAGE_MAP(CLogView, CListView)
	//{{AFX_MSG_MAP(CLogView)
	ON_WM_SIZE()
	ON_NOTIFY_REFLECT(NM_RCLICK, OnRclick)
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CLogView drawing

void CLogView::OnDraw(CDC* pDC)
{
	CDocument* pDoc = GetDocument();
	// TODO: add draw code here
}

/////////////////////////////////////////////////////////////////////////////
// CLogView diagnostics

#ifdef _DEBUG
void CLogView::AssertValid() const
{
	CListView::AssertValid();
}

void CLogView::Dump(CDumpContext& dc) const
{
	CListView::Dump(dc);
}
#endif //_DEBUG

/////////////////////////////////////////////////////////////////////////////
// CLogView message handlers

void CLogView::OnInitialUpdate()
{
	CListView::OnInitialUpdate();
	m_pLogList = &GetListCtrl();
	m_pLogList->SetRedraw(FALSE);
	m_pLogList->SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_ONECLICKACTIVATE | LVS_EX_SUBITEMIMAGES | LVS_EX_GRIDLINES);
	if (m_pLogList->GetHeaderCtrl()->GetItemCount() == 0)
	{
		for (int i = 0; i < g_Log_Count; i++)
		{
			m_pLogList->InsertColumn(i, g_Log_Data[i].title);
			g_Log_Width += g_Log_Data[i].nWidth; // 总宽度
		}
	}

	gLogUpdate = TRUE;

	HWND hWndHeader = m_pLogList->GetDlgItem(0)->GetSafeHwnd();
	m_pLogList->SetRedraw(TRUE);

	//主要调用OnSize函数
	CRect rect;
	this->GetWindowRect(rect);
	ScreenToClient(rect);
	this->OnSize(SIZE_RESTORED, rect.Width(), rect.Height());
}

BOOL CLogView::PreCreateWindow(CREATESTRUCT& cs)
{
	// TODO: Add your specialized code here and/or call the base class
	cs.style |= LVS_REPORT;
	return CListView::PreCreateWindow(cs);
}

void CLogView::OnSize(UINT nType, int cx, int cy)
{
	CListView::OnSize(nType, cx, cy);
	if (gLogUpdate)
	{
		m_pLogList->SetRedraw(FALSE);
		double dcx = cx - 5;     //对话框的总宽度  g_Column_cx
		if (m_pLogList != NULL)
		{
			for (int i = 0; i < g_Log_Count; i++) {                   //遍历每一个列
				double dd = g_Log_Data[i].nWidth;               //得到当前列的宽度
				dd /= g_Log_Width;                              //看一看当前宽度占总长度的几分之几
				dd *= dcx;                                         //用原来的长度乘以所占的几分之几得到当前的宽度
				m_pLogList->SetColumnWidth(i, (int)dd);          //设置当前的宽度
			}

		}
		m_pLogList->SetRedraw(TRUE);
	}

}



void CLogView::OnRclick(NMHDR* pNMHDR, LRESULT* pResult)
{
	LPNMITEMACTIVATE pNMItemActivate = reinterpret_cast<LPNMITEMACTIVATE>(pNMHDR);
	CMenu menu;
	VERIFY(menu.CreatePopupMenu());
	menu.AppendMenu(MF_STRING | MF_ENABLED, 100, _T("&(D)删除选择"));
	menu.AppendMenu(MF_SEPARATOR, NULL);
	menu.AppendMenu(MF_STRING | MF_ENABLED, 101, _T("&(A)全部删除"));
	menu.AppendMenu(MF_STRING | MF_ENABLED, 102, _T("&(B)保存选中"));
	menu.AppendMenu(MF_STRING | MF_ENABLED, 103, _T("&(C)复制选中"));
	CPoint	p;
	GetCursorPos(&p);
	int nMenuResult = menu.TrackPopupMenu(TPM_RETURNCMD | TPM_LEFTALIGN | TPM_RIGHTBUTTON, p.x, p.y, this, NULL);
	menu.DestroyMenu();
	if (!nMenuResult) 	return;

	switch (nMenuResult)
	{
	case 100:
	{
		OnEventDelete();
	}
	break;
	case 101:
	{
		OnAllDelete();
	}
	break;
	case 102:
	{
		OnEventSave();
	}
	break;
	//case 103:
	//{
	//	OnEventCopy();

	//}
	//break;
	}

	*pResult = 0;
}

void CLogView::OnEventDelete()
{
	// TODO: Add your command handler code here
	POSITION pos = m_pLogList->GetFirstSelectedItemPosition();
	if (pos == NULL)
	{
		::MessageBox(NULL, _T("请先选择要删除的事件记录 ..."), _T("提示"), MB_ICONINFORMATION);
		return;
	}
	else
	{
		while (pos)
		{
			int nItem = m_pLogList->GetNextSelectedItem(pos);
			m_pLogList->DeleteItem(nItem);
			pos = m_pLogList->GetFirstSelectedItemPosition();
		}
	}
}

void CLogView::OnAllDelete()
{
	// TODO: Add your command handler code here
	m_pLogList->DeleteAllItems();
}

void CLogView::OnEventSave()
{
	// TODO: Add your command handler code here
	POSITION pos = m_pLogList->GetFirstSelectedItemPosition();
	if (pos == NULL)
	{
		::MessageBox(NULL, _T("请先选择要保存的事件记录 ..."), _T("提示"), MB_ICONINFORMATION);
		return;
	}
	else
	{
		CTime time = CTime::GetCurrentTime(); ///构造CTime对象 
		CString strTime = time.Format(_T("%Y-%m-%d %H-%M-%S"));

		CFileDialog dlg(FALSE, _T("log"), strTime, OFN_OVERWRITEPROMPT, _T("*.log|*.log|*.txt|*.log"), NULL);
		if (dlg.DoModal() != IDOK)
			return;
		CFile file;
		if (file.Open(dlg.GetPathName(), CFile::modeCreate | CFile::modeWrite))
		{
			while (pos)
			{
				int nItem = m_pLogList->GetNextSelectedItem(pos);
				CString strTitle;
				strTitle.Format(_T(" 发生时间:%s	发生事件:%s"), m_pLogList->GetItemText(nItem, 0), m_pLogList->GetItemText(nItem, 1));
				CStringA strTitleA;
				strTitleA = strTitle;
				file.Write(strTitleA.GetBuffer(), strTitleA.GetLength() + 1);
			}
			file.Close();
			strTime = time.Format(_T("[%Y-%m-%d %H:%M:%S]")) + _T(" 日志导出成功 ...");
			::MessageBox(0, strTime, _T("提示"), MB_ICONINFORMATION);
		}
	}
}

void CLogView::OnEventCopy()
{
	// TODO: Add your command handler code here
	int nItem;
	CString strText(_T(""));
	POSITION pos = m_pLogList->GetFirstSelectedItemPosition();
	if (pos == NULL)
	{
		::MessageBox(NULL, _T("请先选择要复制的事件记录 ..."), _T("提示"), MB_ICONINFORMATION);
		return;
	}
	else
	{
		//获取所有选中项目的内容。
		while (pos)
		{
			nItem = m_pLogList->GetNextSelectedItem(pos);
			strText += m_pLogList->GetItemText(nItem, 0) + _T(" ");
			strText += m_pLogList->GetItemText(nItem, 1);
		}
		//将内容保存到剪贴板。
		if (!strText.IsEmpty())
		{
			if (!OpenClipboard()) return;
			if (!EmptyClipboard()) return;
			HGLOBAL hClipboardData = NULL;
			size_t sLen = strText.GetLength() * sizeof(TCHAR);
			hClipboardData = GlobalAlloc(GMEM_DDESHARE, (sLen + 1) * sizeof(wchar_t));
			if (!hClipboardData) return;
			wchar_t* pchData = (wchar_t*)GlobalLock(hClipboardData);
			if (!pchData) return;
			wcscpy_s(pchData, sLen + 1, strText.GetBuffer());
			if (!GlobalUnlock(hClipboardData)) return;
			SetClipboardData(CF_UNICODETEXT, hClipboardData);
			CloseClipboard();
		}
	}
}



void CLogView::InsertLogItem(LPCTSTR Text0, LPCTSTR Text1, LPCTSTR Text2, LPCTSTR Text3, LPCTSTR Text4, LPCTSTR Text5, LPCTSTR Text6,LPCTSTR Text7)
{
	char m_Text[512] = { 0 };
	CTime time = CTime::GetCurrentTime();		//构造CTime对象 

	CString strTime = time.Format(" %Y-%m-%d %H:%M:%S");
	m_pLogList->InsertItem(0, strTime, 0);
	m_pLogList->SetItemText(0, 1, Text0);  
	m_pLogList->SetItemText(0, 2, Text1);
	m_pLogList->SetItemText(0, 3, Text2);
	m_pLogList->SetItemText(0, 4, Text3);
	m_pLogList->SetItemText(0, 5, Text4);
	m_pLogList->SetItemText(0, 6, Text5);
	m_pLogList->SetItemText(0, 7, Text6);
	m_pLogList->SetItemText(0, 8, Text7);
}


















































IMPLEMENT_DYNCREATE(CPeneListView, CListView)

CPeneListView::CPeneListView()
{

}

CPeneListView::~CPeneListView()
{
}


BEGIN_MESSAGE_MAP(CPeneListView, CListView)
	//{{AFX_MSG_MAP(CPeneListView)
	ON_WM_SIZE()

	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CPeneListView drawing

void CPeneListView::OnDraw(CDC* pDC)
{
	CDocument* pDoc = GetDocument();
	// TODO: add draw code here
}

/////////////////////////////////////////////////////////////////////////////
// CPeneListView diagnostics

#ifdef _DEBUG
void CPeneListView::AssertValid() const
{
	CListView::AssertValid();
}

void CPeneListView::Dump(CDumpContext& dc) const
{
	CListView::Dump(dc);
}
#endif //_DEBUG

/////////////////////////////////////////////////////////////////////////////
// CPeneListView message handlers

void CPeneListView::OnInitialUpdate()
{
	CListView::OnInitialUpdate();
	m_pList = &GetListCtrl();
	m_pList->ShowWindow(SW_HIDE);
}

BOOL CPeneListView::PreCreateWindow(CREATESTRUCT& cs)
{
	// TODO: Add your specialized code here and/or call the base class
	cs.style |= LVS_REPORT;
	return CListView::PreCreateWindow(cs);
}

void CPeneListView::OnSize(UINT nType, int cx, int cy)
{
	CListView::OnSize(nType, cx, cy);


}









