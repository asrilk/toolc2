#pragma once

#include "QuickDoc.h"

class CTabView : public CView
{
protected: // create from serialization only
	CTabView();
	DECLARE_DYNCREATE(CTabView)

		// Attributes
public:
	CQuickDoc* GetDocument();
	void UpdateDocTitle();
	BOOL AddView(CRuntimeClass* pViewClass, LPCTSTR lpszTitle);
	BOOL AddGroup(LPCTSTR lpszTitle);
	BOOL UpDateNumber();

	// Operations
public:
	CXTPTabControl m_wndTabControl;
	// Overrides
		// ClassWizard generated virtual function overrides
		//{{AFX_VIRTUAL(CTabView)
public:
	virtual void OnDraw(CDC* pDC);  // overridden to draw this view
	virtual BOOL PreCreateWindow(CREATESTRUCT& cs);
protected:
	//}}AFX_VIRTUAL

// Implementation
public:
	virtual ~CTabView();
#ifdef _DEBUG
	virtual void AssertValid() const;
	virtual void Dump(CDumpContext& dc) const;
#endif


protected:
	// Generated message map functions
protected:
	//{{AFX_MSG(CTabView)
	afx_msg int OnCreate(LPCREATESTRUCT lpCreateStruct);
	afx_msg BOOL OnEraseBkgnd(CDC* pDC);
	afx_msg void OnContextMenu(CWnd* pWnd, CPoint point);
	afx_msg void OnSize(UINT nType, int cx, int cy);
	//}}AFX_MSG
	afx_msg void OnSelectedChanged(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg LRESULT OnAddFindGroup(WPARAM, LPARAM);

	DECLARE_MESSAGE_MAP()
};

#ifndef _DEBUG  // debug version in ClientView.cpp
inline CQuickDoc* CTabView::GetDocument()
{
	return (CQuickDoc*)m_pDocument;
}
#endif
