
#pragma once

/////////////////////////////////////////////////////////////////////////////
// CLogView view

class CLogView : public CListView
{
protected:
	CLogView();           // protected constructor used by dynamic creation
	DECLARE_DYNCREATE(CLogView)
		BOOL gLogUpdate ;
		// Attributes
public:
	int g_Log_Width ;
	int	g_Log_Count ;
	// Operations
public:
	void InsertLogItem(LPCTSTR Text0,LPCTSTR Text1=NULL,LPCTSTR Text2 = NULL,LPCTSTR Text3 = NULL,LPCTSTR Text4 = NULL, LPCTSTR Text5 = NULL,  LPCTSTR Text6 = NULL, LPCTSTR Text7 = NULL);
	// Overrides
		// ClassWizard generated virtual function overrides
		//{{AFX_VIRTUAL(CLogView)
public:
	virtual void OnInitialUpdate();
protected:
	virtual void OnDraw(CDC* pDC);      // overridden to draw this view
	virtual BOOL PreCreateWindow(CREATESTRUCT& cs);
	//}}AFX_VIRTUAL
	void OnEventDelete();
	void OnAllDelete();
	void OnEventSave();
	void OnEventCopy();
// Implementation
protected:
	CXTHeaderCtrl   m_heades;
	virtual ~CLogView();
#ifdef _DEBUG
	virtual void AssertValid() const;
	virtual void Dump(CDumpContext& dc) const;
#endif

	// Generated message map functions
protected:
	//{{AFX_MSG(CLogView)
	afx_msg void OnSize(UINT nType, int cx, int cy);
	afx_msg void OnRclick(NMHDR* pNMHDR, LRESULT* pResult);
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
private:
	CListCtrl* m_pLogList;

};


class CPeneListView : public CListView
{
protected:
	CPeneListView();           // protected constructor used by dynamic creation
	DECLARE_DYNCREATE(CPeneListView)

		// Attributes
public:

	// Operations
public:
	// Overrides
		// ClassWizard generated virtual function overrides
		//{{AFX_VIRTUAL(CLogView)
public:
	virtual void OnInitialUpdate();
protected:
	virtual void OnDraw(CDC* pDC);      // overridden to draw this view
	virtual BOOL PreCreateWindow(CREATESTRUCT& cs);
	//}}AFX_VIRTUAL

	// Implementation
protected:
	CListCtrl* m_pList;
	virtual ~CPeneListView();
#ifdef _DEBUG
	virtual void AssertValid() const;
	virtual void Dump(CDumpContext& dc) const;
#endif

	// Generated message map functions
protected:
	//{{AFX_MSG(CLogView)
	afx_msg void OnSize(UINT nType, int cx, int cy);
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
private:


};

