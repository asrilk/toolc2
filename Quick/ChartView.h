#pragma once

class CChartView : public CXTPResizeFormView
{
	DECLARE_DYNCREATE(CChartView)
public:

	CChartView();
	virtual ~CChartView();
	void AddSeries();
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_CHART };
#endif
#ifdef _DEBUG
	virtual void AssertValid() const;
#ifndef _WIN32_WCE
	virtual void Dump(CDumpContext& dc) const;
#endif
#endif
	virtual void OnInitialUpdate();
protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	//}}AFX_VIRTUAL

	CXTPChartControl m_wndChartControl;
// Implementation
protected:
	DECLARE_MESSAGE_MAP()
		afx_msg void OnMove(int x, int y);
public:
	
	
};



