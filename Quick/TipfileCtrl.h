#pragma once

class CCoolTipfileCtrl : public CWnd
{
	DECLARE_DYNAMIC(CCoolTipfileCtrl)

public:
	CCoolTipfileCtrl();
	virtual ~CCoolTipfileCtrl();

	virtual BOOL Create(CWnd* pParentWnd, bool* pbEnable = NULL);
	void	Show(ClientContext* pContext,bool bshowpic=true);
	void Hide();

protected:
	bool* m_pbEnable;
	HWND	m_hAltWnd;
	BOOL	m_bTimer;
	BOOL	m_bVisible;
	CPoint	m_pOpen;
	DWORD	m_tOpen;
	CSize	m_sz;
	CFont		m_fntBold;
	COLORREF	m_crTipBack;
	COLORREF	m_crTipText;
	COLORREF	m_crTipBorder;
	CDC				m_dcBuffer;
	CBitmap			m_bmBuffer;
	CSize			m_czBuffer;
	HBITMAP			m_bmOldBuffer;
	ClientContext* pContext;
	bool mbshowpic;

	static LPCTSTR	m_hClass;

	void	ShowImpl(bool bChanged = false);
	void	CalcSizeHelper();
	void	AddSize(CDC* pDC, LPCTSTR pszText, int nBase = 0);
	int		GetSize(CDC* pDC, LPCTSTR pszText) const;
	void	GetPaintRect(RECT* pRect);
	void	DrawText(CDC* pDC, POINT* pPoint, LPCTSTR pszText, int nBase);
	void	DrawText(CDC* pDC, POINT* pPoint, LPCTSTR pszText, SIZE* pTextMaxSize = NULL);
	void	DrawRule(CDC* pDC, POINT* pPoint, BOOL bPos = FALSE);
	BOOL	WindowFromPointBelongsToOwner(const CPoint& point);

	COLORREF CCoolTipfileCtrl::CalculateColour(COLORREF crFore, COLORREF crBack, int nAlpha);
	CDC* CCoolTipfileCtrl::GetBuffer(CDC& dcScreen, const CSize& szItem);

	BOOL OnPrepare();
	void OnCalcSize(CDC* pDC);
	void OnShow();
	void OnHide();
	void OnPaint(CDC* pDC);

	afx_msg int OnCreate(LPCREATESTRUCT lpCreateStruct);
	afx_msg void OnDestroy();
	afx_msg BOOL OnEraseBkgnd(CDC* pDC);
	afx_msg void OnPaint();
	afx_msg void OnMouseMove(UINT nFlags, CPoint point);
	afx_msg void OnKeyDown(UINT nChar, UINT nRepCnt, UINT nFlags);
	afx_msg void OnTimer(UINT_PTR nIDEvent);

	DECLARE_MESSAGE_MAP()
};
