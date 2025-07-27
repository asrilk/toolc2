#include "stdafx.h"
#include "Quick.h"
#include "MainFrm.h"
#include "QuickDoc.h"
#include "QuickView.h"
#include "TabView.h"

#include "TipCtrl.h"
#ifdef _DEBUG
#define new DEBUG_NEW
#endif


IMPLEMENT_DYNAMIC(CCoolTipCtrl, CWnd)

BEGIN_MESSAGE_MAP(CCoolTipCtrl, CWnd)
	ON_WM_CREATE()
	ON_WM_DESTROY()
	ON_WM_ERASEBKGND()
	ON_WM_PAINT()
	ON_WM_MOUSEMOVE()
	ON_WM_KEYDOWN()
	ON_WM_TIMER()
END_MESSAGE_MAP()

LPCTSTR CCoolTipCtrl::m_hClass = NULL;

#define TIP_TIMER		100
#define TIP_OFFSET_X	0
#define TIP_OFFSET_Y	24
#define TIP_MARGIN		6
#define TIP_TEXTHEIGHT	14
#define TIP_RULE		14
#define TIP_GAP			5
/////////////////////////////////////////////////////////////////////////////
// CCoolTipCtrl construction

CCoolTipCtrl::CCoolTipCtrl()
	: m_pbEnable(NULL)
	, m_hAltWnd(NULL)
	, m_bTimer(FALSE)
	, m_bVisible(FALSE)
	, m_tOpen(0)
	, mbshowpic(true)
{
	if (m_hClass == NULL)
		m_hClass = AfxRegisterWndClass(CS_SAVEBITS | CS_DROPSHADOW);
	m_crTipBack = GetSysColor(COLOR_INFOBK);
	m_crTipText = GetSysColor(COLOR_INFOTEXT);
	m_crTipBorder = CalculateColour(m_crTipBack, (COLORREF)0, 100);
	m_czBuffer = CSize(0, 0);


	m_fntBold.CreateFont(-14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
		DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
		DEFAULT_PITCH | FF_DONTCARE, _T("����"));
	//m_fntBold.CreateFont(
	//	-11/*�߶�*/, -7.5/*���*/, 0/*���ù�*/, 0/*���ù�*/, 400 /*һ�����ֵ��Ϊ400*/,
	//	FALSE/*����б��*/, FALSE/*�����»���*/, FALSE/*����ɾ����*/,
	//	DEFAULT_CHARSET,  //��������ʹ��Ĭ���ַ��������������� _CHARSET ��β�ĳ�������
	//	OUT_CHARACTER_PRECIS, CLIP_CHARACTER_PRECIS,  //���в������ù�
	//	DEFAULT_QUALITY,  //Ĭ���������
	//	FF_DONTCARE,  //��ָ��������*/
	//	TEXT("΢���ź�")  //������
	//);
}

CCoolTipCtrl::~CCoolTipCtrl()
{
	if (m_bmBuffer.m_hObject != NULL)
	{
		m_dcBuffer.SelectObject(CGdiObject::FromHandle(m_bmOldBuffer));
		m_dcBuffer.DeleteDC();
		m_bmBuffer.DeleteObject();
	}
	m_czBuffer = CSize(0, 0);
	m_fntBold.DeleteObject();
	if (m_hWnd != NULL)
		DestroyWindow();
}

/////////////////////////////////////////////////////////////////////////////
// CCoolTipCtrl operations

BOOL CCoolTipCtrl::Create(CWnd* pParentWnd, bool* pbEnable)
{
	CRect rc(0, 0, 0, 0);

	DWORD dwStyleEx = WS_EX_TOPMOST | 0;
	if (!CWnd::CreateEx(dwStyleEx, m_hClass, NULL, WS_POPUP | WS_DISABLED,
		rc, pParentWnd, 0, NULL)) return FALSE;

	SetOwner(pParentWnd);
	m_pbEnable = pbEnable;

	return TRUE;
}

void CCoolTipCtrl::Hide()
{
	m_tOpen = 0;

	if (m_bVisible)
	{
		OnHide();

		ShowWindow(SW_HIDE);
		ModifyStyleEx(WS_EX_LAYERED, 0);
		m_bVisible = FALSE;
		GetCursorPos(&m_pOpen);
	}

	if (m_bTimer)
	{
		KillTimer(1);
		m_bTimer = FALSE;
	}
}

void CCoolTipCtrl::Show(ClientContext* pContext_new, bool bshowpic)
{
	bool bChanged = pContext != pContext_new;
	pContext = pContext_new;
	mbshowpic = bshowpic;
	ShowImpl(bChanged);
}



void CCoolTipCtrl::ShowImpl(bool bChanged)
{
	if (m_pbEnable != NULL && *m_pbEnable == false)
		return;

	CPoint point;
	GetCursorPos(&point);

	if (!WindowFromPointBelongsToOwner(point))
		return;

	if (m_bVisible)
	{
		if (!bChanged)
			return;

		Hide();
	}
	else if (point != m_pOpen)
	{
		m_pOpen = point;
		m_tOpen = GetTickCount() + 100;

		if (!m_bTimer)
		{
			SetTimer(1, TIP_TIMER, NULL);
			m_bTimer = TRUE;
		}
		return;
	}

	if (m_bVisible)
		return;

	m_sz.cx = m_sz.cy = 0;

	if (!OnPrepare())
		return;

	CRect rc(m_pOpen.x + TIP_OFFSET_X, m_pOpen.y + TIP_OFFSET_Y, 0, 0);
	rc.right = rc.left + m_sz.cx + TIP_MARGIN * 2;
	rc.bottom = rc.top + m_sz.cy + TIP_MARGIN * 2;

	HMONITOR hMonitor = MonitorFromPoint(m_pOpen, MONITOR_DEFAULTTONEAREST);

	MONITORINFO oMonitor = { 0 };
	oMonitor.cbSize = sizeof(MONITORINFO);
	GetMonitorInfo(hMonitor, &oMonitor);

	if (rc.right >= oMonitor.rcWork.right)
	{
		rc.OffsetRect(oMonitor.rcWork.right - rc.right - 4, 0);
	}

	if (rc.bottom >= oMonitor.rcWork.bottom)
	{
		rc.OffsetRect(0, -(m_sz.cy + TIP_MARGIN * 2 + TIP_OFFSET_Y + 4));
	}


	m_bVisible = TRUE;

	OnShow();
	ModifyStyleEx(WS_EX_LAYERED, 0);


	SetWindowPos(&wndTop, rc.left, rc.top, rc.Width(), rc.Height(),
		SWP_ASYNCWINDOWPOS | SWP_SHOWWINDOW | SWP_NOACTIVATE);
	UpdateWindow();

	if (!m_bTimer)
	{
		SetTimer(1, TIP_TIMER, NULL);
		m_bTimer = TRUE;
	}
}

void CCoolTipCtrl::CalcSizeHelper()
{
	CClientDC dc(this);

	m_sz.cx = m_sz.cy = 0;

	CFont* pOldFont = (CFont*)dc.SelectObject(&m_fntBold);

	OnCalcSize(&dc);

	dc.SelectObject(pOldFont);
}

void CCoolTipCtrl::AddSize(CDC* pDC, LPCTSTR pszText, int nBase)
{
	m_sz.cx = max(m_sz.cx, (LONG)GetSize(pDC, pszText) + nBase + 70);
}

int CCoolTipCtrl::GetSize(CDC* pDC, LPCTSTR pszText) const
{
	DWORD dwFlags = DT_RTLREADING |
		DT_SINGLELINE | DT_NOPREFIX;
	CRect rcText(0, 0, 0, 0);
	pDC->DrawText(pszText, -1, &rcText, dwFlags | DT_CALCRECT);
	return rcText.Width();
}

void CCoolTipCtrl::GetPaintRect(RECT* pRect)
{
	pRect->left = 0;
	pRect->top = 0;
	pRect->right = m_sz.cx;
	pRect->bottom = m_sz.cy;
}

void CCoolTipCtrl::DrawText(CDC* pDC, POINT* pPoint, LPCTSTR pszText, int nBase)
{
	POINT pt = { pPoint->x + nBase, pPoint->y };
	DrawText(pDC, &pt, pszText);
}

void CCoolTipCtrl::DrawText(CDC* pDC, POINT* pPoint, LPCTSTR pszText, SIZE* pTextMaxSize)
{
	DWORD dwFlags = DT_RTLREADING |
		DT_SINGLELINE | DT_NOPREFIX;
	CRect rcText(0, 0, 0, 0);
	pDC->DrawText(pszText, -1, &rcText, dwFlags | DT_CALCRECT);
	if (pTextMaxSize)
	{
		if (pTextMaxSize->cx > 0 && pTextMaxSize->cx < rcText.Width())
			rcText.right = rcText.left + pTextMaxSize->cx;
		if (pTextMaxSize->cy > 0 && pTextMaxSize->cy < rcText.Height())
			rcText.bottom = rcText.top + pTextMaxSize->cy;
	}
	rcText.MoveToXY(pPoint->x, pPoint->y);
	pDC->SetBkMode(TRANSPARENT);
	pDC->FillSolidRect(&rcText, m_crTipBack);
	pDC->DrawText(pszText, -1, &rcText, dwFlags | DT_END_ELLIPSIS);
	pDC->ExcludeClipRect(&rcText);
}

COLORREF CCoolTipCtrl::CalculateColour(COLORREF crFore, COLORREF crBack, int nAlpha)
{
	int nRed = GetRValue(crFore) * (255 - nAlpha) / 255 + GetRValue(crBack) * nAlpha / 255;
	int nGreen = GetGValue(crFore) * (255 - nAlpha) / 255 + GetGValue(crBack) * nAlpha / 255;
	int nBlue = GetBValue(crFore) * (255 - nAlpha) / 255 + GetBValue(crBack) * nAlpha / 255;

	return RGB(nRed, nGreen, nBlue);
}


void CCoolTipCtrl::DrawRule(CDC* pDC, POINT* pPoint, BOOL bPos)
{
	pPoint->y += 5;
	if (bPos)
	{
		pDC->Draw3dRect(pPoint->x, pPoint->y,
			m_sz.cx + (TIP_MARGIN - 3) - pPoint->x, 1, m_crTipBorder,
			m_crTipBorder);
		pDC->ExcludeClipRect(pPoint->x, pPoint->y,
			m_sz.cx + (TIP_MARGIN - 3), pPoint->y + 1);
	}
	else
	{
		pDC->Draw3dRect(-(TIP_MARGIN - 3), pPoint->y,
			m_sz.cx + (TIP_MARGIN - 3) * 2, 1, m_crTipBorder,
			m_crTipBorder);
		pDC->ExcludeClipRect(-(TIP_MARGIN - 3), pPoint->y,
			m_sz.cx + (TIP_MARGIN - 3), pPoint->y + 1);
	}
	pPoint->y += 6;
}

BOOL CCoolTipCtrl::WindowFromPointBelongsToOwner(const CPoint& point)
{
	CWnd* pOwner = GetOwner();
	if (!pOwner || !IsWindow(pOwner->GetSafeHwnd()))
		return FALSE;

	CRect rc;
	pOwner->GetWindowRect(&rc);

	if (!rc.PtInRect(point))
		return FALSE;

	CWnd* pWnd = WindowFromPoint(point);

	while (pWnd)
	{
		if (pWnd == pOwner)
			return TRUE;
		HWND hWnd = pWnd->GetSafeHwnd();
		if (m_hAltWnd && hWnd == m_hAltWnd)
			return TRUE;
		if (!IsWindow(hWnd))
			return FALSE;
		pWnd = pWnd->GetParent();
	}

	return FALSE;
}


/////////////////////////////////////////////////////////////////////////////
// CCoolTipCtrl message handlers

int CCoolTipCtrl::OnCreate(LPCREATESTRUCT lpCreateStruct)
{
	if (CWnd::OnCreate(lpCreateStruct) == -1) return -1;
	m_bTimer = FALSE;
	return 0;
}

void CCoolTipCtrl::OnDestroy()
{
	if (m_bTimer) KillTimer(1);
	m_bTimer = FALSE;
	if (m_bVisible) Hide();
	CWnd::OnDestroy();
}

BOOL CCoolTipCtrl::OnEraseBkgnd(CDC* /*pDC*/)
{
	return TRUE;
}

CDC* CCoolTipCtrl::GetBuffer(CDC& dcScreen, const CSize& szItem)
{
	if (szItem.cx <= m_czBuffer.cx && szItem.cy <= m_czBuffer.cy)
	{
		m_dcBuffer.SelectClipRgn(NULL);
		return &m_dcBuffer;
	}

	if (m_bmBuffer.m_hObject)
	{
		m_dcBuffer.SelectObject(CGdiObject::FromHandle(m_bmOldBuffer));
		m_bmBuffer.DeleteObject();
	}

	m_czBuffer.cx = max(m_czBuffer.cx, szItem.cx);
	m_czBuffer.cy = max(m_czBuffer.cy, szItem.cy);

	if (m_dcBuffer.m_hDC == NULL) m_dcBuffer.CreateCompatibleDC(&dcScreen);
	m_bmBuffer.CreateCompatibleBitmap(&dcScreen, m_czBuffer.cx, m_czBuffer.cy);
	m_bmOldBuffer = (HBITMAP)m_dcBuffer.SelectObject(&m_bmBuffer)->GetSafeHandle();

	return &m_dcBuffer;
}

void CCoolTipCtrl::OnPaint()
{
	if (!IsWindow(GetSafeHwnd()) || !IsWindowVisible()) return;

	CPaintDC dc(this);

	CRect rc;
	GetClientRect(&rc);

	CSize size = rc.Size();
	CDC* pMemDC = GetBuffer(dc, size);

	SetLayout(pMemDC->m_hDC, 0);

	pMemDC->SetTextColor(m_crTipText);
	pMemDC->SetBkColor(m_crTipBack);
	CFont* pOldFont = (CFont*)pMemDC->SelectObject(&m_fntBold);
	pMemDC->Draw3dRect(&rc, m_crTipBorder, m_crTipBorder);
	pMemDC->SetViewportOrg(TIP_MARGIN, TIP_MARGIN);
	rc.DeflateRect(1, 1);
	OnPaint(pMemDC);
	pMemDC->SetViewportOrg(0, 0);
	pMemDC->FillSolidRect(&rc, m_crTipBack);
	pMemDC->SelectObject(pOldFont);

	GetClientRect(&rc);
	dc.BitBlt(rc.left, rc.top, rc.Width(), rc.Height(), pMemDC, 0, 0, SRCCOPY);
	SetLayout(pMemDC->m_hDC, LAYOUT_RTL);
}

void CCoolTipCtrl::OnMouseMove(UINT /*nFlags*/, CPoint /*point*/)
{
	Hide();
}

void CCoolTipCtrl::OnKeyDown(UINT nChar, UINT nRepCnt, UINT nFlags)
{
	Hide();
	CWnd::OnKeyDown(nChar, nRepCnt, nFlags);
}

void CCoolTipCtrl::OnTimer(UINT_PTR /*nIDEvent*/)
{
	CPoint point;
	GetCursorPos(&point);

	if (!WindowFromPointBelongsToOwner(point))
	{
		if (m_bVisible) Hide();
		return;
	}

	if (!m_bVisible && m_tOpen && GetTickCount() >= m_tOpen)
	{
		m_tOpen = 0;
		if (point == m_pOpen || m_hAltWnd != NULL) ShowImpl();
	}
}

/////////////////////////////////////////////////////////////////////////////
// CCoolTipCtrl events

BOOL CCoolTipCtrl::OnPrepare()
{
	CalcSizeHelper();
	return TRUE;
}

void CCoolTipCtrl::OnCalcSize(CDC* pDC)
{

	//��ͼ
	if (pContext->PictureSize != 0 && mbshowpic)
	{
		m_sz.cx = pContext->iScreenWidth;
		m_sz.cy = pContext->iScreenHeight;
		m_sz.cy += TIP_RULE;
	}
	//��ǰ����
	if (!pContext->LoginInfo) return;

	//����
	AddSize(pDC, pContext->LoginInfo->Group);
	m_sz.cy += TIP_TEXTHEIGHT;

	//�������
	AddSize(pDC, pContext->LoginInfo->CptName);
	m_sz.cy += TIP_TEXTHEIGHT;

	//ϵͳ��
	AddSize(pDC, pContext->LoginInfo->OSVersion);
	m_sz.cy += TIP_TEXTHEIGHT;

	//CPU
	AddSize(pDC, pContext->LoginInfo->CPU);
	m_sz.cy += TIP_TEXTHEIGHT;
	//Ӳ��+�ڴ�
	AddSize(pDC, pContext->LoginInfo->DAM);
	m_sz.cy += TIP_TEXTHEIGHT;
	//�Կ�
	AddSize(pDC, pContext->LoginInfo->GPU);
	m_sz.cy += TIP_TEXTHEIGHT;
	//�汾
	AddSize(pDC, pContext->LoginInfo->Version);
	m_sz.cy += TIP_TEXTHEIGHT;

	//����ID
	AddSize(pDC, pContext->LoginInfo->pid);
	m_sz.cy += TIP_TEXTHEIGHT;

	//ɱ��
	AddSize(pDC, pContext->LoginInfo->Virus);
	m_sz.cy += TIP_TEXTHEIGHT;

	//ϵͳ����
	AddSize(pDC, pContext->LoginInfo->lpLCData);
	m_sz.cy += TIP_TEXTHEIGHT;
	//��ʾ����Ϣ
	AddSize(pDC, pContext->LoginInfo->Monitors);
	m_sz.cy += TIP_TEXTHEIGHT;
	//ϵͳĿ¼
	AddSize(pDC, pContext->LoginInfo->szSysdire);
	m_sz.cy += TIP_TEXTHEIGHT;
	//����·��
	AddSize(pDC, pContext->LoginInfo->ProcPath);
	m_sz.cy += TIP_TEXTHEIGHT;
	//HWID
	AddSize(pDC, pContext->LoginInfo->szHWID);
	m_sz.cy += TIP_TEXTHEIGHT;
	//����ʱ��
	AddSize(pDC, pContext->LoginInfo->m_Time);
	m_sz.cy += TIP_TEXTHEIGHT;
	

}

void CCoolTipCtrl::OnShow()
{
}

void CCoolTipCtrl::OnHide()
{
}

void CCoolTipCtrl::OnPaint(CDC* pDC)
{
	CPoint pt(0, 0);
	//��ͼ
	if (pContext->PictureSize != 0 && mbshowpic)
	{
		HGLOBAL hGlobal = GlobalAlloc(GMEM_MOVEABLE, pContext->PictureSize);
		void* pData = GlobalLock(hGlobal);
		memcpy(pData, pContext->ScreenPicture, pContext->PictureSize);
		GlobalUnlock(hGlobal);
		IStream* pStream = NULL;
		if (CreateStreamOnHGlobal(hGlobal, TRUE, &pStream) == S_OK)
		{
			CImage image;
			if (SUCCEEDED(image.Load(pStream)))
			{
				IStream* pOutStream = NULL;
				if (CreateStreamOnHGlobal(NULL, TRUE, &pOutStream) == S_OK)
				{

					if (image.GetBPP() == 32) //ȷ�ϸ�ͼ�����Alphaͨ��
					{
						int i;
						int j;
						for (i = 0; i < image.GetWidth(); i++)
						{
							for (j = 0; j < image.GetHeight(); j++)
							{
								byte* pByte = (byte*)image.GetPixelAddress(i, j);
								pByte[0] = pByte[0] * pByte[3] / 255;
								pByte[1] = pByte[1] * pByte[3] / 255;
								pByte[2] = pByte[2] * pByte[3] / 255;
							}
						}
					}
					CRect rcThumb(pt.x, pt.y,
						pt.x + pContext->iScreenWidth, pt.y + pContext->iScreenHeight);
					image.Draw(pDC->GetSafeHdc(), 0, 0);
					pDC->ExcludeClipRect(&rcThumb);
					image.Destroy();
				}
			}
			pStream->Release();
		}
		GlobalFree(hGlobal);
		pt.y += pContext->iScreenHeight;
		DrawRule(pDC, &pt);
	}


	//��ǰ����
	if (!pContext->LoginInfo) return;

	pDC->SetTextColor(RGB(0, 128, 0));

	//����
	DrawText(pDC, &pt, _T(":����"));
	pt.x += 75;
	DrawText(pDC, &pt, pContext->LoginInfo->Group);
	pt.y += TIP_TEXTHEIGHT;

	//�������
	pt.x -= 75;
	DrawText(pDC, &pt, _T(":�������"));
	pt.x += 75;
	DrawText(pDC, &pt, pContext->LoginInfo->CptName);
	pt.y += TIP_TEXTHEIGHT;

	//ϵͳ��
	pt.x -= 75;
	DrawText(pDC, &pt, _T(":ϵͳ"));
	pt.x += 75;
	DrawText(pDC, &pt, pContext->LoginInfo->OSVersion);
	pt.y += TIP_TEXTHEIGHT;

	//CPU
	pt.x -= 75;
	DrawText(pDC, &pt, _T(":CPU����"));
	pt.x += 75;
	DrawText(pDC, &pt, pContext->LoginInfo->CPU);
	pt.y += TIP_TEXTHEIGHT;

	//Ӳ��+�ڴ�
	pt.x -= 75;
	DrawText(pDC, &pt, _T(":Ӳ���ڴ�"));
	pt.x += 75;
	DrawText(pDC, &pt, pContext->LoginInfo->DAM);
	pt.y += TIP_TEXTHEIGHT;

	//�Կ�
	pt.x -= 75;
	DrawText(pDC, &pt, _T(":�Կ�"));
	pt.x += 75;
	DrawText(pDC, &pt, pContext->LoginInfo->GPU);
	pt.y += TIP_TEXTHEIGHT;

	//�汾
	pt.x -= 75;
	DrawText(pDC, &pt, _T(":�汾"));
	pt.x += 75;
	DrawText(pDC, &pt, pContext->LoginInfo->Version);
	pt.y += TIP_TEXTHEIGHT;


	//PID
	pt.x -= 75;
	DrawText(pDC, &pt, _T(":����PID"));
	pt.x += 75;
	DrawText(pDC, &pt, pContext->LoginInfo->pid);
	pt.y += TIP_TEXTHEIGHT;

	//ɱ��
	pt.x -= 75;
	DrawText(pDC, &pt, _T(":ɱ�����"));
	pt.x += 75;
	DrawText(pDC, &pt, pContext->LoginInfo->Virus);
	pt.y += TIP_TEXTHEIGHT;

	//ϵͳ����
	pt.x -= 75;
	DrawText(pDC, &pt, _T(":ϵͳ����"));
	pt.x += 75;
	DrawText(pDC, &pt, pContext->LoginInfo->lpLCData);
	pt.y += TIP_TEXTHEIGHT;
	//��ʾ����Ϣ
	pt.x -= 75;
	DrawText(pDC, &pt, _T(":��ʾ��"));
	pt.x += 75;
	DrawText(pDC, &pt, pContext->LoginInfo->Monitors);
	pt.y += TIP_TEXTHEIGHT;
	//ϵͳĿ¼
	pt.x -= 75;
	DrawText(pDC, &pt, _T(":ϵͳĿ¼"));
	pt.x += 75;
	DrawText(pDC, &pt, pContext->LoginInfo->szSysdire);
	pt.y += TIP_TEXTHEIGHT;
	//����·��
	pt.x -= 75;
	DrawText(pDC, &pt, _T(":����·��"));
	pt.x += 75;
	DrawText(pDC, &pt, pContext->LoginInfo->ProcPath);
	pt.y += TIP_TEXTHEIGHT;
	//HWID
	pt.x -= 75;
	DrawText(pDC, &pt, _T(":�ͻ����"));
	pt.x += 75;
	DrawText(pDC, &pt, pContext->LoginInfo->szHWID);
	pt.y += TIP_TEXTHEIGHT;
	//����ʱ��
	pt.x -= 75;
	DrawText(pDC, &pt, _T(":����ʱ��"));
	pt.x += 75;
	DrawText(pDC, &pt, pContext->LoginInfo->m_Time);
	pt.y += TIP_TEXTHEIGHT;
	

}
