#include "stdafx.h"
#include "Quick.h"
#include "MainFrm.h"
#include "ChartView.h"




IMPLEMENT_DYNCREATE(CChartView, CXTPResizeFormView)
CChartView::CChartView()
	: CXTPResizeFormView(IDD_CHART)
{
}

CChartView::~CChartView()
{
	m_wndChartControl.GetContent()->GetSeries()->RemoveAll();
}

void CChartView::DoDataExchange(CDataExchange* pDX)
{
	CXTPResizeFormView::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_CHARTCONTROL, m_wndChartControl);
}


BEGIN_MESSAGE_MAP(CChartView, CXTPResizeFormView)
	ON_WM_CLOSE()
	ON_WM_MOVE()
END_MESSAGE_MAP()


// CChartView 诊断

#ifdef _DEBUG
void CChartView::AssertValid() const
{
	CXTPResizeFormView::AssertValid();
}

#ifndef _WIN32_WCE
void CChartView::Dump(CDumpContext& dc) const
{
	CXTPResizeFormView::Dump(dc);
}
#endif
#endif //_DEBUG


void CChartView::OnInitialUpdate()
{
	CXTPResizeFormView::OnInitialUpdate();
	static bool binit = false;

	if (!binit)
	{
		SetResize(IDC_CHARTCONTROL, XTP_ANCHOR_TOPLEFT, XTP_ANCHOR_BOTTOMRIGHT);
		CXTPChartTitle* pTitle = m_wndChartControl.GetContent()->GetTitles()->Add(new CXTPChartTitle());
		pTitle->SetText(_T("系统统计"));
		binit = true;
	}

	UpdateData(FALSE);
}

void CChartView::AddSeries()
{

	m_wndChartControl.GetContent()->GetSeries()->RemoveAll();

	CXTPChartSeries* pSeries = m_wndChartControl.GetContent()->GetSeries()->Add(new CXTPChartSeries());

	bool b = false;
	map_osnums::iterator iter = ((CQuickApp*)AfxGetApp())->m_map_osnums.begin();
	while (iter != ((CQuickApp*)AfxGetApp())->m_map_osnums.end()) {
		pSeries->GetPoints()->Add(new CXTPChartSeriesPoint(iter->first, *(iter->second), 1))->m_bSpecial = b;
		b = !b;
		++iter;
	}

 pSeries = m_wndChartControl.GetContent()->GetSeries()->GetAt(0);
	CXTPChart3dPieSeriesStyle* pPieStyle = (CXTPChart3dPieSeriesStyle*)pSeries->SetStyle(new CXTPChart3dPieSeriesStyle());
	pPieStyle->Set3dRotation(-20, 0, 70);
	pPieStyle->SetExplodedDistancePercent(20);
	pPieStyle->SetTorus(TRUE);
	pPieStyle->SetDepth(pPieStyle->GetDepth() * 2);
	((CXTPChartPieSeriesLabel*)pPieStyle->GetLabel())->SetPosition(xtpChartPieLabelOutside);
	((CXTPChartPieSeriesLabel*)pPieStyle->GetLabel())->SetFormat(_T("{V} 台"));

	m_wndChartControl.GetContent()->GetAppearance()->LoadAppearance(_T("CHART_APPEARANCE_GRAY") );
	m_wndChartControl.GetContent()->OnChartChanged();

	m_wndChartControl.GetContent()->GetAppearance()->LoadPalette(_T("CHART_PALETTE_Illustration") );

	m_wndChartControl.GetContent()->OnChartChanged();

	m_wndChartControl.GetContent()->GetLegend()->SetVisible(TRUE);
	GetDlgItem(IDC_CHARTCONTROL)->ShowWindow(SW_SHOW);
}


 void CChartView::OnMove(int x, int y)
{
	 if (IsWindowVisible())
	 {
		 m_wndChartControl.GetContent()->GetLegend()->SetVisible(FALSE);
		 AddSeries();
		 CXTPResizeFormView::OnMove(x, y);
		 m_wndChartControl.GetContent()->GetLegend()->SetVisible(TRUE);
	 }

}