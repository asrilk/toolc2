// QuickDoc.cpp : implementation of the CQuickDoc class
//

#include "stdafx.h"
#include "Quick.h"

#include "QuickDoc.h"
#include "QuickView.h"
#ifdef _DEBUG
#define new DEBUG_NEW
#endif



// CQuickDoc

IMPLEMENT_DYNCREATE(CQuickDoc, CDocument)

BEGIN_MESSAGE_MAP(CQuickDoc, CDocument)
END_MESSAGE_MAP()


// CQuickDoc construction/destruction

CQuickDoc::CQuickDoc()
{
	// TODO: add one-time construction code here

}

CQuickDoc::~CQuickDoc()
{
}

BOOL CQuickDoc::OnNewDocument()
{
	if (!CDocument::OnNewDocument())
		return FALSE;

	// TODO: add reinitialization code here
	// (SDI documents will reuse this document)

	return TRUE;
}




// CQuickDoc serialization

void CQuickDoc::Serialize(CArchive& ar)
{
	//if (ar.IsStoring())
	//{
	//	// TODO: add storing code here
	//}
	//else
	//{
	//	// TODO: add loading code here
	//}
	POSITION pos = GetFirstViewPosition();
	while (pos != NULL)
	{
		CView* pView = GetNextView(pos);
		CQuickView* pReportView = DYNAMIC_DOWNCAST(CQuickView, pView);
		pReportView->GetReportCtrl().SerializeState(ar);
	}
}


// CQuickDoc diagnostics

#ifdef _DEBUG
void CQuickDoc::AssertValid() const
{
	CDocument::AssertValid();
}

void CQuickDoc::Dump(CDumpContext& dc) const
{
	CDocument::Dump(dc);
}
#endif //_DEBUG


// CQuickDoc commands


