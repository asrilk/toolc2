// Quick.h : main header file for the Quick application
//
#pragma once

#ifndef __AFXWIN_H__
	#error "include 'stdafx.h' before including this file for PCH"
#endif

#include "resource.h"       // main symbols
#include <map>

typedef std::map<CString, int*> map_osnums; //��Ų������

// CQuickApp:
// See Quick.cpp for the implementation of this class
//

class CQuickApp : public CXTPWinApp
{
public:
	CQuickApp();
	~CQuickApp();
	CString g_Exename;
	map_osnums m_map_osnums;
	CImageList m_pImageList_Large;  //ϵͳ��ͼ��
	CImageList m_pImageList_Small;	//ϵͳСͼ��
	void ChangeOSnum(CString stros, bool isaddnum);
// Overrides
public:
	virtual BOOL InitInstance();
	char* old_locale;
// Implementation
	afx_msg void OnAppAbout();
	DECLARE_MESSAGE_MAP()
};

extern CQuickApp theApp;