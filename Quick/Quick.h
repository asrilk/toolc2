// Quick.h : main header file for the Quick application
//
#pragma once

#ifndef __AFXWIN_H__
	#error "include 'stdafx.h' before including this file for PCH"
#endif

#include "resource.h"       // main symbols
#include <map>

typedef std::map<CString, int*> map_osnums; //存放插件数据

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
	CImageList m_pImageList_Large;  //系统大图标
	CImageList m_pImageList_Small;	//系统小图标
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