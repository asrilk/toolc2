#pragma once
#include <map>
#include "TKYLockRW.h"

struct DLLInfo
{
	char mark[30];		//标记
	char mode[30];		//直接加载
	BOOL isx86;			//是不是32位
	BOOL isautorun;		//是否自动运行
	TCHAR Group[255];	//菜单分组
	TCHAR dllname[255];	//DLL名字
	TCHAR dlltext[255]; //说明
	BOOL bmutual;		//是不是交互
};


class CPlugView : public CListView
{
protected:
	CPlugView();           // protected constructor used by dynamic creation
	DECLARE_DYNCREATE(CPlugView)
	BOOL ViewUpdate ;
	int g_Log_Width ;
	int	g_Log_Count;
		// Attributes
public:
	PluginsDate m_PlugsDatex86;  //插件数据
	PluginsDate m_PlugsDatex64;  //插件数据
	CListCtrl* m_pPlugList;
	TKYLockRW mLockRM;
	// Operations
public:

	// Overrides
		// ClassWizard generated virtual function overrides
		//{{AFX_VIRTUAL(CPlugView)
public:
	virtual void OnInitialUpdate();
protected:
	virtual void OnDraw(CDC* pDC);      // overridden to draw this view
	virtual BOOL PreCreateWindow(CREATESTRUCT& cs);
	//}}AFX_VIRTUAL
	bool AddFileData(TCHAR* cstrFilePath);
	void WritePortInfo();
	void readfile(CString FileName);
	void ReadPortInfo();

	int memfind(const char* mem, const char* str, int sizem, int sizes);
	// Implementation
protected:
	CXTHeaderCtrl   m_heades;
	virtual ~CPlugView();
#ifdef _DEBUG
	virtual void AssertValid() const;
	virtual void Dump(CDumpContext& dc) const;
#endif

	// Generated message map functions
protected:
	//{{AFX_MSG(CPlugView)
	afx_msg void OnSize(UINT nType, int cx, int cy);
	afx_msg void OnDropFiles(HDROP hDropInfo);
	afx_msg void OnRclick(NMHDR* pNMHDR, LRESULT* pResult);
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
private:
	
};


// CPlugChangeDlg 对话框

class CPlugChangeDlg : public CDialog
{
	DECLARE_DYNAMIC(CPlugChangeDlg)

public:
	CPlugChangeDlg(CWnd* pParent = nullptr);   // 标准构造函数
	virtual ~CPlugChangeDlg();
	CString	mFilePath0;
	CString mFilePath1;
	DWORD dwOffset;
	BOOL Init(CString FilePath0, CString proFilePath1mpt);
	// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum {
		IDD = IDD_PLUGCHANGE
	};
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	DECLARE_MESSAGE_MAP()
public:
	virtual BOOL OnInitDialog();
	virtual void OnOK();

	int memfind(const char* mem, const char* str, int sizem, int sizes);
	CString mgroup;
	CString mname;
	CString mtext;
	DLLInfo mPlugInfo;
};
