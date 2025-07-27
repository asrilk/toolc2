#ifndef IPC_H
#define IPC_H

#include <windows.h>



// Definitions
#define IPC_BLOCK_COUNT			512
#define IPC_BLOCK_SIZE			4096

#define IPC_MAX_ADDR			256

#ifdef MYDEBUG
#include <time.h>
#define mydebug(...) fprintf(stdout, "%ld\t%lu\t", time(NULL), GetCurrentThreadId()); fprintf(stdout, __VA_ARGS__);
#else
#define mydebug(...) ;
#endif


enum EnumLogLevel
{
	LogLevel_Stop = 0,	//ʲô������¼
	LogLevel_Fatal,		//ֻ��¼���ش���
	LogLevel_Error,		//��¼���ش�����ͨ����
	LogLevel_Warning,	//��¼���ش�����ͨ���󣬾���
	LogLevel_Info,		//��¼���ش�����ͨ���󣬾��棬��ʾ��Ϣ(Ҳ����ȫ����¼)

	LogLevel_Fatal_char,		//ֻ��¼���ش���
	LogLevel_Error_char,		//��¼���ش�����ͨ����
	LogLevel_Warning_char,	//��¼���ش�����ͨ���󣬾���
	LogLevel_Info_char		//��¼���ش�����ͨ���󣬾��棬��ʾ��Ϣ(Ҳ����ȫ����¼)
};




typedef struct   //��־����
{
	int mode;
	TCHAR text[2000];
}logInfo;

// ---------------------------------------
// -- Inter-Process Communication class --
// ---------------------------------------------------------------
// Provides intercommunication between processes and there threads
// ---------------------------------------------------------------
class  osIPC
{
public:
	// Block that represents a piece of data to transmit between the
	// client and server
	struct Block
	{
		// Variables
		LONG					Next;						// Next block in the circular linked list
		LONG					Prev;						// Previous block in the circular linked list

		volatile LONG			doneRead;					// Flag used to signal that this block has been read
		volatile LONG			doneWrite;					// Flag used to signal that this block has been written
		LONG					writing;
		
		DWORD					Amount;						// Amount of data help in this block
		DWORD					_Padding;					// Padded used to ensure 64bit boundary

		BYTE					Data[IPC_BLOCK_SIZE];		// Data contained in this block
	};

	// statistics information
	struct Stat {
		volatile unsigned long	nTryGetBlock;
		volatile unsigned long	nGetBlock;
		union {
		volatile unsigned long	nRetBlock;
		volatile unsigned long	nPostBlock;
		};
		volatile unsigned long	nWait;
		volatile unsigned long	nWokeUpSuccess;
		volatile unsigned long	nReleaseSemaphore;
	};

private:
	// Shared memory buffer that contains everything required to transmit
	// data between the client and server
	struct MemBuff
	{
		// Block data, this is placed first to remove the offset (optimisation)
		Block					m_Blocks[IPC_BLOCK_COUNT];	// Array of buffers that are used in the communication

		// Cursors
		volatile LONG			m_ReadEnd;					// End of the read cursor
		volatile LONG			m_ReadStart;				// Start of read cursor

		volatile LONG			m_WriteEnd;					// Pointer to the first write cursor, i.e. where we are currently writting to
		volatile LONG			m_WriteStart;				// Pointer in the list where we are currently writting
	};

public:
	// ID Generator
	static DWORD GetID(void)
	{
		// Generate an ID and return id
		static volatile LONG id = 1;
		return (DWORD)InterlockedIncrement((LONG*)&id);
	};

public:
	// Server class
	class Server
	{
	public:
		// Construct / Destruct
		 Server(const char *addr = NULL);
		 ~Server();

	private:
		Stat					m_stat;
		// Internal variables
		char					*m_sAddr;		// Address of this server
		HANDLE					m_hMapFile;		// Handle to the mapped memory file
		HANDLE					m_hSignal;		// Event used to signal when data exists
		HANDLE					m_hAvail;		// Event used to signal when some blocks become available
		MemBuff					*m_pBuf;		// Buffer that points to the shared memory

	public:
		// Exposed functions
		 DWORD	read(void *pBuff, DWORD buffSize, DWORD timeout = INFINITE);
		char*					getAddress(void) { return m_sAddr; };
		 void		recoveryFromClientDeath(void);
		 BOOL		isInitState(void);
		 void		printStatus(void);


		// Block functions
		Block*					getBlock(DWORD dwTimeout = INFINITE);
		void					retBlock(Block* pBlock);

		// Create and destroy functions
		void					create(const char *addr);
		void					close(void);
	};

	// Client class
	class Client
	{
	public:
		// Construct / Destruct
		 Client(void);
		 Client(const char *connectAddr);
		 ~Client();

	private:
		Stat					m_stat;
		// Internal variables
		char					*m_sAddr;		// Address of this server
		HANDLE					m_hMapFile;		//ӳ���ڴ��ļ��ľ��
		HANDLE					m_hSignal;		// ���������ݴ���ʱ�����źŵ��¼�
		HANDLE					m_hAvail;		//������ĳЩ�����ʱ�����źŵ��¼�
		MemBuff					*m_pBuf;		//ָ�����ڴ�Ļ�����
		int						datasize;
	public:
		// Exposed functions
		 DWORD	write(void *pBuff, DWORD amount, DWORD dwTimeout = INFINITE);	// Writes to the buffer
		 void	write(char* str, int mode);	// Writes to the buffer
		 void	write(CString str,int mode);	// Writes to the buffer
		bool					waitAvailable(DWORD dwTimeout = INFINITE);						// Waits until some blocks become available

		Block*					getBlock(DWORD dwTimeout = INFINITE);							// Gets a block
		void					postBlock(Block *pBlock);										// Posts a block to be processed				
		 void		printStatus(void);
		// Functions
		 BOOL		IsOk(void) { if (m_pBuf) return true; else return false; };
		
	};
};

#endif