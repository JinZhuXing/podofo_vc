
// PdfSignatureDlg.cpp : implementation file
//

#include "pch.h"
#include "framework.h"
#include "PdfSignature.h"
#include "PdfSignatureDlg.h"
#include "afxdialogex.h"
#include "pdf_signing.h"
#include <openssl/applink.c>

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

// UTILITY function
bool dirExists(const std::string& dirName_in)
{
	DWORD ftyp = GetFileAttributesA(dirName_in.c_str());
	if (ftyp == INVALID_FILE_ATTRIBUTES)
		return false;  //something is wrong with your path!

	if (ftyp & FILE_ATTRIBUTE_DIRECTORY)
		return true;   // this is a directory!

	return false;    // this is not a directory!
}



// CAboutDlg dialog used for App About

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

// Implementation
protected:
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedCheck1();
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CPdfSignatureDlg dialog



CPdfSignatureDlg::CPdfSignatureDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_PDFSIGNATURE_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CPdfSignatureDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_CHECK1, LoadKeyAndCert);
	DDX_Control(pDX, IDC_BUTTON_OPEN_KEY, button_open_key);
	DDX_Control(pDX, IDC_BUTTON_OPEN_CERT, button_open_cert);
	DDX_Control(pDX, IDC_EDIT1, m_pdfEdit);
	DDX_Control(pDX, IDC_EDIT2, m_keyEdit);
	DDX_Control(pDX, IDC_EDIT3, m_certEdit);
	DDX_Control(pDX, IDC_RADIO_DSA, DSA_RADIO);
}

BEGIN_MESSAGE_MAP(CPdfSignatureDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON_OPEN_PDF, &CPdfSignatureDlg::OnBnClickedButtonOpenPdf)
	ON_BN_CLICKED(IDC_CHECK1, &CPdfSignatureDlg::OnBnClickedCheck1)
	ON_BN_CLICKED(IDC_BUTTON_OPEN_KEY, &CPdfSignatureDlg::OnBnClickedButtonOpenKey)
	ON_BN_CLICKED(IDC_BUTTON_OPEN_CERT, &CPdfSignatureDlg::OnBnClickedButtonOpenCert)
	ON_BN_CLICKED(IDC_BUTTON4, &CPdfSignatureDlg::OnBnClickedButton4)
	ON_BN_CLICKED(IDC_RADIO_DSA, &CPdfSignatureDlg::OnBnClickedRadioDsa)
END_MESSAGE_MAP()


// CPdfSignatureDlg message handlers

BOOL CPdfSignatureDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// Add "About..." menu item to system menu.

	// IDM_ABOUTBOX must be in the system command range.
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// Set the icon for this dialog.  The framework does this automatically
	//  when the application's main window is not a dialog
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon

	// TODO: Add extra initialization here

	return TRUE;  // return TRUE  unless you set the focus to a control
}

void CPdfSignatureDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// If you add a minimize button to your dialog, you will need the code below
//  to draw the icon.  For MFC applications using the document/view model,
//  this is automatically done for you by the framework.

void CPdfSignatureDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // device context for painting

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// Center icon in client rectangle
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// Draw the icon
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

// The system calls this function to obtain the cursor to display while the user drags
//  the minimized window.
HCURSOR CPdfSignatureDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CPdfSignatureDlg::OnBnClickedButtonOpenPdf()
{
	UpdateData(true);
	// TODO: Add your control notification handler code here
	LPCTSTR pszFile =
		_T("Pdf (*.pdf)|*.pdf|")
		_T("Text (*.txt)|*.txt||");
	CFileDialog file_diaglog(
		true,                                   // true for File Open dialog box
		L"png",               // The default file name extension
		nullptr,                    // The default file name
		OFN_FILEMUSTEXIST | OFN_NOCHANGEDIR,    // bunch of flags http://msdn.microsoft.com/en-us/library/wh5hz49d.aspx
		pszFile,
		AfxGetMainWnd()
	);

	if (file_diaglog.DoModal() != IDOK) {
		MessageBox(L"Fail to open file diaglog");
		return;
	}

	CString file_name = file_diaglog.GetPathName();
	m_pdfEdit.SetWindowTextW(file_name);
	UpdateData(true);
	return;
}

void CPdfSignatureDlg::OnBnClickedCheck1()
{
	// TODO: Add your control notification handler code here
	UpdateData(true);
	int checked = LoadKeyAndCert.GetCheck();

	if (checked == BST_CHECKED) {
		m_keyEdit.SetWindowTextW(L"");
		m_certEdit.SetWindowTextW(L"");
		button_open_cert.EnableWindow(false);
		button_open_key.EnableWindow(false);
		UpdateData(true);
		return;
	}

	button_open_cert.EnableWindow(true);
	button_open_key.EnableWindow(true);
	UpdateData(true);
	return;
}


void CPdfSignatureDlg::OnBnClickedButtonOpenKey()
{
	// TODO: Add your control notification handler code here
	UpdateData(true);
	// TODO: Add your control notification handler code here
	LPCTSTR pszFile =
		_T("Pem (*.pem)|*.pem|");
	CFileDialog file_diaglog(
		true,                                   // true for File Open dialog box
		L"png",               // The default file name extension
		nullptr,                    // The default file name
		OFN_FILEMUSTEXIST | OFN_NOCHANGEDIR,    // bunch of flags http://msdn.microsoft.com/en-us/library/wh5hz49d.aspx
		pszFile,
		AfxGetMainWnd()
	);

	if (file_diaglog.DoModal() != IDOK) {
		MessageBox(L"Fail to open file diaglog");
		return;
	}

	CString file_name = file_diaglog.GetPathName();
	m_keyEdit.SetWindowTextW(file_name);
	UpdateData(true);
	return;
}


void CPdfSignatureDlg::OnBnClickedButtonOpenCert()
{
	// TODO: Add your control notification handler code here
	// TODO: Add your control notification handler code here
	UpdateData(true);
	// TODO: Add your control notification handler code here
	LPCTSTR pszFile =
		_T("Pem (*.pem)|*.pem|");
	CFileDialog file_diaglog(
		true,                                   // true for File Open dialog box
		L"png",               // The default file name extension
		nullptr,                    // The default file name
		OFN_FILEMUSTEXIST | OFN_NOCHANGEDIR,    // bunch of flags http://msdn.microsoft.com/en-us/library/wh5hz49d.aspx
		pszFile,
		AfxGetMainWnd()
	);

	if (file_diaglog.DoModal() != IDOK) {
		MessageBox(L"Fail to open file diaglog");
		return;
	}

	CString file_name = file_diaglog.GetPathName();
	m_certEdit.SetWindowTextW(file_name);
	UpdateData(true);
	return;
}


void CPdfSignatureDlg::OnBnClickedButton4()
{
	CString cert_file;
	CString key_file;
	CString input_file;
	// TODO: Add your control notification handler code here

	keytype key_type = RSA_key;
	if (DSA_RADIO.GetCheck()) {
		key_type = DSA_key;
	}

	m_pdfEdit.GetWindowTextW(input_file);
	std::string file_temp(CW2A(input_file.GetString(), CP_UTF8));
	if (LoadKeyAndCert.GetCheck() == BST_CHECKED) {
		try {
			SignPdf(file_temp, "", "", key_type);
		}
		catch (PdfError& /*e*/) {
			MessageBox(L"An error when processing pdf");
			return;
		}
		
		MessageBox(L"Success in signing the pdf");
		return;
	}

	if (m_certEdit.GetWindowTextLengthW() == 0 || m_keyEdit.GetWindowTextLengthW() == 0) {
		MessageBox(L"Error the value must not be none");
		return;
	}

	m_certEdit.GetWindowTextW(cert_file);
	m_keyEdit.GetWindowTextW(key_file);
	std::string key_temp(CW2A(key_file.GetString(), CP_UTF8));
	std::string cert_temp(CW2A(cert_file.GetString(), CP_UTF8));

	try {
		SignPdf(file_temp, cert_temp, key_temp, key_type);
	}
	catch (PdfError& /*e*/) {
		MessageBox(L"An error when processing pdf");
		return;
	}
	
	MessageBox(L"Success in signing the pdf");
}


void CPdfSignatureDlg::OnBnClickedRadioDsa()
{
	// TODO: Add your control notification handler code here
}
