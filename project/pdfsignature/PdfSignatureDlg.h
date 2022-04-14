
// PdfSignatureDlg.h : header file
//

#pragma once


// CPdfSignatureDlg dialog
class CPdfSignatureDlg : public CDialogEx
{
// Construction
public:
	CPdfSignatureDlg(CWnd* pParent = nullptr);	// standard constructor

// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_PDFSIGNATURE_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support


// Implementation
protected:
	HICON m_hIcon;

	// Generated message map functions
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedButton1();
	afx_msg void OnBnClickedButton2();
	afx_msg void OnBnClickedButtonOpenPdf();
private:
	CString pdfName;
public:
	CButton LoadKeyAndCert;
	CButton button_open_key;
	CButton button_open_cert;
	afx_msg void OnBnClickedCheck1();
	CEdit m_pdfEdit;
	CEdit m_keyEdit;
	CEdit m_certEdit;
	afx_msg void OnBnClickedButtonOpenKey();
	afx_msg void OnBnClickedButtonOpenCert();
	afx_msg void OnBnClickedButton4();
	afx_msg void OnBnClickedRadioDsa();
	CButton DSA_RADIO;
};
