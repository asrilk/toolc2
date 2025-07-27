// QuickDoc.h : interface of the CQuickDoc class
//


#pragma once


class CQuickDoc : public CDocument
{
protected: // create from serialization only
	CQuickDoc();
	DECLARE_DYNCREATE(CQuickDoc)

// Attributes
public:

// Operations
public:

// Overrides
	public:
	virtual BOOL OnNewDocument();
	virtual void Serialize(CArchive& ar);

// Implementation
public:
	virtual ~CQuickDoc();
#ifdef _DEBUG
	virtual void AssertValid() const;
	virtual void Dump(CDumpContext& dc) const;
#endif

protected:

// Generated message map functions
protected:
	DECLARE_MESSAGE_MAP()
public:
	
};
