#pragma once
#include "vfw.h" // DrawDibOpen
#pragma comment(lib, "vfw32.lib")

class CVideoCodec  
{
	COMPVARS	m_cv;
	HIC			m_hIC;
	BITMAPINFO*	m_lpbmiInput;
	BITMAPINFO	m_bmiOutput;
public:
	
	bool InitCompressor(BITMAPINFO*	lpbmi, DWORD fccHandler)
	{
		if (lpbmi == NULL)
			return false;

		m_lpbmiInput = lpbmi;
		
		ZeroMemory(&m_cv, sizeof(m_cv));
		m_cv.cbSize		= sizeof(m_cv);
		m_cv.dwFlags	= ICMF_COMPVARS_VALID;
		m_cv.hic		= m_hIC;
		m_cv.fccType	= ICTYPE_VIDEO;
		m_cv.fccHandler	= fccHandler;
		m_cv.lpbiOut	= NULL;
		m_cv.lKey		= 10;
		m_cv.lDataRate	= 6;
		m_cv.lQ			= ICQUALITY_HIGH;		
		
		m_hIC = ICOpen(ICTYPE_VIDEO, m_cv.fccHandler, ICMODE_COMPRESS | ICMODE_DECOMPRESS);
		
		if (m_hIC == NULL)
		{
			return false;
		}

		ICCompressGetFormat(m_hIC, m_lpbmiInput, &m_bmiOutput);
		// �������������֤
		ICSendMessage(m_hIC, 0x60c9, 0xf7329ace, 0xacdeaea2);
		
		m_cv.hic = m_hIC;
		m_cv.dwFlags = ICMF_COMPVARS_VALID;
		
		if (!ICSeqCompressFrameStart(&m_cv, m_lpbmiInput))
		{
			return false;
		}

		ICDecompressBegin(m_hIC, &m_bmiOutput , m_lpbmiInput);
		
		return true;
	}
	
	bool DecodeVideoData(BYTE *pin, int len, BYTE* pout, int *lenr,DWORD flag)
	{
		if(!pin || !pout ||!m_hIC)		
			return false;
 		if (ICDecompress(m_hIC, flag, &m_bmiOutput.bmiHeader, pin, &m_lpbmiInput->bmiHeader, pout) != ICERR_OK)
 			return false;
		
		if (lenr) *lenr = m_lpbmiInput->bmiHeader.biSizeImage;
		
		return true;	
	}
	
	bool EncodeVideoData(BYTE* pin, int len, BYTE* pout, int* lenr, bool* pKey)
	{
		BYTE	*p;
		long	s = 1;
		BOOL	k = TRUE;
		if ( !pin || !pout || len != (int)m_lpbmiInput->bmiHeader.biSizeImage || !m_hIC)
			return false;
		p = (BYTE*)ICSeqCompressFrame(&m_cv, 0, pin, &k, &s);

		if (!p)		return false;
		if (lenr)	*lenr = s;
		if (pKey)	(*pKey) = k?true:false;
		
		CopyMemory(pout, p, s);
		
		return true;
	}
	
	CVideoCodec()
	{
		m_lpbmiInput = NULL;
	}
	
	virtual ~CVideoCodec()
	{
		// No init yet or init error
		if (m_hIC == NULL)
			return;
		ICDecompressEnd(m_hIC);
		ICSeqCompressFrameEnd(&m_cv);
		ICCompressorFree(&m_cv);
		ICClose(m_hIC);
	}
	
};
