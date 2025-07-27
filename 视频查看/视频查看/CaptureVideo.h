#pragma once
#define STRSAFE_NO_DEPRECATE



#include <list>
#include <string>
#include <atlbase.h>
#include <windows.h>
#include <dshow.h>
#include ".\Include\qedit.h" // ISampleGrabberCB
#include <amvideo.h>
#pragma comment(lib,"Strmiids.lib")
#include "XvidEnc.h"

#ifdef _WIN64

#ifdef _DEBUG
#pragma comment(lib, "xvid_64_d.lib")

#else
#pragma comment(lib, "xvid_64.lib")

#endif


#else

#ifdef _DEBUG
#pragma comment(lib, "xvid_32_d.lib")

#else
#pragma comment(lib, "xvid_32_r.lib")

#endif
#endif

class SmartString
{
public:
	SmartString():str(NULL) {}

	SmartString(char* pStr):str(NULL)
	{
		if (pStr)
		{
			int size = int(strlen(pStr));
			str = new char[size+1];
			strcpy_s(str, strlen(pStr) + 1, pStr);
		}
	}

	SmartString(SmartString& sStr)
	{
		SetString(sStr.GetBuffer());
	}

	~SmartString()
	{
		if (str)
			delete[] str;
	}

	SmartString& operator =(char* pStr)
	{
		SetString(pStr);
		return *this;
	}

	SmartString& operator =(SmartString& sStr)
	{
		SetString(sStr.GetBuffer());
		return *this;
	}

	char* GetBuffer() {return str;}

protected:
	void SetString(char *pStr)
	{
		if (str)
			delete[] str;

		if (!pStr)
		{
			str = NULL;
		}
		else
		{
			int size = int(strlen(pStr));
			str = new char[size + 1];
			strcpy_s(str, strlen(pStr) + 1, pStr);
		}

	}


	char* str;
};

class ResolutionInfo
{
public:
	ResolutionInfo():next(NULL)
	{

	}
	~ResolutionInfo()
	{
		if (next)
			delete next;
	}
	SmartString Resolution;
	ResolutionInfo* next;
};
class DeviceInfo
{
public:
	DeviceInfo():next(NULL), deviceId(-1),resInfo(NULL)
	{
	} 
	~DeviceInfo()
	{
		if (resInfo)
			delete resInfo;
		if (next)
			delete next;
	}


	SmartString friendlyName;
	int			deviceId;	
	ResolutionInfo* resInfo;
	DeviceInfo* next;
};
#define MY_TEST
#ifndef SAFE_RELEASE
#define SAFE_RELEASE( x ) \
if ( NULL != x ) \
{ \
  x->Release( ); \
  x = NULL; \
}
#endif

class CCamFrameHandler {
public:
	virtual void CamFrameData(double dblSampleTime, BYTE * pBuffer, long lBufferSize) = 0 ; 
};

class CSampleGrabberCB : public ISampleGrabberCB 
{
public:
	long				   lWidth ; 
	long				   lHeight ; 
	CCamFrameHandler	*  frame_handler ; 
	BOOL				   bGrabVideo ; 
public:
	CSampleGrabberCB(){ 
		lWidth = 0 ; 
		lHeight = 0 ; 
		bGrabVideo = FALSE ; 
		frame_handler = NULL ; 
	} 
	STDMETHODIMP_(ULONG) AddRef() { return 2; }
	STDMETHODIMP_(ULONG) Release() { return 1; }
	STDMETHODIMP QueryInterface(REFIID riid, void ** ppv) {
		if( riid == IID_ISampleGrabberCB || riid == IID_IUnknown ){ 
			*ppv = (void *) static_cast<ISampleGrabberCB*> ( this );
			return NOERROR;
		} 
		return E_NOINTERFACE;
	}

	STDMETHODIMP SampleCB( double SampleTime, IMediaSample * pSample )  {
		HRESULT hr;
		unsigned char* buffer;
//		static DWORD dwTick = GetTickCount();
		hr = pSample->GetPointer((BYTE**)&buffer);
		if (hr != S_OK) return S_OK;
//		if (GetTickCount() - dwTick > 66)
		{
//			dwTick = GetTickCount();
			if(bGrabVideo && frame_handler) frame_handler->CamFrameData(0, buffer, pSample->GetActualDataLength()) ;
		}
		return 0;
	}

	STDMETHODIMP BufferCB( double dblSampleTime, BYTE * pBuffer, long lBufferSize ){
// 		if (!pBuffer) return E_POINTER;
// 		if(bGrabVideo && frame_handler) frame_handler->CamFrameData(dblSampleTime, pBuffer, lBufferSize) ; 
		return 0;
	}
};

class CCaptureVideo : public CCamFrameHandler,public CXvidEncHandler//,public CXvidDecHandler/*,public CWnd*/ 
{
	friend class CSampleGrabberCB;
	public:
	HANDLE	m_hCaptureEvent;
	std::list<char*> m_lpBuf;
	LPBITMAPINFO m_lpbmi;
	bool IsWebCam();
	LPBYTE GetDIB();
	void CamFrameData(double dblSampleTime, BYTE * pBuffer, long lBufferSize) ; 
	void GrabVideoFrames(BOOL bGrabVideoFrames, CCamFrameHandler * frame_handler = NULL); 
    HRESULT Start(int iDeviceID,HWND hWnd = NULL, int width = 320, int height = 240);
	HRESULT Stop(); 
	int EnumDevices(DeviceInfo *head);
	void PostEncHandler(unsigned char * xvid, int key, int xvid_len) ; 
    bool CheckEncodeNull();
    CCaptureVideo();
    virtual ~CCaptureVideo();
  private:
	CRITICAL_SECTION m_cs;
	DeviceInfo m_devInfo;
	std::list<char*> m_capBufList;
	BOOL m_bIsStarted;
	int m_nWidth ;
	int m_nHeight ;
	CXvidEnc *m_pEnc;
	LPBYTE m_lpDIB;
	bool m_bIsConnected;
    HWND					m_hWnd;
    IGraphBuilder *			m_pGB;
    ICaptureGraphBuilder2*	m_pCapture;
    IBaseFilter*			m_pBF;
    IMediaControl*			m_pMC;
    ISampleGrabber*			m_pGrabber;
	IBaseFilter*	m_pNullRenderer;
  protected:
    void FreeMediaType(AM_MEDIA_TYPE& mt);
    bool BindFilter(int deviceId, IBaseFilter **pFilter);
    HRESULT InitCaptureGraphBuilder();
};
