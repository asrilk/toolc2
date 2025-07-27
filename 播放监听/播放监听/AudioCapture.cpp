#include "stdafx.h"
#include "AudioCapture.h"
#include "SpeakerManager.h"


BOOL FormatTo16Bits(WAVEFORMATEX* pwfx);

CAudioCapture::CAudioCapture()
{
	 m_pDevice=NULL;
	 m_bInited= FALSE;
	 pSpeakerManager= NULL;
	 m_hThreadCapture = NULL;
	 m_hEventStop=NULL;
}

CAudioCapture::~CAudioCapture()
{
	if (m_bInited) Destroy();
}

BOOL CAudioCapture::Initialize(void* pthis)
{
	if (m_bInited) return TRUE;
	pSpeakerManager = pthis;
	 m_pDevice = NULL;
	IMMDeviceEnumerator* pMMDeviceEnumerator = NULL;
	HRESULT hr = CoCreateInstance(__uuidof(MMDeviceEnumerator), NULL, CLSCTX_ALL,__uuidof(IMMDeviceEnumerator),	(void**)&pMMDeviceEnumerator);
	if (FAILED(hr)) return FALSE;
	hr = pMMDeviceEnumerator->GetDefaultAudioEndpoint(eRender, eConsole, &m_pDevice);
	pMMDeviceEnumerator->Release();
	if (m_pDevice == NULL) return FALSE;
	m_hEventStop = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (m_hEventStop == NULL)  return FALSE;
	m_bInited = TRUE;
	return TRUE;
}

UINT CaptureAudio(CAudioCapture* pthis)
{
	HRESULT hr;
	IAudioClient* pAudioClient = NULL;
	WAVEFORMATEX* pwfx = NULL;
	REFERENCE_TIME hnsDefaultDevicePeriod(0);
	HANDLE hTimerWakeUp = NULL;
	IAudioCaptureClient* pAudioCaptureClient = NULL;
	DWORD nTaskIndex = 0;
	HANDLE hTask = NULL;
	BOOL bStarted(FALSE);
	LPBYTE senddate = new BYTE[MAX_SEND_BUFFER * 4];

	do
	{
		hr = pthis->m_pDevice->Activate(__uuidof(IAudioClient), CLSCTX_ALL, NULL, (void**)&pAudioClient);
		if (FAILED(hr)) break;
		hr = pAudioClient->GetDevicePeriod(&hnsDefaultDevicePeriod, NULL);
		if (FAILED(hr)) break;
		hr = pAudioClient->GetMixFormat(&pwfx);
		if (FAILED(hr)) break;
		if (!FormatTo16Bits(pwfx)) break;
		hTimerWakeUp = CreateWaitableTimer(NULL, FALSE, NULL);
		if (hTimerWakeUp == NULL) break;
		hr = pAudioClient->Initialize(AUDCLNT_SHAREMODE_SHARED, AUDCLNT_STREAMFLAGS_LOOPBACK, 0, 0, pwfx, 0);
		if (FAILED(hr)) break;
		hr = pAudioClient->GetService(__uuidof(IAudioCaptureClient), (void**)&pAudioCaptureClient);
		if (FAILED(hr)) break;
		hTask = AvSetMmThreadCharacteristics(_T("Capture"), &nTaskIndex);
		if (NULL == hTask) break;
		hr = pAudioClient->Start();
		if (FAILED(hr)) break;
		UINT32 nNextPacketSize(0);
		BYTE* pData = NULL;
		UINT32 nNumFramesToRead;
		DWORD dwFlags;
		int sendzise = 0;
		LARGE_INTEGER liFirstFire;
		liFirstFire.QuadPart = -hnsDefaultDevicePeriod / 2; // 负意味着相对时间
		LONG lTimeBetweenFires = (LONG)hnsDefaultDevicePeriod / 2 / (10 * 1000); // 转换为毫秒
		BOOL bOK = SetWaitableTimer(hTimerWakeUp, &liFirstFire, lTimeBetweenFires, NULL, NULL, FALSE);
		DWORD	dwWaitResult = 0;
		HANDLE waitArray[2] = { pthis->m_hEventStop, hTimerWakeUp };
		while (TRUE)
		{
			dwWaitResult = WaitForMultipleObjects(2, waitArray, FALSE, INFINITE);
			if(!pthis->m_hThreadCapture) break;
			hr = pAudioCaptureClient->GetNextPacketSize(&nNextPacketSize);
			if (FAILED(hr))	{	break;	}
			if (nNextPacketSize == 0) continue;
			hr = pAudioCaptureClient->GetBuffer(&pData,&nNumFramesToRead,	&dwFlags,	NULL,	NULL);
			if (FAILED(hr)){break;}
			if (0 != nNumFramesToRead)
			{
				sendzise = nNumFramesToRead * pwfx->nBlockAlign + 1;
				senddate[0] = TOKEN_SPEAK_DATA;
				memcpy(senddate + 1, pData, sendzise - 1);
				pAudioCaptureClient->ReleaseBuffer(nNumFramesToRead);
				((CSpeakerManager*)(pthis->pSpeakerManager))->Send((LPBYTE)senddate, sendzise);

			}
			else
				pAudioCaptureClient->ReleaseBuffer(nNumFramesToRead);
		}

	} while (FALSE);
	SAFE_DELETE_AR(senddate);
	if (hTask != NULL) { AvRevertMmThreadCharacteristics(hTask);	hTask = NULL; }
	if (pAudioCaptureClient != NULL) {pAudioCaptureClient->Release();	pAudioCaptureClient = NULL;}
	if (pwfx != NULL){	CoTaskMemFree(pwfx);	pwfx = NULL;}
	if (hTimerWakeUp != NULL)	{CancelWaitableTimer(hTimerWakeUp);CloseHandle(hTimerWakeUp);	hTimerWakeUp = NULL;}
	if (pAudioClient != NULL) {if (bStarted){	pAudioClient->Stop();}pAudioClient->Release();	pAudioClient = NULL;}
	return 0;
}
UINT __stdcall CaptureTheadPro(LPVOID param)
{
	CAudioCapture* pthis = (CAudioCapture*)param;
	CoInitialize(NULL);

	UINT nRet = CaptureAudio(pthis);

	CoUninitialize();

	return nRet;
}

BOOL CAudioCapture::Start()
{
	if (!m_bInited) return FALSE;
	m_hThreadCapture= (HANDLE)_beginthreadex(NULL, 0, &CaptureTheadPro, this, 0, NULL);
	return TRUE;
}

void CAudioCapture::Stop()
{
	if (!m_bInited) return;
	if (m_hThreadCapture != NULL && m_hEventStop != NULL)
	{
		SetEvent(m_hEventStop);
		CloseHandle(m_hThreadCapture);
		m_hThreadCapture = NULL;
	}
}

void CAudioCapture::Destroy()
{
	if (m_pDevice != NULL)
	{
		m_pDevice->Release();
		m_pDevice = NULL;
	}
	if (m_hEventStop != NULL)
	{
		CloseHandle(m_hEventStop);
		m_hEventStop = NULL;
	}
	m_bInited = FALSE;
}

BOOL CAudioCapture::IsInited() const
{
	return m_bInited;
}

BOOL CAudioCapture::IsCapturing() const
{
	return m_hThreadCapture != NULL;
}


BOOL FormatTo16Bits(WAVEFORMATEX* pwfx)
{
	BOOL bRet(FALSE);

	if (pwfx->wFormatTag == WAVE_FORMAT_IEEE_FLOAT)
	{
		pwfx->wFormatTag = WAVE_FORMAT_PCM;
		pwfx->wBitsPerSample = 16;
		pwfx->nBlockAlign = pwfx->nChannels * pwfx->wBitsPerSample / 8;
		pwfx->nAvgBytesPerSec = pwfx->nBlockAlign * pwfx->nSamplesPerSec;

		bRet = TRUE;
	}
	else if (pwfx->wFormatTag == WAVE_FORMAT_EXTENSIBLE)
	{
		PWAVEFORMATEXTENSIBLE pEx = reinterpret_cast<PWAVEFORMATEXTENSIBLE>(pwfx);
		if (IsEqualGUID(KSDATAFORMAT_SUBTYPE_IEEE_FLOAT, pEx->SubFormat))
		{
			pEx->SubFormat = KSDATAFORMAT_SUBTYPE_PCM;
			pEx->Samples.wValidBitsPerSample = 16;
			pwfx->wBitsPerSample = 16;
			pwfx->nBlockAlign = pwfx->nChannels * pwfx->wBitsPerSample / 8;
			pwfx->nAvgBytesPerSec = pwfx->nBlockAlign * pwfx->nSamplesPerSec;

			bRet = TRUE;
		}
	}

	return bRet;
}

