#include "stdafx.h"
#include "AudioRender.h"

BOOL AdjustFormatTo16Bits(WAVEFORMATEX* pwfx);

CAudioRenderImpl::CAudioRenderImpl()
{

	m_hEventStop = NULL;
	m_pDevice = NULL;
	m_hThreadRender = NULL;
	m_bInited = FALSE;
	InitializeCriticalSection(&cs);
}

CAudioRenderImpl::~CAudioRenderImpl()
{
	if (m_bInited) Destroy();
	DeleteCriticalSection(&cs);
}


BOOL CAudioRenderImpl::Initialize()
{
	if (m_bInited) return TRUE;
	m_pDevice = NULL;
	IMMDeviceEnumerator* pMMDeviceEnumerator = NULL;
	HRESULT hr = CoCreateInstance(__uuidof(MMDeviceEnumerator), NULL, CLSCTX_ALL, __uuidof(IMMDeviceEnumerator), (void**)&pMMDeviceEnumerator);
	if (FAILED(hr)) return NULL;
	hr = pMMDeviceEnumerator->GetDefaultAudioEndpoint(eRender, eConsole, &m_pDevice);
	pMMDeviceEnumerator->Release();
	if (m_pDevice == NULL) return FALSE;
	m_hEventStop = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (m_hEventStop == NULL) return FALSE;
	m_bInited = TRUE;
	return m_bInited;
}


UINT RenderAudio(CAudioRenderImpl* pthis)
{
	HRESULT hr;
	IAudioClient* pAudioClient = NULL;
	WAVEFORMATEX* pwfx = NULL;
	IAudioRenderClient* pAudioRenderClient = NULL;
	DWORD nTaskIndex = 0;
	HANDLE hTask = NULL;
	BOOL bStarted(FALSE);
	UINT32 nFrameBufferSize(0);
	HANDLE hEventRequestData = NULL;
	do
	{
		hr = pthis->m_pDevice->Activate(__uuidof(IAudioClient), CLSCTX_ALL, NULL, (void**)&pAudioClient);
		if (FAILED(hr)) break;
		hr = pAudioClient->GetMixFormat(&pwfx);
		if (FAILED(hr)) break;
		if (!AdjustFormatTo16Bits(pwfx)) break;
		hr = pAudioClient->Initialize(AUDCLNT_SHAREMODE_SHARED, AUDCLNT_STREAMFLAGS_EVENTCALLBACK, 0, 0, pwfx, 0);
		if (FAILED(hr)) break;
		hr = pAudioClient->GetBufferSize(&nFrameBufferSize);
		if (FAILED(hr)) break;
		hr = pAudioClient->GetService(__uuidof(IAudioRenderClient), (void**)&pAudioRenderClient);
		if (FAILED(hr)) break;
		hTask = AvSetMmThreadCharacteristics(_T("Playback"), &nTaskIndex);
		if (NULL == hTask) break;
		hEventRequestData = CreateEvent(NULL, FALSE, FALSE, NULL);
		if (hEventRequestData == NULL) break;
		hr = pAudioClient->SetEventHandle(hEventRequestData);
		if (FAILED(hr)) break;
		hr = pAudioClient->Start();
		if (FAILED(hr)) break;
		bStarted = TRUE;
		HANDLE waitArray[2] = { pthis->m_hEventStop, hEventRequestData };
		DWORD dwWaitResult;
		BYTE* pData = NULL;
		UINT32 nFramesOfPadding(0);
		UINT nNeedDataLen(0);
		int bufferlen = 0, audiolen = 0;
		while (TRUE)
		{
			dwWaitResult = WaitForMultipleObjects(sizeof(waitArray) / sizeof(waitArray[0]), waitArray, FALSE, INFINITE);
			if (WAIT_OBJECT_0 == dwWaitResult) { break; }
			if (WAIT_OBJECT_0 + 1 != dwWaitResult) { break; }
			hr = pAudioClient->GetCurrentPadding(&nFramesOfPadding);	if (FAILED(hr)) break;
			if (nFrameBufferSize == nFramesOfPadding) continue;
			nNeedDataLen = nFrameBufferSize - nFramesOfPadding;
			hr = pAudioRenderClient->GetBuffer(nNeedDataLen, &pData);
			if (FAILED(hr))break;
			EnterCriticalSection(&pthis->cs);//进入临界区
			bufferlen = pthis->m_WriteBuffer.GetBufferLen();
			audiolen = nNeedDataLen * pwfx->nBlockAlign;
			if (bufferlen > audiolen && (!IsBadWritePtr(pData, audiolen)))
				pthis->m_WriteBuffer.Read(pData, audiolen);
			if (bufferlen > 60000)   
				pthis->m_WriteBuffer.ClearBuffer();
			LeaveCriticalSection(&pthis->cs);//离开临界区
			pAudioRenderClient->ReleaseBuffer(nNeedDataLen, 0);
		}
	} while (FALSE);
	if (hEventRequestData != NULL) { CloseHandle(hEventRequestData);	hEventRequestData = NULL; }
	if (hTask != NULL) { AvRevertMmThreadCharacteristics(hTask);	hTask = NULL; }
	if (pAudioRenderClient != NULL) { pAudioRenderClient->Release();	pAudioRenderClient = NULL; }
	if (pwfx != NULL) { CoTaskMemFree(pwfx); pwfx = NULL; }
	if (pAudioClient != NULL)
	{
		if (bStarted) { pAudioClient->Stop(); }
		pAudioClient->Release();
		pAudioClient = NULL;
	}
	return 0;
}







UINT __stdcall RenderTheadProc(LPVOID param)
{
	CoInitialize(NULL);
	CAudioRenderImpl* pthis = (CAudioRenderImpl*)param;
	UINT nRet = RenderAudio(pthis);

	CoUninitialize();

	return nRet;
}



BOOL CAudioRenderImpl::Start()
{
	if (!m_bInited) return FALSE;
	m_hThreadRender = (HANDLE)_beginthreadex(NULL, 0, &RenderTheadProc, this, 0, NULL);
	return TRUE;
}

VOID CAudioRenderImpl::Stop()
{
	if (!m_bInited) return;

	if (m_hEventStop != NULL
		&& m_hThreadRender != NULL)
	{
		SetEvent(m_hEventStop);
		if (m_hThreadRender != NULL)
		{
			CloseHandle(m_hThreadRender);
			m_hThreadRender = NULL;
		}
	}
}

VOID CAudioRenderImpl::Destroy()
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




BOOL CAudioRenderImpl::IsInited() const
{
	return m_bInited;
}

BOOL CAudioRenderImpl::IsRendering() const
{
	return m_hThreadRender != NULL;
}


BOOL CAudioRenderImpl::PlayBuffer(LPBYTE szBuffer, DWORD dwBufferSize)
{
	EnterCriticalSection(&cs);
	m_WriteBuffer.Write(szBuffer, dwBufferSize );
	LeaveCriticalSection(&cs);
	return true;
}


BOOL AdjustFormatTo16Bits(WAVEFORMATEX* pwfx)
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


