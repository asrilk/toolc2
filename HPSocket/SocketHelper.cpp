/*
 * Copyright: JessMA Open Source (ldcsaa@gmail.com)
 *
 * Author	: Bruce Liang
 * Website	: https://github.com/ldcsaa
 * Project	: https://github.com/ldcsaa/HP-Socket
 * Blog		: http://www.cnblogs.com/ldcsaa
 * Wiki		: http://www.oschina.net/p/hp-socket
 * QQ Group	: 44636872, 75375912
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
 
#include "stdafx.h"
#include "GeneralHelper.h"
#include "SysHelper.h"
#include "SocketHelper.h"

#include <mstcpip.h>
#pragma comment(lib, "ws2_32")

#if !defined(stscanf_s)
	#ifdef _UNICODE
		#define stscanf_s	swscanf_s
	#else
		#define stscanf_s	sscanf_s
	#endif
#endif

//#include "GeneralHelper.h"
//#include "CriticalSection.h"

#include <MmSystem.h>
#pragma comment(lib, "Winmm")


DWORD GetTimeGap32(DWORD dwOriginal, DWORD dwCurrent)
{
	if (dwCurrent == 0)
		dwCurrent = ::timeGetTime();

	return dwCurrent - dwOriginal;
}
//
//
BOOL PeekMessageLoop(BOOL bDispatchQuitMsg)
{
	BOOL value = TRUE;

	MSG msg;
	while (::PeekMessage(&msg, nullptr, 0, 0, PM_REMOVE))
	{
		if (msg.message == WM_QUIT && !bDispatchQuitMsg)
		{
			value = FALSE;
			break;
		}

		::TranslateMessage(&msg);
		::DispatchMessage(&msg);
	}

	return value;
}
//
DWORD WaitForMultipleObjectsWithMessageLoop(DWORD dwHandles, HANDLE szHandles[], DWORD dwMilliseconds, BOOL bWaitAll, DWORD dwWakeMask)
{
	DWORD dwResult = WAIT_FAILED;
	DWORD dwBeginTime = (dwMilliseconds == INFINITE) ? INFINITE : ::timeGetTime();

	while (TRUE)
	{
		int iWaitTime;
		if (dwBeginTime == INFINITE)
			iWaitTime = INFINITE;
		else
		{
			iWaitTime = dwMilliseconds - (GetTimeGap32(dwBeginTime));

			if (iWaitTime <= 0)
			{
				dwResult = WAIT_TIMEOUT;
				break;
			}
		}

		dwResult = ::MsgWaitForMultipleObjects(dwHandles, szHandles, bWaitAll, (DWORD)iWaitTime, dwWakeMask);

		if (dwResult == (WAIT_OBJECT_0 + dwHandles))
			PeekMessageLoop();
		else
			break;
	}

	return dwResult;
}

BOOL MsgWaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds, BOOL bWaitAll, DWORD dwWakeMask)
{
	DWORD dwResult = WaitForMultipleObjectsWithMessageLoop(1, &hHandle, dwMilliseconds, bWaitAll, dwWakeMask);

	switch (dwResult)
	{
	case WAIT_OBJECT_0:
		return TRUE;
	case WAIT_TIMEOUT:
		::SetLastError(ERROR_TIMEOUT);
		return FALSE;
	case WAIT_FAILED:
		return FALSE;
	default:
		ENSURE(FALSE);
	}

	return FALSE;
}
