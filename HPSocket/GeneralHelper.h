

#pragma once

#ifndef VC_EXTRALEAN
	#define VC_EXTRALEAN
#endif

#ifndef WIN32_LEAN_AND_MEAN
	#define WIN32_LEAN_AND_MEAN
#endif

#ifndef _ATL_CSTRING_EXPLICIT_CONSTRUCTORS
	#define _ATL_CSTRING_EXPLICIT_CONSTRUCTORS
#endif

#if _MSC_VER >= 1400

	#if defined _DEBUG && _MSC_VER < 1600
		#ifndef _SECURE_SCL
			#define _SECURE_SCL					0
		#endif
		#ifndef _HAS_ITERATOR_DEBUGGING
			#define _HAS_ITERATOR_DEBUGGING		0
		#endif
	#endif

	#ifndef _CRT_SECURE_NO_DEPRECATE
		#define _CRT_SECURE_NO_DEPRECATE		1
	#endif

	#ifndef _SCL_SECURE_NO_DEPRECATE
		#define _SCL_SECURE_NO_DEPRECATE		1
	#endif

	#ifndef _ATL_SECURE_NO_WARNINGS
		#define _ATL_SECURE_NO_WARNINGS			1
	#endif

	#ifndef _ATL_SECURE_NO_WARNINGS
		#define _ATL_SECURE_NO_WARNINGS			1
	#endif

	#ifndef _ATL_DISABLE_NOTHROW_NEW
		#define _ATL_DISABLE_NOTHROW_NEW		1
	#endif

	#ifndef _SECURE_ATL
		#define _SECURE_ATL						1
	#endif

	#ifndef _WINSOCK_DEPRECATED_NO_WARNINGS
		#define _WINSOCK_DEPRECATED_NO_WARNINGS	1
	#endif

#endif

#ifndef _WIN32_WINNT
	#if defined (_WIN64)
		#define _WIN32_WINNT	_WIN32_WINNT_WIN7
	#else
		#if _MSC_VER >= 1910
			#define _WIN32_WINNT	_WIN32_WINNT_WIN7
		#else
			#define _WIN32_WINNT	_WIN32_WINNT_WINXP
		#endif
	#endif
#endif

#ifndef WINVER
	#define WINVER	_WIN32_WINNT
#endif

#if _MSC_VER >= 1600
	#include <SDKDDKVer.h>
#else
	#if !defined(nullptr)
		#define nullptr	NULL
	#endif
#endif

#ifdef _DETECT_MEMORY_LEAK
	#ifndef _CRTDBG_MAP_ALLOC
		#define _CRTDBG_MAP_ALLOC
	#endif
#endif



	#include <Windows.h>
	#include <WindowsX.h>
	#include <commctrl.h>
	#include <stdio.h>
	#include <stdlib.h>
	#include <malloc.h>
	#include <memory.h>
	#include <tchar.h>
	#include <atlstr.h>
	#include <atltime.h>

	#ifndef ASSERT
		#define ASSERT(f)	ATLASSERT(f)
	#endif
	#ifndef VERIFY
		#define VERIFY(f)	ATLVERIFY(f)
	#endif
	#ifndef ENSURE
		#define ENSURE(f)	ATLENSURE(f)
	#endif

	#ifndef TRACE
		#include <atltrace.h>

		#define TRACE							AtlTrace
		#define TRACE0(f)						TRACE(f)
		#define TRACE1(f, p1)					TRACE(f, p1)
		#define TRACE2(f, p1, p2)				TRACE(f, p1, p2)
		#define TRACE3(f, p1, p2, p3)			TRACE(f, p1, p2, p3)
		#define TRACE4(f, p1, p2, p3, p4)		TRACE(f, p1, p2, p3, p4)
		#define TRACE5(f, p1, p2, p3, p4, p5)	TRACE(f, p1, p2, p3, p4, p5)
	#endif




#include <atlbase.h>
#include <atlconv.h>

#include "Singleton.h"
//#include "Semaphore.h"
#include "CriticalSection.h"
#include "STLHelper.h"
#include "Win32Helper.h"
#include "PrivateHeap.h"
#include "BufferPtr.h"

