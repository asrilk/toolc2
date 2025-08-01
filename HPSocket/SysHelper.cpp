﻿/*
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
#include "SysHelper.h"
#include "GeneralHelper.h"

///////////////////////////////////////////////////////////////////////////////////////////////////////

DWORD GetDefaultWorkerThreadCount()
{
	static const DWORD s_dwtc = min((::SysGetNumberOfProcessors() * 2 + 2), 512);
	return s_dwtc;
}

DWORD GetSysPageSize()
{
	static const DWORD s_dtsbs = ::SysGetPageSize();
	return s_dtsbs;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////

VOID SysGetSystemInfo(LPSYSTEM_INFO pInfo)
{
	ASSERT(pInfo != nullptr);
	::GetNativeSystemInfo(pInfo);
}

DWORD SysGetNumberOfProcessors()
{
	SYSTEM_INFO si;
	SysGetSystemInfo(&si);
	
	return si.dwNumberOfProcessors;
}

DWORD SysGetPageSize()
{
	SYSTEM_INFO si;
	SysGetSystemInfo(&si);

	return si.dwPageSize;
}
