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

#pragma once










	
#define IsSameThread(tid1, tid2)		((tid1) == (tid2))
#define IsSelfThread(tid)				IsSameThread((tid), 	(::GetCurrentThreadId()))
#define IsSameProcess(pid1, pid2)		((pid1) == (pid2))
#define IsSelfProcess(pid)				IsSameProcess((pid), (::GetCurrentProcessId()))

DWORD GetSysPageSize();
DWORD GetDefaultWorkerThreadCount();

// 获取系统信息
VOID SysGetSystemInfo(LPSYSTEM_INFO pInfo);
// 获取 CPU 核数
DWORD SysGetNumberOfProcessors();
// 获取页面大小
DWORD SysGetPageSize();
