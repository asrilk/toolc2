#pragma once
#include "universal.h"

NTSTATUS readkey(LPWSTR strkeyname, WCHAR* keyvalue, ULONG len, WCHAR* Context);

NTSTATUS RegSetValueKey(LPWSTR REG_KEY_NAME, LPWSTR REG_VALUE_NAME, DWORD DataType, PVOID DataBuffer, DWORD DataLength);

void MyGetTickCount(PULONG msec);

PWCHAR MyCurTimeStr();

NTSTATUS  Ksleep(int times);