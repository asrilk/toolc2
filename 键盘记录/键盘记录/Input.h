#pragma once
#define DIRECTINPUT_VERSION 0x0800
#include <dinput.h>
#pragma comment(lib,"dinput8.lib")
#pragma comment(lib,"dxguid.lib")
template<typename T>
void safeRelease(T obj)
{
	if (obj) obj->Release();
	obj = 0;
}
#define DINPUT_BUFFERSIZE 60
class Input
{
public:
	static bool initialize(const HWND& window, const HINSTANCE& instance);
	static	void UpdateInputData();
	static void destroy();
	static bool GetKerboard(TCHAR* m_key);
	static IDirectInput8* mDInput;
	static IDirectInputDevice8* mKeyboard;
	static IDirectInputDevice8* mMouse;
	static DIMOUSESTATE2 mMouseState;
	static DWORD               dwElements;
	static BOOL               bshift;
	static BOOL               bcaps;
	static DIDEVICEOBJECTDATA  didod[DINPUT_BUFFERSIZE];  // Receives buffered data
private:
	Input() {}
};

