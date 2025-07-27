// SoundToWav.h: interface for the CSoundToWav class.
//

#include <mmsystem.h>

#pragma once


class CSoundToWav
{
public:
	CSoundToWav();
	virtual ~CSoundToWav();

public:
	void  SetWaveFormat(WAVEFORMATEX* pwfx);
	DWORD WriteWavFileHeader();
	DWORD WriteWavData(LPBYTE pData, DWORD nSize);
private:
	DWORD m_dwTotalBytes;
	WAVEFORMATEX m_wfx;

public:

	BOOL Open(LPCTSTR lpFileName, DWORD dwDesiredAccess = FILE_WRITE_DATA | FILE_READ_DATA/*²Î¿¼CreateFile*/);
	DWORD Seek(LONG lDistanceToMove, DWORD dwMoveMethod = FILE_BEGIN/*²Î¿¼SetFilePointer*/);
	DWORD SeekToBegin();
	DWORD SeekToEnd();
	DWORD Write(LPVOID lpBuffer, DWORD nNumberOfBytesToWrite);
	BOOL close();


protected:
	HANDLE m_hFile;
};

