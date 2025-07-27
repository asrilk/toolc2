//
// Created by M君 on 2019/4/29.
//

#ifndef HHMP4V2TEST_MP4RECORD_H
#define HHMP4V2TEST_MP4RECORD_H
#define MP4V2_EXPORTS
#include <mp4v2/mp4v2.h>

#ifdef _DEBUG

#pragma comment(lib, "libmp4v2_UD.lib")
#else

#pragma comment(lib, "libmp4v2_U.lib")
#endif




extern "C"
{
#include <x264.h>
#include <x264_config.h>
}

#define _NALU_SPS_  7
#define _NALU_PPS_  8
#define _NALU_IDR_  5
#define _NALU_BP_   1

typedef enum {
	NALU_TYPE_SLICE = 1,
	NALU_TYPE_DPA = 2,
	NALU_TYPE_DPB = 3,
	NALU_TYPE_DPC = 4,
	NALU_TYPE_IDR = 5,
	NALU_TYPE_SEI = 6,
	NALU_TYPE_SPS = 7,
	NALU_TYPE_PPS = 8,
	NALU_TYPE_AUD = 9,
	NALU_TYPE_EOSEQ = 10,
	NALU_TYPE_EOSTREAM = 11,
	NALU_TYPE_FILL = 12,
} NaluType;



typedef struct Mp4_Config
{
	MP4FileHandle hMp4file;
	MP4TrackId videoId;
	int timeScale;        //视频每秒的ticks数,如90000
	int fps;              //视频帧率
	int width;          //视频宽
	int height;         //视频高

	bool video_track_configured;
}MP4_CONFIG;



MP4_CONFIG* CreateMP4File(const char* pFileName, int fps, int width, int height);

void CloseMP4File(MP4_CONFIG* config);

void WriteH264_SPS(MP4_CONFIG* config, unsigned char* data, int length);

void WriteH264_PPS(MP4_CONFIG* config, unsigned char* data, int length);

void WriteH264_Data(MP4_CONFIG* config, x264_nal_t* nals, int nal_count, size_t  payload_size, bool b_keyframe, int64_t decode_delta, int64_t composition_offset);



//
//// NALU单元
//typedef struct _MP4ENC_NaluUnit
//{
//	int type;
//	int size;
//	unsigned char* data;
//}MP4ENC_NaluUnit;
//
//typedef struct _MP4ENC_Metadata
//{
//	// video, must be h264 type
//	unsigned int	nSpsLen;
//	unsigned char	Sps[1024];
//	unsigned int	nPpsLen;
//	unsigned char	Pps[1024];
//
//} MP4ENC_Metadata, * LPMP4ENC_Metadata;
//
//class MP4Encoder
//{
//public:
//	MP4Encoder(void);
//	~MP4Encoder(void);
//public:
//	// open or creat a mp4 file.
//	MP4FileHandle CreateMP4File(const char* fileName, int width, int height, int timeScale = 90000, int frameRate = 25);
//	// wirte 264 metadata in mp4 file.
//	bool Write264Metadata(MP4FileHandle hMp4File, LPMP4ENC_Metadata lpMetadata);
//	// wirte 264 data, data can contain  multiple frame.
//	int WriteH264Data(MP4FileHandle hMp4File, const unsigned char* pData, int size);
//	// close mp4 file.
//	void CloseMP4File(MP4FileHandle hMp4File);
//	// convert H264 file to mp4 file.
//	// no need to call CreateMP4File and CloseMP4File,it will create/close mp4 file automaticly.
//	bool WriteH264File(const char* pFile264, const char* pFileMp4);
//	// Prase H264 metamata from H264 data frame
//	static bool PraseMetadata(const unsigned char* pData, int size, MP4ENC_Metadata& metadata);
//private:
//	// read one nalu from H264 data buffer
//	static int ReadOneNaluFromBuf(const unsigned char* buffer, unsigned int nBufferSize, unsigned int offSet, MP4ENC_NaluUnit& nalu);
//private:
//	int m_nWidth;
//	int m_nHeight;
//	int m_nFrameRate;
//	int m_nTimeScale;
//	MP4TrackId m_videoId;
//};




#endif //HHMP4V2TEST_MP4RECORD_H
