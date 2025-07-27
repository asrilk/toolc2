#include "stdafx.h"
#include "mp4record.h"
#include "string.h"
#include <stdlib.h>

MP4_CONFIG* CreateMP4File(const char* pFileName, int fps, int width, int height)
{
	MP4_CONFIG* config = new MP4_CONFIG();
	config->videoId = MP4_INVALID_TRACK_ID;

	config->timeScale = 1000;

	config->fps = fps;
	config->width = width;
	config->height = height;

	config->video_track_configured = false;

	config->hMp4file = MP4Create(pFileName, 0);
	if (config->hMp4file == MP4_INVALID_FILE_HANDLE)
	{
		printf("open file fialed.\n");
		return NULL;
	}

	MP4SetTimeScale(config->hMp4file, config->timeScale);    

	return config;
}

void CloseMP4File(MP4_CONFIG* config)
{
	if (config->hMp4file)
	{
		MP4Close(config->hMp4file, 0);
		config->hMp4file = NULL;
	}

}

void WriteH264_SPS(MP4_CONFIG* config, unsigned char* data, int length)
{
	data = data + 4;
	length = length - 4;

	config->videoId = MP4AddH264VideoTrack
	(config->hMp4file,
		config->timeScale,                               //timeScale
		(config->timeScale / config->fps),           //sampleDuration    timeScale/fps
		config->width,     								// width  
		config->height,    								// height    

		data[5], // sps[1] AVCProfileIndication
		data[6], // sps[2] profile_compat
		data[7], // sps[3] AVCLevelIndication

		//0x42,//n->buf[1], // sps[1] AVCProfileIndication    
		//0,// n->buf[2], // sps[2] profile_compat    
		//0x1f,//n->buf[3], // sps[3] AVCLevelIndication    
		3);           // 4 bytes length before each NAL unit 


	if (config->videoId == MP4_INVALID_TRACK_ID)
	{
		printf("add video track failed.\n");
		return;
	}

	//MP4SetVideoProfileLevel(config->hMp4file, 0x0f); //  Simple Profile @ Level 3 
	MP4AddH264SequenceParameterSet(config->hMp4file, config->videoId, data + 4, length - 4);
}

void WriteH264_PPS(MP4_CONFIG * config, unsigned char* data, int length)
{
	MP4AddH264PictureParameterSet(config->hMp4file, config->videoId, data + 4, length - 4);
}

void WriteH264_Data(MP4_CONFIG * config, x264_nal_t * nals, int nal_count, size_t  payload_size, bool b_keyframe, int64_t decode_delta, int64_t composition_offset)
{
	unsigned char* pdata = NULL;
	int datalen = 0;

	x264_nal_t* nal_ptr = NULL;
	for (int i = 0; i < nal_count; i++) {
		nal_ptr = &nals[i];
		switch (nal_ptr->i_type) {
		case NAL_SPS:

			if (config->videoId == MP4_INVALID_TRACK_ID) {


				config->videoId = MP4AddH264VideoTrack
				(config->hMp4file,
					//config->timeScale,                               //timeScale
					//(config->timeScale / config->fps),           //sampleDuration    timeScale/fps
					config->timeScale,
					config->timeScale / config->fps,
					config->width,     								// width  
					config->height,    								// height    
					nal_ptr->p_payload[5],
					nal_ptr->p_payload[6],
					nal_ptr->p_payload[7],

					3);

				MP4SetVideoProfileLevel(config->hMp4file, 0x0f);
				config->video_track_configured = true;
			}

			MP4AddH264SequenceParameterSet(config->hMp4file, config->videoId, nal_ptr->p_payload + 4, nal_ptr->i_payload - 4);
			break;
		case NAL_PPS:

			MP4AddH264PictureParameterSet(config->hMp4file, config->videoId, nal_ptr->p_payload + 4, nal_ptr->i_payload - 4);
			break;
		case NAL_FILLER:

			break;
		case NALU_TYPE_SEI:

			break;
			//case NALU_TYPE_IDR:
			//case NALU_TYPE_SLICE:
		default:
		{

			int remaining_nals = nal_count - i;
			uint8_t* start_ptr = nals[i].p_payload;
			int size = payload_size - (start_ptr - (nals[0].p_payload));

			pdata = start_ptr - 4;

			pdata[0] = size >> 24;
			pdata[1] = size >> 16;
			pdata[2] = size >> 8;
			pdata[3] = size & 0xff;


			if (MP4WriteSample(config->hMp4file, config->videoId, pdata, size + 4, decode_delta, composition_offset, b_keyframe) != true)
				fprintf(stderr, "enc_mp4_write_video_sample: MP4WriteSample (NAL %d) failed\n", i);


			i += remaining_nals;
			break;
		}

		break;
		}
	}

}

//
//
//int WriteH264Data(MP4FileHandle hMp4File, const unsigned char* pData, int size)
//{
//	if (hMp4File == NULL)
//	{
//		return -1;
//	}
//	if (pData == NULL)
//	{
//		return -1;
//	}
//	MP4ENC_NaluUnit nalu;
//	int pos = 0, len = 0;
//	while (len = ReadOneNaluFromBuf(pData, size, pos, nalu))
//	{
//		if (nalu.type == 0x07) // sps
//		{
//			// 添加h264 track    
//			m_videoId = MP4AddH264VideoTrack
//			(hMp4File,
//				m_nTimeScale,
//				m_nTimeScale / m_nFrameRate,
//				m_nWidth,     // width
//				m_nHeight,    // height
//				nalu.data[1], // sps[1] AVCProfileIndication
//				nalu.data[2], // sps[2] profile_compat
//				nalu.data[3], // sps[3] AVCLevelIndication
//				3);           // 4 bytes length before each NAL unit
//			if (m_videoId == MP4_INVALID_TRACK_ID)
//			{
//				printf("add video track failed.\n");
//				return 0;
//			}
//			MP4SetVideoProfileLevel(hMp4File, 1); //  Simple Profile @ Level 3
//
//			MP4AddH264SequenceParameterSet(hMp4File, m_videoId, nalu.data, nalu.size);
//		}
//		else if (nalu.type == 0x08) // pps
//		{
//			MP4AddH264PictureParameterSet(hMp4File, m_videoId, nalu.data, nalu.size);
//		}
//		else
//		{
//			int datalen = nalu.size + 4;
//			unsigned char* data = new unsigned char[datalen];
//			// MP4 Nalu前四个字节表示Nalu长度
//			data[0] = nalu.size >> 24;
//			data[1] = nalu.size >> 16;
//			data[2] = nalu.size >> 8;
//			data[3] = nalu.size & 0xff;
//			memcpy(data + 4, nalu.data, nalu.size);
//			if (!MP4WriteSample(hMp4File, m_videoId, data, datalen, MP4_INVALID_DURATION, 0, 1))
//			{
//				return 0;
//			}
//			delete[] data;
//		}
//
//		pos += len;
//	}
//	return pos;
//}

//
//
//
//
//
//MP4Encoder::MP4Encoder(void) :
//	m_videoId(NULL),
//	m_nWidth(0),
//	m_nHeight(0),
//	m_nTimeScale(0),
//	m_nFrameRate(0)
//{
//}
//
//MP4Encoder::~MP4Encoder(void)
//{
//}
//
//MP4FileHandle MP4Encoder::CreateMP4File(const char* pFileName, int width, int height, int timeScale/* = 90000*/, int frameRate/* = 25*/)
//{
//	if (pFileName == NULL)
//	{
//		return false;
//	}
//	// create mp4 file
//	MP4FileHandle hMp4file = MP4Create(pFileName);
//	if (hMp4file == MP4_INVALID_FILE_HANDLE)
//	{
//		printf("ERROR:Open file fialed.\n");
//		return false;
//	}
//	m_nWidth = width;
//	m_nHeight = height;
//	m_nTimeScale = 90000;
//	m_nFrameRate = 25;
//	MP4SetTimeScale(hMp4file, m_nTimeScale);
//	return hMp4file;
//}
//
//bool MP4Encoder::Write264Metadata(MP4FileHandle hMp4File, LPMP4ENC_Metadata lpMetadata)
//{
//	m_videoId = MP4AddH264VideoTrack
//	(hMp4File,
//		m_nTimeScale,
//		m_nTimeScale / m_nFrameRate,
//		m_nWidth, // width
//		m_nHeight,// height
//		lpMetadata->Sps[1], // sps[1] AVCProfileIndication
//		lpMetadata->Sps[2], // sps[2] profile_compat
//		lpMetadata->Sps[3], // sps[3] AVCLevelIndication
//		3);           // 4 bytes length before each NAL unit
//	if (m_videoId == MP4_INVALID_TRACK_ID)
//	{
//		printf("add video track failed.\n");
//		return false;
//	}
//	MP4SetVideoProfileLevel(hMp4File, 0x01); //  Simple Profile @ Level 3
//
//	// write sps
//	MP4AddH264SequenceParameterSet(hMp4File, m_videoId, lpMetadata->Sps, lpMetadata->nSpsLen);
//
//	// write pps
//	MP4AddH264PictureParameterSet(hMp4File, m_videoId, lpMetadata->Pps, lpMetadata->nPpsLen);
//
//	return true;
//}
//
//int MP4Encoder::WriteH264Data(MP4FileHandle hMp4File, const unsigned char* pData, int size)
//{
//	if (hMp4File == NULL)
//	{
//		return -1;
//	}
//	if (pData == NULL)
//	{
//		return -1;
//	}
//	MP4ENC_NaluUnit nalu;
//	int pos = 0, len = 0;
//	while (len = ReadOneNaluFromBuf(pData, size, pos, nalu))
//	{
//		if (nalu.type == 0x07) // sps
//		{
//			// 添加h264 track    
//			m_videoId = MP4AddH264VideoTrack
//			(hMp4File,
//				m_nTimeScale,
//				m_nTimeScale / m_nFrameRate,
//				m_nWidth,     // width
//				m_nHeight,    // height
//				nalu.data[1], // sps[1] AVCProfileIndication
//				nalu.data[2], // sps[2] profile_compat
//				nalu.data[3], // sps[3] AVCLevelIndication
//				3);           // 4 bytes length before each NAL unit
//			if (m_videoId == MP4_INVALID_TRACK_ID)
//			{
//				printf("add video track failed.\n");
//				return 0;
//			}
//			MP4SetVideoProfileLevel(hMp4File, 1); //  Simple Profile @ Level 3
//
//			MP4AddH264SequenceParameterSet(hMp4File, m_videoId, nalu.data, nalu.size);
//		}
//		else if (nalu.type == 0x08) // pps
//		{
//			MP4AddH264PictureParameterSet(hMp4File, m_videoId, nalu.data, nalu.size);
//		}
//		else
//		{
//			int datalen = nalu.size + 4;
//			unsigned char* data = new unsigned char[datalen];
//			// MP4 Nalu前四个字节表示Nalu长度
//			data[0] = nalu.size >> 24;
//			data[1] = nalu.size >> 16;
//			data[2] = nalu.size >> 8;
//			data[3] = nalu.size & 0xff;
//			memcpy(data + 4, nalu.data, nalu.size);
//			if (!MP4WriteSample(hMp4File, m_videoId, data, datalen, MP4_INVALID_DURATION, 0, 1))
//			{
//				return 0;
//			}
//			delete[] data;
//		}
//
//		pos += len;
//	}
//	return pos;
//}
//
//int MP4Encoder::ReadOneNaluFromBuf(const unsigned char* buffer, unsigned int nBufferSize, unsigned int offSet, MP4ENC_NaluUnit& nalu)
//{
//	int i = offSet;
//	while (i < nBufferSize)
//	{
//		if (buffer[i++] == 0x00 &&
//			buffer[i++] == 0x00 &&
//			buffer[i++] == 0x00 &&
//			buffer[i++] == 0x01
//			)
//		{
//			int pos = i;
//			while (pos < nBufferSize)
//			{
//				if (buffer[pos++] == 0x00 &&
//					buffer[pos++] == 0x00 &&
//					buffer[pos++] == 0x00 &&
//					buffer[pos++] == 0x01
//					)
//				{
//					break;
//				}
//			}
//			if (pos == nBufferSize)
//			{
//				nalu.size = pos - i;
//			}
//			else
//			{
//				nalu.size = (pos - 4) - i;
//			}
//
//			nalu.type = buffer[i] & 0x1f;
//			nalu.data = (unsigned char*)&buffer[i];
//			return (nalu.size + i - offSet);
//		}
//	}
//	return 0;
//}
//
//void MP4Encoder::CloseMP4File(MP4FileHandle hMp4File)
//{
//	if (hMp4File)
//	{
//		MP4Close(hMp4File);
//		hMp4File = NULL;
//	}
//}
//
//bool MP4Encoder::WriteH264File(const char* pFile264, const char* pFileMp4)
//{
//	if (pFile264 == NULL || pFileMp4 == NULL)
//	{
//		return false;
//	}
//
//	MP4FileHandle hMp4File = CreateMP4File(pFileMp4, 352, 288);
//
//	if (hMp4File == NULL)
//	{
//		printf("ERROR:Create file failed!");
//		return false;
//	}
//
//	FILE* fp = fopen(pFile264, "rb");
//	if (!fp)
//	{
//		printf("ERROR:open file failed!");
//		return false;
//	}
//	fseek(fp, 0, SEEK_SET);
//
//	unsigned char* buffer = new unsigned char[(1024 * 1024)];
//	int pos = 0;
//	while (1)
//	{
//		int readlen = fread(buffer + pos, sizeof(unsigned char), (1024 * 1024) - pos, fp);
//
//
//		if (readlen <= 0)
//		{
//			break;
//		}
//
//		readlen += pos;
//
//		int writelen = 0;
//		for (int i = readlen - 1; i >= 0; i--)
//		{
//			if (buffer[i--] == 0x01 &&
//				buffer[i--] == 0x00 &&
//				buffer[i--] == 0x00 &&
//				buffer[i--] == 0x00
//				)
//			{
//				writelen = i + 5;
//				break;
//			}
//		}
//
//		writelen = WriteH264Data(hMp4File, buffer, writelen);
//		if (writelen <= 0)
//		{
//			break;
//		}
//		memcpy(buffer, buffer + writelen, readlen - writelen + 1);
//		pos = readlen - writelen + 1;
//	}
//	fclose(fp);
//
//	delete[] buffer;
//	CloseMP4File(hMp4File);
//
//	return true;
//}
//
//bool MP4Encoder::PraseMetadata(const unsigned char* pData, int size, MP4ENC_Metadata& metadata)
//{
//	if (pData == NULL || size < 4)
//	{
//		return false;
//	}
//	MP4ENC_NaluUnit nalu;
//	int pos = 0;
//	bool bRet1 = false, bRet2 = false;
//	while (int len = ReadOneNaluFromBuf(pData, size, pos, nalu))
//	{
//		if (nalu.type == 0x07)
//		{
//			memcpy(metadata.Sps, nalu.data, nalu.size);
//			metadata.nSpsLen = nalu.size;
//			bRet1 = true;
//		}
//		else if ((nalu.type == 0x08))
//		{
//			memcpy(metadata.Pps, nalu.data, nalu.size);
//			metadata.nPpsLen = nalu.size;
//			bRet2 = true;
//		}
//		pos += len;
//	}
//	if (bRet1 && bRet2)
//	{
//		return true;
//	}
//	return false;
//}