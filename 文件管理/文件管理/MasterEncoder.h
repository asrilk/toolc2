#pragma once

#include <string>
using namespace std;
class MasterEncoder
{
public:
	static MasterEncoder* getInstance();
	MasterEncoder();
	~MasterEncoder();

	void setSignAndKey(char* sign, int signLen, unsigned char key);

	void decode(unsigned char* data, long size);
	void encode(unsigned char* data, long size);

	void writePDF(const string& filePath, unsigned char* data, long size);
	unsigned char* readPDF(const string& filepath, long& size);

public:
	void encodePDF(const string& pdfPath, const string& savePath);
	void decodePDF(const string& pdfPath, const string& savePath);
	unsigned char* decode(const string& pdfPath, long& size);

private:
	static MasterEncoder* _instance;

	unsigned char _codeKey;
	char* _sign;
	int _signLen;

};

