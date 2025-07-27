#include "StdAfx.h"
#include "MasterEncoder.h"
#include <fstream>
#include <string>
#include <cstring>
#include <iostream>

using namespace std;

MasterEncoder* MasterEncoder::_instance = nullptr;

MasterEncoder* MasterEncoder::getInstance()
{
		if (_instance == nullptr)
			_instance = new MasterEncoder();
	return _instance;
}

MasterEncoder::MasterEncoder()
{
	_codeKey = 100;
	_sign = nullptr;
	_signLen = 0;
}

MasterEncoder::~MasterEncoder() 
{

}

void MasterEncoder::setSignAndKey(char* sign, int signLen, unsigned char key) {
	if (sign && signLen)
	{
		_signLen = signLen;
		_sign = new char[signLen];
		if (_sign) {
			memcpy(_sign, sign, signLen);
		}
		else {
			cout << "setSignAndKey Failed!\n";
		}
	}
	_codeKey = key;
}

void MasterEncoder::encode(unsigned char* data, long size) {
	for (long i = 0; i < size; i++)
	{
		data[i] ^= _codeKey;
	}
}

void MasterEncoder::decode(unsigned char* data, long size) {
	for (long i = 0; i < size; i++)
	{
		data[i] ^= _codeKey;
	}
}

unsigned char* MasterEncoder::readPDF(const string& filepath, long& size)
{
	ifstream ifs;
	ifs.open(filepath, ios::in | ios::binary);

	if (!ifs.is_open())
	{
		cout << "文件打开失败" << endl;
		return nullptr;
	}


	ifs.seekg(0, std::ios_base::end);
	size =(long) ifs.tellg();
	ifs.seekg(0, std::ios_base::beg);
	unsigned char* data = new unsigned char[size];
	long count = 0;
	while (count < size)
	{
		ifs.read((char*)&data[count], sizeof(unsigned char));
		//ifs >> data[count];//字符串模式
		//printf("%c", data[count]);
		count++;
	}

	cout << "read PDF size = " << size << endl;

	ifs.close();

	return data;
}

void MasterEncoder::writePDF(const string& filePath, unsigned char* data, long size) {

	ofstream ofs;
	ofs.open(filePath, ios::out | ios::trunc | ios::binary);

	if (!ofs.is_open())
	{
		cout << "文件打开失败" << endl;
		return;
	}

	long count = 0;
	while (count < size) {
		//ofs << data[count];
		ofs.write((char*)&data[count], sizeof(unsigned char));
		count++;
	}
	cout << "save PDF size = " << size << endl;
	ofs.close();

}

void MasterEncoder::encodePDF(const string& pdfPath, const string& savePath) {
	long size = 0;
	unsigned char* data = readPDF(pdfPath, size);

	//判断是否已经加密过
	if (memcmp(data, _sign, _signLen) == 0) {
		cout << "加密过了, 直接保存！" << endl;
		writePDF(savePath, data, size);
	}
	else {
		encode(data, size);

		if (_signLen > 0) {
			unsigned char* p = new unsigned char[size + _signLen];
			memcpy(p, _sign, _signLen);
			memcpy(p + _signLen, data, size);

			writePDF(savePath, p, size + _signLen);

			delete[] p;
		}
		else {
			writePDF(savePath, data, size);
		}
	}

	delete[] data;
}

void MasterEncoder::decodePDF(const string& pdfPath, const string& savePath) {
	long size = 0;
	unsigned char* data = readPDF(pdfPath, size);

	if (_signLen == 0) {
		decode(data, size);
		writePDF(savePath, data, size);
	}
	else if (memcmp(data, _sign, _signLen) == 0) {
		unsigned char* p = (data + _signLen);
		decode(p, size - _signLen);
		writePDF(savePath, p, size - _signLen);
	}
	else {
		cout << "解密失败！" << endl;
	}

	delete[] data;
}

unsigned char* MasterEncoder::decode(const string& pdfPath, long& size) {
	unsigned char* data = readPDF(pdfPath, size);

	if (_signLen == 0) {
		decode(data, size);
		return data;
	}
	else if (memcmp(data, _sign, _signLen) == 0) {
		size -= _signLen;
		unsigned char* p = new unsigned char[size];
		memcpy(p, data + _signLen, size);
		decode(p, size);
		delete[] data;
		return p;
	}
	else {
		return data;
	}
}