// ConsoleApplication88.cpp : ���ļ����� "main" ����������ִ�н��ڴ˴���ʼ��������
//

#include <iostream>
#include<fstream>
#include <cstring>
#include"base_type.h"
#include"buildFlow.h"
#include"MySQLConnector.h"
using namespace std;

extern char* jsonFileName;
int main(int argc, char* argv[])
{
    jsonFileName = argv[2];
    if (argv[1] == "f")
    {
        cout << "file: " << jsonFileName << endl;
        buildFlow();
    }
    else if (argv[1] == "p")
    {
        char* pcapFileName = argv[3];
        cout << "pcapFile: " << pcapFileName << endl;
        cout << "jsonFile: " << jsonFileName << endl;
        parsePcapFile(pcapFileName);
    }
    return 0;
}

// ���г���: Ctrl + F5 ����� >����ʼִ��(������)���˵�
// ���Գ���: F5 ����� >����ʼ���ԡ��˵�

// ����ʹ�ü���: 
//   1. ʹ�ý��������Դ�������������/�����ļ�
//   2. ʹ���Ŷ���Դ�������������ӵ�Դ�������
//   3. ʹ��������ڲ鿴���������������Ϣ
//   4. ʹ�ô����б��ڲ鿴����
//   5. ת������Ŀ��>���������Դ����µĴ����ļ�����ת������Ŀ��>�����������Խ����д����ļ���ӵ���Ŀ
//   6. ��������Ҫ�ٴδ򿪴���Ŀ����ת�����ļ���>���򿪡�>����Ŀ����ѡ�� .sln �ļ�
