// ConsoleApplication88.cpp : ���ļ����� "main" ����������ִ�н��ڴ˴���ʼ��������
//

#include <iostream>
#include<fstream>
#include"base_type.h"
#include"getopt.h"
#include"buildFlow.h"
#include"MySQLConnector.h"
using namespace std;

const char* program_name;
extern const char* jsonFileName;
extern int discard_num;

void print_usage(FILE* stream, int exit_code)
{
    fprintf(stream, "Usage: %s options [ inputfile ]\n",
        program_name);
    fprintf(stream,
        "Set default to use Flow mode\n"
        "  -h  --help       Display this usage information.\n"
        "  -o  --output     Output json file name.[default 1.json]\n"
        "  -p  --pcap       Parse pcap file, need to input pacp file name.\n"
        "  -d  --discard    Discard when packet count smaller than discard.[default 300]\n"
        "Following arguments are only valid in Flow mode:\n"
        "  -t  --time       Time for get packet(second).[default 300]\n"
        "  -i  --interface  Choose interface A,B,C.[default C]\n"
       );
    exit(exit_code);
}


int main(int argc, char* argv[])
{
    char* pcapFileName;
    char opt;
    // �����ú�Ĭ��ֵ
    int time = 300;   //Ӧ��flowʱ��ץ��ʱ��
    char interface_func = 'C';   //�����ӿ�
    bool flow = true;


    const char* const short_options = "hi:o:p:d:t:";
    program_name = argv[0];
    const struct option long_options[] = {
    {"help", 0, NULL, 'h'},
    {"interface", 1, NULL, 'i'},
    {"output", 1, NULL, 'o'},
    {"pcap", 1, NULL, 'p' },
    {"discard", 1, NULL, 'd'},
    {"time", 1, NULL, 't'},
    {NULL, 0, NULL, 0}    /* Required at end of array. */
    };


    do {
        opt = getopt_long(argc, argv, short_options, long_options, NULL);
        switch (opt)
        {
        case 'h':    /* -h or --help */
            print_usage(stdout, 0); //���������ֱ��exit
        case 'o':    /* -o or --output */
            jsonFileName = optarg;
            break;
        case 'p':
            flow = false;
            pcapFileName = optarg;
            break;
        case 'd':
            discard_num = atoi(optarg);
            break;
        //following args only vaild while use Flow
        case 'i':
            interface_func = *optarg;
            break;
        case 't':
            time = atoi(optarg);
            break;
        // handle excption
        case '?':
            print_usage(stderr, 1);
        case -1:    /* Done with options. */
            break;
        default:    /* Something else: unexpected. */
            print_usage(stderr, 1);
        }
    } while (opt != -1);

    if (flow)
    {
        BuildFlow(time, interface_func);
    }
    else
    {
        ParsePcap(pcapFileName);
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
