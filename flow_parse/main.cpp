// ConsoleApplication88.cpp : ���ļ����� "main" ����������ִ�н��ڴ˴���ʼ��������
//

#include <iostream>
#include<fstream>
#include"base_type.h"
#include"getopt.h"
#include"buildFlow.h"
#include"MySQLConnector.h"
#include <pthread.h>
using namespace std;

const char* program_name;
char* jsonFilePath;
extern int discard_num;

void print_usage(FILE* stream, int exit_code)
{
    fprintf(stream, "Usage: %s options [ input ]\n",
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


//TCP���Ķ�ȡ�̣߳�ִ��TCPЭ��ĳ�ɸ����
void* TCP_reader_main(void* ptr) {
    FlowBuilder* run_ptr = (FlowBuilder*)ptr;
    run_ptr->BuildFlow(300, 'A');
    return NULL;
}


int main(int argc, char* argv[])
{
    char* pcapFileName;
    char opt;
    // �����ú�Ĭ��ֵ
    int time = 300;   //Ӧ��flowʱ��ץ��ʱ��
    char interface_func = 'A';   //�����ӿ�
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
            jsonFilePath = optarg;
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
            cout << "invaild option" << endl;
            print_usage(stderr, 1);
        case -1:    /* Done with options. */
            break;
        default:    /* Something else: unexpected. */
            print_usage(stderr, 1);
        }
    } while (opt != -1);


    if (flow)
    {
        //BuildFlow(time, interface_func);
        pthread_t TcpThreadIdList[TCP_WORK_NUM]; 
        FlowBuilder* TcpBuilderList = new FlowBuilder[TCP_WORK_NUM];
        //TcpBuilderList[0].initial_my_mem();
        for (int i = 0; i < TCP_WORK_NUM; i++) {
            TcpBuilderList[i].FilterId = i;             
            stringstream stmp;
            string fileNum = ".json";
            stmp << jsonFilePath << i << fileNum ;
            string tmpFileName = stmp.str();
            TcpBuilderList[i].jsonFileName= const_cast<char*>(tmpFileName.c_str());
            cout << "file path:" << TcpBuilderList[i].jsonFileName << endl;
            int ret = pthread_create(&TcpThreadIdList[i], NULL, TCP_reader_main, &TcpBuilderList[i]);
            if (ret) {
                cerr << "pthread " << i << " create create error!" << endl;
                return 1;
            }
        }

        for (int i = 0; i < TCP_WORK_NUM; i++) {
            pthread_join(TcpThreadIdList[i], NULL);
        }
    }
    else
    {
        return 0;
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
