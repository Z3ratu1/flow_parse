#include"base_type.h"
#include"getopt.h"
#include"buildFlow.h"
#include"MySQLConnector.h"

#include <iostream>
#include<fstream>
#include <pthread.h>
#include <unordered_map>
using namespace std;

int execTime = 300;   //Ӧ��flowʱ��ץ��ʱ��
extern Mem_reader* mc;       //����Ϊȫ�ֱ��������̹߳���
extern int discard_num;
extern pthread_mutex_t mutex;
extern unordered_map<Tuble, int, hashTuble> IPDict;

const char* program_name;
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
        "  -T  --thread     create thread number\n"
       );
    exit(exit_code);
}


//TCP���Ķ�ȡ�̣߳�ִ��TCPЭ��ĳ�ɸ����
void* TCP_reader_main(void* ptr) {
    FlowBuilder* run_ptr = (FlowBuilder*)ptr;
    run_ptr->BuildFlow(execTime);
    return NULL;
}


int main(int argc, char* argv[])
{
    char* pcapFileName;
    char opt;
    // �����ú�Ĭ��ֵ
    bool flow = true;
    int threadNumber = 8;  //�߳���
    char* jsonFilePath;    //�ļ�����·��
    char interface_func = 'A';   //�����ӿ�
    
    const char* const short_options = "hi:o:p:d:t:T:";
    program_name = argv[0];
    const struct option long_options[] = {
    {"help", 0, NULL, 'h'},
    {"interface", 1, NULL, 'i'},
    {"output", 1, NULL, 'o'},
    {"pcap", 1, NULL, 'p' },
    {"discard", 1, NULL, 'd'},
    {"time", 1, NULL, 't'},
    {"thread", 1, NULL, 'T'},
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
        case 'p':    /* -p or --pcap */
            flow = false;
            pcapFileName = optarg;
            break;
        case 'd':    /* -d or --discard */
            discard_num = atoi(optarg);
            break;
        //following args only vaild while use Flow
        case 'i':    /* -i or --interface */
            interface_func = *optarg;
            break;
        case 't':    /* -t or -- time */
            execTime = atoi(optarg);
            break;
        case 'T':
            threadNumber = atoi(optarg);
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
        // net-view�������ӿ�
        mc = get_my_reader();   //mem_reader��ʼ��
        switch (interface_func)
        {
        case 'A':
            if (!init_memA_reader(mc))
            {
                cerr << "init reader err" << endl;
                return 1;
            }
            else
            {
                cerr << "init reader success" << endl;
            }
            break;
        case 'B':
            if (!init_memB_reader(mc))
            {
                cerr << "init reader err" << endl;
                return 1;
            }
            else
            {
                cerr << "init reader success" << endl;
            }
            break;
        case 'C':
            if (!init_memC_reader(mc))
            {
                cerr << "init reader err" << endl;
                return 1;
            }
            else
            {
                cerr << "init reader success" << endl;
            }
            break;
        default:
            if (!init_memA_reader(mc))
            {
                cerr << "init reader err" << endl;
                return 1;
            }
            else
            {
                cerr << "init reader success" << endl;
            }
            break;
        }

        initDict(IPDict);   //��ʼ��ɸ���ֵ�
        cout << IPDict.size() << " records in dict" << endl;

        pthread_t* TcpThreadIdList = new pthread_t[threadNumber];
        FlowBuilder* TcpBuilderList = new FlowBuilder[threadNumber];
        pthread_mutex_init(&mutex, NULL);
        for (int i = 0; i < threadNumber; i++) 
        {
            TcpBuilderList[i].FilterId = i;
            TcpBuilderList[i].jsonFileName = new char[100];
            sprintf(TcpBuilderList[i].jsonFileName, jsonFilePath , i);
            cout << "file path:" << TcpBuilderList[i].jsonFileName << endl;
            int ret = pthread_create(&TcpThreadIdList[i], NULL, TCP_reader_main, &TcpBuilderList[i]);
            if (ret) 
            {
                cerr << "pthread " << i << " create create error!" << endl;
                return 1;
            }
        }

        for (int i = 0; i < threadNumber; i++) {
            pthread_join(TcpThreadIdList[i], NULL);
        }

        delete[] TcpBuilderList;
        delete[] TcpThreadIdList;
        pthread_mutex_destroy(&mutex);
    }
    else
    {
        // pcap
        // ParsePcap(pcapFileName);
        cout << "this function is unholding..." << endl;
        return 0;
    }

    // cout << "before main end" << endl;
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
