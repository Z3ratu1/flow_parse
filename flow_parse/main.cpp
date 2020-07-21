// ConsoleApplication88.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
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


//TCP报文读取线程，执行TCP协议的初筛过滤
void* TCP_reader_main(void* ptr) {
    FlowBuilder* run_ptr = (FlowBuilder*)ptr;
    run_ptr->BuildFlow(300, 'A');
    return NULL;
}


int main(int argc, char* argv[])
{
    char* pcapFileName;
    char opt;
    // 先设置好默认值
    int time = 300;   //应用flow时流抓包时间
    char interface_func = 'A';   //函数接口
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
            print_usage(stdout, 0); //这个函数会直接exit
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

// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门使用技巧: 
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件
