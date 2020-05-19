#ifndef  PCAP_H
#define  PCAP_H

#include "base_type.h"
#include "json.hpp"
//#include "MySQLConnector.h"
#include "base_type.h"

#include <fstream>
#include <iostream>
#include <string>
#include <malloc.h>
#include<string.h>
#include <unordered_map>
#include <fstream>

//#include<WinSock2.h>
//#pragma comment(lib,"ws2_32.lib")   //windows
#include <arpa/inet.h>    //Linux

using namespace std;
using json = nlohmann::json;

#define  PCAP_FILE_MAGIC_1   0Xd4
#define  PCAP_FILE_MAGIC_2   0Xc3
#define  PCAP_FILE_MAGIC_3   0Xb2
#define  PCAP_FILE_MAGIC_4   0Xa1
#define BUFFER_SIZE 268435456   //缓存区大小
#define MTU 1500    //最大单个包大小
#define MAX_FLOW_NUMBER 10000000   //可承载流数
char* jsonFileName;  //定义全局变量


/*pcap file header*/
typedef struct pcapFileHeader
{
    uchar8_t   magic[4];
    uint16_t   version_major;
    uint16_t   version_minor;
    int32_t    thiszone;      /*时区修正*/
    uint32_t   sigfigs;       /*精确时间戳*/
    uint32_t   snaplen;       /*抓包最大长度*/
    uint32_t   linktype;      /*链路类型*/
} pcapFileHeader_t;



/*pcap packet header*/
typedef struct pcapPkthdr
{
    uint32_t   seconds;     /*秒数*/
    uint32_t   u_seconds;   /*毫秒数*/
    uint32_t   caplen;      /*数据包长度*/
    uint32_t   len;         /*文件数据包长度*/
} pcapPkthdr_t;

struct IPInfo   //20字节长ip段
{
    uint8_t version_length; //ip协议版本和字段长度在一个字节中
    uint8_t service_field;
    uint16_t total_length;  //整个报文长度
    uint16_t identification;
    uint16_t flag;
    uint8_t time_to_live;
    uint8_t protocol;
    uint16_t header_check;
    uint32_t sourceIP;
    uint32_t destinationIP;
};

struct TCPInfo  //只需要最前面八个字节的端口
{
    uint16_t sourcePort;
    uint16_t destinationPort;
};

struct Triple   //哈希用三元组
{
    uint16_t sourcePort;
    uint32_t sourceIP;
    uint32_t destinationIP;
};

class PacketTimeAndLen
{
public:
    PacketTimeAndLen()
    {
        next = NULL;
        seconds = 0;
        u_seconds = 0;
        len = 0;
    }
    PacketTimeAndLen(uint32_t s, uint32_t u_s, uint32_t l)
    {
        next = NULL;
        seconds = s;
        u_seconds = u_s;
        len = l;
    }
    uint32_t seconds;     /*秒数*/
    uint32_t u_seconds;   /*毫秒数*/
    uint32_t len;
    PacketTimeAndLen* next;   //链表
};

struct PacketInfo    //需要统计的一个包的全部信息
{
    //两个时间戳
    uint32_t seconds;     /*秒数*/
    uint32_t u_seconds;   /*毫秒数*/
    uint32_t len;   //包长
    Triple port_ip; //端口及ip信息
};

class Flow
{
public:
    Flow()
    {
        packetList = NULL;
        packet_cnt = 1;
        seconds = 0;
        u_seconds = 0;
        flow_byte_cnt = 0;
        port_ip = { 0 };
    }
    Flow(Triple port_ip_info, uint32_t s, uint32_t u_s, int fbc)
    {
        port_ip = port_ip_info;
        packet_cnt = 1;
        seconds = s;
        u_seconds = u_s;
        flow_byte_cnt = fbc;
        packetList = NULL;
    }
    ~Flow()
    {
        PacketTimeAndLen* temp;
        //在这里输出一个json文件

        vector<uint32_t>u_s;
        vector<uint32_t>s;
        vector<uint32_t>len;

        while (packetList != NULL)
        {
            u_s.insert(u_s.begin(), packetList->u_seconds);
            s.insert(s.begin(), packetList->seconds);
            len.insert(len.begin(), packetList->len);
            temp = packetList->next;
            delete packetList;
            packetList = temp;
        }
        flow_byte_cnt = flow_byte_cnt / (1024 * 1024);   //单位换算成MB
        if (packet_cnt > 100)  //小于200的不输出
        {
            //使用nlohmann json
            //创建一个json对象
            json j;
            j["sourceIP"] = port_ip.sourceIP;
            j["sourcePort"] = port_ip.sourcePort;
            j["destinationIP"] = port_ip.destinationIP;
            json j_us(u_s);
            json j_s(s);
            json j_len(len);
            j["u_s"] = j_us;
            j["s"] = j_s;
            j["len"] = j_len;
            j["cnt"] = packet_cnt;
            j["flow_byte_cnt"] = flow_byte_cnt;

            ofstream jsonFile;
            jsonFile.open(jsonFileName, ios::app);   //追加方式写入
            //cout<<"in destruction"<<endl;
            if (!jsonFile)
            {
                cout << "fail to open json file" << endl;
            }
            jsonFile << j.dump(4) << ",\n";  //输出
            jsonFile.close();
        }
    }

    uint32_t seconds;
    uint32_t u_seconds;
    Triple port_ip;
    int packet_cnt;    //包数
    double flow_byte_cnt = 0;    //暂定单位MB
    PacketTimeAndLen* packetList;  //所有包的链表
};


void InsertFlow(unordered_map<string, int>&dict, PacketInfo &packetInfo, Flow* flowList[], int &index)
{
    unordered_map<string, int>::const_iterator got;
    string hashKey = to_string(packetInfo.port_ip.destinationIP) + to_string(packetInfo.port_ip.sourceIP) + to_string(packetInfo.port_ip.sourcePort);
    got = dict.find(hashKey);
    if (got == dict.end())   //查找不到
    {
        if (index < MAX_FLOW_NUMBER)    //限制数组不能越界
        {
            pair<string, int>flow_info(hashKey, index);
            dict.insert(flow_info);
            //流数组添加一项
            flowList[index] = new Flow(packetInfo.port_ip, packetInfo.seconds, packetInfo.u_seconds, packetInfo.len);
            flowList[index]->packet_cnt++;
            flowList[index]->packetList = new PacketTimeAndLen(packetInfo.seconds, packetInfo.u_seconds, packetInfo.len);
            index++;    //数组下标移位
        }
        else
        {
            cout << "流数组已满" << endl;
        }
    }
    else
    {
        int temp_index = got->second;   //first是键，second是值
        flowList[temp_index]->flow_byte_cnt += packetInfo.len;  //记录包长，无论时间
        //链表操作
        if (packetInfo.seconds - flowList[temp_index]->seconds <= 300)  //五分钟截止
        {
            PacketTimeAndLen* listHead = flowList[temp_index]->packetList;
            flowList[temp_index]->packetList = new PacketTimeAndLen(packetInfo.seconds, packetInfo.u_seconds, packetInfo.len);
            flowList[temp_index]->packet_cnt++;
            flowList[temp_index]->packetList->next = listHead;
        }
    }

}


void parsePcapFile(const char* fileName)
{
    fstream fileHandler;
    fileHandler.open(fileName, ios::in|ios::binary);

    if (!fileHandler)
    {
        cout << "The file does not exits or file name is error" << endl;

        return;
    }
    pcapFileHeader_t  pcapFileHeader = { 0 };
    fileHandler.seekg(ios::end);
    cout << fileHandler.tellg() << endl;;
    fileHandler.seekg(0);
    //读取pcap文件头部长度
    fileHandler.read((char*)&pcapFileHeader, 24);
    if (pcapFileHeader.magic[0] != PCAP_FILE_MAGIC_1 || pcapFileHeader.magic[1] != PCAP_FILE_MAGIC_2 ||
        pcapFileHeader.magic[2] != PCAP_FILE_MAGIC_3 || pcapFileHeader.magic[3] != PCAP_FILE_MAGIC_4)
    {
        cout << "The file is not a pcap file" << endl;

        return;
    }

    //定义各个变量
    pcapPkthdr_t  packetHeader = { 0 };
    char8_t* buffer;    //缓冲区
    IPInfo ipinfo;
    TCPInfo tcpinfo;
    PacketInfo packetInfo;
    Triple port_ip;
    Flow** flowList = new Flow*[MAX_FLOW_NUMBER];         //流数组
    for (int i = 0; i < MAX_FLOW_NUMBER; i++)
    {
        flowList[i] = NULL;
    }
    int buffer_pointer = 0;     //定位缓冲区
    long long file_pointer = 24; //int不够用，设置成long long
    long long cnt = 0;
    unordered_map<string, int> dict;
    //unordered_map<string, int> IPDict;    //筛选IP和端口的字典
    //initDict(IPDict);   //初始化筛查字典
    //cout << IPDict.size() << " records in dict" << endl;
    int index = 0;
    double byte_cnt = 0;

    //按块读入数据
    while (!fileHandler.eof())
    {
        buffer = (char8_t*)malloc(BUFFER_SIZE);     //申请内存
        memset(buffer, 0, BUFFER_SIZE);
        buffer_pointer = 0;
        if (buffer == NULL)
        {
            cerr << "malloc memory failed" << endl;
            //处理程序
        }

        fileHandler.seekg(file_pointer);
        fileHandler.read(buffer, BUFFER_SIZE); //读入一批处理的数据


        while (buffer_pointer < BUFFER_SIZE - MTU)
        {
            memcpy((char8_t*)&packetHeader, buffer + buffer_pointer, sizeof(packetHeader));
            buffer_pointer += sizeof(packetHeader);
            buffer_pointer += 14;   //以太网帧
            memcpy((char8_t*)&ipinfo, buffer + buffer_pointer, sizeof(IPInfo));
            // 处理包
            byte_cnt += htons(ipinfo.total_length);
            if (ipinfo.protocol == 0)    //文件以及读完了，指向buffer的空字节部分
            {
                break;
            }
            cnt++;  //全部包数计数器
            if (ipinfo.protocol == 6)  //TCP,ascii为6
            {
                //处理程序
                buffer_pointer += sizeof(IPInfo);
                memcpy((char8_t*)&tcpinfo, buffer+buffer_pointer,sizeof(TCPInfo));
                buffer_pointer += (packetHeader.caplen - sizeof(IPInfo) - 14);  //多减的14为以太网帧

                //端序转换（不知道在Linux的CPU架构下需不需要转换端序）
                ipinfo.total_length = htons(ipinfo.total_length);
                ipinfo.sourceIP = htonl(ipinfo.sourceIP);
                ipinfo.destinationIP = htonl(ipinfo.destinationIP);
                tcpinfo.sourcePort = htons(tcpinfo.sourcePort);

                //unordered_map<string, int>::const_iterator got;
                //got = IPDict.find(to_string(ipinfo.sourceIP) + to_string(tcpinfo.sourcePort));

                //if (got != IPDict.end())    //筛选IP
                //{
                    //创建单个处理对象
                    port_ip.destinationIP = ipinfo.destinationIP;
                    port_ip.sourceIP = ipinfo.sourceIP;
                    port_ip.sourcePort = tcpinfo.sourcePort;
                    packetInfo.len = packetHeader.len;
                    packetInfo.port_ip = port_ip;
                    packetInfo.seconds = packetHeader.seconds;
                    packetInfo.u_seconds = packetHeader.u_seconds;

                    InsertFlow(dict, packetInfo, flowList, index);
                //}
            }
            else    //其他包都不要
            {
                //处理程序
                buffer_pointer += packetHeader.caplen - 14;     //-14以太网帧
            }
        }
        cout << file_pointer << endl;
        file_pointer += buffer_pointer;
        free(buffer);
        
    }

    fileHandler.close();
  
    //处理结束后的收尾程序
    //释放内存
    fstream json_file;
    json_file.open(jsonFileName, ios::out);
    if (!json_file)
    {
        cout << "fail to open " << jsonFileName << endl;
    }
    json_file << "{\n  \"flows\": [\n";
    json_file.close();

    for (int i = 0; i < index; i++)
    {
        delete flowList[i];
        flowList[i] = NULL;
    }
    byte_cnt = byte_cnt / (1024 * 1024);
    json_file.open(jsonFileName, ios::app);
    json_file << "{}],\n \"cnt\": [\n {\"pac_cnt\": " << cnt << ",\n \"flow_cnt\": " << index << ",\n \"byte_cnt\": " << byte_cnt;
    json_file << " }]}\n";
    json_file.close();


    return;
}
#endif
