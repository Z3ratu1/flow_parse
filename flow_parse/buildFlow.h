#ifndef  PCAP_H
#define  PCAP_H

#include "violet_api/mpcap.h"
#include "violet_api/sh_mem.h"
#include "violet_api/sh_mem.cpp"
#include "violet_api/nv_mem.cpp"
#include "base_type.h"
#include "json.hpp"
#include "MySQLConnector.h"

#include <time.h>
#include <fstream>
#include <iostream>
#include <functional>
#include <unordered_map>
#include <arpa/inet.h>
//#include<WinSock2.h>
//#pragma comment(lib,"ws2_32.lib")   //windows
using namespace std;
using json = nlohmann::json;

const char* jsonFileName = "1.json";  //设置默认文件名
int discard_num = 300;  //设置默认剪枝数

class Flow
{
public:
    Flow()
    {
        packetList = NULL;
        flow_byte_cnt = 0;
        packet_cnt = 1;
        seconds = 0;
        port_ip = { 0 };
    }
    Flow(Triple port_ip_info, uint32_t s, uint32_t u_s, int fbc)
    {
        port_ip = port_ip_info;
        packet_cnt = 1;
        seconds = s;
        u_seconds = u_s;
        packetList = NULL;
        flow_byte_cnt = fbc;
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
        if(packet_cnt > discard_num)  //小于300的不输出
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
            j["cnt"] = packet_cnt;  //该条流对应的<srcIP,dstIP,srcPort>
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

void InsertFlow(unordered_map<Triple, int, hashTriple>&dict, PacketInfo &packetInfo, Flow* flowList[], int &index)
{
    unordered_map<Triple, int, hashTriple>::const_iterator got;
    Triple port_ip = packetInfo.port_ip;
    got = dict.find(port_ip);
    if (got == dict.end())   //查找不到
    {
        if (index < MAX_FLOW_NUMBER)    //限制数组不能越界
        {
            pair<Triple, int>flow_info(port_ip, index);
            dict.insert(flow_info);
            //流数组添加一项
            flowList[index] = new Flow(packetInfo.port_ip, packetInfo.seconds, packetInfo.u_seconds, packetInfo.len);
            flowList[index]->packetList = new PacketTimeAndLen(packetInfo.u_seconds, packetInfo.seconds, packetInfo.len);
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
        if (packetInfo.seconds - flowList[temp_index]->seconds <= 300)   //5分钟内才要
        {
            PacketTimeAndLen* listHead = flowList[temp_index]->packetList;
            flowList[temp_index]->packetList = new PacketTimeAndLen(packetInfo.u_seconds, packetInfo.seconds, packetInfo.len);
           // flowList[temp_index]->packet_cnt++;
            flowList[temp_index]->packetList->next = listHead;
        }
        flowList[temp_index]->packet_cnt++;     //待修改
    }
    return ;
}

void BuildFlow(int run_seconds, char inter_func)
{
    //net-view读函数接口
    Mem_reader* mc;
    mc = get_my_reader();

    //init_memA_reader 表示stream_tcp,init_memB_reader 表示stream_udp,init_memC_reader 表示stream_filter
    switch (inter_func)
    {
    case 'A':
        if (!init_memA_reader(mc)) 
        {
            cerr << "init reader err" << endl;
            return;
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
            return;
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
            return;
        }
        else
        {
            cerr << "init reader success" << endl;
        }
        break;
    default:
        if (!init_memC_reader(mc))
        {
            cerr << "init reader err" << endl;
            return;
        }
        else
        {
            cerr << "init reader success" << endl;
        }
        break;
    }


    //定义各个变量
    IPInfo* ipinfo;
    TCPInfo* tcpinfo;
    PacketInfo packetInfo;
    Triple port_ip;
    unordered_map<Triple, int, hashTriple> flowDict;    //查找流下标的字典
    unordered_map<Tuble, int, hashTuble> IPDict;    //筛选IP和端口的字典
    int index = 0;  //总流数，包括被剪枝的流
    Flow** flowList = new Flow * [MAX_FLOW_NUMBER];         //流数组

    //初始化流数组
    for (int i = 0; i < MAX_FLOW_NUMBER; i++)
    {
        flowList[i] = NULL;
    }

    initDict(IPDict);   //初始化筛查字典
    cout << IPDict.size() << " records in dict" << endl;
      
    uint16_t ip_len;
    char* ppt;
    uint16_t len;
    uint16_t mask;
    // len表示被截取的报文长度，mask表示报文属性，在stream中,mask & 0x8000 为true，表示网内到网外，否则相反
    uint32_t seconds;  //包到达时间
    uint32_t u_seconds;
    long long cnt = 0;
    double byte_cnt = 0;    //总字节统计
    time_t start_time = time(NULL);
    while (time(NULL) - start_time < run_seconds)  // 时间为秒
    {        
        cnt++;
        if(cnt % 1000000000 == 0)  //10亿
	      {
	       cout << cnt << endl;
	      }
        ppt = (char*)read_data(mc, len, mask, seconds, u_seconds);
        if (ppt == NULL)
        {
            cerr << "ppt is null\n";
            //读异常
            continue;
        }
        // 如果报文是网外到网内的，则舍弃
        if ((mask & 1024) == 0)
        {
            //cout << "mask & 1024 == 0"<<endl;
            continue;
        }

        //玄幻的数据读入部分
        ipinfo = (IPInfo*)ppt;
        ip_len = ((ipinfo->version_and_length) % 16 * 4);  //移位获取IP段长度
        byte_cnt += htons(ipinfo->total_length);   //统计字节数
        if (int(ipinfo->protocol) == 6)  //TCP
        {
            //端序转换
            ipinfo->destinationIP = htonl(ipinfo->destinationIP);
            ipinfo->sourceIP = htonl(ipinfo->sourceIP);
            ipinfo->total_length = htons(ipinfo->total_length);

            //TCP信息
            tcpinfo = (TCPInfo*)((char*)ipinfo + ip_len);
            tcpinfo->sourcePort = htons(tcpinfo->sourcePort);
            tcpinfo->destinationPort = htons(tcpinfo->destinationPort);

            //取消了端口筛选
            // 查字典
            unordered_map<Tuble, int, hashTuble>::const_iterator got;
            Tuble d(tcpinfo->sourcePort, ipinfo->sourceIP);
            got = IPDict.find(d);

            if (got != IPDict.end())    //筛选IP
            {
                //创建单个处理对象
                port_ip.destinationIP = ipinfo->destinationIP;
                port_ip.sourceIP = ipinfo->sourceIP;
                port_ip.sourcePort = tcpinfo->sourcePort;
                packetInfo.port_ip = port_ip;
                packetInfo.len = ipinfo->total_length;
                packetInfo.seconds = seconds;
                packetInfo.u_seconds = u_seconds;

                InsertFlow(flowDict, packetInfo, flowList, index);
            }

        }
    }
    
    //处理结束后的收尾程序
    //释放内存
    fstream json_file;
    json_file.open(jsonFileName, ios::out);
    if(!json_file)
    {
        cout << "fail to open " << jsonFileName <<endl;
    }
    json_file << "{\n  \"flows\": [\n";
    json_file.close();
    
    for (int i = 0; i < index; i++)
    {
        delete flowList[i];
        flowList[i] = NULL;
    }
    byte_cnt = byte_cnt / (1024*1024);  //单位换算到M
    json_file.open(jsonFileName, ios::app);
    json_file << "{}],\n \"cnt\": [\n {\"pac_cnt\": " << cnt << ",\n \"flow_cnt\": " << index << ",\n \"byte_cnt\": " << byte_cnt;
    json_file << " }]}\n";
    json_file.close();
    return;
}

void ParsePcap(char* fileName)
{
    fstream fileHandler;
    fileHandler.open(fileName, ios::in | ios::binary);

    if (!fileHandler)
    {
        cout << "The file does not exits or file name is error" << endl;

        return;
    }
    pcapFileHeader_t  pcapFileHeader = { 0 };
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
    Flow** flowList = new Flow * [MAX_FLOW_NUMBER];         //流数组
    for (int i = 0; i < MAX_FLOW_NUMBER; i++)
    {
        flowList[i] = NULL;
    }
    int buffer_pointer = 0;     //定位缓冲区
    long long file_pointer = 24; //int不够用，设置成long long
    long long cnt = 0;
    unordered_map<Triple, int, hashTriple> dict;
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
                memcpy((char8_t*)&tcpinfo, buffer + buffer_pointer, sizeof(TCPInfo));
                buffer_pointer += (packetHeader.caplen - sizeof(IPInfo) - 14);  //多减的14为以太网帧

                //端序转换（不知道在Linux的CPU架构下需不需要转换端序）
                ipinfo.total_length = htons(ipinfo.total_length);
                ipinfo.sourceIP = htonl(ipinfo.sourceIP);
                ipinfo.destinationIP = htonl(ipinfo.destinationIP);
                tcpinfo.sourcePort = htons(tcpinfo.sourcePort);

                //创建单个处理对象
                port_ip.destinationIP = ipinfo.destinationIP;
                port_ip.sourceIP = ipinfo.sourceIP;
                port_ip.sourcePort = tcpinfo.sourcePort;
                packetInfo.len = packetHeader.len;
                packetInfo.port_ip = port_ip;
                packetInfo.seconds = packetHeader.seconds;
                packetInfo.u_seconds = packetHeader.u_seconds;

                InsertFlow(dict, packetInfo, flowList, index);
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
