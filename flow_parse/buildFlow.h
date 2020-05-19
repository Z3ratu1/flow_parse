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
using namespace std;
using json = nlohmann::json;

#define MAX_FLOW_NUMBER 10000000   //可承载流数
char* jsonFileName;  //定义全局变量

struct IPInfo   //20字节长ip段
{
    uint8_t version_and_length; //ip协议版本和字段长度在一个字节中
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

struct TCPInfo  //TCP信息
{
    uint16_t sourcePort;
    uint16_t destinationPort;
    uint32_t seq_no;        //序列号   
    uint32_t ack_no;        //确认号   
    uint8_t len;
    uint8_t tag;
    uint16_t wnd_size;    //16位窗口大小   
    uint16_t chk_sum;     //16位TCP检验和   
    uint16_t urgt_p;      //16为紧急指针   
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
        len = 0;
    }
    PacketTimeAndLen(uint32_t u_s,uint32_t s,uint32_t l)
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
        if(packet_cnt > 300)  //小于300的不输出
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


void InsertFlow(unordered_map<string, int>&dict, PacketInfo &packetInfo, Flow* flowList[], int &index)
{
    unordered_map<string, int>::const_iterator got;
    Triple port_ip = packetInfo.port_ip;
    string hashKey = to_string(port_ip.destinationIP) + to_string(port_ip.sourceIP) + to_string(port_ip.sourcePort);
    got = dict.find(hashKey);
    if (got == dict.end())   //查找不到
    {
        if (index < MAX_FLOW_NUMBER)    //限制数组不能越界
        {
            pair<string, int>flow_info(hashKey, index);
            dict.insert(flow_info);
            //流数组添加一项
            flowList[index] = new Flow(packetInfo.port_ip, packetInfo.seconds, packetInfo.u_seconds, packetInfo.len);
            flowList[index]->packetList = new PacketTimeAndLen(packetInfo.u_seconds, packetInfo.seconds, packetInfo.len);     //缺一个微秒
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
        flowList[temp_index]->packet_cnt++;
    }
    return ;
}

void buildFlow()
{
    //net-view读函数接口
    Mem_reader* mc;
    mc = get_my_reader();

    //init_memA_reader 表示stream_tcp,init_memB_reader 表示stream_udp,init_memC_reader 表示stream_filter
    if (!init_memA_reader(mc)) {
        cerr << "init reader err" << endl;
        return;
    }
    else {
        cerr << "init reader success" << endl;
    }

    //定义各个变量
    IPInfo* ipinfo;
    TCPInfo* tcpinfo;
    PacketInfo packetInfo;
    Triple port_ip;
    unordered_map<string, int> flowDict;    //查找流下标的字典
    unordered_map<string, int> IPDict;    //筛选IP和端口的字典
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
    while (time(NULL) - start_time < (6*60))  //分钟
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
        //cout<< int(ipinfo->protocol) <<endl;
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

           // if (tcpinfo->sourcePort == 80 || tcpinfo->sourcePort == 443)  //筛选端口
           //{
                //cout<<ipinfo->sourceIP<<","<<tcpinfo->sourcePort<<endl;
                // 查字典
                unordered_map<string, int>::const_iterator got;
                got = IPDict.find(to_string(ipinfo->sourceIP) + to_string(tcpinfo->sourcePort));

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

                    //cout << "found in dict" <<endl;
                    InsertFlow(flowDict, packetInfo, flowList, index);
                }
           //}
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

#endif
