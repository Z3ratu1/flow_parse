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

#define MAX_FLOW_NUMBER 10000000   //�ɳ�������
char* jsonFileName;  //����ȫ�ֱ���

struct IPInfo   //20�ֽڳ�ip��
{
    uint8_t version_and_length; //ipЭ��汾���ֶγ�����һ���ֽ���
    uint8_t service_field;
    uint16_t total_length;  //�������ĳ���
    uint16_t identification;
    uint16_t flag;
    uint8_t time_to_live;
    uint8_t protocol;
    uint16_t header_check;
    uint32_t sourceIP;
    uint32_t destinationIP;
};

struct TCPInfo  //TCP��Ϣ
{
    uint16_t sourcePort;
    uint16_t destinationPort;
    uint32_t seq_no;        //���к�   
    uint32_t ack_no;        //ȷ�Ϻ�   
    uint8_t len;
    uint8_t tag;
    uint16_t wnd_size;    //16λ���ڴ�С   
    uint16_t chk_sum;     //16λTCP�����   
    uint16_t urgt_p;      //16Ϊ����ָ��   
};

struct Triple   //��ϣ����Ԫ��
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
    uint32_t seconds;     /*����*/
    uint32_t u_seconds;   /*������*/
    uint32_t len;
    PacketTimeAndLen* next;   //����
};

struct PacketInfo    //��Ҫͳ�Ƶ�һ������ȫ����Ϣ
{
    //����ʱ���
    uint32_t seconds;     /*����*/
    uint32_t u_seconds;   /*������*/
    uint32_t len;   //����
    Triple port_ip; //�˿ڼ�ip��Ϣ
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
        //���������һ��json�ļ�

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
        flow_byte_cnt = flow_byte_cnt / (1024 * 1024);   //��λ�����MB
        if(packet_cnt > 300)  //С��300�Ĳ����
        {
            //ʹ��nlohmann json
            //����һ��json����
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
            j["cnt"] = packet_cnt;  //��������Ӧ��<srcIP,dstIP,srcPort>
            j["flow_byte_cnt"] = flow_byte_cnt;
    
            ofstream jsonFile;
            jsonFile.open(jsonFileName, ios::app);   //׷�ӷ�ʽд��
            //cout<<"in destruction"<<endl;
            if (!jsonFile)
            {
                cout << "fail to open json file" << endl;
            }
            jsonFile << j.dump(4) << ",\n";  //���
            jsonFile.close();
        }
    }
    
    uint32_t seconds;
    uint32_t u_seconds;
    Triple port_ip;
    int packet_cnt;    //����
    double flow_byte_cnt = 0;    //�ݶ���λMB
    PacketTimeAndLen* packetList;  //���а�������
};


void InsertFlow(unordered_map<string, int>&dict, PacketInfo &packetInfo, Flow* flowList[], int &index)
{
    unordered_map<string, int>::const_iterator got;
    Triple port_ip = packetInfo.port_ip;
    string hashKey = to_string(port_ip.destinationIP) + to_string(port_ip.sourceIP) + to_string(port_ip.sourcePort);
    got = dict.find(hashKey);
    if (got == dict.end())   //���Ҳ���
    {
        if (index < MAX_FLOW_NUMBER)    //�������鲻��Խ��
        {
            pair<string, int>flow_info(hashKey, index);
            dict.insert(flow_info);
            //���������һ��
            flowList[index] = new Flow(packetInfo.port_ip, packetInfo.seconds, packetInfo.u_seconds, packetInfo.len);
            flowList[index]->packetList = new PacketTimeAndLen(packetInfo.u_seconds, packetInfo.seconds, packetInfo.len);     //ȱһ��΢��
            index++;    //�����±���λ
        }
        else
        {
            cout << "����������" << endl;
        }
    }
    else
    {
        int temp_index = got->second;   //first�Ǽ���second��ֵ
        flowList[temp_index]->flow_byte_cnt += packetInfo.len;  //��¼����������ʱ��
        //�������
        if (packetInfo.seconds - flowList[temp_index]->seconds <= 300)   //5�����ڲ�Ҫ
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
    //net-view�������ӿ�
    Mem_reader* mc;
    mc = get_my_reader();

    //init_memA_reader ��ʾstream_tcp,init_memB_reader ��ʾstream_udp,init_memC_reader ��ʾstream_filter
    if (!init_memA_reader(mc)) {
        cerr << "init reader err" << endl;
        return;
    }
    else {
        cerr << "init reader success" << endl;
    }

    //�����������
    IPInfo* ipinfo;
    TCPInfo* tcpinfo;
    PacketInfo packetInfo;
    Triple port_ip;
    unordered_map<string, int> flowDict;    //�������±���ֵ�
    unordered_map<string, int> IPDict;    //ɸѡIP�Ͷ˿ڵ��ֵ�
    int index = 0;  //����������������֦����
    Flow** flowList = new Flow * [MAX_FLOW_NUMBER];         //������

    //��ʼ��������
    for (int i = 0; i < MAX_FLOW_NUMBER; i++)
    {
        flowList[i] = NULL;
    }

    initDict(IPDict);   //��ʼ��ɸ���ֵ�
    cout << IPDict.size() << " records in dict" << endl;
      
    uint16_t ip_len;
    char* ppt;
    uint16_t len;
    uint16_t mask;
    // len��ʾ����ȡ�ı��ĳ��ȣ�mask��ʾ�������ԣ���stream��,mask & 0x8000 Ϊtrue����ʾ���ڵ����⣬�����෴
    uint32_t seconds;  //������ʱ��
    uint32_t u_seconds;
    long long cnt = 0;
    double byte_cnt = 0;    //���ֽ�ͳ��
    time_t start_time = time(NULL);
    while (time(NULL) - start_time < (6*60))  //����
    {        
        cnt++;
        if(cnt % 1000000000 == 0)  //10��
	      {
	       cout << cnt << endl;
	      }
        ppt = (char*)read_data(mc, len, mask, seconds, u_seconds);
        if (ppt == NULL)
        {
            cerr << "ppt is null\n";
            //���쳣
            continue;
        }
        // ������������⵽���ڵģ�������
        if ((mask & 1024) == 0)
        {
            //cout << "mask & 1024 == 0"<<endl;
            continue;
        }

        //���õ����ݶ��벿��
        ipinfo = (IPInfo*)ppt;
        ip_len = ((ipinfo->version_and_length) % 16 * 4);  //��λ��ȡIP�γ���
        byte_cnt += htons(ipinfo->total_length);   //ͳ���ֽ���
        //cout<< int(ipinfo->protocol) <<endl;
        if (int(ipinfo->protocol) == 6)  //TCP
        {
            //����ת��
            ipinfo->destinationIP = htonl(ipinfo->destinationIP);
            ipinfo->sourceIP = htonl(ipinfo->sourceIP);
            ipinfo->total_length = htons(ipinfo->total_length);

            //TCP��Ϣ
            tcpinfo = (TCPInfo*)((char*)ipinfo + ip_len);
            tcpinfo->sourcePort = htons(tcpinfo->sourcePort);
            tcpinfo->destinationPort = htons(tcpinfo->destinationPort);

           // if (tcpinfo->sourcePort == 80 || tcpinfo->sourcePort == 443)  //ɸѡ�˿�
           //{
                //cout<<ipinfo->sourceIP<<","<<tcpinfo->sourcePort<<endl;
                // ���ֵ�
                unordered_map<string, int>::const_iterator got;
                got = IPDict.find(to_string(ipinfo->sourceIP) + to_string(tcpinfo->sourcePort));

                if (got != IPDict.end())    //ɸѡIP
                {
                    //���������������
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
    
    //������������β����
    //�ͷ��ڴ�
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
    byte_cnt = byte_cnt / (1024*1024);  //��λ���㵽M
    json_file.open(jsonFileName, ios::app);
    json_file << "{}],\n \"cnt\": [\n {\"pac_cnt\": " << cnt << ",\n \"flow_cnt\": " << index << ",\n \"byte_cnt\": " << byte_cnt;
    json_file << " }]}\n";
    json_file.close();
    return;
}

#endif
