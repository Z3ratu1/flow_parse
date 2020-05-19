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
#define BUFFER_SIZE 268435456   //��������С
#define MTU 1500    //��󵥸�����С
#define MAX_FLOW_NUMBER 10000000   //�ɳ�������
char* jsonFileName;  //����ȫ�ֱ���


/*pcap file header*/
typedef struct pcapFileHeader
{
    uchar8_t   magic[4];
    uint16_t   version_major;
    uint16_t   version_minor;
    int32_t    thiszone;      /*ʱ������*/
    uint32_t   sigfigs;       /*��ȷʱ���*/
    uint32_t   snaplen;       /*ץ����󳤶�*/
    uint32_t   linktype;      /*��·����*/
} pcapFileHeader_t;



/*pcap packet header*/
typedef struct pcapPkthdr
{
    uint32_t   seconds;     /*����*/
    uint32_t   u_seconds;   /*������*/
    uint32_t   caplen;      /*���ݰ�����*/
    uint32_t   len;         /*�ļ����ݰ�����*/
} pcapPkthdr_t;

struct IPInfo   //20�ֽڳ�ip��
{
    uint8_t version_length; //ipЭ��汾���ֶγ�����һ���ֽ���
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

struct TCPInfo  //ֻ��Ҫ��ǰ��˸��ֽڵĶ˿�
{
    uint16_t sourcePort;
    uint16_t destinationPort;
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
        if (packet_cnt > 100)  //С��200�Ĳ����
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
            j["cnt"] = packet_cnt;
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
    string hashKey = to_string(packetInfo.port_ip.destinationIP) + to_string(packetInfo.port_ip.sourceIP) + to_string(packetInfo.port_ip.sourcePort);
    got = dict.find(hashKey);
    if (got == dict.end())   //���Ҳ���
    {
        if (index < MAX_FLOW_NUMBER)    //�������鲻��Խ��
        {
            pair<string, int>flow_info(hashKey, index);
            dict.insert(flow_info);
            //���������һ��
            flowList[index] = new Flow(packetInfo.port_ip, packetInfo.seconds, packetInfo.u_seconds, packetInfo.len);
            flowList[index]->packet_cnt++;
            flowList[index]->packetList = new PacketTimeAndLen(packetInfo.seconds, packetInfo.u_seconds, packetInfo.len);
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
        if (packetInfo.seconds - flowList[temp_index]->seconds <= 300)  //����ӽ�ֹ
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
    //��ȡpcap�ļ�ͷ������
    fileHandler.read((char*)&pcapFileHeader, 24);
    if (pcapFileHeader.magic[0] != PCAP_FILE_MAGIC_1 || pcapFileHeader.magic[1] != PCAP_FILE_MAGIC_2 ||
        pcapFileHeader.magic[2] != PCAP_FILE_MAGIC_3 || pcapFileHeader.magic[3] != PCAP_FILE_MAGIC_4)
    {
        cout << "The file is not a pcap file" << endl;

        return;
    }

    //�����������
    pcapPkthdr_t  packetHeader = { 0 };
    char8_t* buffer;    //������
    IPInfo ipinfo;
    TCPInfo tcpinfo;
    PacketInfo packetInfo;
    Triple port_ip;
    Flow** flowList = new Flow*[MAX_FLOW_NUMBER];         //������
    for (int i = 0; i < MAX_FLOW_NUMBER; i++)
    {
        flowList[i] = NULL;
    }
    int buffer_pointer = 0;     //��λ������
    long long file_pointer = 24; //int�����ã����ó�long long
    long long cnt = 0;
    unordered_map<string, int> dict;
    //unordered_map<string, int> IPDict;    //ɸѡIP�Ͷ˿ڵ��ֵ�
    //initDict(IPDict);   //��ʼ��ɸ���ֵ�
    //cout << IPDict.size() << " records in dict" << endl;
    int index = 0;
    double byte_cnt = 0;

    //�����������
    while (!fileHandler.eof())
    {
        buffer = (char8_t*)malloc(BUFFER_SIZE);     //�����ڴ�
        memset(buffer, 0, BUFFER_SIZE);
        buffer_pointer = 0;
        if (buffer == NULL)
        {
            cerr << "malloc memory failed" << endl;
            //�������
        }

        fileHandler.seekg(file_pointer);
        fileHandler.read(buffer, BUFFER_SIZE); //����һ�����������


        while (buffer_pointer < BUFFER_SIZE - MTU)
        {
            memcpy((char8_t*)&packetHeader, buffer + buffer_pointer, sizeof(packetHeader));
            buffer_pointer += sizeof(packetHeader);
            buffer_pointer += 14;   //��̫��֡
            memcpy((char8_t*)&ipinfo, buffer + buffer_pointer, sizeof(IPInfo));
            // �����
            byte_cnt += htons(ipinfo.total_length);
            if (ipinfo.protocol == 0)    //�ļ��Լ������ˣ�ָ��buffer�Ŀ��ֽڲ���
            {
                break;
            }
            cnt++;  //ȫ������������
            if (ipinfo.protocol == 6)  //TCP,asciiΪ6
            {
                //�������
                buffer_pointer += sizeof(IPInfo);
                memcpy((char8_t*)&tcpinfo, buffer+buffer_pointer,sizeof(TCPInfo));
                buffer_pointer += (packetHeader.caplen - sizeof(IPInfo) - 14);  //�����14Ϊ��̫��֡

                //����ת������֪����Linux��CPU�ܹ����費��Ҫת������
                ipinfo.total_length = htons(ipinfo.total_length);
                ipinfo.sourceIP = htonl(ipinfo.sourceIP);
                ipinfo.destinationIP = htonl(ipinfo.destinationIP);
                tcpinfo.sourcePort = htons(tcpinfo.sourcePort);

                //unordered_map<string, int>::const_iterator got;
                //got = IPDict.find(to_string(ipinfo.sourceIP) + to_string(tcpinfo.sourcePort));

                //if (got != IPDict.end())    //ɸѡIP
                //{
                    //���������������
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
            else    //����������Ҫ
            {
                //�������
                buffer_pointer += packetHeader.caplen - 14;     //-14��̫��֡
            }
        }
        cout << file_pointer << endl;
        file_pointer += buffer_pointer;
        free(buffer);
        
    }

    fileHandler.close();
  
    //������������β����
    //�ͷ��ڴ�
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
