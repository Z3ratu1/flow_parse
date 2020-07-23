#ifndef  BASE_TYPE_H
#define  BASE_TYPE_H
#define  PCAP_FILE_MAGIC_1   0Xd4
#define  PCAP_FILE_MAGIC_2   0Xc3
#define  PCAP_FILE_MAGIC_3   0Xb2
#define  PCAP_FILE_MAGIC_4   0Xa1
#define BUFFER_SIZE 268435456   //��������С
#define MTU 1500    //��󵥸�����С
#define MAX_FLOW_NUMBER 10000000   //�ɳ�������
#define SQL_QUERY_NUM 2000000  //���β�ѯ�ֵ��¼��
#include <stdlib.h>
typedef  unsigned char uint8_t;
typedef  char  char8_t;
typedef  unsigned short uint16_t;
typedef  short int16_t;
typedef  unsigned int uint32_t;
typedef  int int32_t;
typedef  unsigned long  ulong64_t;
typedef  long long64_t;

using namespace std;


/*pcap file header*/
typedef struct pcapFileHeader
{
    uint8_t   magic[4];
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

    bool operator==(const Triple &t) const   //���������ʵ���ֵ��Զ����ֵ
    {
        return (this->sourceIP == t.sourceIP) && (this->destinationIP == t.destinationIP) && (this->sourcePort == t.sourcePort);
    }
};

struct hashTriple
{
    uint32_t operator()(const Triple& tri) const   //����hashKey
    {
        Triple t = tri;
        uint32_t hash_value = 5381;
        while (t.sourceIP > 0)
        {
            hash_value = ((hash_value << 5) + hash_value) + t.sourceIP % 1000;
            t.sourceIP >>= 8;
        }
        while (t.sourcePort > 0) {
            hash_value = ((hash_value << 5) + hash_value) + t.sourcePort % 1000;
            t.sourcePort >>= 8;
        }

        while (t.destinationIP > 0)
        {
            hash_value = ((hash_value << 5) + hash_value) + t.destinationIP % 1000;
            t.destinationIP >>= 8;
        }
        return hash_value;
    }
};


struct Tuble   //��ϣ�ö�Ԫ��
{
    uint16_t sourcePort;
    uint32_t sourceIP;
    Tuble(uint16_t sp, uint32_t sip)
    {
        sourcePort = sp;
        sourceIP = sip;
    }
    bool operator==(const Tuble& d) const   //���������ʵ���ֵ��Զ����ֵ
    {
        return (this->sourceIP == d.sourceIP) && (this->sourcePort == d.sourcePort);
    }
};

struct hashTuble
{
    uint32_t operator()(const Tuble& dou) const   //����hashKey
    {
        Tuble d = dou;
        uint32_t hash_value = 5381;
        while (d.sourceIP > 0)
        {
            hash_value = ((hash_value << 5) + hash_value) + d.sourceIP % 1000;
            d.sourceIP >>= 8;
        }
        while (d.sourcePort > 0) {
            hash_value = ((hash_value << 5) + hash_value) + d.sourcePort % 1000;
            d.sourcePort >>= 8;
        }
        return hash_value;
    }
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
    PacketTimeAndLen(uint32_t u_s, uint32_t s, uint32_t l)
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

#endif