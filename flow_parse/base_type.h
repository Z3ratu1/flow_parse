#ifndef  BASE_TYPE_H
#define  BASE_TYPE_H
#define  PCAP_FILE_MAGIC_1   0Xd4
#define  PCAP_FILE_MAGIC_2   0Xc3
#define  PCAP_FILE_MAGIC_3   0Xb2
#define  PCAP_FILE_MAGIC_4   0Xa1
#define BUFFER_SIZE 268435456   //缓存区大小
#define MTU 1500    //最大单个包大小
#define MAX_FLOW_NUMBER 10000000   //可承载流数
#define SQL_QUERY_NUM 2000000  //单次查询字典记录数
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

    bool operator==(const Triple &t) const   //重载运算符实现字典自定义键值
    {
        return (this->sourceIP == t.sourceIP) && (this->destinationIP == t.destinationIP) && (this->sourcePort == t.sourcePort);
    }
};

struct hashTriple
{
    uint32_t operator()(const Triple& tri) const   //生成hashKey
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


struct Tuble   //哈希用二元组
{
    uint16_t sourcePort;
    uint32_t sourceIP;
    Tuble(uint16_t sp, uint32_t sip)
    {
        sourcePort = sp;
        sourceIP = sip;
    }
    bool operator==(const Tuble& d) const   //重载运算符实现字典自定义键值
    {
        return (this->sourceIP == d.sourceIP) && (this->sourcePort == d.sourcePort);
    }
};

struct hashTuble
{
    uint32_t operator()(const Tuble& dou) const   //生成hashKey
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

#endif