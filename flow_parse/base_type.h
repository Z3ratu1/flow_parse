#ifndef  BASE_TYPE_H
#define  BASE_TYPE_H

typedef  unsigned char uchar8_t;
typedef  char  char8_t;
typedef  unsigned short uint16_t;
typedef  short int16_t;
typedef  unsigned int uint32_t;
typedef  int int32_t;
typedef  unsigned long  ulong64_t;
typedef  long long64_t;


#define  PCAP_FILE_MAGIC_1   0Xd4
#define  PCAP_FILE_MAGIC_2   0Xc3
#define  PCAP_FILE_MAGIC_3   0Xb2
#define  PCAP_FILE_MAGIC_4   0Xa1
#define BUFFER_SIZE 268435456   //缓存区大小
#define MTU 1500    //最大单个包大小
#define MAX_FLOW_NUMBER 10000000   //可承载流数

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