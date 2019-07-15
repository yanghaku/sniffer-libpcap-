#ifndef LBPCAP_H
#define LBPCAP_H

#ifdef __cplusplus
extern "C"{
#endif
#include <pcap.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <string.h>


#pragma pack(1) //指定按1字节对齐

struct ether_header{//14 byte
    u_int8_t ether_dest_addr[6];
    u_int8_t ether_source_addr[6];
    u_int16_t ether_type;
};

const char* ether_type_val_to_name(u_int16_t type);

struct arp_header{
    u_int16_t arp_hardware_type;
    u_int16_t arp_protocol_type;
    u_int8_t arp_hardware_size;
    u_int8_t arp_protocol_size;
    u_int16_t arp_operation_code;
    //以上为ARP报头,8字节

    u_int8_t arp_source_macaddr[6];
    const struct in_addr arp_souce_ipaddr;
    u_int8_t arp_dest_macaddr[6];
    const struct in_addr arp_dest_ipaddr;
};

struct ip_header{//20-60byte
#ifdef WORDS_BIGENDIAN
    u_int8_t ip_version:4,
              ip_header_len:4; //per 4 byte
#else
    u_int8_t ip_header_len:4,
             ip_version:4;
#endif
    u_int8_t ip_tos;//0-5ESCP  6,7ECN
    u_int16_t ip_length;//总长度

    u_int16_t ip_id; //标识
    u_int16_t ip_offset;
    //ip片偏移,前三位为标志位,后13为偏移量, 第1位保留位,第二位DF(1为不能分段),第三位MF位(1为还有下一段)

    u_int8_t ip_ttl;    //生存时间
    u_int8_t ip_protocol;//协议
    u_int16_t ip_checksum;//首部校验和

    const struct in_addr ip_source_addr;

    const struct in_addr ip_dest_addr;

    /**
        以上为4*5=20字节,后面还可以有40字节可选内容(ip header 在20到60字节)
      */

};


#define ip_header_protocol_namelist_size 133u
extern const char* ip_header_protocol[ip_header_protocol_namelist_size];


struct tcp_header{
    u_int16_t tcp_source_port;
    u_int16_t tcp_dest_port;

    u_int32_t tcp_acknowedgement; //序列号

    u_int32_t tcp_ack;//确认号

#ifdef WORDS_BIGENDIAN
    u_int8_t tcp_header_len:4,
            tcp_reserved:4;
#else
    u_int8_t tcp_reserved:4,
            tcp_header_len:4;
#endif
    u_int8_t tcp_flag;
/**
    12保留, 345678标志位U,A,P,R,S,F
    3 URG紧急指针(urgent pointer)有效
    4 ACK:确认序号有效
    5 PSH:接收方应该尽快将这个报文段交给应用层
    6 RST:重建连接
    7 SYN:发起一个连接
    8 FIN:释放一个连接。
    */
    u_int16_t tcp_windows;

    u_int16_t tcp_checksum;
    //tcp 校验和计算加上伪首部
    //伪首部共有12字节:源IP地址,目的IP地址,保留字节(置0),传输层协议号(TCP是6),TCP报文长度(报头+数据)
    u_int16_t tcp_urgent_point;
    /**
      以上是20字节,还有40字节的可选项,头部长度为20-60字节
      */
};


struct udp_header{
    u_int16_t udp_source_port;
    u_int16_t udp_dest_port;

    u_int16_t udp_len;
    u_int16_t udp_checksum;
};

struct icmp_header{
    u_int8_t icmp_type;
    u_int8_t icmp_code;
    u_int16_t icmp_checksum;
    u_int16_t icmp_id;
    u_int16_t icmp_seq;
};
/**
  //icmp
TYPE	CODE	Description	Query	Error
0 	0 	Echo Reply——回显应答（Ping应答） 	x
3 	0 	Network Unreachable——网络不可达 	  	x
3 	1 	Host Unreachable——主机不可达 	  	x
3 	2 	Protocol Unreachable——协议不可达 	  	x
3 	3 	Port Unreachable——端口不可达 	  	x
3 	4 	Fragmentation needed but no frag. bit set——需要进行分片但设置不分片比特 	  	x
3 	5 	Source routing failed——源站选路失败 	  	x
3 	6 	Destination network unknown——目的网络未知 	  	x
3 	7 	Destination host unknown——目的主机未知 	  	x
3 	8 	Source host isolated (obsolete)——源主机被隔离（作废不用） 	  	x
3 	9 	Destination network administratively prohibited——目的网络被强制禁止 	  	x
3 	10 	Destination host administratively prohibited——目的主机被强制禁止 	  	x
3 	11 	Network unreachable for TOS——由于服务类型TOS，网络不可达 	  	x
3 	12 	Host unreachable for TOS——由于服务类型TOS，主机不可达 	  	x
3 	13 	Communication administratively prohibited by filtering——由于过滤，通信被强制禁止 	  	x
3 	14 	Host precedence violation——主机越权 	  	x
3 	15 	Precedence cutoff in effect——优先中止生效 	  	x
4 	0 	Source quench——源端被关闭（基本流控制）
5 	0 	Redirect for network——对网络重定向
5 	1 	Redirect for host——对主机重定向
5 	2 	Redirect for TOS and network——对服务类型和网络重定向
5 	3 	Redirect for TOS and host——对服务类型和主机重定向
8 	0 	Echo request——回显请求（Ping请求） 	x
9 	0 	Router advertisement——路由器通告
10 	0 	Route solicitation——路由器请求
11 	0 	TTL equals 0 during transit——传输期间生存时间为0 	  	x
11 	1 	TTL equals 0 during reassembly——在数据报组装期间生存时间为0 	  	x
12 	0 	IP header bad (catchall error)——坏的IP首部（包括各种差错） 	  	x
12 	1 	Required options missing——缺少必需的选项 	  	x
13 	0 	Timestamp request (obsolete)——时间戳请求（作废不用） 	x
14 	  	Timestamp reply (obsolete)——时间戳应答（作废不用） 	x
15 	0 	Information request (obsolete)——信息请求（作废不用） 	x
16 	0 	Information reply (obsolete)——信息应答（作废不用） 	x
17 	0 	Address mask request——地址掩码请求 	x
18 	0 	Address mask reply——地址掩码应答
  */
#pragma pack()


#ifdef __cplusplus
}
#endif


//1.网络接口名字和掩码
//2.抓包
//3.以太网
//4.ARP
//5.IP
//6.TCP
//7.UDP
//8.ICMP


extern pcap_if_t *alldev,*nowdev;

extern char err_buf[PCAP_ERRBUF_SIZE];

extern pcap_t* pcap_handle;


#endif // LBPCAP_H
