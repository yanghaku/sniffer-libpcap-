#ifndef STATISTICS_H
#define STATISTICS_H
#include <ctime>
#include <set>

struct MacAddr{
    MacAddr(const unsigned char x[]){
        for(int i=0;i<6;++i)byte[i]=x[i];
    }

    unsigned char byte[6];

    bool is_broadcast()const{
        for(int i=0;i<6;++i)if(byte[i] != 0xff)return false;
        return true;
    }
    bool operator<(const MacAddr& b)const{
        for(int i=0;i<6;++i)if(byte[i]<b.byte[i])return true;
        return false;
    }
    bool operator==(const MacAddr& b)const{
        for(int i=0;i<6;++i)if(byte[i]!=b.byte[i])return false;
        return true;
    }
};


//Statistics统计,保存统计信息
class Statistics
{
public:
    Statistics(){
        this->clear();
    }
    void clear();

    //data
    std::set<MacAddr>mac_set;
    time_t start_time;

    int mac_num;
    int mac_short;// < 64
    int mac_long;// >1518
    int mac_byte; // to cal bit/s, mac byte speed, mac packet speed
    int mac_broadcast;

    int ip_num;
    int ip_broadcast;

    int icmp_num;
    int icmp_redirect;
    int icmp_unreachable;

    int tcp_num;
    int udp_num;

};


#endif // STATISTICS_H
