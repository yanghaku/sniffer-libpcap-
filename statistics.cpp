#include "statistics.h"

//Statistics统计,保存统计信息

void Statistics::clear(){
    ip_num=mac_byte=mac_long=mac_short=mac_num=0;
    tcp_num=udp_num=icmp_num=icmp_redirect=icmp_unreachable=0;
    ip_broadcast=mac_broadcast=0;
    time(&start_time);
    mac_set.clear();
}
