#include "capturethread.h"
#include <QDebug>

void CaptureThread::run(){
    pcap_pkthdr* tmp_pkthdr;
    const u_char* tmp_packet;
    err_buf[0]=0;
    while(is_run){
        if(mainwindow->packet_list.size()>9999)break;
        int res=pcap_next_ex(pcap_handle,&tmp_pkthdr,&tmp_packet);
        if(res==1){
            u_char* res=new uchar[tmp_pkthdr->len];
            memcpy(res,tmp_packet,tmp_pkthdr->len);
            mainwindow->packet_list.push_back(res);
            mainwindow->pkthdr_list.push_back(*tmp_pkthdr);
        }
        else if(res==0){//time out
            strcpy(err_buf,"time out!");
            //mainwindow->on_actionstop_triggered();
            break;
        }
        else{
            strcpy(err_buf,"capture Error!");
            //mainwindow->on_actionstop_triggered();
            break;
        }
        mainwindow->refresh_table();
    }
}
