#include "capturethread.h"
#include <QDebug>

void CaptureThread::run(){
    pcap_pkthdr* tmp_pkthdr;
    const u_char* tmp_packet;
    while(is_run){
        if(mainwindow->packet_list.size()>9999)break;
        int res=pcap_next_ex(pcap_handle,&tmp_pkthdr,&tmp_packet);
        if(res==1){
            u_char* res=new uchar[tmp_pkthdr->len];
            memcpy(res,tmp_packet,tmp_pkthdr->len);
            mainwindow->packet_list.push_back(res);
            mainwindow->pkthdr_list.push_back(*tmp_pkthdr);
        }
        else if(res==0){
            qDebug()<<"time out"<<endl;
            break;
        }
        else{
            qDebug()<<"eror"<<endl;
            break;
        }
        mainwindow->refresh_table();
    }
}
