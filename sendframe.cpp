#include "sendframe.h"
#include "ui_sendframe.h"
#include <cstring>
#include <cstdio>
#include <unistd.h>
#include <QMessageBox>
#include <sys/socket.h> // socket()
#include <sys/types.h>  //uint8_t,uint16_t,
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>  //ioctl
#include <bits/ioctls.h>
#include "lbpcap.h"
#include <QInputDialog>

const static QRegExp reg_ip("^([1]?/d/d?|2[0-4]/d|25[0-5])/.([1]?/d/d?|2[0-4]/d|25[0-5])/.([1]?/d/d?|2[0-4]/d|25[0-5])/.([1]?/d/d?|2[0-4]/d|25[0-5])$");
const static QRegExp reg_mac("([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})");

SendFrame::SendFrame(const char* device_name,QWidget *parent) :
    QDialog(parent),
    ui(new Ui::SendFrame)
{
    ui->setupUi(this);
    setFixedSize(this->width(),this->height());
    ui->progressBar->reset();
//    ui->source_mac->setValidator(new QRegExpValidator(reg_mac,this));
//    ui->dest_mac->setValidator(new QRegExpValidator(reg_mac,this));
//    ui->arp_sourcemac->setValidator(new QRegExpValidator(reg_mac,this));
//    ui->arp_destmac->setValidator(new QRegExpValidator(reg_mac,this));
//    ui->arp_destip->setValidator(new QRegExpValidator(reg_ip,this));
//    ui->arp_sourceip->setValidator(new QRegExpValidator(reg_ip,this));
//    ui->ip_sourceip->setValidator(new QRegExpValidator(reg_ip,this));
//    ui->ip_destip->setValidator(new QRegExpValidator(reg_ip,this));

    ui->number->setValidator(new QIntValidator(1,10000,this));
    ui->time_interval->setValidator(new QIntValidator(500,10000,this));
    ui->ip_foff->setValidator(new QIntValidator(0,(1<<13)-1,this));
    ui->ip_id->setValidator(new QIntValidator(0,0xffff,this));
    ui->ip_ttl->setValidator(new QIntValidator(0,0xff,this));
    ui->icmp_id->setValidator(new QIntValidator(0,0xffff,this));
    ui->icmp_seq->setValidator(new QIntValidator(0,0xffff,this));
    ui->icmp_code->setValidator(new QIntValidator(0,0xff,this));
    ui->icmp_type->setValidator(new QIntValidator(0,0xff,this));
    ui->tcp_sourceport->setValidator(new QIntValidator(0,0xffff,this));
    ui->tcp_destport->setValidator(new QIntValidator(0,0xffff,this));
    ui->tcp_acknum->setValidator(new QIntValidator(0,0xffffffff,this));
    ui->tcp_seqnum->setValidator(new QIntValidator(0,0xffffffff,this));
    ui->tcp_urgentpoint->setValidator(new QIntValidator(0,0xffff,this));
    ui->tcp_windowsize->setValidator(new QIntValidator(0,0xffff,this));
    ui->udp_destport->setValidator(new QIntValidator(0,65535,this));
    ui->udp_sourceport->setValidator(new QIntValidator(0,65535,this));

    ui->ip_page->setEnabled(false);
    ui->icmp_page->setEnabled(false);
    ui->tcp_page->setEnabled(false);
    ui->udp_page->setEnabled(false);

    ok=createDevice(device_name);
    QString tmp;
    tmp.sprintf("%02x:%02x:%02x:%02x:%02x:%02x",device.sll_addr[0],device.sll_addr[1],device.sll_addr[2],
            device.sll_addr[3],device.sll_addr[4],device.sll_addr[5]);
    ui->source_mac->setText(tmp);
}

SendFrame::~SendFrame()
{
    if(ok)::close(sockfd);
    delete ui;
}

/**
 * struct sockaddr_ll{
 *  unsigned short sll_family;
 *  _be16 sll_protocol;
 *  int   sll_ifindex;
 *  unsigned short sll_hatype;
 *  unsigned char sll_pkttype;
 *  unsigned char sll_halen;
 *  unsigned char sll_addr[8];
 *
 */

bool SendFrame::createDevice(const char* device_name){
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

void SendFrame::on_pushButton_send_clicked()
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
    if(!ok || time_sleep<500 || time_sleep>50000){
        QMessageBox::critical(this,"Error","the time interval is invalued!");
        ui->pushButton_send->setEnabled(true);
        return;
    }
    time_sleep/=1000; //ms -> s
    for(int i=1;i<=num;++i){
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

int SendFrame::createPacket(uint8_t *packet){
    uint32_t tmp_mac[6];
    ether_header* ether=(ether_header*)packet;
    memcpy(ether->ether_source_addr,device.sll_addr,6);//source mac
    if(!reg_mac.exactMatch(ui->dest_mac->text())){
        QMessageBox::critical(this,"Error","Dest Mac Adress is invalued!");
        return -1;
    }
    sscanf((const char*)ui->dest_mac->text().toLower().toLatin1(),"%x:%x:%x:%x:%x:%x",&tmp_mac[0],
            &tmp_mac[1],&tmp_mac[2],&tmp_mac[3],&tmp_mac[4],&tmp_mac[5]);
    for(int i=0;i<6;++i)ether->ether_dest_addr[i]=tmp_mac[i];

    if(ui->ether_type->currentText()=="ARP"){
        ether->ether_type=htons(0x0806);
        int len=sizeof(ether_header);
        arp_header* arp=(arp_header*)(packet+len);
        arp->arp_hardware_type=htons(1);//ethernet(1)
        arp->arp_hardware_size=6;
        arp->arp_protocol_type=htons(0x0800);//ipv4;
        arp->arp_protocol_size=4;
        if(ui->arp_opcode->currentText()=="request(1)")
            arp->arp_operation_code=htons(1);
        else arp->arp_operation_code=htons(2);//reply

        if(!reg_mac.exactMatch(ui->arp_destmac->text())){
            QMessageBox::critical(this,"Error","arp Dest Mac Adress is invalued!");
            return -1;
        }
        sscanf((const char*)ui->arp_destmac->text().toLower().toLatin1(),"%x:%x:%x:%x:%x:%x",&tmp_mac[0],
                &tmp_mac[1],&tmp_mac[2],&tmp_mac[3],&tmp_mac[4],&tmp_mac[5]);
        for(int i=0;i<6;++i)arp->arp_dest_macaddr[i]=tmp_mac[i];

        if(!reg_mac.exactMatch(ui->arp_sourcemac->text())){
            QMessageBox::critical(this,"Error","arp source Mac Adress is invalued!");
            return -1;
        }
        sscanf((const char*)ui->arp_sourcemac->text().toLower().toLatin1(),"%x:%x:%x:%x:%x:%x",&tmp_mac[0],
                &tmp_mac[1],&tmp_mac[2],&tmp_mac[3],&tmp_mac[4],&tmp_mac[5]);
        for(int i=0;i<6;++i)arp->arp_source_macaddr[i]=tmp_mac[i];

//        if(!reg_ip.exactMatch(ui->arp_destip->text())){
//            QMessageBox::critical(this,"Error","arp dest ip adress is invalued!");
//            return -1;
//        }
//        if(!reg_ip.exactMatch(ui->arp_sourceip->text())){
//            QMessageBox::critical(this,"Error","arp source ip adress is invalued!");
//            return -1;
//        }
        struct in_addr* ip_addr=(struct in_addr*)(packet+(((const uint8_t*)&arp->arp_dest_ipaddr) - packet));
        if(inet_aton(ui->arp_destip->text().toLatin1(),ip_addr)==-1){
            QMessageBox::critical(this,"Error","arp dest ip adress is invalued!");
            return -1;
        }
        ip_addr=(struct in_addr*)(packet+(((const uint8_t*)&arp->arp_souce_ipaddr) - packet));
        if(inet_aton(ui->arp_sourceip->text().toLatin1(),ip_addr)==-1){
            QMessageBox::critical(this,"Error","arp source ip adress is invalued!");
            return -1;
        }
        len+=sizeof(arp_header);
        int data_len=ui->Data->toPlainText().length();
        if(data_len+len>1500){
            QMessageBox::critical(this,"Error","Data is two long!");
            return -1;
        }
        memcpy(packet+len,ui->Data->toPlainText().toLatin1(),data_len);
        return data_len+len;
    }
    else if(ui->ether_type->currentText()=="Other"){
        int x=QInputDialog::getInt(this,"protocol","please input the ether protocol: ",0,0,0xffff);
        ether->ether_type=htons(x);
        x=ui->Data->toPlainText().length();
        if(sizeof(ether_header)+x>1500){
            QMessageBox::critical(this,"Error","Data is two long!");
            return -1;
        }
        memcpy(packet+sizeof(ether_header),ui->Data->toPlainText().toLatin1(),x);
        return x+sizeof(ether_header);
    }
    else{//"ip"
        ether->ether_type=htons(0x0800);
        int len=sizeof(ether_header);
        ip_header* ip=(ip_header*)(packet+len);
        len+=sizeof(ip_header);
        ip->ip_version=4;
        ip->ip_header_len=5;//20bytes;
        ip->ip_tos=0;
        bool ok=1;
        ip->ip_ttl=ui->ip_ttl->text().toInt(&ok);
        if(!ok){
            QMessageBox::critical(this,"Error","ip ttl is invalued!");
            return -1;
        }
        ip->ip_id=htons(ui->ip_id->text().toInt(&ok));
        if(!ok){
            QMessageBox::critical(this,"Error","ip id is invalued!");
            return -1;
        }
        ip->ip_offset=htons(ui->ip_foff->text().toInt(&ok));
        if(!ok){
            QMessageBox::critical(this,"Error","ip offset is invalued!");
            return -1;
        }
        if(ui->ip_df->isChecked())
            ip->ip_offset |= 1<<14;
        if(ui->ip_mf->isChecked())
            ip->ip_offset |= 1<<13;
        struct in_addr* ip_addr=(struct in_addr*)(packet+(((const uint8_t*)&ip->ip_dest_addr) - packet));
        if(inet_aton(ui->ip_destip->text().toLatin1(),ip_addr)==-1){
            QMessageBox::critical(this,"Error","ip dest address is invalued!");
            return -1;
        }
        ip_addr=(struct in_addr*)(packet+(((const uint8_t*)&ip->ip_source_addr) - packet));
        if(inet_aton(ui->ip_sourceip->text().toLatin1(),ip_addr)==-1){
            QMessageBox::critical(this,"Error","ip source adress is invalued!");
            return -1;
        }

        if(ui->ip_protocol->currentText()=="ICMP"){//icmp
            ip->ip_protocol=1;
            icmp_header* icmp=(icmp_header*)(packet+len);
            len+=sizeof(icmp_header);
            icmp->icmp_id=htons(ui->icmp_id->text().toInt(&ok));
            if(!ok){
                QMessageBox::critical(this,"Error","icmp id is invalued!");
                return -1;
            }
            icmp->icmp_seq=htons(ui->icmp_seq->text().toInt(&ok));
            if(!ok){
                QMessageBox::critical(this,"Error","icmp seq is invalued!");
                return -1;
            }
            icmp->icmp_code=ui->icmp_code->text().toInt(&ok);
            if(!ok){
                QMessageBox::critical(this,"Error","icmp code is invalued!");
                return -1;
            }
            icmp->icmp_type=ui->icmp_type->text().toInt(&ok);
            if(!ok){
                QMessageBox::critical(this,"Error","icmp type is invalued!");
                return -1;
            }
            icmp->icmp_checksum=0;
            icmp->icmp_checksum=htons(icmp_checksum(icmp));
        }
        else if(ui->ip_protocol->currentText()=="TCP"){//tcp
            tcp_header* tcp=(tcp_header*)(packet+len);
            ip->ip_protocol=6;
            len+=sizeof(tcp_header);
            tcp->tcp_dest_port=htons(ui->tcp_destport->text().toInt(&ok));
            if(!ok){
                QMessageBox::critical(this,"Error","tcp dest port is invalued!");
                return -1;
            }
            tcp->tcp_source_port=htons(ui->tcp_sourceport->text().toInt(&ok));
            if(!ok){
                QMessageBox::critical(this,"Error","tcp source port is invalued!");
                return -1;
            }
            tcp->tcp_acknowedgement=htonl(ui->tcp_seqnum->text().toUInt(&ok));
            if(!ok){
                QMessageBox::critical(this,"Error","tcp seq num is invalued!");
                return -1;
            }
            tcp->tcp_ack=htonl(ui->tcp_acknum->text().toUInt(&ok));
            if(!ok){
                QMessageBox::critical(this,"Error","tcp ack num is invalued!");
                return -1;
            }
            tcp->tcp_header_len=5;
            tcp->tcp_windows=htonl(ui->tcp_windowsize->text().toUInt(&ok));
            if(!ok){
                QMessageBox::critical(this,"Error","Tcp windows size is invalued!");
                return -1;
            }
            tcp->tcp_urgent_point=htonl(ui->tcp_urgentpoint->text().toUInt(&ok));
            if(!ok){
                QMessageBox::critical(this,"Error","TCp urgent point is invalued!");
                return -1;
            }
            tcp->tcp_flag=0;
            tcp->tcp_reserved=0;
            if(ui->tcp_ack->isChecked()){
                tcp->tcp_flag |= 1<<4;
            }
            if(ui->tcp_fin->isChecked()){
                tcp->tcp_flag |= 1<<0;
            }
            if(ui->tcp_syn->isChecked()){
                tcp->tcp_flag |= 1<<1;
            }
            if(ui->tcp_rst->isChecked()){
                tcp->tcp_flag |= 1<<2;
            }
            if(ui->tcp_urg->isChecked()){
                tcp->tcp_flag |= 1<<5;
            }
            if(ui->tcp_cwr->isChecked()){
                tcp->tcp_flag |= 1<<7;
            }
            if(ui->tcp_ecn->isChecked()){
                tcp->tcp_flag |= 1<<6;
            }
            if(ui->tcp_push->isChecked()){
                tcp->tcp_flag |= 1<<3;
            }
            uint16_t tcp_len=20+ui->Data->toPlainText().length();
            tcp->tcp_checksum=0;
            tcp->tcp_checksum=tcp_checksum(tcp,&ip->ip_source_addr,&ip->ip_dest_addr,htons(tcp_len));
        }

        else if(ui->ip_protocol->currentText()=="UDP"){//udp
            udp_header* udp=(udp_header*)(packet+len);
            ip->ip_protocol=17;
            len+=sizeof(udp_header);
            udp->udp_source_port=htons(ui->udp_sourceport->text().toInt(&ok));
            if(!ok){
                QMessageBox::critical(this,"Error","udp source port is invalued!");
                return -1;
            }
            udp->udp_dest_port=htons(ui->udp_destport->text().toInt(&ok));
            if(!ok){
                QMessageBox::critical(this,"Error","udp dest port is invalued!");
                return -1;
            }
            udp->udp_checksum=0;
            udp->udp_len=htons(ui->Data->toPlainText().length());
            udp->udp_checksum=udp_checksum(udp,&ip->ip_source_addr,&ip->ip_dest_addr,udp->udp_len+8);
        }
        else{//Other
            ip->ip_protocol=QInputDialog::getInt(this,"Protocol","please input the protocol",0,0,0xffff);
        }
        int data_len=ui->Data->toPlainText().length();
        if(data_len+len>1500){
            QMessageBox::critical(this,"Error","data is two long!!");
            return -1;
        }
        memcpy(packet+len,ui->Data->toPlainText().toLatin1(),data_len);
        ip->ip_length=htons(len+data_len-sizeof(ether_header));
        ip->ip_checksum=0;
        ip->ip_checksum=htons(ip_checksum(ip));
        return len+data_len;
    }
}

void SendFrame::on_ether_type_currentIndexChanged(const QString &arg1)
{
    if(arg1=="ARP"){
        ui->arp_page->setEnabled(true);
        ui->ip_page->setEnabled(false);
        ui->icmp_page->setEnabled(false);
        ui->tcp_page->setEnabled(false);
        ui->udp_page->setEnabled(false);
    }
    else if(arg1=="IP"){
        ui->arp_page->setEnabled(false);
        ui->ip_page->setEnabled(true);
        if(ui->ip_protocol->currentText()=="ICMP"){
            ui->icmp_page->setEnabled(true);
            ui->tcp_page->setEnabled(false);
            ui->udp_page->setEnabled(false);
        }
        else if(ui->ip_protocol->currentText()=="TCP"){
            ui->icmp_page->setEnabled(false);
            ui->tcp_page->setEnabled(true);
            ui->udp_page->setEnabled(false);
        }
        else if(ui->ip_protocol->currentText()=="UDP"){
            ui->icmp_page->setEnabled(false);
            ui->tcp_page->setEnabled(false);
            ui->udp_page->setEnabled(true);
        }
        else{
            ui->icmp_page->setEnabled(false);
            ui->tcp_page->setEnabled(false);
            ui->udp_page->setEnabled(false);
        }
    }
    else{
        ui->ip_page->setEnabled(false);
        ui->icmp_page->setEnabled(false);
        ui->tcp_page->setEnabled(false);
        ui->udp_page->setEnabled(false);
        ui->arp_page->setEnabled(false);
    }
}

void SendFrame::on_ip_protocol_currentIndexChanged(const QString &arg1)
{
    if(arg1=="ICMP"){
        ui->icmp_page->setEnabled(true);
        ui->tcp_page->setEnabled(false);
        ui->udp_page->setEnabled(false);
    }
    else if(arg1=="TCP"){
        ui->icmp_page->setEnabled(false);
        ui->tcp_page->setEnabled(true);
        ui->udp_page->setEnabled(false);
    }
    else if(arg1=="UDP"){
        ui->icmp_page->setEnabled(false);
        ui->tcp_page->setEnabled(false);
        ui->udp_page->setEnabled(true);
    }
    else{
        ui->icmp_page->setEnabled(false);
        ui->tcp_page->setEnabled(false);
        ui->udp_page->setEnabled(false);
    }
}

uint16_t SendFrame::ip_checksum(const ip_header * ip){
    const uint16_t* p=(const uint16_t*)ip;
    uint32_t ans=0;
    for(int i=0;i<10;++i){
        ans=ans+p[i];
        ans=(ans>>16)+(ans&0xffff);
    }
    return ~uint16_t(ans);
}
uint16_t SendFrame::icmp_checksum(const icmp_header *icmp){
    const uint16_t* p=(const uint16_t*)icmp;
    uint32_t ans=0;
    for(int i=0;i<4;++i){
        ans=ans+p[i];
        ans=(ans>>16)+(ans&0xffff);
    }
    return ~uint32_t(ans);
}
uint16_t SendFrame::tcp_checksum(const tcp_header *tcp,const in_addr* ip1,const in_addr* ip2,const uint16_t tcp_len){
    uint32_t ans=17+tcp_len;
    const uint16_t* p=(const uint16_t*)tcp;
    for(int i=0;i<4;++i){
        ans=ans+p[i];
        ans=(ans>>16)+(ans&0xffff);
    }
    p=(const uint16_t*)ip1;
    for(int i=0;i<2;++i){
        ans=ans+p[i];
        ans=(ans>>16)+(ans&0xffff);
    }
    p=(const uint16_t*)ip2;
    for(int i=0;i<2;++i){
        ans=ans+p[i];
        ans=(ans>>16)+(ans&0xffff);
    }
    return 0;
}
uint16_t SendFrame::udp_checksum(const udp_header *udp,const in_addr* ip1,const in_addr* ip2,const uint16_t udp_len){
    uint32_t ans=6+udp_len;
    const uint16_t* p=(const uint16_t*)udp;
    for(int i=0;i<10;++i){
        ans=ans+p[i];
        ans=(ans>>16)+(ans&0xffff);
    }
    p=(const uint16_t*)ip1;
    for(int i=0;i<2;++i){
        ans=ans+p[i];
        ans=(ans>>16)+(ans&0xffff);
    }
    p=(const uint16_t*)ip2;
    for(int i=0;i<2;++i){
        ans=ans+p[i];
        ans=(ans>>16)+(ans&0xffff);
    }
    return ~uint16_t(ans);
}
