#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "lbpcap.h"
#include "device.h"
#include "devicedetail.h"
#include "capture.h"
#include <QDebug>
#include <QLabel>
#include <QMessageBox>

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    int datalink=pcap_datalink(pcap_handle);
    if(datalink!=-1){
        ui->statusBar->addPermanentWidget(new QLabel(QString("datalink: ")
        +pcap_datalink_val_to_name(datalink)+QString(pcap_datalink_val_to_description(datalink))));
    }
    ui->statusBar->addPermanentWidget(new QLabel(pcap_lib_version()));
    now_dev_status=new QLabel(QString("now device: ")+nowdev->name);
    ui->statusBar->addPermanentWidget(now_dev_status);
    connect(ui->tableWidget,SIGNAL(itemSelectionChanged()),this,SLOT(show_detail_packet()));
}

MainWindow::~MainWindow()
{
    for(unsigned i=0;i<packet_list.size();++i){
        delete [] packet_list[i];
    }
    delete ui;
}


void MainWindow::on_actionchange_triggered()
{
    Device device;
    device.exec();
    now_dev_status->setText(QString("now device: ")+nowdev->name);
}

void MainWindow::on_actiondetail_triggered()
{
    DeviceDetail dlg(nowdev);
    dlg.exec();
}

void MainWindow::on_actionstart_triggered()
{
    QString filter;
    if(ui->actionIP->isChecked()){
        if(!filter.isEmpty())filter=filter+" or ";
        filter=filter+"ip ";
    }
    if(ui->actionARP->isChecked()){
        if(!filter.isEmpty())filter=filter+" or ";
        filter=filter+"arp ";
    }
    if(ui->actionRARP->isChecked()){
        if(!filter.isEmpty())filter=filter+" or ";
        filter=filter+"rarp ";
    }
    if(ui->actionICMP->isChecked()){
        if(!filter.isEmpty())filter=filter+" or ";
        filter=filter+"icmp ";
    }
    if(ui->actionTCP->isChecked()){
        if(!filter.isEmpty())filter=filter+" or ";
        filter=filter+"tcp ";
    }
    if(ui->actionUDP->isChecked()){
        if(!filter.isEmpty())filter=filter+" or ";
        filter=filter+"udp ";
    }
    if(filter.isEmpty()){
        QMessageBox::critical(this,"Error","please select a protocol!");
        return;
    }
    bpf_program pro;
    if(pcap_compile(pcap_handle,&pro,filter.toLatin1(),0,0)==-1){
        QMessageBox::critical(this,"Error",QString("error: pcap_compile() ")+err_buf);
        return ;
    }
    if(pcap_setfilter(pcap_handle,&pro)==-1){
        QMessageBox::critical(this,"Error",QString("error: pcap_setfilter() ")+err_buf);
        return;
    }
    Capture dlg(this);
    dlg.exec();
    ui->tableWidget->setRowCount(int(pkthdr_list.size()));
    char buf[10];
    for(unsigned i=0;i<this->pkthdr_list.size();++i){
        ui->tableWidget->setItem(int(i),0,new QTableWidgetItem(QString::number(i)));
        tm* tim=localtime(&pkthdr_list[i].ts.tv_sec);
        sprintf(buf,"%02d:%02d:%02d:",tim->tm_hour,tim->tm_min,tim->tm_sec);
        ui->tableWidget->setItem(int(i),1,new QTableWidgetItem(buf+QString::number(pkthdr_list[i].ts.tv_usec)));
        ui->tableWidget->setItem(int(i),5,new QTableWidgetItem(QString::number(pkthdr_list[i].len)));
    }
}

void MainWindow::show_detail_packet(){
    ui->treeWidget->clear();
    QTreeWidgetItem* item=new QTreeWidgetItem(ui->treeWidget);
    int row=ui->tableWidget->currentRow();
    item->setText(0,ui->tableWidget->item(row,1)->text());

    //treewidget
    ui->treeWidget->clear();
    QTreeWidgetItem* frame=new QTreeWidgetItem(ui->treeWidget);
    frame->setText(0,QString("Frame %1: %2 bytes on wire (%3 bits), %4 bytes captured (%5 bits) on interface %6")
                   .arg(row).arg(pkthdr_list[row].len).arg(pkthdr_list[row].len*8).arg(pkthdr_list[row].caplen)
                    .arg(pkthdr_list[row].caplen*8).arg(nowdev->name));

    QTreeWidgetItem* tree_item=new QTreeWidgetItem(frame);
    tree_item->setText(0,QString("Interface name: %1").arg(nowdev->name));
    tree_item=new QTreeWidgetItem(frame);
    tree_item->setText(0,QString("Encapsulation type: %1").arg(pcap_datalink_val_to_description(pcap_datalink(pcap_handle))));
    tree_item=new QTreeWidgetItem(frame);
    tree_item->setText(0,(QString("Arrival time: %1").arg(ctime((time_t*)&pkthdr_list[row].ts.tv_sec))).trimmed());
    tree_item=new QTreeWidgetItem(frame);
    tree_item->setText(0,QString("Epoch time: %1.%2 seconds").arg(pkthdr_list[row].ts.tv_sec).arg(pkthdr_list[row].ts.tv_usec));
    tree_item=new QTreeWidgetItem(frame);
    tree_item->setText(0,QString("Frame Number: %1").arg(row));
    tree_item=new QTreeWidgetItem(frame);
    tree_item->setText(0,QString("Frame Length: %1bytes (%2 bits)").arg(pkthdr_list[row].len).arg(pkthdr_list[row].len*8));
    tree_item=new QTreeWidgetItem(frame);
    tree_item->setText(0,QString("Capture Length: %1bytes (%2 bits)").arg(pkthdr_list[row].caplen).arg(pkthdr_list[row].caplen*8));
    parsing_ether(packet_list[row],pkthdr_list[row].len);

    // TextEdit
    QString str;
    char buf[13];
    for(unsigned i=0;i<pkthdr_list[row].len;++i){
        if(i%16==0){
            sprintf(buf,"%04X:    ",i/16);
            str=str+buf;
        }
        sprintf(buf,"%02X ",packet_list[row][i]);
        str=str+buf;
        if(i%16==7)str=str+"  ";
        if(i%16==15 || i==pkthdr_list[row].len-1){
            if(i%16<7){
                for(unsigned k=0;k<(7-i%16)*3;++k)str=str+" ";
                str=str+"  ";
            }
            if(i%16<15)for(unsigned k=0;k<std::min(8u,(15-i%16))*3;++k)str=str+" ";
            str=str+"    ";
            for(unsigned j=i-i%16;j<=i;++j){
                if(isprint(packet_list[row][j]))str=str+QString(packet_list[row][j]);
                else str=str+".";
            }
            str=str+"\n";
        }
    }
    ui->textEdit->setText(str);
}


void MainWindow::parsing_ether(const u_char *packet, int len) const{
    const ether_header* ether=((const ether_header*)packet);
    QString dest,source,typestr;
    dest.sprintf("%02X:%02X:%02X:%02X:%02X:%02X",ether->ether_dest_addr[0],ether->ether_dest_addr[1],
            ether->ether_dest_addr[2],ether->ether_dest_addr[3],
            ether->ether_dest_addr[4],ether->ether_dest_addr[5]);
    source.sprintf("%02X:%02X:%02X:%02X:%02X:%02X",ether->ether_source_addr[0],ether->ether_source_addr[1],
            ether->ether_source_addr[2],ether->ether_source_addr[3],
            ether->ether_source_addr[4],ether->ether_source_addr[5]);
    u_int16_t type=ntohs(ether->ether_type);
    typestr.sprintf("Type:     %s (0x%04X)",ether_type_val_to_name(type),type);
    QTreeWidgetItem* item=new QTreeWidgetItem(ui->treeWidget);
    item->setText(0,"Ethernet II, Src: "+source+", Dst: "+dest);
    QTreeWidgetItem* item1=new QTreeWidgetItem(item);
    item1->setText(0,"Destination: "+dest);
    item1=new QTreeWidgetItem(item);
    item1->setText(0,"Source:      "+source);
    item1=new QTreeWidgetItem(item);
    item1->setText(0,typestr);

    switch(type){
    case 0x0800://ip
        parsing_ip(packet+sizeof(ether_header),len-sizeof(ether_header));
        break;
    case 0x0806://arp
        parsing_arp(packet+sizeof(ether_header));
        break;
    default:
        qDebug()<<"I don\'t know"<<endl;
        break;
    }
}

void MainWindow::parsing_ip(const u_char *packet, int len) const{
    const ip_header* ip=(const ip_header*)(packet);
    int head_len=ip->ip_header_len*4;
    QString source=inet_ntoa(ip->ip_source_addr);
    QString dest=inet_ntoa(ip->ip_dest_addr);

    QTreeWidgetItem* item=new QTreeWidgetItem(ui->treeWidget);
    item->setText(0,"Internet Protocol Version 4, Src: "+source+", Dst: "+dest);
    QTreeWidgetItem* p=new QTreeWidgetItem(item);
    p->setText(0,QString("%1 .... = Version: %2").arg(ip->ip_version,4,2,QLatin1Char('0')).arg(ip->ip_version));
    p=new QTreeWidgetItem(item);
    p->setText(0,QString(".... %1 = Header Length: %2 bytes (%3)").arg(ip->ip_header_len,4,2,QLatin1Char('0')).arg(head_len).arg(ip->ip_header_len));

    //tos
    QString dscp,ecn,dscp_detail,ecn_detail;
    if(ip->ip_tos>>2==0){
        dscp="BE";
        dscp_detail="Default (0)";
    }
    else if(((ip->ip_tos>>2)&0x7)==0){
        dscp=QString("CS")+QString::number(ip->ip_tos>>5);
        dscp_detail="Class Selector "+QString::number(ip->ip_tos>>5)+" ("+QString::number(ip->ip_tos>>2)+")";
    }
    else if(ip->ip_tos>>2==46){
        dscp="EF";
        dscp_detail="Expendited Forwarding ("+QString::number(ip->ip_tos>>2)+")";
    }
    else if((ip->ip_tos>>5)<=4&&(ip->ip_tos>>5)>=1&&((ip->ip_tos>>2)&0x7)!=0){
        dscp="AF"+QString::number(ip->ip_tos>>5);
        dscp_detail="Assured Forwarding "+QString::number(ip->ip_tos>>5)+" ("+QString::number(ip->ip_tos>>2)+")";
    }
    else{
        dscp="unknown";
        dscp_detail="unknown";
    }
    if((ip->ip_tos&0x3)==0){
        ecn="Not-ECT";
        ecn_detail="Not ECN-capable Transport (0)";
    }
    else if((ip->ip_tos&0x3)==1){
        ecn="ECT1";
        ecn_detail="ECN-capable Transport (1)";
    }
    else if((ip->ip_tos&0x3)==2){
        ecn="ECT2";
        ecn_detail="ECN-capable Transport (2)";
    }
    else{
        ecn="CE";
        ecn_detail="ECN-capable Transport (3)";
    }
    p=new QTreeWidgetItem(item);
    p->setText(0,QString("Differentiated Services Field: 0x%1 (DSCP: ").arg(ip->ip_tos)+dscp+", ECN: "+ecn+")");
    QTreeWidgetItem* son_p=new QTreeWidgetItem(p);
    son_p->setText(0,QString("%1 %2.. = Differentiated Services Codepoint: ").arg(ip->ip_tos>>4,4,2,QLatin1Char('0')).arg((ip->ip_tos>>2)&0x3,2,2,QLatin1Char('0'))+dscp_detail);
    son_p=new QTreeWidgetItem(p);
    son_p->setText(0,QString(".... ..%1 = Explicit Congestion Notification: ").arg(ip->ip_tos&0x3,2,2,QLatin1Char('0'))+ecn_detail);


    p=new QTreeWidgetItem(item);
    p->setText(0,QString("Total Length: %1").arg(ntohs(ip->ip_length)));
    p=new QTreeWidgetItem(item);
    p->setText(0,QString("Identification: 0x%1 (%2)").arg(ntohs(ip->ip_id),0,16).arg(ntohs(ip->ip_id)));

    //flag offset
    p=new QTreeWidgetItem(item);
    QString flag;
    u_int16_t offset=ntohs(ip->ip_offset);
    if((offset>>14)&1)flag="Don't fragment";
    else{
        if((offset>>13)&1)flag="More fragment";
        else flag="No More fragment";
    }
    p->setText(0,QString("Flags: 0x%1, ").arg(offset,4,16,QLatin1Char('0'))+flag);
    son_p=new QTreeWidgetItem(p);
    if((offset>>15)&1)
        son_p->setText(0,QString("1... .... .... .... = Reserved bit: Set"));
    else son_p->setText(0,"0... .... .... .... = Reserved bit: Not set");
    son_p=new QTreeWidgetItem(p);
    if((offset>>14)&1)
        son_p->setText(0,".1.. .... .... .... = Don't fragment: Set");
    else son_p->setText(0,".0.. .... .... .... = Don't fragment: Not set");
    son_p=new QTreeWidgetItem(p);
    if((offset>>13)&1)
        son_p->setText(0,"..1. .... .... .... = More fragment: Set");
    else son_p->setText(0,"..0. .... .... .... = More fragment: Not set");
    son_p=new QTreeWidgetItem(p);
    flag.sprintf("...%d %d%d%d%d %d%d%d%d %d%d%d%d = Fragment offset: 0x%04X",(offset>>12)&1,(offset>>11)&1,
                 (offset>>10)&1,(offset>>9)&1,(offset>>8)&1,(offset>>7)&1,(offset>>6)&1,(offset>>5)&1,
                 (offset>>4)&1,(offset>>3)&1,(offset>>2)&1,(offset>>1)&1,offset&1,offset&0x1fff);
    son_p->setText(0,flag);

    //ttl
    p=new QTreeWidgetItem(item);
    p->setText(0,QString("Time to live: %1").arg(ip->ip_ttl));
    //protocol
    p=new QTreeWidgetItem(item);
    if(ip->ip_protocol<ip_header_protocol_namelist_size){
        p->setText(0,QString("Protocol: ")+ip_header_protocol[ip->ip_protocol]+QString(" (%1)").arg(ip->ip_protocol));
    }
    else if(ip->ip_protocol==255){
        p->setText(0,"保留 (255)");
    }else p->setText(0,"unknow protocol");
    //checksum
    p=new QTreeWidgetItem(item);
    p->setText(0,"Header checksum: 0x"+QString::number(ntohs(ip->ip_checksum),16));
    p=new QTreeWidgetItem(item);
    p->setText(0,"Source:      "+source);
    p=new QTreeWidgetItem(item);
    p->setText(0,"Destination: "+dest);

    if(ip->ip_protocol==6){//tcp
        parsing_tcp(packet+head_len,len-head_len);
    }
    else if(ip->ip_protocol==17){//udp
        parsing_udp(packet+head_len,len-head_len);
    }
    else if(ip->ip_protocol==1){//icmp
        parsing_icmp(packet+head_len,len-head_len);
    }

}

void MainWindow::parsing_arp(const u_char *packet) const{
    const arp_header* arp=((const arp_header*)packet);
    u_int16_t hardware_type=ntohs(arp->arp_hardware_type);
    u_int16_t protocol_type=ntohs(arp->arp_protocol_type);
    u_int16_t oper=ntohs(arp->arp_operation_code);
    QString send_mac,target_mac,send_ip,target_ip;
    send_ip=inet_ntoa(arp->arp_souce_ipaddr);
    target_ip=inet_ntoa(arp->arp_dest_ipaddr);
    send_mac.sprintf("%02X:%02X:%02X:%02X:%02X:%02X",arp->arp_source_macaddr[0],arp->arp_source_macaddr[1],
            arp->arp_source_macaddr[2],arp->arp_source_macaddr[3],
            arp->arp_source_macaddr[4],arp->arp_source_macaddr[5]);
    target_mac.sprintf("%02X:%02X:%02X:%02X:%02X:%02X",arp->arp_dest_macaddr[0],arp->arp_dest_macaddr[1],
            arp->arp_dest_macaddr[2],arp->arp_dest_macaddr[3],
            arp->arp_dest_macaddr[4],arp->arp_dest_macaddr[5]);
    QTreeWidgetItem* item=new QTreeWidgetItem(ui->treeWidget);
    item->setText(0,QString("Address Resolution Protocol ")+(oper==1?"(request)":"(reply)"));
    QTreeWidgetItem* p=new QTreeWidgetItem(item);
    p->setText(0,QString("Hardware type: ")+(hardware_type==1?"Ethernet":"not known"));
    p=new QTreeWidgetItem(item);
    p->setText(0,QString("Protocol type: ")+ether_type_val_to_name(protocol_type)+QString(" (0x%1)").arg(protocol_type,4,16,QLatin1Char('0')));
    p=new QTreeWidgetItem(item);
    p->setText(0,QString("Hardware size: %1").arg(arp->arp_hardware_size));
    p=new QTreeWidgetItem(item);
    p->setText(0,QString("protocol size: %1").arg(arp->arp_protocol_size));
    p=new QTreeWidgetItem(item);
    p->setText(0,oper==1?"Opcode: request (1)":"Opcode: reply (2)");
    p=new QTreeWidgetItem(item);
    p->setText(0,"Sender MAC adress: "+send_mac);
    p=new QTreeWidgetItem(item);
    p->setText(0,"Sender IP adress:  "+send_ip);
    p=new QTreeWidgetItem(item);
    p->setText(0,"Target MAC adress: "+target_mac);
    p=new QTreeWidgetItem(item);
    p->setText(0,"Target IP adress:  "+target_ip);
}

void MainWindow::parsing_tcp(const u_char *packet, int len) const{
    const tcp_header* tcp=((const tcp_header*)packet);
    u_int16_t dst_port=ntohs(tcp->tcp_source_port);
    u_int16_t src_port=ntohs(tcp->tcp_dest_port);
    u_int32_t seq=ntohl(tcp->tcp_acknowedgement);
    u_int32_t ack=ntohl(tcp->tcp_ack);
    QString str;
    str.sprintf("Transmission Control Protocol, Src Port: %d, Dst Port: %d, Seq: %u, Ack: %u, Len: %d",src_port,dst_port,seq,ack,len);
    QTreeWidgetItem* item=new QTreeWidgetItem(ui->treeWidget);
    item->setText(0,str);
    QTreeWidgetItem* p=new QTreeWidgetItem(item);
    p->setText(0,QString("Souce Port:       %1").arg(src_port));
    p=new QTreeWidgetItem(item);
    p->setText(0,QString("Destination Port: %1").arg(dst_port));
    p=new QTreeWidgetItem(item);
    p->setText(0,QString("Sequence number: %1").arg(seq));
    p=new QTreeWidgetItem(item);
    p->setText(0,QString("Acknowledgement number: %1").arg(ack));
    //header:
    p=new QTreeWidgetItem(item);
    str.sprintf("%d%d%d%d .... = Header Length: %d bytes (%d)",(tcp->tcp_header_len>>3)&1,
                (tcp->tcp_header_len>>2)&1,(tcp->tcp_header_len>>1)&1,tcp->tcp_header_len&1,
                tcp->tcp_header_len*4,tcp->tcp_header_len);
    p->setText(0,str);

    //flag:
    u_int16_t flag=tcp->tcp_reserved&0x3;
    flag=(flag<<4)| u_int16_t(tcp->tcp_flag);
    QTreeWidgetItem* flag_node=new QTreeWidgetItem(item);
    str.sprintf("Flags: 0x%03x ",flag);
    if((flag>>5)&1)str=str+" (URG)";
    if((flag>>4)&1)str=str+" (ACK)";
    if((flag>>3)&1)str=str+" (PSH)";
    if((flag>>2)&1)str=str+" (RST)";
    if((flag>>1)&1)str=str+" (SYN)";
    if(flag&1)str=str+" (FYN) ";
    flag_node->setText(0,str);
    p=new QTreeWidgetItem(flag_node);
    p->setText(0,QString("%1. .... .... = Reserved: 0x%2").arg(tcp->tcp_reserved,3,2,QLatin1Char('0')).arg(tcp->tcp_reserved,1,16));
    p=new QTreeWidgetItem(flag_node);
    p->setText(0,QString("...%1 .... .... = Nonce: ").arg(tcp->tcp_reserved&1)+(tcp->tcp_reserved&1?"Set":"Not set"));
    p=new QTreeWidgetItem(flag_node);
    p->setText(0,QString(".... %1... .... = Congestion Window Reduced(CWR): ").arg((tcp->tcp_flag>>7)&1)+(((tcp->tcp_flag>>7)&1)?"Set":"Not set"));
    p=new QTreeWidgetItem(flag_node);
    p->setText(0,QString(".... .%1.. .... = ECN-Echo: ").arg((tcp->tcp_flag>>6)&1)+(((tcp->tcp_flag>>6)&1)?"Set":"Not set"));
    p=new QTreeWidgetItem(flag_node);
    p->setText(0,QString(".... ..%1. .... = Urgent: ").arg((tcp->tcp_flag>>5)&1)+(((tcp->tcp_flag>>5)&1)?"Set":"Not set"));
    p=new QTreeWidgetItem(flag_node);
    p->setText(0,QString(".... ...%1 .... = Acknowledgement: ").arg((tcp->tcp_flag>>4)&1)+(((tcp->tcp_flag>>4)&1)?"Set":"Not set"));
    p=new QTreeWidgetItem(flag_node);
    p->setText(0,QString(".... .... %1... = Push: ").arg((tcp->tcp_flag>>3)&1)+(((tcp->tcp_flag>>3)&1)?"Set":"Not set"));
    p=new QTreeWidgetItem(flag_node);
    p->setText(0,QString(".... .... .%1.. = Reset: ").arg((tcp->tcp_flag>>2)&1)+(((tcp->tcp_flag>>2)&1)?"Set":"Not set"));
    p=new QTreeWidgetItem(flag_node);
    p->setText(0,QString(".... .... ..%1. = Syn: ").arg((tcp->tcp_flag>>1)&1)+(((tcp->tcp_flag>>1)&1)?"Set":"Not set"));
    p=new QTreeWidgetItem(flag_node);
    p->setText(0,QString(".... .... ...%1 = Fin: ").arg((tcp->tcp_flag)&1)+(((tcp->tcp_flag)&1)?"Set":"Not set"));


    //windows size
    p=new QTreeWidgetItem(item);
    p->setText(0,QString("Windwow size value: %1").arg(ntohs(tcp->tcp_windows)));
    //checksum
    p=new QTreeWidgetItem(item);
    p->setText(0,QString("Checksum: 0x%1").arg(ntohs(tcp->tcp_checksum),4,16,QLatin1Char('0')));
    //urgent point
    p=new QTreeWidgetItem(item);
    p->setText(0,QString("Urgent point: 0x%1").arg(ntohs(tcp->tcp_urgent_point),4,16,QLatin1Char('0')));
}

void MainWindow::parsing_udp(const u_char *packet, int len) const{
    const udp_header* udp=((const udp_header*)packet);
    u_int16_t src_port=ntohs(udp->udp_source_port);
    u_int16_t dst_port=ntohs(udp->udp_dest_port);
    QString str;
    str.sprintf("User Datagram Protocol, Src Port: %d, Dst Port: %d, Len: %d",src_port,dst_port,len);
    QTreeWidgetItem* item=new QTreeWidgetItem(ui->treeWidget);
    item->setText(0,str);
    QTreeWidgetItem* p=new QTreeWidgetItem(item);
    p->setText(0,QString("Source Port: %1").arg(src_port));
    p=new QTreeWidgetItem(item);
    p->setText(0,QString("Destination Port: %1").arg(dst_port));
    p=new QTreeWidgetItem(item);
    p->setText(0,QString("Length: %1").arg(ntohs(udp->udp_len)));
    p=new QTreeWidgetItem(item);
    p->setText(0,QString("Checksum: 0x%1").arg(ntohs(udp->udp_checksum),4,16,QLatin1Char('0')));
}

void MainWindow::parsing_icmp(const u_char *packet, int len) const{
    const icmp_header* icmp=((const icmp_header*)packet);
    QTreeWidgetItem* item=new QTreeWidgetItem(ui->treeWidget);
    item->setText(0,QString("Internet Control Message Protocol (Len=%1)").arg(len));
    QTreeWidgetItem* p=new QTreeWidgetItem(item);
    p->setText(0,QString("Type: %1").arg(icmp->icmp_type));
    p=new QTreeWidgetItem(item);
    p->setText(0,QString("Code: %1").arg(icmp->icmp_code));
    p=new QTreeWidgetItem(item);
    p->setText(0,QString("Checksum: 0x%1").arg(ntohs(icmp->icmp_checksum),4,16,QLatin1Char('0')));
    p=new QTreeWidgetItem(item);
    p->setText(0,QString("Identifier: %1 (0x%2)").arg(ntohs(icmp->icmp_id)).arg(ntohs(icmp->icmp_id),4,16,QLatin1Char('0')));
    p=new QTreeWidgetItem(item);
    p->setText(0,QString("Sequence number: %1 (0x%2)").arg(ntohs(icmp->icmp_seq)).arg(ntohs(icmp->icmp_seq),4,16,QLatin1Char('0')));
}








const char* ether_type_val_to_name(u_int16_t type){
    if(type<=0x05DC)return "IEEE 802.3 长度";
    if(type>=0x0101&&type<=0x01FF)return "实验";
    switch (type) {
    case 0x0600: return "XEROX NS IDP";
    case 0x0660: return "DLOG";
    case 0x0661: return "DLOG";
    case 0x0800: return "网际协议 IPv4";
    case 0x0801: return "X.75 Internet";
    case 0x0802: return "NBS Internet";
    case 0x0803: return "ECMA Internet";
    case 0x0804: return "Chaosnet";
    case 0x0805: return "X.25 Level 3";
    case 0x0806: return "地址解析协议ARP(Address Resolution Protocol)";
    case 0x0808: return "帧中继 ARP(Frame Relay ARP)[RFC1701]";
    case 0x6559: return "原始帧中继(Raw Frame Relay)[RFC1701]";
    case 0x8035: return "动态 DARP(DRARP:Dynamic RARP)反向地址解析协议(RARP：Reverse Address Resolution Protocol)";
    case 0x8037: return "Novell Netware IPX";
    case 0x809B: return "EtherTalk";
    case 0x80D5: return "IBM SNA Services over Ethernet";
    case 0x80F3: return "AppleTalk 地址解析协议(AARP：AppleTalk Address Resolution Protocol)";
    case 0x8100: return "以太网自动保护开关(EAPS：Ethernet Automatic Protection Switching)";
    case 0x8137: return "因特网包交换(IPX：Internet Packet Exchange)";
    case 0x814C: return "简单网络管理协议(SNMP：Simple Network Management Protocol)";
    case 0x86DD: return "网际协议v6(IPv6,Internet Protocol version 6)";
    case 0x880B: return "点对点协议(PPP：Point-to-Point Protocol)";
    case 0x880C: return "通用交换管理协议(GSMP：General Switch Management Protocol)";
    case 0x8847: return "多协议标签交换(单播)MPLS：Multi-Protocol Label Switching <unicast>)";
    case 0x8848: return "多协议标签交换(组播)(MPLS, Multi-Protocol Label Switching <multicast>)";
    case 0x8863: return "以太网上的 PPP(发现阶段)(PPPoE：PPP Over Ethernet <Discovery Stage>)";
    case 0x8864: return "以太网上的 PPP(会话阶段)(PPPoE，PPP Over Ethernet<PPP Session Stage>)";
    case 0x88BB: return "轻量级访问点协议(LWAPP：Light Weight Access Point Protocol)";
    case 0x88CC: return "链接层发现协议(LLDP：Link Layer Discovery Protocol)";
    case 0x8E88: return "局域网上的 EAP(EAPOL：EAP over LAN)";
    case 0x9000: return "配置测试协议(Loopback)";
    case 0x9100: return "VLAN 标签协议标识符(VLAN Tag Protocol Identifier)";
    case 0x9200: return "VLAN 标签协议标识符(VLAN Tag Protocol Identifier)";
    case 0xFFFF: return "保留";
    default:return "Not known type";
    }
}

const char* ip_header_protocol[ip_header_protocol_namelist_size]={
/*0  */     "保留字段,用于IPv6(跳跃点到跳跃点选项)",
/*1  */     "Internet控制消息(ICMP)",
/*2  */     "Internet组管理(IGMP)",
/*3  */     "网关到网关(GGP)",
/*4  */     "IP中的IP(封装)",
/*5  */     "流",
/*6  */     "传输控制(TCP)",
/*7  */     "CBT",
/*8  */     "外部网关协议(EGP)",
/*9  */     "任何私有内部网关(Cisco在它的IGRP实现中使用)(IGP)",
/*10 */     "BBNRCC监视",
/*11 */     "网络语音协议",
/*12 */     "PUP",
/*13 */     "ARGUS",
/*14 */     "EMCON",
/*15 */     "网络诊断工具",
/*16 */     "混乱(Chaos)",
/*17 */     "用户数据报文(UDP)",
/*18 */     "复用",
/*19 */     "DCN测量子系统",
/*20 */     "主机监视",
/*21 */     "包无线测量",
/*22 */     "XEROXNSIDP",
/*23 */     "Trunk-1",
/*24 */     "Trunk-2",
/*25 */     "Leaf-1",
/*26 */     "Leaf-2",
/*27 */     "可靠的数据协议",
/*28 */     "Internet可靠交易",
/*29 */     "ISO传输协议第四类(TP4)",
/*30 */     "大块数据传输协议",
/*31 */     "MFE网络服务协议",
/*32 */     "MERIT节点之间协议",
/*33 */     "序列交换协议",
/*34 */     "第三方连接协议",
/*35 */     "域之间策略路由协议",
/*36 */     "XTP",
/*37 */     "数据报文传递协议",
/*38 */     "IDPR控制消息传输协议",
/*39 */     "TP++传输协议",
/*40 */     "IL传输协议",
/*41 */     "IPv6",
/*42 */     "资源命令路由协议",
/*43 */     "IPv6的路由报头",
/*44 */     "IPv6的片报头",
/*45 */     "域之间路由协议",
/*46 */     "保留协议",
/*47 */     "通用路由封装",
/*48 */     "可移动主机路由协议",
/*49 */     "BNA",
/*50 */     "IPv6封装安全有效负载",
/*51 */     "IPv6验证报头",
/*52 */     "集成的网络层安全TUBA",
/*53 */     "带加密的IP",
/*54 */     "NBMA地址解析协议",
/*55 */     "IP可移动性",
/*56 */     "使用Kryptonet钥匙管理的传输层安全协议",
/*57 */     "SKIP",
/*58 */     "IPv6的ICMP",
/*59 */     "IPv6的无下一个报头",
/*60 */     "IPv6的信宿选项",
/*61 */     "任何主机内部协议",
/*62 */     "CFTP",
/*63 */     "任何本地网络",
/*64 */     "SATNET和BackroomEXPAK",
/*65 */     "Kryptolan",
/*66 */     "MIT远程虚拟磁盘协议",
/*67 */     "Internet Pluribus包核心",
/*68 */     "任何分布式文件系统",
/*69 */     "SATNET监视",
/*70 */     "VISA协议",
/*71 */     "Internet包核心工具",
/*72 */     "计算机协议Network Executive",
/*73 */     "计算机协议Heart Beat",
/*74 */     "Wang Span网络",
/*75 */     "包视频协议",
/*76 */     "Backroom SATNET监视",
/*77 */     "SUN ND PROTOCOL—临时",
/*78 */     "WIDEBAND监视",
/*79 */     "WIDEBAND EXPAK",
/*80 */     "ISO Internet协议",
/*81 */     "VMTP",
/*82 */     "SECURE—VMTP(安全的VMTP)",
/*83 */     "VINES",
/*84 */     "TTP",
/*85 */     "NSFNET—IGP",
/*86 */     "不同网关协议",
/*87 */     "TCF",
/*88 */     "EIGRP",
/*89 */     "OSPF IGP",
/*90 */     "Sprite RPC协议",
/*91 */     "Locus地址解析协议",
/*92 */     "多播传输协议",
/*93 */     "AX.25帧",
/*94 */     "IP内部的IP封装协议",
/*95 */     "可移动网络互连控制协议",
/*96 */     "旗语通讯安全协议",
/*97 */     "IP中的以太封装",
/*98 */     "封装报头",
/*99 */     "任何私有加密方案",
/*100*/     "GMTP",
/*101*/     "Ipsilon流量管理协议",
/*102*/     "PNNI over IP",
/*103*/     "协议独立多播",
/*104*/     "ARIS",
/*105*/     "SCPS",
/*106*/     "QNX",
/*107*/     "活动网络",
/*108*/     "IP有效负载压缩协议",
/*109*/     "Sitara网络协议",
/*110*/     "Compaq对等协议",
/*111*/     "IP中的IPX",
/*112*/     "虚拟路由器冗余协议",
/*113*/     "PGM可靠传输协议",
/*114*/     "任何0跳跃协议",
/*115*/     "第二层隧道协议",
/*116*/     "D-II数据交换(DDX)",
/*117*/     "交互式代理传输协议",
/*118*/     "日程计划传输协议",
/*119*/     "SpectraLink无线协议",
/*120*/     "UTI",
/*121*/     "简单消息协议",
/*122*/     "SM",
/*123*/     "性能透明性协议",
/*124*/     "ISIS over IPv4",
/*125*/     "FIRE",
/*126*/     "Combat无线传输协议",
/*127*/     "Combat无线用户数据报文",
/*128*/     "SSCOPMCE",
/*129*/     "IPLT",
/*130*/     "安全包防护",
/*131*/     "IP中的私有IP封装",
/*132*/     "流控制传输协议"
};
