#include "devicedetail.h"
#include "ui_devicedetail.h"

QString getStr(struct sockaddr* addr){
    if(addr==nullptr){
        return "NULL";
    }
    if(addr->sa_family==AF_INET){//ipv4
        return inet_ntoa(((sockaddr_in*)addr)->sin_addr)+
                QString("  port= ")+QString::number(ntohs(((sockaddr_in*)addr)->sin_port));
    }
    else if(addr->sa_family==AF_INET6){//ipv6
        return "ipv6";
    }
    return "Unknown type";
}


DeviceDetail::DeviceDetail(pcap_if_t* dev,QWidget *parent) :
    QDialog(parent),
    ui(new Ui::DeviceDetail)
{
    ui->setupUi(this);

    ui->name->setText(dev->name);
    if(dev->description==nullptr)ui->description->setText("NULL");
    else ui->description->setText(dev->description);
    if(dev->addresses==nullptr){
        QTreeWidgetItem* item=new QTreeWidgetItem(ui->treeWidget);
        item->setText(0,"No IP Adress");
    }
    pcap_addr_t* p=dev->addresses;
    int num=0;
    while(p!=nullptr){
        QTreeWidgetItem* item=new QTreeWidgetItem(ui->treeWidget);
        item->setText(0,"Adress "+QString::number(++num));
        QTreeWidgetItem* son=new QTreeWidgetItem(item);
        son->setText(0,"IP address: "+getStr(p->addr));
        son=new QTreeWidgetItem(item);
        son->setText(0,"net mask: "+getStr(p->netmask));
        son=new QTreeWidgetItem(item);
        son->setText(0,"broad: "+getStr(p->broadaddr));
        son=new QTreeWidgetItem(item);
        son->setText(0,"dest adress: "+getStr(p->dstaddr));
        p=p->next;
    }
}

DeviceDetail::~DeviceDetail()
{
    delete ui;
}

void DeviceDetail::on_pushButton_clicked()
{
    accept();
}
