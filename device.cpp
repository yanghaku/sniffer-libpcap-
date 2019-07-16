#include "device.h"
#include "ui_device.h"
#include <QMessageBox>
#include "lbpcap.h"
#include "devicedetail.h"
#include <QDebug>
#include <QValidator>

Device::Device(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::Device)
{
    ui->setupUi(this);
    ui->lineEdit->setValidator(new QIntValidator(0,1<<30,this));
    menu=new QMenu(ui->listWidget);
    QAction* refresh=new QAction("refresh");
    QAction* detail=new QAction("show detail");
    QAction* select=new QAction("select");
    menu->addAction(select);
    menu->addAction(refresh);
    menu->addAction(detail);
    connect(refresh,SIGNAL(triggered()),this,SLOT(on_pushButton_refresh_clicked()));
    connect(detail,SIGNAL(triggered()),this,SLOT(show_detail()));
    connect(select,SIGNAL(triggered()),this,SLOT(on_button_ok_accepted()));
    connect(ui->listWidget,SIGNAL(customContextMenuRequested(QPoint)),this,SLOT(show_menu(QPoint)));
    connect(ui->listWidget,SIGNAL(itemDoubleClicked(QListWidgetItem*)),this,SLOT(item_doubleclicked(QListWidgetItem*)));
    on_pushButton_refresh_clicked();
}

Device::~Device()
{
    delete menu;
    delete ui;
}

void Device::on_button_ok_accepted()
{
    QListWidgetItem* item=ui->listWidget->currentItem();
    if(item==nullptr){
        QMessageBox::critical(this,"Error","please select a device!");
    }
    else item_doubleclicked(item);
}

void Device::on_pushButton_refresh_clicked()
{
    ui->listWidget->clear();
    if(alldev){pcap_freealldevs(alldev);alldev=nullptr;}
    if(pcap_findalldevs(&alldev,err_buf)==-1){
        QMessageBox::critical(this,"Error",QString("error: pcap_findalldevs()")+err_buf);
        exit(1);
    }
    for(pcap_if_t* p=alldev;p;p=p->next){
        QListWidgetItem* item=new QListWidgetItem(p->name);
        ui->listWidget->addItem(item);
    }
}


void Device::item_doubleclicked(QListWidgetItem* item){
    if(item==nullptr){
        QMessageBox::critical(this,"Error","invalued item!");
        return;
    }
    int timelimit=ui->lineEdit->text().toInt();
    pcap_t* new_pcap=pcap_open_live(item->text().toLatin1(),65535,ui->checkBox->isChecked(),timelimit,err_buf);
    nowdev=alldev;
    while(nowdev!=nullptr){
        if(QString(nowdev->name)==item->text())break;
        nowdev=nowdev->next;
    }
    if(new_pcap){
        if(pcap_handle)pcap_close(pcap_handle);
        pcap_handle=new_pcap;
        accept();
    }
    else{
        QMessageBox::critical(this,"Error",QString("Error pcap_open_live() ")+err_buf);
        return;
    }
}


void Device::show_menu(QPoint pos){
    QListWidgetItem* item=ui->listWidget->itemAt(pos);
    if(item)menu->exec(QCursor::pos());
}

void Device::show_detail(){
    int num=ui->listWidget->currentRow();
    if(num<0||num>=ui->listWidget->count() || alldev==nullptr){
        QMessageBox::critical(this,"Error","selected is unvalued!");
        return;
    }
    pcap_if_t* p=alldev;
    while(num--){
        p=p->next;
        if(p==nullptr){
            QMessageBox::critical(this,"Error","selected is unvalued!");
            return;
        }
    }
    DeviceDetail detail(p);
    detail.exec();
}

