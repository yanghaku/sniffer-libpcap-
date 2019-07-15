#include "capture.h"
#include "ui_capture.h"
#include <QDebug>
#include <QThread>
#include <QMovie>
#include <QMessageBox>
#include "lbpcap.h"

Capture::Capture(MainWindow* mainwindow,QWidget *parent) :
    QDialog(parent),
    ui(new Ui::Capture)
{
    ui->setupUi(this);
    QMovie* movie=new QMovie(":icon/download.gif");
    movie->setScaledSize(ui->label->size());
    ui->label->setMovie(movie);
    movie->start();

    mythread.status=ui->lineEdit;
    ui->lineEdit->setText("now capture 0 packet");
    mythread.mainwindow=mainwindow;
    mythread.start();
}

Capture::~Capture()
{
    delete ui;
}

void Capture::on_pushButton_stop_clicked()
{
    mythread.is_run=0;
    mythread.wait();
    reject();
}


void Mythread::run(){
    int x=0;
    pcap_pkthdr* tmp_pkthdr;
    const u_char* tmp_packet;
    time_t t1=time(nullptr),t2;
    while(is_run){
        qDebug()<<x<<endl;
        t2=time(nullptr);
        if(t2-t1>=1){//refresh the UI 1s
            t1=t2;
            status->setText(QString("now capture ")+QString::number(x)+" packet");
        }
        if(mainwindow->packet_list.size()>=2000)break;
        int res=pcap_next_ex(pcap_handle,&tmp_pkthdr,&tmp_packet);
        if(res==1){
            ++x;
            u_char* res=new uchar[tmp_pkthdr->len];
            memcpy(res,tmp_packet,tmp_pkthdr->len);
            mainwindow->packet_list.push_back(res);
            mainwindow->pkthdr_list.push_back(*tmp_pkthdr);
        }
        else if(res==0){
            QMessageBox::critical(mainwindow,"Error",QString("Time out ")+err_buf);
            break;
        }
        else{
            QMessageBox::critical(mainwindow,"Error",QString("Error ")+err_buf);
            break;
        }
    }
}

