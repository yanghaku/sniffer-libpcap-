#include "statistics_ui.h"
#include "ui_statistics_ui.h"
#include <QDateTime>
#include <ctime>

Statistics_UI::Statistics_UI(const Statistics* d,QWidget *parent) :
    QDialog(parent),
    ui(new Ui::Statistics_UI)
{
    ui->setupUi(this);
    setFixedSize(this->width(),this->height());
    this->data=d;
    this->on_pushButton_refresh_clicked();
    timer = new QTimer(this);
    connect(timer,SIGNAL(timeout()),this,SLOT(on_pushButton_refresh_clicked()));
    timer->start(1000);
}

Statistics_UI::~Statistics_UI()
{
    delete timer;
    delete ui;
}

void Statistics_UI::on_pushButton_refresh_clicked()
{
    time_t now;
    time(&now);
    ui->start_time->setText(QDateTime::fromTime_t(data->start_time).toString());
    ui->end_time->setText(QDateTime::fromTime_t(now).toString());
    int second=now-data->start_time;if(second<=0)second=1;
    ui->frame_num->setText(QString::number(data->mac_num));
    ui->frame_byte->setText(QString::number(data->mac_byte));
    ui->frame_broadcast->setText(QString::number(data->mac_broadcast));
    ui->frame_short->setText(QString::number(data->mac_short));
    ui->frame_long->setText(QString::number(data->mac_long));
    ui->bit_peed->setText(QString::number((data->mac_byte<<3)/second));
    ui->byte_speed->setText(QString::number(data->mac_byte/second));
    ui->packet_speed->setText(QString::number(data->mac_num/second));

    ui->ip_num->setText(QString::number(data->ip_num));
    ui->ip_broadcast->setText(QString::number(data->ip_broadcast));
    ui->icmp_num->setText(QString::number(data->icmp_num));
    ui->icmp_redirect->setText(QString::number(data->icmp_redirect));
    ui->icmp_unreachable->setText(QString::number(data->icmp_unreachable));
    ui->tcp_num->setText(QString::number(data->tcp_num));
    ui->udp_num->setText(QString::number(data->udp_num));

    ui->listWidget->clear();
    QString tmp;
    for(auto it=data->mac_set.begin();it!=data->mac_set.end();++it){
        tmp.sprintf("%02X:%02X:%02X:%02X:%02X:%02X",it->byte[0],it->byte[1],it->byte[2],it->byte[3],
                it->byte[4],it->byte[5]);
        ui->listWidget->addItem(tmp);
    }
}
