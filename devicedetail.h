#ifndef DEVICEDETAIL_H
#define DEVICEDETAIL_H
#include "lbpcap.h"
#include <QDialog>

namespace Ui {
class DeviceDetail;
}

class DeviceDetail : public QDialog
{
    Q_OBJECT

public:
    explicit DeviceDetail(pcap_if_t* dev,QWidget *parent = nullptr);
    ~DeviceDetail();

private slots:
    void on_pushButton_clicked();

private:
    Ui::DeviceDetail *ui;
};

#endif // DEVICEDETAIL_H
