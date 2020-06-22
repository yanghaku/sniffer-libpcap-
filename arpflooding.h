#ifndef ARPFLOODING_H
#define ARPFLOODING_H
#include <linux/if_packet.h>// sockaddr_ll
#include "lbpcap.h"
#include <sys/socket.h>
#include <QDialog>

namespace Ui {
class ArpFlooding;
}

class ArpFlooding : public QDialog
{
    Q_OBJECT

public:
    bool device_ok;


    explicit ArpFlooding(const char* device_name, QWidget *parent = nullptr);
    ~ArpFlooding();

private slots:
    void on_pushButton_send_clicked();

private:
    Ui::ArpFlooding *ui;

    sockaddr_ll device;
    int sockfd;
    int createPacket(uint8_t* packet);
    bool createDevice(const char* device_name);
};

#endif // ARPFLOODING_H
