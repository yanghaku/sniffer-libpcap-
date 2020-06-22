#ifndef ARPSPOOFING_H
#define ARPSPOOFING_H

#include <QDialog>
#include <linux/if_packet.h>// sockaddr_ll
#include "lbpcap.h"
#include <sys/socket.h>


namespace Ui {
class ArpSpoofing;
}

class ArpSpoofing : public QDialog
{
    Q_OBJECT

public:
    bool device_ok;

    explicit ArpSpoofing(const char* device_name, QWidget *parent = nullptr);
    ~ArpSpoofing();

private slots:
    void on_pushButton_send_clicked();

private:
    Ui::ArpSpoofing *ui;

    sockaddr_ll device;
    int sockfd;
    int createPacket(uint8_t* packet);
    bool createDevice(const char* device_name);
};

#endif // ARPSPOOFING_H
