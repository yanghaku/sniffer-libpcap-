#ifndef SENDFRAME_H
#define SENDFRAME_H

#include <QDialog>
#include <sys/socket.h>
#include <linux/if_packet.h>// sockaddr_ll
#include "lbpcap.h"

namespace Ui {
class SendFrame;
}

class SendFrame : public QDialog
{
    Q_OBJECT

public:
    bool ok;

    explicit SendFrame(const char* device_name,QWidget *parent = nullptr);
    ~SendFrame();

private slots:
    void on_pushButton_send_clicked();

    void on_ether_type_currentIndexChanged(const QString &arg1);

    void on_ip_protocol_currentIndexChanged(const QString &arg1);

private:
    Ui::SendFrame *ui;

    sockaddr_ll device;
    int sockfd;

    int createPacket(uint8_t* packet);
    bool createDevice(const char* device_name);
    uint16_t ip_checksum(const ip_header*);
    uint16_t icmp_checksum(const icmp_header*);
    uint16_t tcp_checksum(const tcp_header*,const in_addr*,const in_addr*,const uint16_t);
    uint16_t udp_checksum(const udp_header*,const in_addr*source_ip,const in_addr* dest_ip,const uint16_t udp_len);
};

#endif // SENDFRAME_H
