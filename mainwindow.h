#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QLabel>
#include <vector>
#include "lbpcap.h"
#include "statistics.h"

namespace Ui {
class MainWindow;
}

class CaptureThread;

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

    QLabel *now_dev_status;
    QLabel *now_capture_status;

    std::vector<pcap_pkthdr>pkthdr_list;

    std::vector<const u_char*>packet_list;

    Statistics packet_statistics;

    CaptureThread* mythread;

    void refresh_table();

    void parsing_ether(const u_char*,int)const;

    void parsing_ip(const u_char*,int)const;

    void parsing_arp(const u_char*)const;

    void parsing_tcp(const u_char*,int)const;

    void parsing_udp(const u_char*,int)const;

    void parsing_icmp(const u_char*,int)const;

    void parsing_ftp(const u_char *packet, int len) const;

    void parsing_http(const u_char *packet, int len) const;

private slots:
    void on_actionchange_triggered();

    void on_actiondetail_triggered();

    void on_actionstart_triggered();

    void show_detail_packet();

    void on_actionstop_triggered();

    void on_actionclose_triggered();

    void on_actionopen_triggered();

    void on_actionsave_triggered();

    void on_actiondisplay_statistics_triggered();

    void on_actionreset_triggered();

    void on_actionCreate_triggered();

    void on_actionARP_spoofing_triggered();

    void on_actionARP_flooding_triggered();

private:
    Ui::MainWindow *ui;

};

#endif // MAINWINDOW_H
