#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QLabel>
#include <vector>
#include "lbpcap.h"

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

    QLabel *now_dev_status;

    std::vector<pcap_pkthdr>pkthdr_list;

    std::vector<const u_char*>packet_list;

    void parsing_ether(const u_char*,int)const;

    void parsing_ip(const u_char*,int)const;

    void parsing_arp(const u_char*)const;

    void parsing_tcp(const u_char*,int)const;

    void parsing_udp(const u_char*,int)const;

    void parsing_icmp(const u_char*,int)const;


private slots:
    void on_actionchange_triggered();

    void on_actiondetail_triggered();

    void on_actionstart_triggered();

    void show_detail_packet();
private:
    Ui::MainWindow *ui;
};

#endif // MAINWINDOW_H
