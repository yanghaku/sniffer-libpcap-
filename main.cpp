#include "mainwindow.h"
#include <QApplication>
#include "device.h"
#include "lbpcap.h"

pcap_if_t *alldev,*nowdev;
pcap_t* pcap_handle;
char err_buf[PCAP_ERRBUF_SIZE];


int main(int argc, char *argv[])
{
    alldev=nullptr;
    pcap_handle=nullptr;
    QApplication a(argc, argv);
    Device device;
    if(device.exec()==QDialog::Accepted){
        MainWindow w;
        w.show();
        return a.exec();
    }
    if(alldev)pcap_freealldevs(alldev);
    if(pcap_handle)pcap_close(pcap_handle);
    return 0;
}
