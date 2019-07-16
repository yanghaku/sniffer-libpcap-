#ifndef CAPTURETHREAD_H
#define CAPTURETHREAD_H

#include <QThread>
#include "mainwindow.h"


class CaptureThread : public QThread{
public:
    bool is_run;
    MainWindow* mainwindow;
    CaptureThread():QThread(){
    }
    virtual void run();
};

#endif // CAPTURETHREAD_H
