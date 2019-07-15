#ifndef CAPTURE_H
#define CAPTURE_H
#include <QThread>
#include <QDialog>
#include "mainwindow.h"
#include <QLineEdit>

namespace Ui {
class Capture;
}

class Mythread : public QThread{
public:
    bool is_run;
    QLineEdit* status;
    MainWindow* mainwindow;
    Mythread():QThread(){
        is_run=1;
    }
    virtual void run();
};


class Capture : public QDialog
{
    Q_OBJECT

public:
    explicit Capture(MainWindow* mainwindow,QWidget *parent = nullptr);
    ~Capture();
    Mythread mythread;

private slots:
    void on_pushButton_stop_clicked();

private:
    Ui::Capture *ui;
};


#endif // CAPTURE_H
