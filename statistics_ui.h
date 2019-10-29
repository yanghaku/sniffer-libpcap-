#ifndef STATISTICS_UI_H
#define STATISTICS_UI_H

#include <QDialog>
#include <QTimer>
#include "statistics.h"

namespace Ui {
class Statistics_UI;
}

class Statistics_UI : public QDialog
{
    Q_OBJECT

public:
    explicit Statistics_UI(const Statistics* d,QWidget *parent = nullptr);
    ~Statistics_UI();

private slots:
    void on_pushButton_refresh_clicked();

private:
    const Statistics* data;
    QTimer *timer;
    Ui::Statistics_UI *ui;
};

#endif // STATISTICS_UI_H
