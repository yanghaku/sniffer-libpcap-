#ifndef DEVICE_H
#define DEVICE_H

#include <QDialog>
#include <QMenu>
#include <QListWidgetItem>

namespace Ui {
class Device;
}

class Device : public QDialog
{
    Q_OBJECT

public:
    explicit Device(QWidget *parent = nullptr);
    ~Device();
    QMenu* menu;

private slots:
    void on_button_ok_accepted();

    void on_pushButton_refresh_clicked();

    void show_detail();

    void show_menu(QPoint);

    void item_doubleclicked(QListWidgetItem*);


private:
    Ui::Device *ui;
};

#endif // DEVICE_H
