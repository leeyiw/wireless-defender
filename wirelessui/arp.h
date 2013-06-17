#ifndef ARP_H
#define ARP_H

#include <QWidget>

namespace Ui {
class arp;
}

class arp : public QWidget
{
    Q_OBJECT
    
public:
    explicit arp(QWidget *parent = 0);
    ~arp();
    
private:
    Ui::arp *ui;
    void make_model();
    void show_table();
};

#endif // ARP_H
