#ifndef APLIST_H
#define APLIST_H
#include <QWidget>
#include <QStandardItem>
#include <QtNetwork>
#include "network.h"
namespace Ui {
class aplist;
}
class aplist : public QWidget
{
    Q_OBJECT
    
public:
    explicit aplist(QWidget *parent = 0);
    void get_veriyed();
    ~aplist();
    
private:
    Ui::aplist *ui;

private slots:
    void require_ap_list();
    void show_data();
    void show_data_static();
   // void get_ap_num();
   // void get_head();
    void make_model();
    void get_ap_list();

};
#endif // APLIST_H
