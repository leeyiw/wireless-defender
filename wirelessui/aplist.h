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
    void make_model();
    void get_ap_list();

    void on_ap_table_doubleClicked(const QModelIndex &index);
};
#endif // APLIST_H
