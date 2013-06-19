#ifndef FAKEAP_H
#define FAKEAP_H

#include <QWidget>
#include <QtNetwork>

namespace Ui {
class fakeap;
}

class fakeap : public QWidget
{
    Q_OBJECT
    
public:
    explicit fakeap(QWidget *parent = 0);
    ~fakeap();
    
private:
    Ui::fakeap *ui;
private slots:
    void require_fake_list();
    void show_data();
    //void show_data_static();
    void make_model();
    void get_fake_list();
};

#endif // FAKEAP_H
