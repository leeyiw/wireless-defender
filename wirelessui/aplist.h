#ifndef APLIST_H
#define APLIST_H
#include <QWidget>
#include <QStandardItem>
namespace Ui {
class aplist;
}
class aplist : public QWidget
{
    Q_OBJECT
    
public:
    explicit aplist(QWidget *parent = 0);
    ~aplist();
    
private:
    Ui::aplist *ui;
    void make_model();
private slots:
    void show_data();
};
#endif // APLIST_H