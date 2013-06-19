#ifndef ANTI_CRACK_H
#define ANTI_CRACK_H

#include <QWidget>

namespace Ui {
class anti_crack;
}

class anti_crack : public QWidget
{
    Q_OBJECT
    
public:
    explicit anti_crack(QWidget *parent = 0);
    ~anti_crack();
    
private:
    Ui::anti_crack *ui;
};

#endif // ANTI_CRACK_H
