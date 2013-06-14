#ifndef CONNECT_H
#define CONNECT_H

#include <QWidget>
#include <QtNetwork>



namespace Ui {
class Widget;
}

class Connect : public QWidget
{
    Q_OBJECT

public:
    explicit Connect(QWidget *parent = 0); 
    ~Connect();

private:
    Ui::Widget *ui;
    QTcpSocket tcpSocket;
    quint32 security_type;
    quint8 status;
    quint8 verified_type;
    quint32 verified_failure_code;
    const int Timeout = 5 * 1000;
    bool connected=false;

private slots:
    void connectToServer();
    void sendMessage();
    void getStatus();  //接收数据
    void error();
    void verifyed();
    int verified_status();
    void verified_error();
};


#endif // CONNECT_H
