#include "connect.h"
#include "ui_Connect.h"
#include <QMessageBox>
Connect::Connect(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::Widget)
{
    ui->setupUi(this);
    connect(&tcpSocket, SIGNAL(connected()), this, SLOT(sendMessage()));
    connect(ui->ConnectButton, SIGNAL(clicked()), this, SLOT(connectToServer()));
}
void Connect:: connectToServer()
{
    tcpSocket.abort(); //取消已有的连接
    tcpSocket.connectToHost(ui->hostLineEdit->text(),9387);
    if (!tcpSocket.waitForConnected(Timeout)) {			//连接超时处理
        QMessageBox::about(NULL, "错误", " <font color='red'>连接超时</font>");
        return;
    }
    connected = tcpSocket.waitForConnected();
    //连接到主机
}
void Connect::sendMessage()
{
    QByteArray block;
    quint8 type = 0x01;
    quint32 version = 0x00010000;
    quint32 security_type = 0x00000000;
    QDataStream out(&block, QIODevice::WriteOnly);
    out.setByteOrder(QDataStream::LittleEndian);
    out <<type<<version<<security_type;
    tcpSocket.write(block);
    connect(&tcpSocket,SIGNAL(readyRead()),this,SLOT(getStatus()));
}
void Connect::getStatus()
{
    QDataStream in(&tcpSocket);
    in.setByteOrder(QDataStream::LittleEndian);
    if(tcpSocket.bytesAvailable()==5)
    {  in>>status>>security_type;
    }
    if(status==0x03)
    {
        tcpSocket.close();
        error();
    }
    if(status==0x02)
    {
        if(security_type==0x00000000)
        {
            ui->LoginButton->setEnabled(true);
            connect(ui->LoginButton, SIGNAL(clicked()), this, SLOT(verifyed()));
        }
        if(security_type==0x01000000)
        {
        }
    }
    disconnect(&tcpSocket,SIGNAL(readyRead()),this,SLOT(getStatus()));
}
void Connect::error()
{
    if(security_type==0x01000000)
    {
        QMessageBox::about(NULL, "错误", " <font color='red'>协议错误，请联系开发者</font>");
    }
    else if(security_type==0x02000000)
    {
        QMessageBox::about(NULL, "错误", " <font color='red'>请使用SSL安全连接</font>");
    }
}
void Connect::verifyed()
{
    QByteArray block;
    quint8 type=0x01;
    QString username = ui->usernameEdit->text();
    QDataStream out(&block, QIODevice::WriteOnly);
    //MD5加密
    QString password=ui->passwordEdit->text(),passwordmd5;
    QByteArray ba=password.toLatin1(),bb;
    QCryptographicHash md(QCryptographicHash::Md5);
    md.addData(ba);
    bb = md.result();
    passwordmd5=(bb.toHex());
    //写数据
    out<<type<<(quint8)(username.length()+1)/*<<quint8(0x00)*/;
    out.writeRawData(username.toLatin1(),username.length()+1);
    out.writeRawData(passwordmd5.toLatin1(),passwordmd5.length());
    tcpSocket.write (block);
    connect(&tcpSocket,SIGNAL(readyRead()),this,SLOT(verified_status()));
}
int Connect::verified_status()
{
    QDataStream in(&tcpSocket);
    in.setByteOrder(QDataStream::LittleEndian);
    if(tcpSocket.bytesAvailable()==5)
    {  in>>verified_type>>verified_failure_code;
    }
    if(verified_type==0x02)
    {
        return 0x01;
    }
    if(verified_type==0x03)
    {
        tcpSocket.close();
        verified_error();
    }
    disconnect(&tcpSocket,SIGNAL(readyRead()),this,SLOT(verified_status()));
}
void Connect::verified_error()
{
    if(verified_failure_code==0x00000001)
    {
        QMessageBox::about(NULL, "错误", " <font color='red'>协议错误</font>");
    }
    if(verified_failure_code==0x00000002)
    {
        QMessageBox::about(NULL, "错误", " <font color='red'>账号或密码错误，请更正后重试</font>");
    }
}
Connect::~Connect()
{
    delete ui;
}