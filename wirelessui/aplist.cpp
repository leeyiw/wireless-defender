#include "aplist.h"
#include "ui_aplist.h"
#include <QStandardItem>
#include <QMessageBox>
extern QString host_address;
extern QTcpSocket tcpSocket;
extern bool logged;
typedef struct AP_list {
    quint8 ssid_len;
    QString ssid;
    quint8 encrypt_type;
    unsigned char bssid[6];

} AP_list_t;
AP_list_t ap_li[200];
quint8  n_ap=0;
QStandardItemModel *ap_model = new QStandardItemModel();
aplist::aplist(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::aplist)
{
    ui->setupUi(this);
  //  ui->aplistButton->setEnabled(false);
    connect(ui->aplistButton, SIGNAL(clicked()),SLOT(require_ap_list()));
    make_model();
    get_veriyed();
}
void aplist::get_veriyed()
{
    if(logged==true)
    {
        ui->aplistButton->setEnabled(true);
      //  connect(ui->aplistButton, SIGNAL(clicked()),SLOT(require_ap_list()));
    }
}


void aplist::make_model()
{
    ap_model->setHorizontalHeaderItem(0, new QStandardItem(QObject::tr("SSID")));
    ap_model->setHorizontalHeaderItem(1, new QStandardItem(QObject::tr("BSSID")));
    ap_model->setHorizontalHeaderItem(2, new QStandardItem(QObject::tr("加密方式")));
    ap_model->setHorizontalHeaderItem(3, new QStandardItem(QObject::tr("流量统计")));
    //利用setModel()方法将数据模型与QTableView绑定
    //ui->student_tableview
    ui->ap_table->setModel(ap_model);
    //设置表格的各列的宽度值
    ui->ap_table->setColumnWidth(0,200);
    ui->ap_table->setColumnWidth(1,150);
    ui->ap_table->setColumnWidth(2,150);
    ui->ap_table->setColumnWidth(3,100);
    //隐藏行头
    ui->ap_table->verticalHeader()->hide();
    //设置选中时为整行选中
    ui->ap_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    //设置表格的单元为只读属性，即不能编辑
    ui->ap_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    //require_ap_list();

}
void  aplist::require_ap_list()
{

  // tcpSocket.connectToHost(host_address,9387);
    //tcpSocket.connectToHost("127.0.0.1",9387);
    QByteArray block;
    quint8 type = 0x01;
    quint8 request_type = 0x01;
    QDataStream out(&block, QIODevice::WriteOnly);
    out.setByteOrder(QDataStream::LittleEndian);
    out <<type<<request_type;
    tcpSocket.write(block);
    connect(&tcpSocket,SIGNAL(readyRead()),this,SLOT(get_ap_list()));
}

/*void aplist::get_ap_list()
{
    QDataStream in(&tcpSocket);
    quint8 type;
    quint8 request_type;
    in.setByteOrder(QDataStream::LittleEndian);
    in>>type>>request_type>>n_ap;;

    if(type!=0x02)
    {
        tcpSocket.close();
        //error();
    }
    if(type==0x02)
    {
        //QMessageBox::about(NULL, "1", " re_type_0x02");
        if(request_type==0x01)
        {
            //QMessageBox::about(NULL, "2", " re_type_0x01");
            connect(&tcpSocket,SIGNAL(readyRead()),this,SLOT(get_ap_num()));
        }
        else
        {
            tcpSocket.close();
            //           error();
        }
    }
    disconnect(&tcpSocket,SIGNAL(readyRead()),this,SLOT(get_head()));
}*/

/*void aplist::get_ap_num()
{

    QDataStream in(&tcpSocket);
    in.setByteOrder(QDataStream::LittleEndian);
    if(tcpSocket.bytesAvailable()==1)
    {
        in>>n_ap;
    }
    ui->ap_num->display(n_ap);
    disconnect(&tcpSocket,SIGNAL(readyRead()),this,SLOT(get_ap_num()));
    connect(&tcpSocket,SIGNAL(readyRead()),this,SLOT(get_ap_list()));

}*/

void aplist::get_ap_list()
{
    QDataStream in(&tcpSocket);
    quint8 type;
    quint8 request_type;
    char ssid_buf[512] = {0};
    in.setByteOrder(QDataStream::LittleEndian);
    in>>type>>request_type>>n_ap;
    if(type!=0x02)
    {
        tcpSocket.close();
        //error();
    }
    else if(type==0x02)
    {
        in.setByteOrder(QDataStream::LittleEndian);
        if(request_type==0x01)
        {
            for(int i=0;i<n_ap;i++)
            {
                in>>ap_li[i].ssid_len;
                in.readRawData(ssid_buf, ap_li[i].ssid_len);
                ssid_buf[ap_li[i].ssid_len] = '\0';
                ap_li[i].ssid = QString(ssid_buf);
                in>>ap_li[i].encrypt_type;
                in.readRawData((char *)ap_li[i].bssid, sizeof(ap_li[i].bssid));
            }
            show_data();
        }
    }
    connect(&tcpSocket,SIGNAL(readyRead()),this,SLOT(show_data()));
}

   void aplist::show_data()
    {
        for(int i=0;i<n_ap;i++)
        {
            char bssid_buf[256];
            /* SSID */
            ap_model->setItem(i, 0, new QStandardItem(ap_li[i].ssid));
            ap_model->item(i,0)->setTextAlignment(Qt::AlignCenter);
            ap_model->item(i, 0)->setFont( QFont( "Times", 10, QFont::Black ) );

            /* BSSID */
            sprintf(bssid_buf, "%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x", ap_li[i].bssid[0],
                    ap_li[i].bssid[1], ap_li[i].bssid[2],
                    ap_li[i].bssid[3], ap_li[i].bssid[4],
                    ap_li[i].bssid[5]);
            ap_model->setItem(i, 1, new QStandardItem(bssid_buf));
            ap_model->item(i,1)->setTextAlignment(Qt::AlignCenter);

            /* 加密方式 */
            switch(ap_li[i].encrypt_type) {
            case 0x00:
                ap_model->setItem(i, 2, new QStandardItem("未加密"));
                break;
            case 0x01:
                ap_model->setItem(i, 2, new QStandardItem("WEP"));
                break;
            case 0x02:
                ap_model->setItem(i, 2, new QStandardItem("WPA"));
                break;
            default:
                ap_model->setItem(i, 2, new QStandardItem("未知"));
                break;
            }
            ap_model->item(i,2)->setTextAlignment(Qt::AlignCenter);

            /* 流量统计 */
            ap_model->setItem(i, 3, new QStandardItem("流量统计"));
            ap_model->item(i,3)->setTextAlignment(Qt::AlignCenter);
        }


    }
    void aplist::show_data_static()
    {
        ap_model->setItem(0, 0, new QStandardItem("CMCC"));
        ap_model->setItem(1, 0, new QStandardItem("CMCC-EDU"));
        ap_model->setItem(2, 0, new QStandardItem("ChinaMobile"));
        ap_model->setItem(3, 0, new QStandardItem("ChinaUnicome"));
        ap_model->item(0,0)->setTextAlignment(Qt::AlignCenter);
        ap_model->item(1,0)->setTextAlignment(Qt::AlignCenter);
        ap_model->item(2,0)->setTextAlignment(Qt::AlignCenter);
        ap_model->item(3,0)->setTextAlignment(Qt::AlignCenter);
        //加粗
        ap_model->item(0, 0)->setFont( QFont( "Times", 10, QFont::Black ) );
        ap_model->item(1, 0)->setFont( QFont( "Times", 10, QFont::Black ) );
        ap_model->item(2, 0)->setFont( QFont( "Times", 10, QFont::Black ) );
        ap_model->item(3, 0)->setFont( QFont( "Times", 10, QFont::Black ) );
    }
    aplist::~aplist()
    {
        delete ui;
    }

void aplist::on_ap_table_doubleClicked(const QModelIndex &index)
{
    class MyMessageBox : public QMessageBox {
    protected:
    void showEvent(QShowEvent* event) {
    QMessageBox::showEvent(event);
    setFixedSize(640, 480);
    }
    };
    QMessageBox my;
    my.setWindowTitle(tr("流量"));
    my.setInformativeText("HTTP : 10KB/45KB\nSMTP : 12KB/81KB\nSSH : 20/31KB\nFTP : 300/298KB");
    my.exec();

}
