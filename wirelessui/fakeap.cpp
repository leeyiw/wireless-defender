#include "fakeap.h"
#include "ui_fakeap.h"
#include <QStandardItem>

extern QString host_address;
extern QTcpSocket tcpSocket;
typedef struct fake_list {
    quint8 ssid_len;
    QString ssid;
    quint8 encrypt_type;
    unsigned char bssid[6];

} fake_list_t;
fake_list_t fake_li[200];
quint8  n_fake=0;
QStandardItemModel *fake_model = new QStandardItemModel();
fakeap::fakeap(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::fakeap)
{
    ui->setupUi(this);
    connect(ui->fakelistButton, SIGNAL(clicked()),SLOT(require_fake_list()));
    make_model();
}
void fakeap::make_model()
{
    fake_model->setHorizontalHeaderItem(0, new QStandardItem(QObject::tr("ssid")));
    fake_model->setHorizontalHeaderItem(1, new QStandardItem(QObject::tr("bssid")));
    fake_model->setHorizontalHeaderItem(2, new QStandardItem(QObject::tr("加密方式")));
    fake_model->setHorizontalHeaderItem(3, new QStandardItem(QObject::tr("查看详情")));
    //利用setModel()方法将数据模型与QTableView绑定
    //ui->student_tableview
    ui->fake_table->setModel(fake_model);
    //设置表格的各列的宽度值
      ui->fake_table->setColumnWidth(0,200);
      ui->fake_table->setColumnWidth(1,150);
      ui->fake_table->setColumnWidth(2,150);
      ui->fake_table->setColumnWidth(3,100);
    //隐藏行头
    ui->fake_table->verticalHeader()->hide();
    //设置选中时为整行选中
    ui->fake_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    //设置表格的单元为只读属性，即不能编辑
    ui->fake_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    //require_ap_list();

}
void  fakeap::require_fake_list()
{
    QByteArray block;
    quint8 type = 0x01;
    quint8 request_type = 0x02;
    QDataStream out(&block, QIODevice::WriteOnly);
    out.setByteOrder(QDataStream::LittleEndian);
    out <<type<<request_type;
    tcpSocket.write(block);
    connect(&tcpSocket,SIGNAL(readyRead()),this,SLOT(get_fake_list()));
}

void fakeap::get_fake_list()
{
    QDataStream in(&tcpSocket);
    quint8 type;
    quint8 request_type;
    char ssid_buf[512] = {0};
    in.setByteOrder(QDataStream::LittleEndian);
    in>>type>>request_type>>n_fake;
    ui->fake_num->display(n_fake);
    if(type!=0x02)
    {
        tcpSocket.close();
        //error();
    }
    else if(type==0x02)
    {
        in.setByteOrder(QDataStream::LittleEndian);
        if(request_type==0x02)
        {
            for(int i=0;i<n_fake;i++)
            {
                in>>fake_li[i].ssid_len;
                in.readRawData(ssid_buf, fake_li[i].ssid_len);
                ssid_buf[fake_li[i].ssid_len] = '\0';
                fake_li[i].ssid = QString(ssid_buf);
                in>>fake_li[i].encrypt_type;
                in.readRawData((char *)fake_li[i].bssid, sizeof(fake_li[i].bssid));
            }
            show_data();
        }
    }
    connect(&tcpSocket,SIGNAL(readyRead()),this,SLOT(show_data()));
}
void fakeap::show_data()
 {
     for(int i=0;i<n_fake;i++)
     {
         char bssid_buf[256];
         fake_model->setItem(i, 0, new QStandardItem(fake_li[i].ssid));
         sprintf(bssid_buf, "%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x", fake_li[i].bssid[0],
                 fake_li[i].bssid[1], fake_li[i].bssid[2],
                 fake_li[i].bssid[3], fake_li[i].bssid[4],
                 fake_li[i].bssid[5]);
         fake_model->setItem(i, 1, new QStandardItem(bssid_buf));
         switch(fake_li[i].encrypt_type) {
         case 0x00:
             fake_model->setItem(i, 2, new QStandardItem("未加密"));
             break;
         case 0x01:
             fake_model->setItem(i, 2, new QStandardItem("WEP"));
             break;
         case 0x02:
             fake_model->setItem(i, 2, new QStandardItem("WPA"));
             break;
         default:
             fake_model->setItem(i, 2, new QStandardItem("未知"));
             break;
         }

         fake_model->item(i, 0)->setFont( QFont( "Arial", 10, QFont::Black ) );
         fake_model->item(i, 1)->setFont( QFont( "Arial", 10, QFont::Black ) );
         fake_model->item(i, 2)->setFont( QFont( "微软雅黑", 10, QFont::Black ) );
     }
}
fakeap::~fakeap()
{
    delete ui;
}
