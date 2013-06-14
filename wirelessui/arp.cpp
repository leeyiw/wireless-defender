#include "arp.h"
#include "ui_arp.h"
#include <QStandardItem>
QStandardItemModel *arp_model = new QStandardItemModel();
arp::arp(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::arp)
{
    ui->setupUi(this);
    make_model();
}
void arp::make_model()
{
    arp_model->setHorizontalHeaderItem(0, new QStandardItem(QObject::tr("Internet地址")));
    arp_model->setHorizontalHeaderItem(1, new QStandardItem(QObject::tr("物理地址")));
    arp_model->setHorizontalHeaderItem(2, new QStandardItem(QObject::tr("类型")));
    //利用setModel()方法将数据模型与QTableView绑定
    ui->arp_table->setModel(arp_model);
    //设置表格的各列的宽度值
    ui->arp_table->setColumnWidth(0,180);
    ui->arp_table->setColumnWidth(1,250);
    ui->arp_table->setColumnWidth(2,65);
    //隐藏行头
    ui->arp_table->verticalHeader()->hide();
    //设置选中时为整行选中
    ui->arp_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    //只读
    ui->arp_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    show_table();
}
void arp::show_table()
{
    arp_model->setItem(0, 0, new QStandardItem("192.168.58.2"));
    arp_model->setItem(1, 0, new QStandardItem("192.168.58.254"));
    arp_model->setItem(2, 0, new QStandardItem("192.168.58.255"));
    arp_model->setItem(3, 0, new QStandardItem("224.0.0.2"));
    arp_model->setItem(4, 0, new QStandardItem("224.0.0.252"));
    arp_model->setItem(5, 0, new QStandardItem("239.255.255.0"));
    arp_model->setItem(0, 1, new QStandardItem("40:BB:1E:98:85:86"));
    arp_model->setItem(1, 1, new QStandardItem("46:88:15:AA:31:60"));
    arp_model->setItem(2, 1, new QStandardItem("76:AA:74:DC:37:C0"));
    arp_model->setItem(3, 1, new QStandardItem("BE:AA:24:64:74:DC"));
    arp_model->setItem(4, 1, new QStandardItem("29:FF:B7:DB:5B:E1"));
    arp_model->setItem(5, 1, new QStandardItem("BE:4D:BC:1C:B3:0E"));
    for(int i=0;i<2;i++)
    {
        arp_model->setItem(i, 2, new QStandardItem("静态"));
    }
    for(int i=2;i<6;i++)
    {
        arp_model->setItem(i, 2, new QStandardItem("动态"));
    }
    //居中
    /*arp_model->item(0,0)->setTextAlignment(Qt::AlignCenter);
    arp_model->item(1,0)->setTextAlignment(Qt::AlignCenter);
    arp_model->item(2,0)->setTextAlignment(Qt::AlignCenter);
    arp_model->item(3,0)->setTextAlignment(Qt::AlignCenter);
    arp_model->item(4,0)->setTextAlignment(Qt::AlignCenter);
    arp_model->item(5,0)->setTextAlignment(Qt::AlignCenter);*/
    //加粗
    for(int i=0;i<6;i++)
        for(int j=0;j<3;j++)
        {
            arp_model->item(i, j)->setFont( QFont( "Arial", 10, QFont::Normal ) );
        }
}
arp::~arp()
{
    delete ui;
}