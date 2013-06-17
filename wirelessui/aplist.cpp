#include "aplist.h"
#include "ui_aplist.h"
#include <QStandardItem>
QStandardItemModel *ap_model = new QStandardItemModel();
aplist::aplist(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::aplist)
{
    ui->setupUi(this);
    connect(ui->aplistButton, SIGNAL(clicked()),SLOT(show_data()));
    make_model();
}
void aplist::make_model()
{
    ap_model->setHorizontalHeaderItem(0, new QStandardItem(QObject::tr("ssid")));
    //利用setModel()方法将数据模型与QTableView绑定
    //ui->student_tableview
    ui->ap_table->setModel(ap_model);
    //设置表格的各列的宽度值
    ui->ap_table->setColumnWidth(0,470);
    //隐藏行头
    ui->ap_table->verticalHeader()->hide();
    //设置选中时为整行选中
    ui->ap_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    //设置表格的单元为只读属性，即不能编辑
    ui->ap_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
}
void aplist::show_data()
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