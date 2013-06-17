#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "connect.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    connect(ui->minButton,SIGNAL(released()),this,SLOT(showMinimized()));

    connect(ui->closeButton,SIGNAL(clicked()),qApp,SLOT(quit()));


    initData();

}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::paintEvent(QPaintEvent *)
{
    QPainter painter(this);
    painter.drawPixmap(m_pixmapBg.rect(), m_pixmapBg);
}

void MainWindow::mouseMoveEvent(QMouseEvent *e)
{
    this->move(e->globalPos() - m_pointStart);
}

void MainWindow::mousePressEvent(QMouseEvent *e)
{
    m_pointPress = e->globalPos();
    m_pointStart = m_pointPress - this->pos();

}

void MainWindow::setNomalStyle()
{
    QFile styleSheet(":/res/qss/wireless.qss");
    if (!styleSheet.open(QIODevice::ReadOnly))
    {
        qWarning("Can't open the style sheet file.");
        return;
    }
    qApp->setStyleSheet(styleSheet.readAll());
}


void MainWindow::on_setButton_clicked()
{
    m_menu->exec(this->mapToGlobal(QPoint(700, 20)));
}

void MainWindow::initData()
{
    setWindowFlags(Qt::FramelessWindowHint);
    setAttribute(Qt::WA_TranslucentBackground);
    ui->stackedWidget->addWidget(&list);

    anticrack=new QLabel(this);
    anticrack->setText("this is anticrack");
    fakeap=new QLabel(this);
    fakeap->setText("this is fakeap");
    ui->stackedWidget->addWidget(&arp_tab);
    ui->stackedWidget->addWidget(anticrack);
    ui->stackedWidget->addWidget(fakeap);

    ui->stackedWidget->addWidget(&network);



    m_menu = new QMenu();
    m_Aactionsetting = new QAction(tr("设置"), this);
    connect(m_Aactionsetting,SIGNAL(triggered()),this,SLOT(connecting()));
    m_menu->addAction(m_Aactionsetting);
    m_menu->addSeparator();
    m_menu->addAction(tr("关于我们"));


    ///背景加载;
    m_pixmapBg.load(":/res/image/frame.png");

    m_vecBtn.push_back(ui->networkButton);
    m_vecBtn.push_back(ui->arpButton);
    m_vecBtn.push_back(ui->anticrackButton);
    m_vecBtn.push_back(ui->fakeapButton);
    m_vecBtn.push_back(ui->devicesButton);
    m_actbtn.push_back(m_Aactionsetting);
    //setwidget();



    for (int i = 0; i != m_vecBtn.size(); ++i)
    {

        ///功能选中判断;
        m_vecBtn[i]->setCheckable(true);
        m_vecBtn[i]->setAutoExclusive(true);
    }

    ///状态栏
    ui->label_CheckLogin->setText(
                tr("<font color=blue>未登录</font></a>"));
    setNomalStyle();
}

void MainWindow::on_networkButton_clicked()
{

    setCurrentWidget();
}
void MainWindow::on_arpButton_clicked()
{
    setCurrentWidget();
}
void MainWindow::on_anticrackButton_clicked()
{
    setCurrentWidget();
}
void MainWindow::on_fakeapButton_clicked()
{
    setCurrentWidget();
}
void MainWindow::on_devicesButton_clicked()
{
    setCurrentWidget();
}
void MainWindow::connecting()
{
    setCurrentWidgetact();
}
void MainWindow::setCurrentWidget()
{
    for (int i = 0; i != m_vecBtn.size(); ++i)
    {
        if ( m_vecBtn[i]->isChecked() )
        {


            ui->stackedWidget->setCurrentIndex(i);
        }
    }
}


void MainWindow::setCurrentWidgetact()
{
    for (int i = 0; i != m_actbtn.size(); ++i)
    {
        \
        ui->stackedWidget->setCurrentIndex(i+m_vecBtn.size());

    }
}


