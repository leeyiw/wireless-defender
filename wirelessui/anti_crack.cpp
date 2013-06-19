#include "anti_crack.h"
#include "ui_anti_crack.h"

anti_crack::anti_crack(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::anti_crack)
{
    ui->setupUi(this);
}

anti_crack::~anti_crack()
{
    delete ui;
}
