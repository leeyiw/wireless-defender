#-------------------------------------------------
#
# Project created by QtCreator 2013-04-14T20:20:31
#
#-------------------------------------------------

QT       += core gui
QT      += network

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = wirelessui
TEMPLATE = app


SOURCES += main.cpp\
        mainwindow.cpp \
    connect.cpp \
    aplist.cpp \
    arp.cpp

HEADERS  += mainwindow.h \
    connect.h \
    aplist.h \
    arp.h \
    network.h

FORMS    += mainwindow.ui \
    Connect.ui \
    aplist.ui \
    arp.ui

RESOURCES += \
    res.qrc
RC_FILE = icon.rc

