#include "mainwindow.h"
#include <QDebug>
#include <QApplication>
#include <QThread>
#include "workerthread.h"

int main(int argc, char *argv[])
{
    //*.cpp
    //使用方法




    QApplication a(argc, argv);

    MainWindow w;
    w.show();
    return a.exec();
}
