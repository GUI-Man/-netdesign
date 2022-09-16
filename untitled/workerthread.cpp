#include "workerthread.h"
#include <QDebug>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include "ui_mainwindow.h"
#include <unistd.h>
WorkerThread::WorkerThread()
    : QThread()
{
    fd=open("/dev/tests",O_RDWR);
    qDebug()<<fd;
}

WorkerThread::~WorkerThread()
{
}
void WorkerThread::run()
{
    char buf[510]={0};
    while(1){
        read(fd,buf,500);
        qDebug()<<buf<<endl;
        diary->append(buf);
        //emit writediary(buf);
        memset(buf,0,sizeof(char)*510);
        usleep(100);
    }

}
bool WorkerThread::stop(){
    close(this->fd);
    this->quit();
    return true;
}
