// work定义了线程要执行的工作
#ifndef WORKER_H
#define WORKER_H
#include <QObject>
#include<QDebug>
#include<QThread>

class Worker:public QObject
{
    Q_OBJECT
public:
    Worker(QObject* parent = nullptr){}
public slots:
     // doWork定义了线程要执行的操作
    void doWork(int parameter)
    {
        qDebug()<<"receive the execute signal---------------------------------";
        qDebug()<<"     current thread ID:"<<QThread::currentThreadId();
       // 循环一百万次
       for(int i = 0;i!=1000000;++i)
       {
        ++parameter;
       }
       // 发送结束信号
       qDebug()<<"      finish the work and sent the resultReady signal\n";
       emit resultReady(parameter);
    }

// 线程完成工作时发送的信号
signals:
    void resultReady(const int result);
};

#endif // WORKER_H

