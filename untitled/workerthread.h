//WorkerThread.h
#ifndef _WORKERTHREAD_
#define _WORKERTHREAD_
#include <QThread>
#include <QTextBrowser>

class WorkerThread : public QThread
{
    Q_OBJECT

public:
    QTextBrowser *diary;
    int fd;
    explicit WorkerThread ();
    ~WorkerThread ();
    bool stop();

signals:
    void writediary(const QString &text);

private:
    void	run();    //虚函数

};

#endif
