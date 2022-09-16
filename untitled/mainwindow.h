#ifndef MAINWINDOW_H
#define MAINWINDOW_H
#include <QMainWindow>
#include <QMovie>
#include <QTimer>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QMessageBox>
#include <QSqlRelationalTableModel>
#include <QSqlRelationalDelegate>
#include <QDateTime>
#include "workerthread.h"
QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE
typedef struct {
    int clear;
    unsigned src_ip[4];
    unsigned dst_ip[4];
    unsigned src_mask;
    unsigned dst_mask;
    int src_port;
    int dst_port;
    int protocol;
    int action;
    int log;
    int starttime;
    int endtime;
} Rule;
class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
private:
    Ui::MainWindow *ui;
    QMovie mv;
    QMovie dice[7];
    QTimer *m_pTimerDeny,*m_pTimerAllow;
    int     stragy = 1;   //默认策略是允许通过
    void InitDB();
    int ID=1;
    Rule rule[500];
    QDateTime current_date_time =QDateTime::currentDateTime();
    WorkerThread m_workerThread;
public :
   void slotForSubmmit(bool);
   void slotFordstIP1(int);
   void slotFordstIP2(int);
   void slotFordstIP3(int);
   void slotFordstIP4(int);
   void slotForsrcMask(int);
   void slotFordstMaskAdd1(bool);
   void slotFordstMaskAdd5(bool);
   void slotFordstMaskAdd10(bool);
   void slotFordstMaskSub1(bool);
   void slotFordstMaskSub5(bool);
   void slotFordstMaskSub10(bool);
   void slotRollDice(bool);
   void slotLineEditAllow();
   void slotLineEditDeny();
   void slotOntimer();
   void slotForSubmitter(bool);
protected:
   void readdiary();
};
#endif // MAINWINDOW_H
