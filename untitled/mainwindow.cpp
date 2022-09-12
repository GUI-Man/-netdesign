#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "QTime"
#include "QMovie"
#include "QDebug"
#include "QTimer"
#include <stdio.h>
#include "QString"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    //ComboBox  Setting
    ui->setupUi(this);
    this->setFixedSize(800,600);
    InitDB();
    QSqlRelationalTableModel *model = new QSqlRelationalTableModel(this);
    //model->setEditStrategy(QSqlTableModel::OnFieldChange); //属性变化时写入数据库
    model->setTable("RULE");
//    model->setHeaderData(0, Qt::Horizontal, QObject::tr("src_ip1"));
//    model->setHeaderData(1, Qt::Horizontal, QObject::tr("src_ip2"));
//    model->setHeaderData(2, Qt::Horizontal, QObject::tr("src_ip3"));
    model->select();
    ui->tableView->setModel(model);
    ui->tableView->setItemDelegate(new QSqlRelationalDelegate(ui->tableView));
    int index=0;
    char ip[100];
    for (index=0;index<256;index++) {
        sprintf(ip,"%d",index);
        if(index<=60){
            if(index<=24){
            ui->endtime_hour->addItem(ip);
            ui->beginning_time_hour->addItem(ip);
            }
            ui->beginning_time_minute->addItem(ip);
            ui->endtime_minute->addItem(ip);
        }

        ui->IPBOX1->addItem(ip);
        ui->IPBOX1_2->addItem(ip);
        ui->IPBOX1_3->addItem(ip);
        ui->IPBOX1_4->addItem(ip);
    }
    ui->Protocol->addItem("TCP");
    ui->Protocol->addItem("ANY");
    ui->Protocol->addItem("UDP");
    ui->Protocol->addItem("ICMP");
    //Scroll bar Setting
    ui->HS_dstIP1->setMaximum(255);
    ui->HS_dstIP2->setMaximum(255);
    ui->HS_dstIP3->setMaximum(255);
    ui->HS_dstIP4->setMaximum(255);
    ui->hSBsrcmask->setMaximum(32);
    this->m_pTimerDeny=new QTimer(this);
    this->m_pTimerAllow=new QTimer(this);
    connect(ui->HS_dstIP1,&QSlider::valueChanged,this,&MainWindow::slotFordstIP1);
    connect(ui->HS_dstIP2,&QSlider::valueChanged,this,&MainWindow::slotFordstIP2);
    connect(ui->HS_dstIP3,&QSlider::valueChanged,this,&MainWindow::slotFordstIP3);
    connect(ui->HS_dstIP4,&QSlider::valueChanged,this,&MainWindow::slotFordstIP4);
    connect(ui->hSBsrcmask,&QScrollBar::valueChanged,this,&MainWindow::slotForsrcMask);
    connect(ui->pushButtondstmaskSub1,&QPushButton::clicked,this,&MainWindow::slotFordstMaskSub1);
    connect(ui->pushButtondstmaskSub5,&QPushButton::clicked,this,&MainWindow::slotFordstMaskSub5);
    connect(ui->pushButtondstmaskSub10,&QPushButton::clicked,this,&MainWindow::slotFordstMaskSub10);
    connect(ui->pushButtondstmaskAdd1,&QPushButton::clicked,this,&MainWindow::slotFordstMaskAdd1);
    connect(ui->pushButtondstmaskAdd5,&QPushButton::clicked,this,&MainWindow::slotFordstMaskAdd5);
    connect(ui->pushButtondstmaskAdd10,&QPushButton::clicked,this,&MainWindow::slotFordstMaskAdd10);
    connect(ui->pushButton_dice,&QPushButton::clicked,this,&MainWindow::slotRollDice);
    connect(this->m_pTimerDeny,&QTimer::timeout,this,&MainWindow::slotLineEditDeny);
    connect(this->m_pTimerAllow,&QTimer::timeout,this,&MainWindow::slotLineEditAllow);
    connect(ui->pushButtonSubmit,&QPushButton::clicked,this,&MainWindow::slotForSubmmit);
    connect(ui->SubmitAll,&QPushButton::clicked,this,&MainWindow::slotForSubmitter);
    mv.setFileName(":/new/prefix1/used.gif");
    ui->jiantou->setMovie(&mv);
    mv.start();
    dice[1].setFileName(":/new/prefix1/dice.gif");
    dice[2].setFileName(":/new/prefix1/dice2.gif");
    dice[3].setFileName(":/new/prefix1/dice3.gif");
    dice[4].setFileName(":/new/prefix1/dice4.gif");
    dice[5].setFileName(":/new/prefix1/dice5.gif");
    dice[6].setFileName(":/new/prefix1/dice6.gif");
}
void MainWindow::slotForSubmitter(bool){
    QSqlQuery query;
    int index=0;
    query.exec("select * from Rule");
    while(query.next()){
        if(index==0){
            this->rule[index].clear=1;
        }else{
            this->rule[index].clear=0;
        }
        this->rule[index].log=1;
        this->rule[index].src_ip[0]=query.value(1).toInt();
        this->rule[index].src_ip[1]=query.value(2).toInt();
        this->rule[index].src_ip[2]=query.value(3).toInt();
        this->rule[index].src_ip[3]=query.value(4).toInt();
        this->rule[index].src_port=query.value(5).toInt();
        this->rule[index].dst_ip[0]=query.value(6).toInt();
        this->rule[index].dst_ip[1]=query.value(7).toInt();
        this->rule[index].dst_ip[2]=query.value(8).toInt();
        this->rule[index].dst_ip[3]=query.value(9).toInt();
        this->rule[index].dst_port=query.value(10).toInt();
        this->rule[index].dst_mask=query.value(11).toInt();
        this->rule[index].src_mask=query.value(12).toInt();
        this->rule[index].protocol=query.value(13).toInt();
        this->rule[index].action=this->stragy;
        this->rule[index].starttime=query.value(14).toInt()*60+query.value(15).toInt();
        this->rule[index].endtime=query.value(16).toInt()*60+query.value(17).toInt();
        if(ui->Any_Src_ip->isChecked()==true){
            this->rule[index].src_ip[0]=256;
            this->rule[index].src_ip[1]=256;
            this->rule[index].src_ip[2]=256;
            this->rule[index].src_ip[3]=256;
        }
        if(ui->Any_Dst_ip->isChecked()==true){
            this->rule[index].dst_ip[0]=256;
            this->rule[index].dst_ip[1]=256;
            this->rule[index].dst_ip[2]=256;
            this->rule[index].dst_ip[3]=256;

        }
        index++;
        int fd=open("/dev/tests",O_RDWR);
            if(fd<=0)
            {
                qDebug()<<"open"<<endl;
            }
        qDebug()<< "start write.....\n"<<endl;
        ::write(fd,&(this->rule[index-1]),sizeof(this->rule[index]));
        qDebug()<<"Write Over"<<endl;
        ::close(fd);
        qDebug()<<this->rule[index-1].log<<" "<<this->rule[index-1].src_ip[0]<<this->rule[index-1].src_ip[1]<<this->rule[index-1].src_ip[2]<<this->rule[index-1].src_ip[3];
    }
}
void MainWindow::slotForSubmmit(bool){
    int src_ip[4],dst_ip[4],dstMask,srcMask,begin_time_hour,begin_time_minute,end_time_hour,end_time_minute,protocol=0,dst_port,src_port;
    char submitString[500];
    src_ip[0]=ui->IPBOX1->currentText().toInt();
    src_ip[1]=ui->IPBOX1_2->currentText().toInt();
    src_ip[2]=ui->IPBOX1_3->currentText().toInt();
    src_ip[3]=ui->IPBOX1_4->currentText().toInt();
    dst_ip[0]=ui->HS_dstIP1->value();
    dst_ip[1]=ui->HS_dstIP2->value();
    dst_ip[2]=ui->HS_dstIP3->value();
    dst_ip[3]=ui->HS_dstIP4->value();
    dst_port=ui->dstport1->value()*10000+ui->dstport2->value()*1000+ui->dstport3->value()*100+ui->dstport4->value()*10+ui->dstport5->value();
    src_port=ui->srcport1->value()*10000+ui->srcport2->value()*1000+ui->srcport3->value()*100+ui->srcport4->value()*10+ui->srcport5->value();
    QString sb;
    sb=ui->Protocol->currentText();
    if(QString::compare(sb,"ANY")==0){
        protocol=100;
    }
    else if(QString::compare(sb,"TCP")){
        protocol=6;
    }
    else if(QString::compare(sb,"UDP")){
        protocol=17;
    }
    else if(QString::compare(sb,"ICMP")){
        protocol=1;
    }
    dstMask=ui->lineEditdstmask->text().toUInt();
    srcMask=ui->lineEditsrcmask->text().toUInt();
    begin_time_hour=ui->beginning_time_hour->currentText().toInt();
    begin_time_minute=ui->beginning_time_minute->currentText().toInt();
    end_time_hour=ui->endtime_hour->currentText().toInt();
    end_time_minute=ui->endtime_minute->currentText().toInt();
    this->ID++;
    sprintf(submitString,"insert into Rule values (%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d)",
            this->ID,src_ip[0],src_ip[1],src_ip[2],src_ip[3],dst_ip[0],
            dst_ip[1],dst_ip[2],dst_ip[3],dstMask,srcMask,protocol,begin_time_hour,begin_time_minute,end_time_hour,end_time_minute,this->stragy);
    QSqlQuery query;
    query.prepare("insert into Rule values (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)");
    query.addBindValue(this->ID);
    query.addBindValue(src_ip[0]);
    query.addBindValue(src_ip[1]);
    query.addBindValue(src_ip[2]);
    query.addBindValue(src_ip[3]);
    query.addBindValue(src_port);
    query.addBindValue(dst_ip[0]);
    query.addBindValue(dst_ip[1]);
    query.addBindValue(dst_ip[2]);
    query.addBindValue(dst_ip[3]);
    query.addBindValue(dst_port);
    query.addBindValue(dstMask);
    query.addBindValue(srcMask);
    query.addBindValue(protocol);
    query.addBindValue(begin_time_hour);
    query.addBindValue(begin_time_minute);
    query.addBindValue(end_time_hour);
    query.addBindValue(end_time_minute);
    query.addBindValue(this->stragy);

    if(query.exec()==false){
        qDebug()<<"Failed"<<endl;
    }
    QSqlRelationalTableModel *model = new QSqlRelationalTableModel(this);
    model->setTable("RULE");
//    model->setHeaderData(0, Qt::Horizontal, QObject::tr("src_ip1"));
//    model->setHeaderData(1, Qt::Horizontal, QObject::tr("src_ip2"));
//    model->setHeaderData(2, Qt::Horizontal, QObject::tr("src_ip3"));
    model->select();
    ui->tableView->setModel(model);
    ui->tableView->setItemDelegate(new QSqlRelationalDelegate(ui->tableView));
    qDebug()<<submitString<<endl;
}
void MainWindow::slotFordstMaskAdd1(bool){
    int x;
    x=ui->lineEditdstmask->text().toInt();
    if(x+1>32){
        x=32;
    }
    else{
        x=x+1;
    }
    ui->lineEditdstmask->setText(QString::number(x));
}
void MainWindow::slotLineEditDeny(){
    int index=1;
    for(index=1;index<=6;index++){
        this->dice[index].stop();
    }
    this->stragy=0;
    this->m_pTimerDeny->stop();
    ui->lineEditStragy->setText("默认拒绝");
}
void MainWindow::slotLineEditAllow(){
    int index=1;
    for(index=1;index<=6;index++){
        this->dice[index].stop();
    }
    this->m_pTimerAllow->stop();
    this->stragy=1;
    ui->lineEditStragy->setText("默认允许");
}
void MainWindow::slotRollDice(bool){
    int x;
    qDebug()<<"1"<<dice[1].state()<<endl;
    qDebug()<<"2"<<dice[2].state()<<endl;
    qDebug()<<"3"<<dice[3].state()<<endl;
    qDebug()<<"4"<<dice[4].state()<<endl;
    qDebug()<<"5"<<dice[5].state()<<endl;
    qDebug()<<"6"<<dice[6].state()<<endl;
    qsrand(QTime(0,0,0).secsTo(QTime::currentTime()));
    x=qrand()%6+1;
    ui->dice->setMovie(&dice[x]);
    dice[x].start();
    if(x%2==1){
        this->m_pTimerDeny->start(1800);
    }
    else{
        this->m_pTimerAllow->start(1800);
    }
}
void MainWindow::slotFordstMaskAdd5(bool){
    int x;
    x=ui->lineEditdstmask->text().toInt();
    if(x+5>32){
        x=32;
    }
    else{
        x=x+5;
    }
    ui->lineEditdstmask->setText(QString::number(x));
}
void MainWindow::slotFordstMaskAdd10(bool){
    int x;
    x=ui->lineEditdstmask->text().toInt();
    if(x+10>32){
        x=32;
    }
    else{
        x=x+10;
    }
    ui->lineEditdstmask->setText(QString::number(x));
}
void MainWindow::slotFordstMaskSub1(bool){
    int x;

    x=ui->lineEditdstmask->text().toInt();
    if(x-1<0){
        x=0;
    }
    else{
        x=x-1;
    }
    ui->lineEditdstmask->setText(QString::number(x));
}
void MainWindow::slotFordstMaskSub5(bool){
    int x;

    x=ui->lineEditdstmask->text().toInt();
    if(x-5<0){
        x=0;
    }
    else{
        x=x-5;
    }
    ui->lineEditdstmask->setText(QString::number(x));
}
void MainWindow::slotFordstMaskSub10(bool){
    int x;

    x=ui->lineEditdstmask->text().toInt();
    if(x-10<0){
        x=0;
    }
    else{
        x=x-10;
    }
    ui->lineEditdstmask->setText(QString::number(x));
}

void MainWindow::slotFordstIP1(int ip){
    ui->lineEditdstip1->setText(QString::number(ip));
}
void MainWindow::slotFordstIP2(int ip){
    ui->lineEditdstip2->setText(QString::number(ip));
}
void MainWindow::slotFordstIP3(int ip){
    ui->lineEditdstip3->setText(QString::number(ip));
}
void MainWindow::slotFordstIP4(int ip){
    ui->lineEditdstip4->setText(QString::number(ip));
}
void MainWindow::slotForsrcMask(int mask){
    ui->lineEditsrcmask->setText(QString::number(mask));
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::InitDB()
{
    QSqlDatabase db=QSqlDatabase::addDatabase("QSQLITE");
    db.setDatabaseName("test");
    if(!db.open())
    {
        QMessageBox::critical(this,"error","open");
        return;
    }
    QSqlQuery query;
    query.exec("drop table Rule");
    query.exec("create table Rule (id int primary key, srcip1 int,srcip2 int,srcip3 int,srcip4 int,srcport int,dstip1 int,dstip2 int ,dstip3 int ,"
               "dstip4 int,dstport int,dstmask int,srcmask int,protocol int,start_time_hour int,start_time_minute int ,"
               "end_time_hour int ,end_time_minute int ,stragedy int)");
//query.exec("insert into Rule values (1,192,168,100,123,192,168,100,124,24,24,3,8,30,17,30,1)");
    return;

}
