#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/timer.h>

#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/ioctl.h>
#include <linux/slab.h>
#include <linux/string.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/udp.h>
#include <asm/uaccess.h>
#include <net/ip.h>
#include <linux/rtc.h>
MODULE_LICENSE("GPL");
MODULE_AUTHOR("freeman");
#define MAX_RULE_NUM 200
//哈希表,对于actioon而言1为通过，0为拒绝
typedef struct HASHTABLE{
	int protocol;//协议
	int src_ip[4];
	int dst_ip[4];
	int srcport;
	int action;//通过还是拒绝
	int dstport;
	int currenttime;//只是一个时间戳，以秒来计时；
	struct HASHTABLE *next;// 虽然在这里感觉更加简单的方法是直接整一个数组。
	struct HASHTABLE *before;//前向指针d
};
struct HASHTABLE StatusLinkHead[500];
//一个非常简单的HASH函数
int MAKEHASH(int src_ip[4],int dst_ip[4],int protocol){
	unsigned int MASK=0x19198104|protocol;
	unsigned int HASHNUMBER1=(src_ip[0]+dst_ip[0])|((src_ip[1]+dst_ip[1])<<8)|((dst_ip[2]+src_ip[2])<<16)|((dst_ip[3]+src_ip[3])<<24);
	unsigned int HASH=(HASHNUMBER1^MASK)%500;
	return HASH;
}
//规则结构
typedef struct {
	unsigned clear;//如果是1则清空所有规则
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
//默认规则
int stretagy=1;//1为默认通过，0为默认禁止
// 规则表
static Rule rules[MAX_RULE_NUM];
// 规则数
static int rule_num = 0;
//设备号和设备名
#define MYMAJOR	200
#define MYNAME	"chardev_test_byHc"
//钩子
unsigned int hook_out(void *priv,
			struct sk_buff *skb,
			const struct nf_hook_state *state);
unsigned int hook_in(void *priv,
			struct sk_buff *skb,
			const struct nf_hook_state *state);
static struct nf_hook_ops nfhi = {
    .hook		= hook_in,				// hook处理函数
    .pf         = PF_INET,              // 协议类型
    .hooknum    = NF_INET_PRE_ROUTING,	// hook注册点
    .priority   = NF_IP_PRI_FIRST       // 优先级
};
static struct nf_hook_ops nfho = {
    .hook		= hook_out,				// hook处理函数
    .pf         = PF_INET,              // 协议类型
    .hooknum    = NF_INET_POST_ROUTING,	// hook注册点
    .priority   = NF_IP_PRI_FIRST       // 优先级
};
//处理进来的报文
//处理端口的函数
unsigned int dealport(int nowdst,int nowsrc,int src_port,int dst_port){
	//nowdst是目标端口，nowsrc是源端口
	printk("Guize port dst:%d\n",dst_port);
	printk("Guize port src:%d\n",src_port);
	printk("Now port dst:%d\n",htons(nowdst));
	printk("Now port dst:%d\n",htons(nowsrc));
	int flag=0;//1为一致，0为不一致
	if((src_port==0&&dst_port==0)||(src_port==htons(nowsrc)&&htons(nowdst)==dst_port)||(src_port==0&&htons(nowdst)==dst_port)||(src_port==htons(nowsrc)
	&&dst_port==0)){
		flag=1;

	}
	else{
		flag=0;
		
	}
	return flag;
}

//基于ip的处理函数
unsigned int dealIP(struct sk_buff *skb,int ip1,int ip2,int ip3,int ip4,int dip1,int dip2,int dip3,int dip4,int mask,int dmask){
	printk("Start Dealing ip \n");
	int srcipmask,dstipmask,askedipmask,askeddstipmask,src_ip[4],dst_ip[4];//抓到的报文ip
	unsigned int index,remove=0,remove2=0,base=0;
		struct iphdr *iph;
	iph = ip_hdr(skb);
	src_ip[0]=((unsigned char*)&iph->saddr)[0];
	src_ip[1]=((unsigned char*)&iph->saddr)[1];
	src_ip[2]=((unsigned char*)&iph->saddr)[2];
	src_ip[3]=((unsigned char*)&iph->saddr)[3];
	dst_ip[0]=((unsigned char*)&iph->daddr)[0];
	dst_ip[1]=((unsigned char*)&iph->daddr)[1];
	dst_ip[2]=((unsigned char*)&iph->daddr)[2];
	dst_ip[3]=((unsigned char*)&iph->daddr)[3];

	for(index=0;index<32;index++){
		base+=(1<<index);
	}
	for(index=0;index<32-mask;index++){
	remove+=(1<<index);
	}
	for(index=0;index<32-dmask;index++){
		remove2+=(1<<index);
	}

	srcipmask=((src_ip[0]<<24)|(src_ip[1]<<16)|(src_ip[2]<<8)|src_ip[3])&(base-remove);
	dstipmask=((dst_ip[0]<<24)|(dst_ip[1]<<16)|(dst_ip[2]<<8)|dst_ip[3])&(base-remove2);
	printk("Guize:src_ip after mask:%x\n",srcipmask);
	printk("Guize:dst_ip after mask:%x\n",dstipmask);
	askedipmask=((ip1<<24)|(ip2<<16)|(ip3<<8)|ip4)&(base-remove);
	askeddstipmask=((dip1<<24)|(dip2<<16)|(dip3<<8)|dip4)&(base-remove2);
	printk("Srcip after mask:%x\n",askedipmask);
	printk("dstip after mask:%x\n",askeddstipmask);
	if(ip1!=256&&dip1!=256){
		if((srcipmask==askedipmask)&&(dstipmask==askeddstipmask)){
			printk("Catched ip:%d.%d.%d.%d\n",src_ip[0],src_ip[1],src_ip[2],src_ip[3]);
			return 1;
		}
		else{
			return 0;
		}
	}
	else if(ip1==256&&dip1!=256){
		if((dstipmask==askeddstipmask)){
			printk("Catched ip:%d.%d.%d.%d\n",src_ip[0],src_ip[1],src_ip[2],src_ip[3]);
			return 1;
		}
		else{
			return 0;
		}
	}
	else if(ip1!=256&&dip1==256){
		if((srcipmask==askedipmask)){
			printk("Catched ip:%d.%d.%d.%d\n",src_ip[0],src_ip[1],src_ip[2],src_ip[3]);
			return 1;
		}
		else{
			return 0;
		}
	}
	else{
		return 1;
	}
	return 0;
}
//返回1说明找到了并且通过，返回0说明找到了并且按照规则应该拒绝，返回2说明没有找到按规则已经插入
int searchHASH(int HASH,int dst_ip[4],int src_ip[4],int src_port,int dst_port,int protocol){
	struct HASHTABLE *head=&StatusLinkHead[HASH],*nextpot,*beforepot;//
	//获取当前时间
		ktime_t time;
    	struct rtc_time cur_tm;
		printk("thread_flush_time start\n");
    	time=ktime_get_real();
    	cur_tm=rtc_ktime_to_tm(time);
    	cur_tm.tm_year+=1900;
    	cur_tm.tm_mon+=1;
    	cur_tm.tm_hour+=8;
    	//printk("UTC time :%d-%d-%d %d:%d:%d\n",cur_tm.tm_year,cur_tm.tm_mon, cur_tm.tm_mday,cur_tm.tm_hour,cur_tm.tm_min,cur_tm.tm_sec);
	while(head->next!=NULL){

		head=head->next;
		int GUIZEsrcip[4],GUIZEdstip[4],guize_srcport,guize_dstport;
		GUIZEsrcip[0]=head->src_ip[0];
		GUIZEsrcip[1]=head->src_ip[1];
		GUIZEsrcip[2]=head->src_ip[2];
		GUIZEsrcip[3]=head->src_ip[3];
		GUIZEdstip[0]=head->dst_ip[0];
		GUIZEdstip[1]=head->dst_ip[1];
		GUIZEdstip[2]=head->dst_ip[2];
		GUIZEdstip[3]=head->dst_ip[3];
		guize_dstport=head->dstport;
		guize_srcport=head->srcport;
		int guize_protocol=protocol;
		int action=head->action;
		//如果一样或者相反则通过
		//首先是一样的情况
		printk("In status dst ip:%d.%d.%d.%d:%d\n",GUIZEdstip[0],GUIZEdstip[1],GUIZEdstip[2],GUIZEdstip[3],guize_dstport);
		printk("In status src ip:%d.%d.%d.%d:%d\n",GUIZEsrcip[0],GUIZEsrcip[1],GUIZEsrcip[2],GUIZEsrcip[3],guize_srcport);
		printk("Now dst ip:%d.%d.%d.%d:%d\n",dst_ip[0],dst_ip[1],dst_ip[2],dst_ip[3],dst_port);
		printk("Now src ip:%d.%d.%d.%d:%d\n",src_ip[0],src_ip[1],src_ip[2],src_ip[3],src_port);
		printk("Guize rule is%d,Your rule is %d\n",guize_protocol,protocol);
		if((GUIZEdstip[0]==dst_ip[0])&&(GUIZEdstip[1]==dst_ip[1])&&(GUIZEdstip[2]==dst_ip[2])&&(GUIZEdstip[3]==dst_ip[3])&&(GUIZEsrcip[0]==src_ip[0])&&
		(GUIZEsrcip[1]==src_ip[1])&&(GUIZEsrcip[2]==src_ip[2])&&(GUIZEsrcip[3]==src_ip[3])&&(guize_dstport==dst_port)&&(guize_srcport==src_port)
		&&(protocol==guize_protocol)){
			printk("In status MApping....");
			if(action==1){
				return 1;
			}
			else{
				return 0;
			}
		}
		else if((GUIZEdstip[0]==src_ip[0])&&(GUIZEdstip[1]==src_ip[1])&&(GUIZEdstip[2]==src_ip[2])&&(GUIZEdstip[3]==src_ip[3])&&(GUIZEsrcip[0]==dst_ip[0])&&
		(GUIZEsrcip[1]==dst_ip[1])&&(GUIZEsrcip[2]==dst_ip[2])&&(GUIZEsrcip[3]==dst_ip[3])&&(guize_dstport==src_port)&&(guize_srcport==dst_port)
		&&(protocol==guize_protocol)){
				printk("In status Mapping....");
				if(action==1){
					return 1;
				}
				else{
					return 0;
				}
		}
	}
	head->next=(struct HASHTABLE *)kmalloc(sizeof(struct HASHTABLE),GFP_KERNEL);
	nextpot=head->next;
	nextpot->before=head;
	head=head->next;
	//插入哈希规则
	//能到这一步说明Hash表中没有对应规则
	return 2;
}
//插入HASH规则
void InsertHash(int HASH,struct sk_buff *skb,int action){
	int time_sign=0;
	printk("Now Insert!\n");
	//获取当前时间
		ktime_t time;
    	struct rtc_time cur_tm;
		printk("thread_flush_time start\n");
    	time=ktime_get_real();
    	cur_tm=rtc_ktime_to_tm(time);
    	cur_tm.tm_year+=1900;
    	cur_tm.tm_mon+=1;
    	cur_tm.tm_hour+=8;
		int currenttime=cur_tm.tm_hour*60*60+cur_tm.tm_min*60+cur_tm.tm_sec;//时间戳
	//获得SKB里的东西
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct udphdr *udph;
	iph = ip_hdr(skb);
	int dstport=0,srcport=0;
	int This_Protocol=iph->protocol;
	if(This_Protocol== IPPROTO_TCP){
		tcph = (void *)iph + iph->ihl*4;//TCP包头
		iph->protocol;//这个是协议
		dstport=tcph->dest;//目标端口
		srcport=tcph->source;//源端口
		tcph->fin;//释放一个连接，它表示发送方已经没有数据要传输了。
		tcph->syn;//同步序号，用来发送一个连接。syn被用于建立连接的过程，在连接请求中，syn=1；ack=0表示该数据段没有使用捎带的确认域。连接应答捎带了一个确认，所以有syn=1;ack=1。本质上，syn位被用于表示connection request和connection accepted，然而进一步用ack位来区分这两种情况。
		tcph->rst;//该位用于重置一个混乱的连接，之所以混乱，可能是因为主机崩溃或者其他原因。该位也可以被用来拒绝一个无效的数据段，或者拒绝一个连接请求，一般而言，如果你得到的数据段设置了rst位，说明你这一端有了问题。
		tcph->ack;//ack位被设置为1表示tcphdr->ack_seq是有效的，如果ack为0，则表示该数据段不包含确认信息，所以tcphdr->ack_seq域应该被忽略。
		printk("Receive TCP!\n");
	}
	if(This_Protocol==IPPROTO_UDP){
		udph= (void *)iph + iph->ihl*4;//UDP包头
		dstport=udph->dest;//udp目标端口
		srcport=udph->source;//UDP源端口
		printk("Receive UDP!\n");
	}
	//获取当前HASH表尾的东西
	struct HASHTABLE *head;
	struct HASHTABLE *origin_head;
	head=&StatusLinkHead[HASH];
	while(head->next!=NULL){
		head=head->next;
	}
	head->next=(struct HASHTABLE*)kmalloc(sizeof(struct HASHTABLE),GFP_KERNEL);
	origin_head=head;
	head=head->next;
	head->next=NULL;
	head->before=origin_head;
	head->src_ip[0]=((unsigned char *)&iph->saddr)[0];
	head->src_ip[1]=((unsigned char *)&iph->saddr)[1];
	head->src_ip[2]=((unsigned char *)&iph->saddr)[2];
	head->src_ip[3]=((unsigned char *)&iph->saddr)[3];
	head->dst_ip[0]=((unsigned char *)&iph->daddr)[0];
	head->dst_ip[1]=((unsigned char *)&iph->daddr)[1];
	head->dst_ip[2]=((unsigned char *)&iph->daddr)[2];
	head->dst_ip[3]=((unsigned char *)&iph->daddr)[3];
	head->action=action;
	head->currenttime=currenttime;
	head->srcport=srcport;
	head->dstport=dstport;
	head->protocol=This_Protocol;
	printk("Insert finished,Hash is %d\n",HASH);
	return;
}
//读取规则(所有)
void ReadRules(void){
	int temp=0;
	printk("Here is all %d rules",rule_num);
	for(temp=0;temp<rule_num;temp++){
		printk("src_ip:%u.%u.%u.%u\n",rules[temp].src_ip[0],rules[temp].src_ip[1],rules[temp].src_ip[2],rules[temp].src_ip[3]);
		printk("dst_ip:%u.%u.%u.%u\n",rules[temp].dst_ip[0],rules[temp].dst_ip[1],rules[temp].dst_ip[2],rules[temp].dst_ip[3]);
		printk("src_mask:%u\n",rules[temp].src_mask);
		printk("dst_mask:%u\n",rules[temp].dst_mask);
		printk("src_port:%u\n",rules[temp].src_port);
		printk("dst_port:%u\n",rules[temp].dst_port);
		printk("protocol:%u\n",rules[temp].protocol);
		printk("action:%u\n",rules[temp].action);
		printk("log%u\n",rules[temp].log);
		}
}
unsigned int hook_out(void *priv,
			struct sk_buff *skb,
			const struct nf_hook_state *state){
				//printk("catched!");
				return NF_ACCEPT;
			}
unsigned int hook_in(void *priv,
			struct sk_buff *skb,
			const struct nf_hook_state *state)
{
	//首先是获取当前时间
	//获取当前时间
		ktime_t time;
    	struct rtc_time cur_tm;
		printk("thread_flush_time start\n");
    	time=ktime_get_real();
    	cur_tm=rtc_ktime_to_tm(time);
    	cur_tm.tm_year+=1900;
    	cur_tm.tm_mon+=1;
    	cur_tm.tm_hour+=8;
		int currenttime=cur_tm.tm_hour*60+cur_tm.tm_min;
	printk("time is hour:%d:%d:%d,and sign of time is:%d",cur_tm.tm_hour,cur_tm.tm_min,cur_tm.tm_sec,currenttime);
	int index=0,flag;// 在默认允许的条件下，flag=1即丢弃,在默认拒绝的情况下，flag2=1即通过
	//默认允许的清况下
	//对ip进行过滤,
		struct iphdr *iph;
	struct tcphdr *tcph;
	struct udphdr *udph;
	iph = ip_hdr(skb);
	int dstport=0,srcport=0;
	int This_Protocol=iph->protocol;//这个报文的协议
	if(This_Protocol== IPPROTO_TCP){
		tcph = (void *)iph + iph->ihl*4;//TCP包头
		iph->protocol;//这个是协议
		dstport=tcph->dest;//目标端口
		srcport=tcph->source;//源端口
		tcph->fin;//释放一个连接，它表示发送方已经没有数据要传输了。
		tcph->syn;//同步序号，用来发送一个连接。syn被用于建立连接的过程，在连接请求中，syn=1；ack=0表示该数据段没有使用捎带的确认域。连接应答捎带了一个确认，所以有syn=1;ack=1。本质上，syn位被用于表示connection request和connection accepted，然而进一步用ack位来区分这两种情况。
		tcph->rst;//该位用于重置一个混乱的连接，之所以混乱，可能是因为主机崩溃或者其他原因。该位也可以被用来拒绝一个无效的数据段，或者拒绝一个连接请求，一般而言，如果你得到的数据段设置了rst位，说明你这一端有了问题。
		tcph->ack;//ack位被设置为1表示tcphdr->ack_seq是有效的，如果ack为0，则表示该数据段不包含确认信息，所以tcphdr->ack_seq域应该被忽略。
		printk("Receive TCP!,SYN:%d?\n",tcph->syn);
	}
	if(This_Protocol==IPPROTO_UDP){
		udph= (void *)iph + iph->ihl*4;//UDP包头
		dstport=udph->dest;//udp目标端口
		srcport=udph->source;//UDP源端口
		printk("Receive UDP!\n");
	}
	
	printk(KERN_INFO "Here is in dstip: %d.%d.%d.%d\n",
		((unsigned char *)&iph->daddr)[0],
		((unsigned char *)&iph->daddr)[1],
		((unsigned char *)&iph->daddr)[2],
		((unsigned char *)&iph->daddr)[3]);
	printk(KERN_INFO "Here is in srcip:%d.%d.%d.%d\n",
		((unsigned char *)&iph->saddr)[0],
		((unsigned char *)&iph->saddr)[1],
		((unsigned char *)&iph->saddr)[2],
		((unsigned char *)&iph->saddr)[3]
	);
	
	//获取源ip地址
	int SRCIP[4],DSTIP[4];
	SRCIP[0]=((unsigned char *)&iph->saddr)[0];
	SRCIP[1]=((unsigned char *)&iph->saddr)[1];
	SRCIP[2]=((unsigned char *)&iph->saddr)[2];
	SRCIP[3]=((unsigned char *)&iph->saddr)[3];//这四个是本报文源ip地址
	DSTIP[0]=((unsigned char *)&iph->daddr)[0];
	DSTIP[1]=((unsigned char *)&iph->daddr)[1];
	DSTIP[2]=((unsigned char *)&iph->daddr)[2];
	DSTIP[3]=((unsigned char *)&iph->daddr)[3];//这四个是本报文的目的ip地址
	//生成HASH值
	int HASH=MAKEHASH(SRCIP,DSTIP,This_Protocol);
	printk("HashMaked is %d\n",HASH);
	// 查询状态检测表，如果找到了则直接根据结果返回，后续根据能不能找到来搜寻，注意，即使规则转换，但是如果该系列在此前已经被拒绝或者允许通过，那么
	//他们依旧可以通过
	if((This_Protocol==IPPROTO_TCP)||(This_Protocol==IPPROTO_UDP)){
		int result;
		printk("Start Search!\n");
		result=searchHASH(HASH,DSTIP,SRCIP,srcport,dstport,This_Protocol);
		if(result==1){
			printk("Has found ,Accept\n");
			return NF_ACCEPT;
		}
		else if(result==0){
			printk("Has found ,Reject\n");
			return NF_DROP;
		}
		else if(result==2){
			printk("Has not found,continue\n");
		}
	}
	
	for(index=0;index<rule_num;index++){
			printk("Here is %d rules",rule_num);
			int GuizeMaxTime,GuizeMinTime;
			int guize_protocol=rules[index].protocol;
			GuizeMaxTime=rules[index].endtime;
			GuizeMinTime=rules[index].starttime;
			int tempstg=rules[index].action;//策略是通过还是拒绝，如果是通过，直接下一条否则继续
			//先检测时间在不在范围里面
			printk("Current time is:%d,?(%d--%d)\n",currenttime,GuizeMinTime,GuizeMaxTime);
			if(currenttime>=GuizeMinTime&&currenttime<=GuizeMaxTime){
				printk("Time is corrected!\n");
				flag=1;
			}
			else{
				flag=0;
				continue;
			}
			//检查ip是否合法，toge为源ip,toge2为目的ip
			int toge=dealIP(skb,rules[index].src_ip[0],rules[index].src_ip[1],rules[index].src_ip[2],rules[index].src_ip[3],
			rules[index].dst_ip[0],rules[index].dst_ip[1],rules[index].dst_ip[2],rules[index].dst_ip[3],rules[index].src_mask,rules[index].dst_mask);
			if(toge==1){
				printk("IP is corrected\n");
				flag=1;//暂时满足条件
			}
			else{
				flag=0;
				continue;
			}
			//匹配协议
			if((This_Protocol==guize_protocol)||(guize_protocol==0)){
				printk("Matched!,Protocol number is :%d\n",This_Protocol);
				flag=1;
				if(((This_Protocol==IPPROTO_TCP)&&(tcph->syn==1))||(This_Protocol==IPPROTO_UDP)){
				//如果是TCP，插入TCP_HASH规则(当然还得是SYN报文才有资格插入)
				printk("Start Deal port\n");
				if(dealport(dstport,srcport,rules[index].src_port,rules[index].dst_port)==1){
						printk("Port corrected:%d-%d,%d-%d\n",rules[index].src_port,htons(srcport),rules[index].dst_port,htons(dstport));
						InsertHash(HASH,skb,rules[index].action);
						flag=1;

					}
					else{
						flag=0;
						continue;
					}
			}
			}
			//获取协议信息
			
			//如果检测匹配，根据规则做出行为
			if(flag==1){
				if(rules[index].action==1){
					printk("Rule is matched\n");
					return NF_ACCEPT;
				}
				else{
					return NF_DROP;
				}
			}		
					
	}
	//到这里还没有出结果，说明规则表里没有对应匹配
	if(stretagy==1){
		if(((This_Protocol==IPPROTO_TCP)&&(tcph->syn==1))||(This_Protocol==IPPROTO_UDP)){
			InsertHash(HASH,skb,stretagy);
		}
		return NF_ACCEPT;
	}
	else{
		if(((This_Protocol==IPPROTO_TCP)&&(tcph->syn==1))||(This_Protocol==IPPROTO_UDP)){
			InsertHash(HASH,skb,stretagy);
		}
		return NF_DROP;
	}
	
}

// unsigned int telnet_filter(void *priv,
// 			struct sk_buff *skb,
// 			const struct nf_hook_state *state)
// {
// 	struct iphdr *iph;
// 	struct tcphdr *tcph;

// 	iph = ip_hdr(skb);
// 	tcph = (void *)iph + iph->ihl*4;
// 		printk(KERN_INFO "Dropping telnet packet to %d.%d.%d.%d\n",
// 		((unsigned char *)&iph->daddr)[0],
// 		((unsigned char *)&iph->daddr)[1],
// 		((unsigned char *)&iph->daddr)[2],
// 		((unsigned char *)&iph->daddr)[3]);
// 	if(iph->protocol == IPPROTO_TCP && tcph->dest == htons(23))
// 	{
// 		printk(KERN_INFO "Dropping telnet packet to %d.%d.%d.%d\n",
// 		((unsigned char *)&iph->daddr)[0],
// 		((unsigned char *)&iph->daddr)[1],
// 		((unsigned char *)&iph->daddr)[2],
// 		((unsigned char *)&iph->daddr)[3]);
// 		return NF_DROP;
// 	}
// 	else{
// 		return NF_ACCEPT;
// 	}
// }

char* BUFF;//缓冲区
//DEVICE ID
dev_t devid;
struct cdev cdev;

DECLARE_WAIT_QUEUE_HEAD(myqueue);
int xx=0;

static int chardev_open(struct inode *inode, struct file *file)
{
	printk(KERN_INFO "chardev open\n");
	return 0;
}

static ssize_t chardev_read(struct file *file, char __user *buf,
	size_t size, loff_t *ppos)
{
	//printk("Reading...%s",BUFF);
		if (copy_to_user(buf,BUFF,sizeof(Rule))==0)
        {
        	printk("IS Reading...");
		
        }
    else
    {
	printk("Reading failed");
    }
	return 0;
} 

static ssize_t chardev_write(struct file *file, const char __user *buf, size_t size, loff_t * ppos)
{	
	printk("Writing...");
	int xx=0;
	
	if ((xx=copy_from_user(BUFF, buf,size))==0)
        {
			if(((Rule *)BUFF)->clear==1){
		rule_num=0;
	}
        	printk("IS writing...%s",BUFF);
		memcpy(&rules[rule_num],BUFF,size);
		rule_num++;
		//ReadRules();
        }
    else
    {
	printk("Writing failed,xx:%d",xx);
    }
	ReadRules();
//	xx=1;
//	wake_up_interruptible(&myqueue);
	return 0;
}

static const struct file_operations chardev_fops = {
	.open = chardev_open,
	.read = chardev_read,
	.write = chardev_write,
};

#define DevName "tests"
#define ClassName "class_tests"

struct class    *mem_class;
struct Pci_dev  *test_devices;
struct cdev 	_cdev;
dev_t    dev;

static int __init mymodule_init(void)
{
	//对Hash表进行初始化
	int index=0;
	for(index=0;index<500;index++){
		StatusLinkHead[index].next=NULL;
	}
	printk("Chain init finished");
	nf_register_net_hook(&init_net,&nfho);
	nf_register_net_hook(&init_net,&nfhi);
//
	BUFF=(char *)kmalloc(sizeof(char)*200,GFP_KERNEL);
	printk("Initing....");
	int result = alloc_chrdev_region(&dev, 0, 2, DevName);
	
	if (result < 0)
	{
		printk("Err:failed in alloc_chrdev_region!\n");
		return result;
	}
	//创建class实例
	mem_class = class_create(THIS_MODULE,ClassName);// /dev/ create devfile 
    	if (IS_ERR(mem_class))
    	{
		printk("Err:failed in creating class!\n");
  	}
  	//动态创建设备描述文件 /dev/test

	device_create(mem_class,NULL,dev,NULL,DevName);
	cdev_init(&_cdev,&chardev_fops);
	_cdev.owner = THIS_MODULE;
	_cdev.ops = &chardev_fops;//Create Dev and file_operations Connected
	result = cdev_add(&_cdev,dev,1);

	return 0;
}

static void __exit mymodule_exit(void)
{
	//清空HASH表
	int index=0;
	struct HASHTABLE *head,*temp;
	for(index=0;index<500;index++){
		head=&StatusLinkHead[index];
		while(head->next!=NULL){
			temp=head;
			temp->before=NULL;
			temp->next=NULL;
			head=head->next;
			kfree(temp);
		}
		//kfree(head);
	}
    cdev_del(&_cdev);
	printk(KERN_INFO "chrdev_exit helloworld exit\n");
	cdev_del(&cdev);
	
	unregister_chrdev_region(devid,255);
		if (0 != mem_class)
    {
        device_destroy(mem_class,dev);
        class_destroy(mem_class);
        mem_class = 0;
    }
    //卸载钩子
    nf_unregister_net_hook(&init_net,&nfho);
    nf_unregister_net_hook(&init_net,&nfhi);
    printk("Exit...\n");
    
}

module_init(mymodule_init);
module_exit(mymodule_exit);


