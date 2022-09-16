#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
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
void*threadtest(void*p)
{
	int fd=(int*)p;
	char buf[10];
	read(fd,buf,10);
	printf("over\n");
	return 0;
}
int InputRules(Rule *input){
	int fd=open("/dev/tests",O_RDWR);
	if(fd<=0)
	{
		perror("open");
		return 0;
	}
	printf("start write.....\n");
	write(fd,input,sizeof(*input));
	printf("Write Over");
	close(fd);
}
int main()
{
	static Rule inputrules[4];
	inputrules[0].clear=1;
	inputrules[0].src_ip[0]=192;
	inputrules[0].src_ip[1]=168;
	inputrules[0].src_ip[2]=43;
	inputrules[0].src_ip[3]=169;
	inputrules[0].dst_ip[0]=192;
	inputrules[0].dst_ip[1]=168;
	inputrules[0].dst_ip[2]=43;
	inputrules[0].dst_ip[3]=1;
	inputrules[0].src_mask=32;
	inputrules[0].dst_mask=32;
	inputrules[0].src_port=0;
	inputrules[0].dst_port=0;
	inputrules[0].protocol=6;
	inputrules[0].action=0;
	inputrules[0].log=2;
	inputrules[0].starttime=8*60+20;
	inputrules[0].endtime=23*60+30;
	InputRules(&inputrules[0]);
	inputrules[1].clear=0;
	inputrules[1].src_ip[0]=192;
	inputrules[1].src_ip[1]=168;
	inputrules[1].src_ip[2]=43;
	inputrules[1].src_ip[3]=200;
	inputrules[1].dst_ip[0]=192;
	inputrules[1].dst_ip[1]=168;
	inputrules[1].dst_ip[2]=43;
	inputrules[1].dst_ip[3]=13;
	inputrules[1].src_mask=32;
	inputrules[1].dst_mask=32;
	inputrules[1].src_port=0;
	inputrules[1].dst_port=0;
	inputrules[1].protocol=6;
	inputrules[1].action=1;
	inputrules[1].log=2;
	inputrules[1].starttime=8*60+20;
	inputrules[1].endtime=23*60+30;
	InputRules(&inputrules[1]);
		inputrules[0].clear=1;
	inputrules[3].src_ip[0]=256;
	inputrules[3].src_ip[1]=256;
	inputrules[3].src_ip[2]=256;
	inputrules[3].src_ip[3]=256;
	inputrules[3].dst_ip[0]=192;
	inputrules[3].dst_ip[1]=168;
	inputrules[3].dst_ip[2]=43;
	inputrules[3].dst_ip[3]=169;
	inputrules[3].src_mask=32;
	inputrules[3].dst_mask=32;
	inputrules[3].src_port=0;
	inputrules[3].dst_port=0;
	inputrules[3].protocol=6;
	inputrules[3].action=0;
	inputrules[3].log=2;
	inputrules[3].starttime=8*60+20;
	inputrules[3].endtime=23*60+30;
	InputRules(&inputrules[3]);
	return 0;
} 
