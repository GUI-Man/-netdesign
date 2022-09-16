#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>

void*threadtest(void*p)
{
	int fd=(int*)p;
	char buf[510]={0};
	while(1){
		read(fd,buf,500);
		printf("%s",buf);
		memset(buf,0,sizeof(char)*510);
	}
	printf("over\n");
	return 0;
}

int main()
{
	int fd=open("/dev/tests",O_RDWR);
	if(fd<=0)
	{
		perror("open");
		return 0;
	}
	
	pthread_t id;
	pthread_create(&id,NULL,(void *)threadtest,(void*)fd);
	pthread_join(id,NULL);
	return 0;
} 

