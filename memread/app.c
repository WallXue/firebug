#include <stdio.h>
#include <fcntl.h>

int a_int = 2147483647;
char a_str[] = "XUEWU";
float a_float = 123.123;
double a_double = 456.456;

int main(){
	int b_int = 2222;
	char b_str[] = "NIUBI";
	int pid = getpid();
	printf("pid is %d\n", pid);
	printf("a_int is %d, point is %p\n", a_int, &a_int);
    printf("a_str is %s, point is %p\n", a_str, &a_str);
    printf("a_float is %f, point is %p\n", a_float, &a_float);
    printf("a_double is %f, point is %p\n", a_double, &a_double);
	printf("b_int is %d, point is %p\n", b_int, &b_int);
	printf("b_str is %s, point is %p\n", b_str, &b_str);
	printf("b_int point - a_int point  is %lx\n", (&b_int - &a_int));
	
	//打开内存文件
	int memhandle;
	char mempath[64];
	sprintf(mempath, "/proc/%d/mem", pid);
	memhandle = open(mempath, O_RDWR);
	printf("memhandle is %d\n", memhandle);
	
	//根据a_int的内存地址读取数据
	int buff;
	pread64(memhandle, &buff, 4, &a_int);
	printf("a_int read from mem value is %d \n ", buff);
	
	//根据b_int的内存地址读取数据
	buff = 0;
	pread64(memhandle, &buff, 4, &b_int);
	printf("b_int read from mem value is %d \n ", buff);

	//读取字符串
	char *byte_buff[8];
	pread64(memhandle, &byte_buff, 5, &a_str);
	printf("a_str read from mem value is %s \n ", byte_buff);

	sleep(199999);
	return 0;
}

