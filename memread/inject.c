#include <stdio.h>
#include <fcntl.h>
#include "firebugcore.h"

char *pkgName = "./app";
char *moduleName = "/root/inject/app";

int main(){
	int pid = getPID(pkgName);
	printf("pid is %d\n", pid);
    long baseAddress = getModuleBase(pid, moduleName);
    printf("baseAddress is %lx\n", baseAddress);
    //读取a_int
    char memPath[64];
    sprintf(memPath, "/proc/%d/mem", pid);
    int handle = open(memPath, O_RDWR);
    //读取int
    int aInt = readInt(handle, baseAddress + 0x201058);
    printf("aInt is %d\n", aInt);
    //读取字符串
    char aStr[8];
    readStr(handle, aStr, baseAddress + 0x20105C);
    printf("aStr is %s\n", aStr);
    //读取float
    float aFloat = readFloat(handle, baseAddress + 0x201064);
    printf("aFloat is %f\n", aFloat);
    //读取double
    double aDouble = readDouble(handle, baseAddress + 0x201068);
    printf("aDouble is %f\n", aDouble);
	return 0;
}

