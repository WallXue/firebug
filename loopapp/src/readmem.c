#include <stdio.h>
#include <dirent.h>
#include <sys/types.h>
#include <stdint.h>
#include <fcntl.h>


#ifndef BYTE
#define BYTE unsigned char
#endif


int getPID(char *pkgName) {
    int pid = -1;
    DIR *dir;
    FILE *fp;
    char filename[64];
    char cmdline[64];
    struct dirent *entry;
    dir = opendir("/proc");
    while ((entry = readdir(dir)) != NULL) {
        pid = atoi(entry->d_name);
        if (pid != 0) {
            sprintf(filename, "/proc/%d/cmdline", pid);
            fp = fopen(filename, "r");
            if (fp) {
                fgets(cmdline, sizeof(cmdline), fp);
                fclose(fp);
                if (strcmp(pkgName, cmdline) == 0) {
                    return pid;
                }
            }
        }
    }
    closedir(dir);
    puts("获取PID失败");
    return -1;
}

long getModuleBase(int pid, char *module_name) {
    FILE *pFile;
    long address = 0;
    char *line;
    char *pCh;
    char filename[64];
    snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
    pFile = fopen(filename, "r");
    if (pFile != NULL) {
        while (fgets(line, 1024, pFile)) {
            if (strstr(line, module_name)) {
                pCh = strtok(line, "-");
                address = strtoul(pCh, NULL, 16);
                if (address == 0x8000)
                    address = 0;
                break;
            }
        }
        fclose(pFile);
    }
    return address;
}

void readMem(int pid, long address, unsigned int len, BYTE *bytes) {
    char memPath[200];
    sprintf(memPath, "/proc/%d/mem", pid);
    int handle = open(memPath, O_RDWR);
    pread64(handle, bytes, len, address);
}
void writeMem(int pid, long address, unsigned int len, BYTE *bytes) {
    char memPath[200];
    sprintf(memPath, "/proc/%d/mem", pid);
    int handle = open(memPath, O_RDWR);
    pwrite64(handle, bytes, len, address);
}

void printCharInHexadecimal(const BYTE *str, int len) {
    for (int i = 0; i < len; ++ i) {
        uint8_t val = str[i];
        char tbl[] = "0123456789ABCDEF";
        printf("0x");
        printf("%c", tbl[val / 16]);
        printf("%c", tbl[val % 16]);
        printf(" ");
    }
    printf("\n");
}

int main() {
    char *appName = "LoopApp_linux_x86_64";
    char *procName = malloc(200);
    strcpy(procName, "./");
    strcat(procName, appName);
    int pid = getPID(procName);
    long moduleBase = getModuleBase(pid, appName);
    printf("pid=%d, moduleBase=%lx\n", pid, moduleBase);
    long opCodeAddr = moduleBase + 0x64C;
    printf("opCodeAddr=%lx\n", opCodeAddr);
    BYTE readMemOpCode[4];
    readMem(pid, opCodeAddr, 4, readMemOpCode);
    printCharInHexadecimal(readMemOpCode, 4);
    //修改指令,改变程序运行逻辑
    readMemOpCode[3] = 0x00;
    writeMem(pid, opCodeAddr, 4, readMemOpCode);
    return 1;
}
