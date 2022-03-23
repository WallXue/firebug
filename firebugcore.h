#include <stdio.h>
#include <sys/types.h>
#include <dirent.h>


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


int readInt(int handle, long address) {
    int val = 0;
    pread64(handle, &val, 4, address);
    return val;
}


float readFloat(int handle, long address) {
    float val = 0;
    pread64(handle, &val, 4, address);
    return val;
}


double readDouble(int handle, long address) {
    double val = 0;
    pread64(handle, &val, 8, address);
    return val;
}


void readStr(int handle, char *val, long address) {
    pread64(handle, val, 8, address);
}