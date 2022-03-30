#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


char a_str[20] = "XUEWU";
char b_str[20] = "NO";

void getName(char *pName, int val){
    if(val > 10) {
        strcpy(pName, a_str);
    }else{
        char temp[] = "TEMP";
        char *temp2 = "TEMP2";
        strcpy(pName, temp2);
    }
}

int main(){
//    char pName[200];
    char *pName = malloc(200);
    while(1) {
        getName(pName, 5);
        puts(pName);
        sleep(1000);
    }
}

