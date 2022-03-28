#include <stdio.h>
//#include <Android/log.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <stdbool.h>
#include <stdint.h>

#ifndef BYTE
#define BYTE unsigned char
#endif


#define OPCODEMAXLEN 8      //inline hook所需要的opcodes最大长度

//#define LOG_TAG "GSLab"
//#define LOGI(fmt, args...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, fmt, ##args);

/** shellcode里用到的参数、变量*/
extern unsigned long _shellcode_start_s;
extern unsigned long _shellcode_end_s;
extern unsigned long _hookstub_function_addr_s; //根函数地址
extern unsigned long _old_function_addr_s;  //原指令地址

//hook点信息
typedef struct tagINLINEHOOKINFO{
    void *pHookAddr;                //hook的地址
    void *pStubShellCodeAddr;            //跳过去的shellcode stub的地址
    void (*onCallBack)(struct pt_regs *);
    //回调函数，跳转过去的函数地址
    void ** ppOldFuncAddr;             //shellcode 中存放old function的地址
    BYTE szbyBackupOpcodes[OPCODEMAXLEN];    //原来的opcodes
} INLINE_HOOK_INFO;

//更高内存页属性
bool ChangePageProperty(void *pAddress, size_t size);

//获取模块基址
extern void * GetModuleBaseAddr(pid_t pid, char* pszModuleName);

//初始化ARM指令集的hook信息结构体
bool InitArmHookInfo(INLINE_HOOK_INFO* pstInlineHook);

//构建桩函数
bool BuildStub(INLINE_HOOK_INFO* pstInlineHook);

//构建跳转代码
bool BuildArmJumpCode(void *pCurAddress , void *pJumpAddress);

//构建原指令的函数
bool BuildOldFunction(INLINE_HOOK_INFO* pstInlineHook);

//重写hook点的原指令，使其跳转到桩函数处
bool RebuildHookTarget(INLINE_HOOK_INFO* pstInlineHook);

//HOOK的总流程
extern bool HookArm(INLINE_HOOK_INFO* pstInlineHook);