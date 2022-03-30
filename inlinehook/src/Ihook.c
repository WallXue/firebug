#include "../include/Ihook.h"

void LOGI(char *log) {
    puts(log);
}

bool HookArm(INLINE_HOOK_INFO* pstInlineHook)
{
    //hook结果
    bool bRet = false;

    while(1)
    {
        //判断是否传入Hook点信息的结构体
        if(pstInlineHook == NULL)
        {
            LOGI("pstInlineHook is null.");
            break;
        }

        /* 初始化hook点的信息，如原指令地址、将要执行的用户自定义函数*/
        if(InitArmHookInfo(pstInlineHook) == false)
        {
            LOGI("Init Arm HookInfo fail.");
            break;
        }

        /* 1. 构造桩函数*/
        if(BuildStub(pstInlineHook) == false)
        {
            LOGI("BuildStub fail.");
            break;
        }

        /* 2. 构造原指令函数，执行被覆盖指令并跳转回原始指令流程*/
        if(BuildOldFunction(pstInlineHook) == false)
        {
            LOGI("BuildOldFunction fail.");
            break;
        }

        /* 3. 改写原指令为跳转指令，跳转到桩函数处*/
        if(RebuildHookTarget(pstInlineHook) == false)
        {
            LOGI("RebuildHookAddress fail.");
            break;
        }

        bRet = true;
        break;
    }

    return bRet;
}

/**
 *  初始化hook点信息，保存原指令的opcode
 *
 *  @param  pstInlineHook hook点相关信息的结构体
 *  @return 初始化是否成功
 */
bool InitArmHookInfo(INLINE_HOOK_INFO* pstInlineHook)
{
    bool bRet = false;

    if(pstInlineHook == NULL)
    {
        LOGI("pstInlineHook is null");
        return bRet;
    }

    memcpy(pstInlineHook->szbyBackupOpcodes, pstInlineHook->pHookAddr, 8);
    return bRet;
}

/**
 *  修改页属性，改成可读可写可执行
 *  @param   pAddress   需要修改属性起始地址
 *  @param   size       需要修改页属性的长度，byte为单位
 *  @return  bool       修改是否成功
 */
bool ChangePageProperty(void *pAddress, size_t size)
{
    bool bRet = false;

    if(pAddress == NULL)
    {
        LOGI("change page property error.");
        return bRet;
    }
    //计算包含的页数、对齐起始地址
    unsigned long ulPageSize = sysconf(_SC_PAGESIZE);
    int iProtect = PROT_READ | PROT_WRITE | PROT_EXEC;
    //页对齐，把小于4096的位数(前12位)都置0，只取大于4096的位数且其值必然是4096的整数倍
    //并且这个值必然小于等于参数pAddress
    unsigned long ulNewPageStartAddress = (unsigned long)(pAddress) & ~(ulPageSize - 1);

    long lPageCount = (size / ulPageSize) + 1;
    int iRet = mprotect((void *)(ulNewPageStartAddress), lPageCount*ulPageSize , iProtect);
    if(iRet == -1)
    {
//        LOGI("mprotect error:%s", strerror(errno));
        LOGI("mprotect error 11111");
        return bRet;
    }
    return true;
}

/*
 * 通过/proc/$pid/maps，获取模块基址
 * @param   pid                 模块所在进程pid，如果访问自身进程，可填小余0的值，如-1
 * @param   pszModuleName       模块名字
 * @return  void*               模块基址，错误则返回0
 */
void * GetModuleBaseAddr(pid_t pid, char* pszModuleName)
{
    FILE *pFileMaps = NULL;
    unsigned long ulBaseValue = 0;
    char szMapFilePath[256] = {0};
    char szFileLineBuffer[1024] = {0};

    //pid判断，确定maps文件
    if (pid < 0)
    {
        snprintf(szMapFilePath, sizeof(szMapFilePath), "/proc/self/maps");
    }
    else
    {
        snprintf(szMapFilePath, sizeof(szMapFilePath),  "/proc/%d/maps", pid);
    }

    pFileMaps = fopen(szMapFilePath, "r");
    if (NULL == pFileMaps)
    {
        return (void *)ulBaseValue;
    }

    //循环遍历maps文件，找到相应模块，截取地址信息
    while (fgets(szFileLineBuffer, sizeof(szFileLineBuffer), pFileMaps) != NULL)
    {
        if (strstr(szFileLineBuffer, pszModuleName))
        {
            char *pszModuleAddress = strtok(szFileLineBuffer, "-");
            if (pszModuleAddress)
            {
                ulBaseValue = strtoul(pszModuleAddress, NULL, 16);

                if (ulBaseValue == 0x8000)
                {
                    ulBaseValue = 0;
                }
                break;
            }
        }
    }

    fclose(pFileMaps);
    return (void *)ulBaseValue;
}

/**
 *  1. 构造桩函数。这里的桩函数我们主要在shellcode中实现
 *      * 保存寄存器的值
 *      * 跳转到用户自定义函数callback
 *      * 寄存器还原操作
 *      * 跳转到构造好的原指令函数中
 *
 *  @param  pstInlineHook hook点相关信息的结构体
 *  @return inlinehook桩是否构造成功
 */
bool BuildStub(INLINE_HOOK_INFO* pstInlineHook)
{
    bool bRet = false;

    while(1)
    {
        if(pstInlineHook == NULL)
        {
            LOGI("pstInlineHook is null");
            break;
        }

        //导入数据段中shellcdoe的开始、结束地址，为用户自定义函数callback和将要构造的原指令函数保留的地址
        void *p_shellcode_start_s = &_shellcode_start_s;
        void *p_shellcode_end_s = &_shellcode_end_s;
        void *p_hookstub_function_addr_s = &_hookstub_function_addr_s;
        void *p_old_function_addr_s = &_old_function_addr_s;

        //malloc一块内存，将shellcode拷贝进去并修改这块内存为可执行权限
        //并且更新hook点结构体的数据，让结构体中保存有桩函数(shellcode)的地址和一个变量的地址，这个变量存放着原指令函数的地址，并且这个变量在构造原指令函数的时候才会存进真实的地址
        size_t sShellCodeLength = p_shellcode_end_s - p_shellcode_start_s;
        void *pNewShellCode = malloc(sShellCodeLength);
        if(pNewShellCode == NULL)
        {
            LOGI("shell code malloc fail.");
            break;
        }
        memcpy(pNewShellCode, p_shellcode_start_s, sShellCodeLength);
        if(ChangePageProperty(pNewShellCode, sShellCodeLength) == false)
        {
            LOGI("change shell code page property fail.");
            break;
        }

        //从参数中获取用户自定义函数callback的地址，并填充到shellcode中
        void **ppHookStubFunctionAddr = pNewShellCode + (p_hookstub_function_addr_s - p_shellcode_start_s);
        *ppHookStubFunctionAddr = pstInlineHook->onCallBack;
        //桩函数(shellcode)的地址
        pstInlineHook->pStubShellCodeAddr = pNewShellCode;
        //变量地址，存放原指令函数地址的变量
        pstInlineHook->ppOldFuncAddr  = pNewShellCode + (p_old_function_addr_s - p_shellcode_start_s);
        bRet = true;
        break;
    }

    return bRet;
}


/**
 *  (ARM)修改指定位置的指令为跳转到另一个指定位置的跳转指令。
 *  @param  pCurAddress      当前地址，要构造跳转指令的位置
 *  @param  pJumpAddress     目的地址，要从当前位置跳过去的地址
 *  @return                  跳转指令是否构造成功
 */
bool BuildArmJumpCode(void *pCurAddress , void *pJumpAddress)
{
    bool bRet = false;

    while(1)
    {
        if(pCurAddress == NULL || pJumpAddress == NULL)
        {
            LOGI("address null.");
            break;
        }

        //LDR PC, [PC, #-4]的机器码是0xE51FF004
        BYTE szLdrPCOpcodes[8] = {0x04, 0xF0, 0x1F, 0xE5};
        //LDR PC, [PC, #-4]指令执行时，PC的值刚好是PC+8的位置，也就是PC-4=pc+8-4=pc+4的值就是下一条指令的值
        //我们用地址代替指令值，实现修改PC寄存器执行到指定地址的功能
        memcpy(szLdrPCOpcodes + 4, &pJumpAddress, 4);
        //修改指定位置的指令
        memcpy(pCurAddress, szLdrPCOpcodes, 8);
        cacheflush(*((uint32_t*)pCurAddress), 8, 0);

        bRet = true;
        break;
    }

    return bRet;
}

/**
 *  2.构造原指令函数。
 *      * 执行原指令
 *      * 跳转到原始指令流程中，即原指令的下一条指令处
 *  出了上面两个功能我们还需要将shellcode中的原指令函数地址进行填充，承接上面的流程
 *
 *  @param  pstInlineHook hook点相关信息的结构体
 *  @return 原指令函数是否构造成功
 */
bool BuildOldFunction(INLINE_HOOK_INFO* pstInlineHook)
{
    bool bRet = false;

    while(1)
    {
        if(pstInlineHook == NULL)
        {
            LOGI("pstInlineHook is null");
            break;
        }

        //8字节原指令，8字节原指令的下一条指令
        void * pNewEntryForOldFunction = malloc(16);
        if(pNewEntryForOldFunction == NULL)
        {
            LOGI("new entry for old function malloc fail.");
            break;
        }

        if(ChangePageProperty(pNewEntryForOldFunction, 16) == false)
        {
            LOGI("change new entry page property fail.");
            break;
        }

        //拷贝原指令到内存块中
        memcpy(pNewEntryForOldFunction, pstInlineHook->szbyBackupOpcodes, 8);
        //拷贝跳转指令到内存块中
        if(BuildArmJumpCode(pNewEntryForOldFunction + 8, pstInlineHook->pHookAddr + 8) == false)
        {
            LOGI("build jump opcodes for new entry fail.");
            break;
        }

        //填充shellcode里stub的回调地址
        *(pstInlineHook->ppOldFuncAddr) = pNewEntryForOldFunction;

        bRet = true;
        break;
    }

    return bRet;
}

/**
 * 3. 覆盖HOOK点的指令，跳转到桩函数的位置
 * @param  pstInlineHook inlinehook信息
 * @return 原地跳转指令是否构造成功
 */
bool RebuildHookTarget(INLINE_HOOK_INFO* pstInlineHook)
{
    bool bRet = false;

    while(1)
    {
        if(pstInlineHook == NULL)
        {
            LOGI("pstInlineHook is null");
            break;
        }

        //修改原位置的页属性，保证可写
        if(ChangePageProperty(pstInlineHook->pHookAddr, 8) == false)
        {
            LOGI("change page property error.");
            break;
        }

        //覆盖原指令为跳转指令
        if(BuildArmJumpCode(pstInlineHook->pHookAddr, pstInlineHook->pStubShellCodeAddr) == false)
        {
            LOGI("build jump opcodes for new entry fail.");
            break;
        }

        bRet = true;
        break;
    }

    return bRet;
}