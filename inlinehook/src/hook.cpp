#include <vector>

extern "C"
{
    #include "../include/Ihook.h"
}

//声明函数在加载库时被调用,也是hook的主函数
void ModifyIBored() __attribute__((constructor));

typedef std::vector<INLINE_HOOK_INFO*> InlineHookInfoPVec;
static InlineHookInfoPVec gs_vecInlineHookInfo;     //管理HOOK点

/**
 *  对外inline hook接口，负责管理inline hook信息
 *  @param  pHookAddr     要hook的地址
 *  @param  onCallBack    要插入的回调函数
 *  @return inlinehook是否设置成功（已经设置过，重复设置返回false）
 */
bool InlineHook(void *pHookAddr, void (*onCallBack)(struct pt_regs *))
{
    bool bRet = false;

    if(pHookAddr == NULL || onCallBack == NULL)
    {
        return bRet;
    }

    //填写hook点位置和用户自定义回调函数
    INLINE_HOOK_INFO* pstInlineHook = new INLINE_HOOK_INFO();
    pstInlineHook->pHookAddr = pHookAddr;
    pstInlineHook->onCallBack = onCallBack;

    if(HookArm(pstInlineHook) == false)
    {
        LOGI("HookArm fail.");
        delete pstInlineHook;
        return bRet;
    }

    gs_vecInlineHookInfo.push_back(pstInlineHook);
    return true;
}

/**
 *  用户自定义的回调函数，修改r0寄存器大于300
 */
void EvilHookStubFunctionForIBored(pt_regs *regs)
{
    LOGI("In Evil Hook Stub.");
    regs->uregs[0] = 0x333;
}

/**
 *  1.Hook入口
 */
void ModifyIBored()
{
    LOGI("In IHook's ModifyIBored.");
    void* pModuleBaseAddr = GetModuleBaseAddr(-1, "loop");
    if(pModuleBaseAddr == 0)
    {
        LOGI("get module base error.");
        return;
    }

    //模块基址加上HOOK点的偏移地址就是HOOK点在内存中的位置
    uint32_t uiHookAddr = (uint32_t)pModuleBaseAddr + 0x3349c;
//    LOGI("uiHookAddr is %X", uiHookAddr);
    LOGI("uiHookAddr is %X");

    //HOOK函数
    InlineHook((void*)(uiHookAddr), EvilHookStubFunctionForIBored);
}

int main(){
    puts("start!");
}