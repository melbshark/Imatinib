//////////////////////////////////////////////////////////////////////
// Authored by AmesianX in powerhacker.net.
// -------------------------------------------------------------------
//////////////////////////////////////////////////////////////////////
#define _IMATINIB_
#include "Imatinib.h"
#include "direct.h"

CAppModule _Module;

DNA_STRUCTURES *dna;

CRITICAL_SECTION cs;

BOOL ProcessAttach(HMODULE hDll);
BOOL ProcessDetach(HMODULE hDll);
BOOL ThreadAttach(HMODULE hDll);
BOOL ThreadDetach(HMODULE hDll);

BOOL APIENTRY DllMain(HANDLE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    /*
    char Path[255];
    GetModuleFileName(NULL, Path, 255);    
    
    char *ptr = strrchr(Path, '\\');

    CString FileName = ptr + 1;

    FileName.MakeLower();
    if (FileName == "ida.exe")
    {
        HMODULE hHandle = GetModuleHandle("ida.wll");
        if (hHandle == NULL) return TRUE;
        // FreeLibraryAndExitThread((HINSTANCE)hModule, 1);
    }
    */

    switch (ul_reason_for_call)
    {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls((HINSTANCE)hModule);
#ifdef _DEBUG
            OutputDebugString(""[+][IMATINIB] DLL_PROCESS_ATTACH\n");
#endif
            fflush(stdout);
            Sleep(50);
            Sleep(50);
            DetourRestoreAfterWith();
            ProcessAttach((HINSTANCE)hModule);
            break;

        case DLL_PROCESS_DETACH:
#ifdef _DEBUG
            OutputDebugString(""[+][IMATINIB] DLL_PROCESS_DETACH\n");
#endif
            ProcessDetach((HINSTANCE)hModule);
            break;

        case DLL_THREAD_ATTACH:
#ifdef _DEBUG
            OutputDebugString(""[+][IMATINIB] DLL_THREAD_ATTACH\n");
#endif
            ThreadAttach((HINSTANCE)hModule);
            break;

        case DLL_THREAD_DETACH:
#ifdef _DEBUG
            OutputDebugString(""[+][IMATINIB] DLL_THREAD_DETACH\n");
#endif
            ThreadDetach((HINSTANCE)hModule);
            break;
    }

    return TRUE;
}
