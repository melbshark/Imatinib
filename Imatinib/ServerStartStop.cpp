//////////////////////////////////////////////////////////////////////
// Authored by AmesianX in powerhacker.net.
// -------------------------------------------------------------------
//////////////////////////////////////////////////////////////////////
#define _IMATINIB_
#include "Imatinib.h"
#include "include/myinttypes.h"
#include "include/capstone.h"

#pragma comment(lib, "capstone_dll.lib")

// ����� �������� ����
DBGDATA dbg;

// ���� ���������� �����µ� ���̳ʸ� ��Ʈ���� ã�� ���Ѵٸ�, �װ�
// ��ġ�� DLL �� �ε��� �ȵƱ� �����̹Ƿ� �����ε� ���Ѽ� ��ġ�ؾ��Ѵ�.
char* NeededDlls[] = { "wwlib.dll", NULL };

extern CRITICAL_SECTION cs;

// Capston ����
csh handle;

cs_arch arch;
cs_mode mode;

size_t size;
char *comment;
unsigned char *code;

cs_opt_type opt_type;
cs_opt_value opt_value;

/*
ENG: If you use VC++ 6.0, you must install "MICROSOFT PLATFORM SDK FOR WINDOWS SERVER 2003 R2".
KOR: ����, VC++ 6.0 �� ������̶�� MICROSOFT PLATFORM SDK FOR WINDOWS SERVER 2003 R2 �� ��ġ�ؼ�
     ������ Tools->Options->Include Files ���� ���� �ֻ����� �������ְ� �������ؾߵ˴ϴ�.

ENG: I tested only in VC++ 6.0. Recommended VC++ 6.0.
KOR: ���� MSVC 2013 �� ���� ���� �����Ϸ��� ������ ������ ���Ƽ� �� ������� �ʽ��ϴ�.
     �׷��� 32 ��Ʈ ��ŷ�� �ٷ� ���� ������ VC++ 6.0 ������ �׽�Ʈ�մϴ�. ���� ����
     �����Ϸ��δ� ���� ȯ���� ������ �ʾ�����, ū ������ ���� �� �����ϴ�.

KOR: ���� ����� �� ������.. -_-;

<TEST>

Microsoft Office Word 2007 (���ϵ忡 �����ƴٴϴ� ���� ��ġ ���� ���� ����)

1. setdll.exe ������ ���� ������ �־���.
2. ���� ������ capstone.dll �� ���丮�� ���� �־��־�� ��.
3. ���� ������ �� ���� �ƴ϶�� Release ���丮�� �ִ� Imatinib.dll ������ ����ؾߵ�.
4. DebugView �� �Ѱ� ���� �ɼǿ��� [+] ���ڷ� ���͸� �ǵ��� ������.
5. C:\Program Files (x86)\Microsoft Office\Office12> setdll.exe /d:Imatinib.dll winword.exe
6. C:\Program Files (x86)\Microsoft Office\Office12> winword.exe c:\test.docx
*/

////////////////////////////////////////
// ServerStart
////////////////////////////////////////
BOOL PRIVATE ServerStart(HANDLE hModule)
{
    CString DBGMSG;

    dna = new DNA_STRUCTURES;
    memset(&dbg, 0, sizeof(_DBGDATA));
    memset(dna, 0, sizeof(DNA_STRUCTURES));

    dna->GetImageSize   = &GetImageSize;
    dna->GetBaseAddress = &GetBaseAddress;

    for (int i=0; NeededDlls[i] != NULL; i++)
    {
        if(LoadLibrary(NeededDlls[i]) == NULL) {
			DBGMSG.Format("[+][IMATINIB] LoadLibrary(%s) Failed\n", NeededDlls[i]);
			OutputDebugString(DBGMSG);
			break;
        }
    }

	/*
	dna->hProcess = FindWindowEx(NULL, NULL, "TFormImatinibCenter", "IDAImatinib");
	if (!dna->hProcess)
	{
#ifdef _DEBUG
		OutputDebugString("FindWindowEx is failed..");
#endif
		return FALSE;
	}

    DWORD dwThread;
    CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)DBG_CONNECT, (LPVOID)NULL, NULL, &dwThread);
    */

	if (DNA_FingerPrintList(0, 0, dna->DNA.Imatinib)) {

		InitializeCriticalSection(&cs);

        // Ư���� ���� ������ ���س���
		dna->DNA.Imatinib.tid = GetCurrentThreadId();

        // Capstone �ʱ�ȭ
        // Initialize Capstone Engine
	    if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle)) {
#ifdef _DEBUG
            DBGMSG.Format("[+][IMATINIB] Failed on cs_open() with error returned\n");
            OutputDebugString(DBGMSG);
#endif
		    return FALSE;
	    }

	    if (opt_type)
		    cs_option(handle, opt_type, opt_value);

	    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

        // ���� ������
        DNA_Injector(INST_CALL, (DWORD)&Imatinib_STUB, dna->DNA.Imatinib);
    }
    else {
#ifdef _DEBUG
        DBGMSG.Format("[+][IMATINIB] GetFingerprintList Failed\n");
        OutputDebugString(DBGMSG);
#endif
		return FALSE;
    }

    return TRUE;
}

/////////////////////////////
// ServerStop
/////////////////////////////
BOOL PRIVATE ServerStop(void)
{
    // Capstone ����
	cs_close(&handle);

    DeleteCriticalSection(&cs);

    for (int i=0; NeededDlls[i] != NULL; i++) FreeLibrary(GetModuleHandle(NeededDlls[i]));

    delete dna;

    return TRUE;
}

///////////////////
// Dummy
///////////////////
VOID EXPORT Dummy()
{
    return;
}
