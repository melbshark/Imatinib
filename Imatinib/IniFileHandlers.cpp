//////////////////////////////////////////////////////////////////////
// Authored by AmesianX in powerhacker.net.
// -------------------------------------------------------------------
//////////////////////////////////////////////////////////////////////
#define _IMATINIB_
#include "Imatinib.h"

/////////////////////////////////////////////////////////////////////////////
// GetFingerprintList
/////////////////////////////////////////////////////////////////////////////
BOOL PRIVATE DNA_FingerPrintList(int mode, int index, FINGERPRINTSTRUCT &dna)
{
    int i, nFields = 0;

#ifdef _DEBUG
    CString DBGMSG;
#endif

    char DNA_Sequences[1][512];

    // Binary's DNA Sequence
    // strcpy(DNA_Sequences[0], "wwlib.dll,6,23,68000200008D7E0C5756FFB5xxxxxxxx50FF15xxxxxxxx85C074396A0153FFB5xxxxxxxxE8xxxxxxxx8946088B07");
    // strcpy(DNA_Sequences[1], "wwlib.dll,7,30,8BBDECFBFFFF576892000000E8xxxxxxxx3BC30F85D2FEFFFF8B078B4010FF30E8xxxxxxxx8985F0FBFFFFE972FFFFFF");

    // ù��° ��: "��ġ�� EXE �� DLL ���ϸ�"
    
    // �ι�° ��: "��ġ�� ���� �ν�Ʈ���� ������ (5����Ʈ �̻����� �����ؾ� ��. �۴ٸ� ��ɾ� ��� ��������)"
    
    // ����° ��: "���� �������� ���̳ʸ� ��Ʈ������ �α��� ������ 1 ����Ʈ�� ���� ��� �������� ��������"
    //            �̷��� ���� �ϴ� ���� ��ġ�� ��ġ�� ��Ȯ���� �ø��� ���ؼ� �յ��� ��ɾ ���ֱ� ������,
    //            ������ ���� �� �� �ְ� ���� ����.

    // �׹�° ��: "���̳ʸ��� ��Ʈ��"
    //            ���̳ʸ� ��Ʈ���� xxxx ó�� ����ŷ�ؼ� �������� �� ����. ����ŷ�� �ϴ� �κ���
    //            ���� ���ص� ����� ����. ������� E8 00 00 00 00 ���� 00 00 00 00 �κ��� ������
    //            ����ؼ� ���� ���� ���� �����Ƿ� �� �κ��� xx xx xx xx ó���� ���ִµ� �� �κ�
    //            ���� ��� �κп��� �̷��� ó���� ������ ������ ���̳ʸ� ��Ʈ���� ã�� ���ϴ�
    //            ��Ȳ�� ����. �̷����� ��Ȳ���� ���� � ���� Rebasing (�ּ� ���ġ)�� �Ǵ���
    //            ������ �����غ��� �ٽ� ���̳ʸ� ��Ʈ���� ����ŷ�� �ϳ��� �߰����ָ鼭 ������ ��.

    // �׹�° �� �ٸ��� ����: �׹�° ���� !NameOfFuntion ó�� �Լ� �̸��� �������־ ��. �Ǵ� ���� ��ȣ��
    //                        !10005 ó�� �������־ ��. �ƴϸ� �ƿ� �׳� �ּ���ü�� #6fba80b4 ó�� �־ ��.
    //                        �׷��� �Ǹ� ��׵鵵 ������ �� �ּ��̱� ������ �������� �������� ���ϴ��� �� �� ��
    //                        �ְԵǴ� ����. ����, ��ġ�� ����� ����� �� �� �������־�� ��.

    // �� ������ ������ �־��µ��� �� �𸣰ڴٸ� powerhacker.net �� �����ؼ� Art of Hooking ������
    // �о�� ģ���ϰ� ������ ���Ҵ�. �װ͵� �ſ� �������ϰ� ���̴�. ���ġ �������� ��� �� �ٷ�
    // �����ϱ� �о�� ���ذ� �� �� ���̴�.
    strcpy(DNA_Sequences[0], "wwlib.dll,5,0,3BC38946207473663918746E50FF15xxxxxxxx50FF7620E8xxxxxxxx3BC38985xxxxxxxx745468000200008D7E0C5756FFB5xxxxxxxx50FF15xxxxxxxx85C07439");
    
    strcpy(dna.Name, DNA_Sequences[index]);
    if (!strlen(DNA_Sequences[index]))
    {
#ifdef _DEBUG
        DBGMSG.Format("[+][IMATINIB] Can't find fingerprint for '%s'", DNA_Sequences[index]);
        OutputDebugString(DBGMSG);
#endif

        return FALSE;
    }
    
    for (i=0; DNA_Sequences[index][i]; i++)
        if (DNA_Sequences[index][i] == ',')
            nFields++;
        
    if (nFields != 3)
    {

#ifdef _DEBUG
        DBGMSG.Format("[+][IMATINIB] Fingerprint for '%s'", DNA_Sequences[index]);
        OutputDebugString(DBGMSG);
#endif

        return FALSE;
    }
    
    for (; i != 0; i--)
    {
        if (DNA_Sequences[index][i] == ',')
        {
            DNA_Sequences[index][i] = 0;
            nFields--;
            
            switch (nFields)
            {
            case 2:
                strcpy(dna.FingerPrint, &DNA_Sequences[index][i+1]);
                break;
            case 1:
                dna.Offset=atoi(&DNA_Sequences[index][i+1]);
                break;
            case 0:
                dna.PatchSize=atoi(&DNA_Sequences[index][i+1]);
                break;
            }
        }
    }

    strcpy(dna.ModuleName, DNA_Sequences[index]);

    if ((dna.AddressFound=GetMemoryAddressFromPattern(dna.ModuleName, dna.FingerPrint, dna.Offset)) < 0x100)
    {
#ifdef _DEBUG
        DBGMSG.Format("[+][IMATINIB] Unable to find location for '%s'.", DNA_Sequences[index]);
        OutputDebugString(DBGMSG);
#endif
 
        return FALSE;
    } else {
#ifdef _DEBUG
        DBGMSG.Format("[+][IMATINIB] Found '%s' at %.8x", DNA_Sequences[index], dna.AddressFound);
        OutputDebugString(DBGMSG);
#endif

        return TRUE;
    }
}