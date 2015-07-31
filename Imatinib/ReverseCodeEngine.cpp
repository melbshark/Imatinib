//////////////////////////////////////////////////////////////////////
// Authored by AmesianX in powerhacker.net.
// -------------------------------------------------------------------
//////////////////////////////////////////////////////////////////////
#define _IMATINIB_
#include "Imatinib.h"
#include "include/myinttypes.h"
#include "include/capstone.h"

// ����� �������� ����
extern DBGDATA dbg;

// Capston ����
extern csh handle;

extern cs_arch arch;
extern cs_mode mode;

extern size_t size;
extern char *comment;
extern unsigned char *code;

extern cs_opt_type opt_type;
extern cs_opt_value opt_value;

extern CRITICAL_SECTION cs;

extern void dumpcode(unsigned char *buff, int len);



static void print_string_hex(char *comment, unsigned char *str, size_t len)
{
    CString DBGMSG;
    CString Temp;

	unsigned char *c;

	DBGMSG.Format("[+][IMATINIB] %s", comment);

	for (c = str; c < str + len; c++) {
	    Temp.Format("0x%02x ", *c & 0xff);
        DBGMSG += Temp;
	}

    Temp.Format("\n");
    DBGMSG += Temp;
    OutputDebugString(DBGMSG);
}

static void print_insn_detail(csh ud, cs_mode mode, cs_insn *ins)
{
    CString DBGMSG;

	int count, i;
	cs_x86 *x86;

	if (ins->detail == NULL)
		return;

	x86 = &(ins->detail->x86);

	print_string_hex("        Prefix:", x86->prefix, 4);

	print_string_hex("        Opcode:", x86->opcode, 4);

	DBGMSG.Format("[+][IMATINIB]         rex: 0x%x\n", x86->rex);
    OutputDebugString(DBGMSG);

	DBGMSG.Format("[+][IMATINIB]         addr_size: %u\n", x86->addr_size);
    OutputDebugString(DBGMSG);
	DBGMSG.Format("[+][IMATINIB]         modrm: 0x%x\n", x86->modrm);
    OutputDebugString(DBGMSG);
	DBGMSG.Format("[+][IMATINIB]         disp: 0x%x\n", x86->disp);
    OutputDebugString(DBGMSG);

	// SIB is not available in 16-bit mode
	if ((mode & CS_MODE_16) == 0) {
		DBGMSG.Format("[+][IMATINIB]         sib: 0x%x\n", x86->sib);
        OutputDebugString(DBGMSG);
        if (x86->sib_base != X86_REG_INVALID) {
			DBGMSG.Format("[+][IMATINIB]                 sib_base: %s\n", cs_reg_name(handle, x86->sib_base));
            OutputDebugString(DBGMSG);
        }
        if (x86->sib_index != X86_REG_INVALID) {
			DBGMSG.Format("[+][IMATINIB]                 sib_index: %s\n", cs_reg_name(handle, x86->sib_index));
            OutputDebugString(DBGMSG);
        }
        if (x86->sib_scale != 0) {
			DBGMSG.Format("[+][IMATINIB]                 sib_scale: %d\n", x86->sib_scale);
            OutputDebugString(DBGMSG);
        }
	}

	// SSE code condition
	if (x86->sse_cc != X86_SSE_CC_INVALID) {
		DBGMSG.Format("[+][IMATINIB]         sse_cc: %u\n", x86->sse_cc);
        OutputDebugString(DBGMSG);
	}

	// AVX code condition
	if (x86->avx_cc != X86_AVX_CC_INVALID) {
		DBGMSG.Format("[+][IMATINIB]         avx_cc: %u\n", x86->avx_cc);
        OutputDebugString(DBGMSG);
	}

	// AVX Suppress All Exception
	if (x86->avx_sae) {
		DBGMSG.Format("[+][IMATINIB]         avx_sae: %u\n", x86->avx_sae);
        OutputDebugString(DBGMSG);
	}

	// AVX Rounding Mode
	if (x86->avx_rm != X86_AVX_RM_INVALID) {
		DBGMSG.Format("[+][IMATINIB]         avx_rm: %u\n", x86->avx_rm);
        OutputDebugString(DBGMSG);
	}

	count = cs_op_count(ud, ins, X86_OP_IMM);
	if (count) {
		DBGMSG.Format("[+][IMATINIB]         imm_count: %u\n", count);
        OutputDebugString(DBGMSG);
		for (i = 1; i < count + 1; i++) {
			int index = cs_op_index(ud, ins, X86_OP_IMM, i);
			DBGMSG.Format("[+][IMATINIB]                 imms[%u]: 0x%"PRIx64 "\n", i, x86->operands[index].imm);
            OutputDebugString(DBGMSG);
		}
	}

    if (x86->op_count) {
		DBGMSG.Format("[+][IMATINIB]         op_count: %u\n", x86->op_count);
        OutputDebugString(DBGMSG);
    }
	for (i = 0; i < x86->op_count; i++) {
		cs_x86_op *op = &(x86->operands[i]);

		switch((int)op->type) {
			case X86_OP_REG:
				DBGMSG.Format("[+][IMATINIB]                 operands[%u].type: REG = %s\n", i, cs_reg_name(handle, op->reg));
                OutputDebugString(DBGMSG);
				break;
			case X86_OP_IMM:
				DBGMSG.Format("[+][IMATINIB]                 operands[%u].type: IMM = 0x%"PRIx64 "\n", i, op->imm);
                OutputDebugString(DBGMSG);
				break;
			case X86_OP_FP:
				DBGMSG.Format("[+][IMATINIB]                 operands[%u].type: FP = %f\n", i, op->fp);
                OutputDebugString(DBGMSG);
				break;
			case X86_OP_MEM:
				DBGMSG.Format("[+][IMATINIB]                 operands[%u].type: MEM\n", i);
                OutputDebugString(DBGMSG);
                if (op->mem.segment != X86_REG_INVALID) {
					DBGMSG.Format("[+][IMATINIB]                         operands[%u].mem.segment: REG = %s\n", i, cs_reg_name(handle, op->mem.segment));
                    OutputDebugString(DBGMSG);
                }
                if (op->mem.base != X86_REG_INVALID) {
					DBGMSG.Format("[+][IMATINIB]                         operands[%u].mem.base: REG = %s\n", i, cs_reg_name(handle, op->mem.base));
                    OutputDebugString(DBGMSG);
                }
                if (op->mem.index != X86_REG_INVALID) {
					DBGMSG.Format("[+][IMATINIB]                         operands[%u].mem.index: REG = %s\n", i, cs_reg_name(handle, op->mem.index));
                    OutputDebugString(DBGMSG);
                }
                if (op->mem.scale != 1) {
					DBGMSG.Format("[+][IMATINIB]                         operands[%u].mem.scale: %u\n", i, op->mem.scale);
                    OutputDebugString(DBGMSG);
                }
                if (op->mem.disp != 0) {
					DBGMSG.Format("[+][IMATINIB]                         operands[%u].mem.disp: 0x%" PRIx64 "\n", i, op->mem.disp);
                    OutputDebugString(DBGMSG);
                }
				break;
			default:
				break;
		}

		// AVX broadcast type
        if (op->avx_bcast != X86_AVX_BCAST_INVALID) {
			DBGMSG.Format("[+][IMATINIB]                 operands[%u].avx_bcast: %u\n", i, op->avx_bcast);
            OutputDebugString(DBGMSG);
        }

		// AVX zero opmask {z}
        if (op->avx_zero_opmask != false) {
			DBGMSG.Format("[+][IMATINIB]                 operands[%u].avx_zero_opmask: TRUE\n", i);
            OutputDebugString(DBGMSG);
        }

		DBGMSG.Format("[+][IMATINIB]                 operands[%u].size: %u\n", i, op->size);
        OutputDebugString(DBGMSG);
	}

	DBGMSG.Format("[+][IMATINIB] \n");
    OutputDebugString(DBGMSG);
}

// SizeNextInst ���� ���� ��ŷ�� ���� ��ġ�󿡼��� ù��° �ν�Ʈ���� ������ ��.
// ��ŷ�� �� ���� 5 ����Ʈ���� ������ �ΰ��� ����� �Ѳ����� ��ġ�� ��찡 �ֱ�
// ������ ù��° ��� ����� ���ؼ� �Ѱ���. �� ���� SizeNextInst ���̰� �� ����
// ��ŷ�ɶ� ������ �� ��ġ�� �������� dna.PatchSize ���� ���� 5 ���� �۾ƾ� ��.
// �׷��� ������ ����� ��ġ�� ������ �ִٴ� �ǹ��̹Ƿ� ������ ����� �����ϸ� ��.
DWORD GetSizeNextFetchInst(FINGERPRINTSTRUCT &dna, DWORD SizeNextInst)
{
#ifdef _DEBUG
    CString DBGMSG;
#endif

    // �� ��ġ�� ���� ũ�⿡�� ���� �ν�Ʈ���� ������ ũ�⸦ ���� �� 5 ����Ʈ
    // ũ�Ⱑ���� ������ ������ Ȯ���ϱ� ���ؼ� ���� ��ġ�� �ν�Ʈ���� ������
    // �𽺾�����ؼ� �������ߵȴ�. �� ��ġ�� ������� ���� �ν�Ʈ������
    // SizeNextInst ���� ���� 5 ������ ���� ���Եȴ�. ����, 7 ����Ʈ�� �� ��ġ
    // �ؼ� ����߰� ���� �ν�Ʈ������ �������� 2 ����Ʈ�� 5 ����Ʈ�� ���յ�
    // ��Ȳ�̶�� 2 ��ŭ�� ���� �ν�Ʈ���� �������̹Ƿ�, 2 ��ŭ ���� 5 �� ����
    // ���� �ִ�. �̷� ��쿡�� ���������� ��ġ�� ������ ����ϴٴ� �ǹ��̹Ƿ�
    // ����� �����ϰ� �����Ѵ�. �׷��� �ʰ� ���� 6 ����Ʈ���� 2 ����Ʈ�� ����
    // �̰� 4 ����Ʈ�� ������ ���̶�� 5 ����Ʈ�� �ȵǼ� ���ڶ�Ƿ� ������ ����
    // �ν�Ʈ���� ����� ���ļ� ��ġ�������� ����ؾߵȴ�. �׷���, �ϴ� 4 ����Ʈ
    // ���� ���� ����ִ� ������ �Ǵ� ���̹Ƿ� �ʱⰪ���� ����Ѵ�. �׷��� ������
    // ���ʿ��ϰ� ���� �ν�Ʈ������ �������� ��ƹ����ԵǹǷ� ���񰡵ȴ�.
    DWORD DNA_InjectionSize = dna.PatchSize - SizeNextInst;
    if (DNA_InjectionSize >= 5)
        return DNA_InjectionSize;

    // ���⼭ �ּҴ� �ܼ��� �������༭ ǥ���ϴ� �뵵�� ����Ѵ�. �̶� �ּҴ� �翬��
    // dna.AddressFound(��ŷ�ҷ��� ó�� ã�� ����) + dna.PatchSize(�� ��ġ�� ������)
    // �ٷ� ������ �������� ��ġ�� �ּҴ� �����ϴ�. ���⼭���� 16 ����Ʈ�� �� �о
    // �𽺾������ ���� �Ŀ� �˳��� �ν�Ʈ���� ������ Ȯ���Ǹ� �ߴ��Ѵ�. �˳���
    // ������� 5 ����Ʈ�� ����ϴ�.
    uint64_t address = dbg.reg.eip + dna.PatchSize;
	cs_insn *insn;
	size_t count;

    // ���̳ʸ� ����ũ ���� ��Ī���� ã�� ��ġ�� ���� �ּҿ��� ��ġ�� ������
    // ��ŭ�� ���� ��ġ���� ��ɾ Ž���ذ��鼭 5 ����Ʈ ������ Ȯ���ϱ�
    // �����ؾߵ�. �� ���� dna.AddressFound + dna.PatchSize �� �Ǹ� �� ����
    // �������� �� ������ ���� �� ��ƾ�� ����ɶ��� �̹� ���� ���� �ּ� ������
    // ��ġ�� ��Ȳ��. �׷��Ƿ� �ܼ��� �׳� �����ϸ� ��ġ�� �ڵ带 �𽺾���ϱ�
    // ������, �� �� ��ġ�� ������ ��ŭ�� �ǳʶٰ� �м��Ѵ�. ����, �� ��ġ��
    // ����� �˰��ֱ� ������ �̷����ص� �����ϴ�. ���� ��ɾ� �ΰ��� ������
    // ���·� 5 ����Ʈ���� ū ������ Ȯ������ Ȯ���� ũ�� ������, �� ��ġ��
    // ������� ���� �������� � ��� �ΰ��� ���������� ����� ���ϸ�
    // ����� ���� ���� ������ �ٷ� ���� �ڵ忡�� ������. SizeNextInst ����
    // �� ���ε� �� �� ���õ� �𽺾������ ������ ���س� ���̴�. �׷��Ƿ�
    // �̹� ��ŷ�Ǿ� ��ġ�Ǿ� �ִ� ������ dna.AddressFound ��ġ���� �ϴ� ��
    // ��ġ�� ������ŭ �ǳʶپ �м��� ������ ���ڶ� �뷮�� ä���� �Ѵ�.
    // ���⼭ ���ڶ� ���� �̹� �˰� �ִ� ������ ������ >= 5 �� ������ �־���
    // ������ ���� ��ġ�� ������ ���ġ ������ �˰� �ִ� ��Ȳ�̴�.
	// (unsigned char *)(dbg.reg.eip + dna.PatchSize),
    // �˳���� 16 ����Ʈ�� �� �����ͼ� �𽺾������ �¿��. ��ġ�� ��ŭ
    // ����� �ν�Ʈ������ ó������ �߰ߵ� Ȯ���� ������ �׷��� ���� ��쵵
    // �����. �׷��Ƿ� �˳���Ƽ� 16 ����Ʈ�� �� �о�ͼ� �м���Ų��.
    // ������ �׽�Ʈ �غ��� 14 ����Ʈ ������ �ص� �ȴ�. 14 ����Ʈ ���� ������
    // ������.
    count = cs_disasm(handle, (unsigned char *)(dbg.reg.eip + dna.PatchSize), 14, address, 0, &insn);
	if (count) {
		size_t j;

		for (j = 0; j < count; j++) {
#ifdef _DEBUG
            DBGMSG.Format("[+][IMATINIB] 0x%0.8I64X:    %s    %s\n",
                           insn[j].address,
                           insn[j].mnemonic,
                           insn[j].op_str);
            
            OutputDebugString(DBGMSG);

            print_insn_detail(handle, CS_MODE_32, &insn[j]);
#endif

            // ó���� �ʱⰪ���� �� ������� ���� 16 ����Ʈ�� �о�ͼ�
            // �𽺾���� �������� ���� ù��° ����� ���ؼ� ����� 5 ����
            // ū�� Ȯ���ϰ� ũ�ٸ� ����� ������ ���õǾ����� �극��ũ�� �ɰ�
            // ������. �׷���, �׷��� �ʴٸ� �𽺾������ �ѹٲ� �� ���Ƽ�
            // ���� ����� ����� ����. �׸��� ������ ������ ���غ���
            // ���ϴ� ������ ���õɶ����� ���ٰ� ����������. 5 ����Ʈ�� ���
            // �ϱ� ������ ���� ��κ� �ιٲ� ���� �̻��� �� Ȯ���� 0.0001%
            // ������ ���̴�.
            DNA_InjectionSize += insn[j].size;

            if (DNA_InjectionSize >= 5) {
                break;
            }
        }

		// free memory allocated by cs_disasm()
		cs_free(insn, count);
	} else {
#ifdef _DEBUG
		DBGMSG.Format("[+][IMATINIB] ****************\n");
        OutputDebugString(DBGMSG);
		DBGMSG.Format("[+][IMATINIB] ERROR: Failed to disasm given code!\n");
        OutputDebugString(DBGMSG);
#endif
	}

#ifdef _DEBUG
	DBGMSG.Format("[+][IMATINIB] \n");
    OutputDebugString(DBGMSG);
#endif

    return DNA_InjectionSize;
}

DWORD GetNextInst(FINGERPRINTSTRUCT &dna)
{
    // �� �Լ��� ������ ���� ����. ���� ��ŷ���� ��ġ�� ������ ��ġ�� �� ������
    // ��ġ������ ��� �ڵ尡 ���� ��� �ν�Ʈ������ ���յ� ���³ĸ� �˾Ƴ���
    // ���ؼ� ����� �ڵ��̴�. �׷��� �ؼ� ���յ� ��ɾ��� ��쿡�� �и����Ѽ�
    // ����� ���� �ϴµ�, ������ ���յ� ��ɾ��� ù��° ��� ����� �˸�
    // �ȴ�. �ֳĸ� �������� ������Ѽ� �ν�Ʈ������̼��ؾ��� ��ġ�� ���� (��ŷ��)
    // ��� �������� ��ġ���� �ϱ� �����̴�. �׷��� �̸� �� ������ ��ġ��ų���� ����
    // �ν�Ʈ���� ����� �˸�ȴ�. �׸�ŭ ������Ű�� ��ġ��ų �������� ������ ������
    // ���鼭 ó���ϹǷ� �׶� �ٽ� ������ ���̱� �����̴�. �� �Լ��� �� ������ ����
    // �ڵ��̴�. �ϴ�, �� �Լ��� ���� ��ŷ�ɾ ��ŷ ��ƾ�ӿ� ���� ������ ������
    // ��ɾ ������ ������ ó�� ����� ����� ��� �Լ���� �˰� ������ �ȴ�.
    // ���� ���Ѽ� ���� ��ġ�� �ٽ� ����ŷ�� �ɱ� ���ؼ��̴�. ����, ����ŷ�� �ٽ�
    // �ɷ��� ��ŷ�� ��ġ�� ������ ������� üũ�ؾߵǴµ� �� �ڵ�� ���� �̹� ����
    // �س���. GetSizeNextFetchInst �Լ����� �� GetNextInst �Լ��� ����ؼ� ����ϸ�
    // ��ġ�� ������ Ȯ���Ѵ�.

// #ifdef _DEBUG
    CString DBGMSG;
// #endif

    DWORD SizeNextInst = -1;

    // �ּ� ��ü�� ǥ�ÿ��̴�. �׷��Ƿ� ���� ������ �൵ �ȴ�. �ش� ��ġ�� ���̳ʸ�
    // ���븸 ������ϸ� �ȴ�.
    uint64_t address = dbg.reg.eip;
	cs_insn *insn;
	size_t count;

    // ���⼭ dna.DNA_SourceCode �� ��� �ڵ��̴�. ���� �������� ��ġ�ϴ���
    // ����� �ٸ� ���� ������ �ص� ���ε�, �׳� ������ DNA_SourceCode ���
    // �̸��� �ٿ��� ����ü�ȿ��ٰ� ���۸� ���� �����صξ���.
    // �̰������� �ݵ�� �� ���� ��ߵǴ� ������ �ִµ�, �ֳĸ� �̹� �� ��ƾ��
    // ����Ǵ� ���������� ���������� �з��ִ�. ��, �ζ��� ��ġ�� �� ���¿���
    // ���� ����Ǵ� ���̹Ƿ� ���������� �ڵ�� ��ŷ�ڵ�� ��ġ�Ǿ� �����Ƿ�
    // �����س��� �����ڵ带 �ְ� �𽺾������ ���Ѽ� ���� �ڵ尡 ��ɾ�
    // ��� ���յ� ���³ĸ� �˾Ƴ��� �Ѵ�. �ֳĸ�, ������ ��� ��ġ�� �̸�
    // ��ġ�� �ɱ� ���ؼ��ε� ��ɾ ���յǾ� ��ġ������ ���� ���¶�� ������
    // � ��ɾ ���յǾ��ְ� ������� ���̳İ� �ʿ��ѵ�, �̹� ���� ������
    // �и������̱� ������ ���� �ڵ� ������ �������ְ� �𽺾������ ���Ѽ�
    // �м��ϸ� �ȵȴ�. �����ص� �ڵ带 �м���Ű�� ������ ��ġ�� �� �����Ʈ��
    // ��ġ���� ����� �������ְ��ֱ� ������ �� ��ġ�� ������� �����ص� ���۸�
    // �������༭ ����� �м��ؼ� ���󳽴�. ����, ���ʿ� ������ �������ٶ��� ��
    // ��ġ ����� �������� �־�����, ���ݺ��ʹ� �ν�Ʈ������̼� �Ǹ鼭 �ڵ�
    // ���� ��ġ����� ���ؼ� �����ϸ� ��� ���޾� ��ġ�ϸ鼭 ����ǵ��� ¥����
    // ���ؼ� �̷��ڵ带 ���� ���̴�.
	count = cs_disasm(handle, (unsigned char *)dna.DNA_SourceCode, dna.PatchSize, address, 0, &insn);
	if (count) {
		size_t j;

		for (j = 0; j < count; j++)
        {
            if (j == 0)
            {
// #ifdef _DEBUG
		        DBGMSG.Format("[+][IMATINIB] 0x%0.8I64X:    %s    %s\n",
                               insn[j].address - GetBaseAddress(dna.ModuleName),
                               insn[j].mnemonic,
                               insn[j].op_str);

                OutputDebugString(DBGMSG);

//              print_insn_detail(handle, CS_MODE_32, &insn[j]);
// #endif
                SizeNextInst = insn[j].size;

                cs_x86 *x86;
                x86 = &(((cs_insn *)(&insn[j]))->detail->x86);
                int index = 1;
                int count = cs_op_count(handle, &insn[j], X86_OP_IMM);
                if (count) {
                    index = cs_op_index(handle, &insn[j], X86_OP_IMM, 1);
                }

                // ���� ��� �귣ġ�� ó���ϰ� �ص��� ������. ���⿡ �귣ġ
                // ó���� �ص��� ������ ���� ��ü�� ���� ��Ű�� ����̱� ������
                // ���� ���� ��ġ�� �ζ��� ��ġ�� ���� ���ϰ� ��. �׷��� ������
                // ���⿡ �ִ� ���� ó�� �κ��� �ϳ� ������ ������Ѻ��� �� ���
                // ��� ���Ŀ��� ����� ���̻� �ȳ��� ����. ���α׷��� ������ ��
                // ������ �ν�Ʈ���� ����� ���̻� �ȳ��´ٴ� ���� ���� �Ϸ���
                // ������ �ζ��� ��ġ�� ���� ���߱� ������ ��ŷ ��ƾ�� Ÿ�� �ٽ�
                // ������ ���ϰ� ���α׷��� ��� ����ǰ� �ִ� �����. �׷���
                // ������ ���⿡�� ó���ϴ� ���� ��ƾ���� ���� ������ ��Ű����
                // �ǵ��� �ְ� ���ÿ� ������ ������ �ζ��� ��ġ�� �ɷ��� ����.
                // �׷��� �翬�� eflag ���� üũ�ؼ� ���� ������ ������ ������ ��
                // �ִ� ���� �ƴ��� eflag ���� ���� �� üũ�ؼ� ������ �� ������
                // ������ ���� ��ġ�� �ɰ� ���� �� �� ���� ������ ���� �ν�Ʈ����
                // ���� �����ؼ� �ٸ� ���ο� �ζ��� ��ġ�� �ɾ�� ��. �̰� ���
                // �������� �Ͼ�� ��� �ζ��� ��ġ�Ǹ鼭 ��ŷ��ƾ ������ ���
                // ���������� ���� ������ ����.
                switch (x86->opcode[0])
                {
                case 0x70:  // JO :: OF = 1 (short jump opcodes)
                    {
                        BOOL OF = dbg.reg.eflags & X86_EFLAGS_OF ? 1 : 0;
                        if (OF)
                        {
                            dna.branch_jump = true;
                            dna.SavedPatchSize = dna.PatchSize;
                            dna.PatchSize = 0;
                            SizeNextInst = 0;
                            dbg.reg.eip = x86->operands[index].imm;
                        }
                    }
                    break;
                case 0x71:  // JNO :: OF = 0 (short jump opcodes)
                    {
                        BOOL OF = dbg.reg.eflags & X86_EFLAGS_OF ? 1 : 0;
                        if (OF == 0)
                        {
                            dna.branch_jump = true;
                            dna.SavedPatchSize = dna.PatchSize;
                            dna.PatchSize = 0;
                            SizeNextInst = 0;
                            dbg.reg.eip = x86->operands[index].imm;
                        }
                    }
                    break;
                case 0x72:  // JB, JNAE, JC :: CF = 1 (short jump opcodes)
                    {
                        BOOL CF = dbg.reg.eflags & X86_EFLAGS_CF ? 1 : 0;
                        if (CF)
                        {
                            dna.branch_jump = true;
                            dna.SavedPatchSize = dna.PatchSize;
                            dna.PatchSize = 0;
                            SizeNextInst = 0;
                            dbg.reg.eip = x86->operands[index].imm;
                        }
                    }
                    break;
                case 0x73:  // JNB, JAE, JNC :: CF = 0 (short jump opcodes)
                    {
                        BOOL CF = dbg.reg.eflags & X86_EFLAGS_CF ? 1 : 0;
                        if (CF == 0)
                        {
                            dna.branch_jump = true;
                            dna.SavedPatchSize = dna.PatchSize;
                            dna.PatchSize = 0;
                            SizeNextInst = 0;
                            dbg.reg.eip = x86->operands[index].imm;
                        }
                    }
                case 0x74:  // JE, JZ :: ZF = 1 (short jump opcodes)
                    {
                        // �����̳� �����̳� �� �Ȱ��� �����̶� ���⿡��
                        // �������. ���� �÷��� ���� ���ؼ� 1 �̸� ������
                        // ��Ŵ. �̶�, dna.branch_jump �� �������༭ �ڵ带
                        // ������ų�� �����ϵ��� ��. dbg.reg.eip ���� �ް�
                        // �ϰ� x86->operands[index].imm ��, ���� ���� ����
                        // �ش� �ּҰ����� �ٲٴ� �۾���. �Ϲ� ��ɵ��� ���
                        // dbg.reg.eip ���� ������Ų �ڵ� �������� �ٽ� �ǵ�����
                        // ���� ��ɾ ����ǵ��� �س��ٸ�, ���⼭�� �׷���
                        // ���� �׳� �ٷ� �����帧�� dbg.reg.eip �� �������༭
                        // ������������ �ٷ� ������ �س��� �Ŷ� �����.
                        // �̷��� �Ǹ� dna.PathSize ���� �� ����صΰ� �� ����
                        // 0 ���� ������. SizeNextInst �� 0 ���� ������.
                        // ������, �����ѵ� ������ �����ؼ� �帧�� �ٲ��ٰǵ�
                        // �׷����� �帧�� �ٲ�����µ� �ϴ� �ڵ带 ���� ���ѳ���
                        // �ٴ��� ������ �ؾ��� ���̱⿡ ����, ���ÿ� ������ �ٴ�
                        // �ּ� ��ġ���� �ζ��� ��ġ�� �ɾ���� ���߻�Ȳ�� �߻���.
                        // �ᱹ, dna.PatchSize ���� 0 ���� ���������� ���� �ڵ带
                        // �����ϰ� ���� �ּҷ� �۰ǵ�, ���� �ڵ忡�� dna.PatchSize
                        // ���� �����Ѵ� ����. �ڵ带 ¥�ٺ��� �� �����ϰ� �Ȱ�
                        // ���� �ζ��� ��ġ�� ������ ������ �����̴ϱ� �� ��������
                        // ��ġ�� ������ ������� ����Ҷ��� dna.PatchSize ���� 0
                        // �̾�߸� ��. �ֳĸ�, dna.PatchSize ���� ��ġ�� ���� ��
                        // �������ε� ��ɾ ��� ���ļ� ����� ���� ���� ���
                        // ������ ���� ������ְ� �ִ� ����. ���� ����� ���� �ִ�
                        // ��ɾ� ���̰� SizeNextInst ���ε� �� �� ��ŭ dna.PatchSize
                        // ���� ���ָ� ������ ���ؾ��� ��ɾ� ����� ���� �� �ֱ�
                        // ������. ������ �� �ΰ��� �۾��� �� �� ��ġ�� �ҷ��� ��Ȳ
                        // �̱� �����ε� ������ ������ġ, �ٸ� ������ �ް��� ������
                        // �������� ��ġ��. �ᱹ, ���⼭ ������ �߻��ϴ� ���� �ѷ�
                        // ��ġ ��������. �� ���� 0 �� �Ǿ�� �ϴµ� �ڵ带 ������ų
                        // ���� 0 �̸� �ȵȴٴ� ���. �ᱹ, ����� �صξ ������ų��
                        // ����� �� �ֵ��� dna.SavedPatchSize �� �����ص�.
                        // ���� ��ɾ �����ϱ� ���ؼ� ��ġ�� ���� dna.SavedPatchSize
                        // ���� ����ϰ� ������ ���� �ζ��� ��ġ�� �̸� �ɾ�ѷ��� �Ҷ���
                        // ���� ��� ����� �ǹ̰� ���� ������ ����� �ϱ����� ����
                        // ������ ����ϱ� ������ 0 ���� ���� ���� �����.
                        // ���⼭ 0 �� �߿��� ���� ������ ����Ҷ�, ������ ������ �����
                        // ��ġ������ �ִ��� üũ�ҷ��� �𽺾���� ��Ű�� �ּ� ��ü��
                        // ���⿡�� dbg.reg.eip �� x86->operands[index].imm ��, �����ּ�
                        // ��ü�� �������ְ� �ֱ� ������. ����� ������ üũ�ϴ� �Լ�������
                        // dbg.reg.eip ���� �������� �𽺾���� ��Ŵ. �׷��� ������
                        // dbg.reg.eip �� SizeNextInst ���� ���ϴ� �Ϲ� �ν�Ʈ���� ó��
                        // ���·� ó���ҷ��� ������â�� �� ����. �׷��� SizeNextInst ����
                        // ���� ����� ����� �� ����Ʈ�ΰ��� 0 ���� ������־�� ��.
                        // �׷��� ���������� dna.PatchSize �� 0 ���� ������ִ� ���� ��
                        // �Ȱ��� �ǹ̰� ��. ��, ������������ dbg.reg.eip �帧�� ������
                        // �־��µ� ����� ������ Ȯ���ϴ� �𽺾���� �Լ��� �� ����
                        // �����Ϸ� �м��ϱ⿡ ��� 0 ���� ������ִ� ����. ������ �� ��
                        // ��ü�� 0 ���� ����� ���� ��ġ�Ǿ��ִ� ������ ���� ������ �ڵ带
                        // ������Ű�µ� ������ �߻��Ѵٴ� ��⿴��. �׷��� dna.branch_jump
                        // ��� �÷��׵� ���� ���� ��Ȳ�̸� �ٸ��� ó���ϵ��� �����
                        // ���� �ξ���.
                        BOOL ZF = dbg.reg.eflags & X86_EFLAGS_ZF ? 1 : 0;
                        if (ZF)
                        {
                            dna.branch_jump = true;
                            dna.SavedPatchSize = dna.PatchSize;
                            dna.PatchSize = 0;
                            SizeNextInst = 0;
                            dbg.reg.eip = x86->operands[index].imm;
                        }
                    }
                    break;
                case 0x75:  // JNE, JNZ :: ZF = 0 (short jump opcodes)
                    {
                        BOOL ZF = dbg.reg.eflags & X86_EFLAGS_ZF ? 1 : 0;
                        if (ZF == 0)
                        {
                            dna.branch_jump = true;
                            dna.SavedPatchSize = dna.PatchSize;
                            dna.PatchSize = 0;
                            SizeNextInst = 0;
                            dbg.reg.eip = x86->operands[index].imm;
                        }
                    }
                    break;
                case 0x76:  // JBE, JNA :: CF = 1 or ZF = 1 (short jump opcodes)
                    {
                        BOOL CF = dbg.reg.eflags & X86_EFLAGS_CF ? 1 : 0;
                        BOOL ZF = dbg.reg.eflags & X86_EFLAGS_ZF ? 1 : 0;
                        if (CF || ZF)
                        {
                            dna.branch_jump = true;
                            dna.SavedPatchSize = dna.PatchSize;
                            dna.PatchSize = 0;
                            SizeNextInst = 0;
                            dbg.reg.eip = x86->operands[index].imm;
                        }
                    }
                    break;
                case 0x77:  // JA, JNBE :: CF = 0 and ZF = 0 (short jump opcodes)
                    {
                        BOOL CF = dbg.reg.eflags & X86_EFLAGS_CF ? 1 : 0;
                        BOOL ZF = dbg.reg.eflags & X86_EFLAGS_ZF ? 1 : 0;
                        if (CF == 0 && ZF == 0)
                        {
                            dna.branch_jump = true;
                            dna.SavedPatchSize = dna.PatchSize;
                            dna.PatchSize = 0;
                            SizeNextInst = 0;
                            dbg.reg.eip = x86->operands[index].imm;
                        }
                    }
                    break;
                case 0x78:  // JS :: SF = 1 (short jump opcodes)
                    {
                        BOOL SF = dbg.reg.eflags & X86_EFLAGS_SF ? 1 : 0;
                        if (SF)
                        {
                            dna.branch_jump = true;
                            dna.SavedPatchSize = dna.PatchSize;
                            dna.PatchSize = 0;
                            SizeNextInst = 0;
                            dbg.reg.eip = x86->operands[index].imm;
                        }
                    }
                    break;
                case 0x79:  // JNS :: SF = 0 (short jump opcodes)
                    {
                        BOOL SF = dbg.reg.eflags & X86_EFLAGS_SF ? 1 : 0;
                        if (SF == 0)
                        {
                            dna.branch_jump = true;
                            dna.SavedPatchSize = dna.PatchSize;
                            dna.PatchSize = 0;
                            SizeNextInst = 0;
                            dbg.reg.eip = x86->operands[index].imm;
                        }
                    }
                    break;
                case 0x7A:  // JP, JPE :: PF = 1 (short jump opcodes)
                    {
                        BOOL PF = dbg.reg.eflags & X86_EFLAGS_PF ? 1 : 0;
                        if (PF)
                        {
                            dna.branch_jump = true;
                            dna.SavedPatchSize = dna.PatchSize;
                            dna.PatchSize = 0;
                            SizeNextInst = 0;
                            dbg.reg.eip = x86->operands[index].imm;
                        }
                    }
                    break;
                case 0x7B:  // JNP, JPO :: PF = 0 (short jump opcodes)
                    {
                        BOOL PF = dbg.reg.eflags & X86_EFLAGS_PF ? 1 : 0;
                        if (PF == 0)
                        {
                            dna.branch_jump = true;
                            dna.SavedPatchSize = dna.PatchSize;
                            dna.PatchSize = 0;
                            SizeNextInst = 0;
                            dbg.reg.eip = x86->operands[index].imm;
                        }
                    }
                    break;
                case 0x7C:  // JL, JNGE :: SF <> OF (short jump opcodes)
                    {
                        BOOL SF = dbg.reg.eflags & X86_EFLAGS_SF ? 1 : 0;
                        BOOL OF = dbg.reg.eflags & X86_EFLAGS_OF ? 1 : 0;
                        if (SF != OF)
                        {
                            dna.branch_jump = true;
                            dna.SavedPatchSize = dna.PatchSize;
                            dna.PatchSize = 0;
                            SizeNextInst = 0;
                            dbg.reg.eip = x86->operands[index].imm;
                        }
                    }
                    break;
                case 0x7D:  // JGE, JNL :: SF = OF (short jump opcodes)
                    {
                        BOOL SF = dbg.reg.eflags & X86_EFLAGS_SF ? 1 : 0;
                        BOOL OF = dbg.reg.eflags & X86_EFLAGS_OF ? 1 : 0;
                        if (SF == OF)
                        {
                            dna.branch_jump = true;
                            dna.SavedPatchSize = dna.PatchSize;
                            dna.PatchSize = 0;
                            SizeNextInst = 0;
                            dbg.reg.eip = x86->operands[index].imm;
                        }
                    }
                    break;
                case 0x7E:  // JLE, JNG :: ZF = 1 or SF <> OF (short jump opcodes)
                    {
                        BOOL ZF = dbg.reg.eflags & X86_EFLAGS_ZF ? 1 : 0;
                        BOOL SF = dbg.reg.eflags & X86_EFLAGS_SF ? 1 : 0;
                        BOOL OF = dbg.reg.eflags & X86_EFLAGS_OF ? 1 : 0;
                        if (ZF || SF != OF)
                        {
                            dna.branch_jump = true;
                            dna.SavedPatchSize = dna.PatchSize;
                            dna.PatchSize = 0;
                            SizeNextInst = 0;
                            dbg.reg.eip = x86->operands[index].imm;
                        }
                    }
                    break;
                case 0x7F:  // JG, JNLE :: ZF = 0 and SF = OF (short jump opcodes)
                    {
                        BOOL ZF = dbg.reg.eflags & X86_EFLAGS_ZF ? 1 : 0;
                        BOOL SF = dbg.reg.eflags & X86_EFLAGS_SF ? 1 : 0;
                        BOOL OF = dbg.reg.eflags & X86_EFLAGS_OF ? 1 : 0;
                        if (ZF == 0 && SF == OF)
                        {
                            dna.branch_jump = true;
                            dna.SavedPatchSize = dna.PatchSize;
                            dna.PatchSize = 0;
                            SizeNextInst = 0;
                            dbg.reg.eip = x86->operands[index].imm;
                        }
                    }
                    break;
                case 0x0F:
                    {
                        switch(x86->opcode[1])
                        {
                        case 0x80:  // JO :: OF = 1 (near jump opcodes)
                            {
                                BOOL OF = dbg.reg.eflags & X86_EFLAGS_OF ? 1 : 0;
                                if (OF)
                                {
                                    dna.branch_jump = true;
                                    dna.SavedPatchSize = dna.PatchSize;
                                    dna.PatchSize = 0;
                                    SizeNextInst = 0;
                                    dbg.reg.eip = x86->operands[index].imm;
                                }
                            }
                            break;
                        case 0x81:  // JNO :: OF = 0 (near jump opcodes)
                            {
                                BOOL OF = dbg.reg.eflags & X86_EFLAGS_OF ? 1 : 0;
                                if (OF == 0)
                                {
                                    dna.branch_jump = true;
                                    dna.SavedPatchSize = dna.PatchSize;
                                    dna.PatchSize = 0;
                                    SizeNextInst = 0;
                                    dbg.reg.eip = x86->operands[index].imm;
                                }
                            }
                            break;
                        case 0x82:  // JB, JNAE, JC :: CF = 1 (near jump opcodes)
                            {
                                BOOL CF = dbg.reg.eflags & X86_EFLAGS_CF ? 1 : 0;
                                if (CF)
                                {
                                    dna.branch_jump = true;
                                    dna.SavedPatchSize = dna.PatchSize;
                                    dna.PatchSize = 0;
                                    SizeNextInst = 0;
                                    dbg.reg.eip = x86->operands[index].imm;
                                }
                            }
                            break;
                        case 0x83:  // JNB, JAE, JNC :: CF = 0 (near jump opcodes)
                            {
                                BOOL CF = dbg.reg.eflags & X86_EFLAGS_CF ? 1 : 0;
                                if (CF == 0)
                                {
                                    dna.branch_jump = true;
                                    dna.SavedPatchSize = dna.PatchSize;
                                    dna.PatchSize = 0;
                                    SizeNextInst = 0;
                                    dbg.reg.eip = x86->operands[index].imm;
                                }
                            }
                            break;
                        case 0x84:  // JE, JZ :: ZF = 1 (near jump opcodes)
                            {
                                BOOL ZF = dbg.reg.eflags & X86_EFLAGS_ZF ? 1 : 0;
                                if (ZF)
                                {
                                    dna.branch_jump = true;
                                    dna.SavedPatchSize = dna.PatchSize;
                                    dna.PatchSize = 0;
                                    SizeNextInst = 0;
                                    dbg.reg.eip = x86->operands[index].imm;
                                }
                            }
                            break;
                        case 0x85:  // JNE, JNZ :: ZF = 0 (near jump opcodes)
                            {
                                BOOL ZF = dbg.reg.eflags & X86_EFLAGS_ZF ? 1 : 0;
                                if (ZF == 0)
                                {
                                    dna.branch_jump = true;
                                    dna.SavedPatchSize = dna.PatchSize;
                                    dna.PatchSize = 0;
                                    SizeNextInst = 0;
                                    dbg.reg.eip = x86->operands[index].imm;
                                }
                            }
                            break;
                        case 0x86:  // JBE, JNA :: CF = 1 or ZF = 1 (near jump opcodes)
                            {
                                BOOL CF = dbg.reg.eflags & X86_EFLAGS_CF ? 1 : 0;
                                BOOL ZF = dbg.reg.eflags & X86_EFLAGS_ZF ? 1 : 0;
                                if (CF || ZF)
                                {
                                    dna.branch_jump = true;
                                    dna.SavedPatchSize = dna.PatchSize;
                                    dna.PatchSize = 0;
                                    SizeNextInst = 0;
                                    dbg.reg.eip = x86->operands[index].imm;
                                }
                            }
                            break;
                        case 0x87:  // JA, JNBE :: CF = 0 and ZF = 0 (near jump opcodes)
                            {
                                BOOL CF = dbg.reg.eflags & X86_EFLAGS_CF ? 1 : 0;
                                BOOL ZF = dbg.reg.eflags & X86_EFLAGS_ZF ? 1 : 0;
                                if (CF == 0 && ZF == 0)
                                {
                                    dna.branch_jump = true;
                                    dna.SavedPatchSize = dna.PatchSize;
                                    dna.PatchSize = 0;
                                    SizeNextInst = 0;
                                    dbg.reg.eip = x86->operands[index].imm;
                                }
                            }
                            break;
                        case 0x88:  // JS :: SF = 1 (near jump opcodes)
                            {
                                BOOL SF = dbg.reg.eflags & X86_EFLAGS_SF ? 1 : 0;
                                if (SF)
                                {
                                    dna.branch_jump = true;
                                    dna.SavedPatchSize = dna.PatchSize;
                                    dna.PatchSize = 0;
                                    SizeNextInst = 0;
                                    dbg.reg.eip = x86->operands[index].imm;
                                }
                            }
                            break;
                        case 0x89:  // JNS :: SF = 0 (near jump opcodes)
                            {
                                BOOL SF = dbg.reg.eflags & X86_EFLAGS_SF ? 1 : 0;
                                if (SF == 0)
                                {
                                    dna.branch_jump = true;
                                    dna.SavedPatchSize = dna.PatchSize;
                                    dna.PatchSize = 0;
                                    SizeNextInst = 0;
                                    dbg.reg.eip = x86->operands[index].imm;
                                }
                            }
                            break;
                        case 0x8A:  // JP, JPE :: PF = 1 (near jump opcodes)
                            {
                                BOOL PF = dbg.reg.eflags & X86_EFLAGS_PF ? 1 : 0;
                                if (PF)
                                {
                                    dna.branch_jump = true;
                                    dna.SavedPatchSize = dna.PatchSize;
                                    dna.PatchSize = 0;
                                    SizeNextInst = 0;
                                    dbg.reg.eip = x86->operands[index].imm;
                                }
                            }
                            break;
                        case 0x8B:  // JNP, JPO :: PF = 0 (near jump opcodes)
                            {
                                BOOL PF = dbg.reg.eflags & X86_EFLAGS_PF ? 1 : 0;
                                if (PF == 0)
                                {
                                    dna.branch_jump = true;
                                    dna.SavedPatchSize = dna.PatchSize;
                                    dna.PatchSize = 0;
                                    SizeNextInst = 0;
                                    dbg.reg.eip = x86->operands[index].imm;
                                }
                            }
                            break;
                        case 0x8C:  // JL, JNGE :: SF <> OF (near jump opcodes)
                            {
                                BOOL SF = dbg.reg.eflags & X86_EFLAGS_SF ? 1 : 0;
                                BOOL OF = dbg.reg.eflags & X86_EFLAGS_OF ? 1 : 0;
                                if (SF != OF)
                                {
                                    dna.branch_jump = true;
                                    dna.SavedPatchSize = dna.PatchSize;
                                    dna.PatchSize = 0;
                                    SizeNextInst = 0;
                                    dbg.reg.eip = x86->operands[index].imm;
                                }
                            }
                            break;
                        case 0x8D:  // JGE, JNL :: SF = OF (near jump opcodes)
                            {
                                BOOL SF = dbg.reg.eflags & X86_EFLAGS_SF ? 1 : 0;
                                BOOL OF = dbg.reg.eflags & X86_EFLAGS_OF ? 1 : 0;
                                if (SF == OF)
                                {
                                    dna.branch_jump = true;
                                    dna.SavedPatchSize = dna.PatchSize;
                                    dna.PatchSize = 0;
                                    SizeNextInst = 0;
                                    dbg.reg.eip = x86->operands[index].imm;
                                }
                            }
                            break;
                        case 0x8E:  // JLE, JNG :: ZF = 1 or SF <> OF (near jump opcodes)
                            {
                                BOOL ZF = dbg.reg.eflags & X86_EFLAGS_ZF ? 1 : 0;
                                BOOL SF = dbg.reg.eflags & X86_EFLAGS_SF ? 1 : 0;
                                BOOL OF = dbg.reg.eflags & X86_EFLAGS_OF ? 1 : 0;
                                if (ZF || SF != OF)
                                {
                                    dna.branch_jump = true;
                                    dna.SavedPatchSize = dna.PatchSize;
                                    dna.PatchSize = 0;
                                    SizeNextInst = 0;
                                    dbg.reg.eip = x86->operands[index].imm;
                                }
                            }
                            break;
                        case 0x8F:  // JG, JNLE :: ZF = 0 and SF = OF (near jump opcodes)
                            {
                                BOOL ZF = dbg.reg.eflags & X86_EFLAGS_ZF ? 1 : 0;
                                BOOL SF = dbg.reg.eflags & X86_EFLAGS_SF ? 1 : 0;
                                BOOL OF = dbg.reg.eflags & X86_EFLAGS_OF ? 1 : 0;
                                if (ZF == 0 && SF == OF)
                                {
                                    dna.branch_jump = true;
                                    dna.SavedPatchSize = dna.PatchSize;
                                    dna.PatchSize = 0;
                                    SizeNextInst = 0;
                                    dbg.reg.eip = x86->operands[index].imm;
                                }
                            }
                            break;
                        }
                    }
                    break;
                case 0xE8:  // CALL
                    {
                        dna.branch_jump = true;
                        dna.SavedPatchSize = dna.PatchSize;
                        dna.PatchSize = 0;
                        SizeNextInst = 0;
                        dbg.reg.esp -= 4;
                        *((DWORD *)(dbg.reg.esp)) = dbg.reg.eip + 5;
                        dbg.reg.eip = x86->operands[index].imm;
                        dbg.reg.call = true;
                    }
                    break;
                case 0xE9:  // JMP
                    {
                        dna.branch_jump = true;
                        dna.SavedPatchSize = dna.PatchSize;
                        dna.PatchSize = 0;
                        SizeNextInst = 0;
                        dbg.reg.eip = x86->operands[index].imm;
                    }
                    break;
                case 0xEB:  // JMP
                    {
                        dna.branch_jump = true;
                        dna.SavedPatchSize = dna.PatchSize;
                        dna.PatchSize = 0;
                        SizeNextInst = 0;
                        dbg.reg.eip = x86->operands[index].imm;
                    }
                    break;
                case 0xFF:
                    {
                        switch(x86->modrm)
                        {
                        case 0x25:  // JMP
                            {
                                // ENG: This is symbol of import function addresses.
                                // KOR: �ɺ� ó���� �ؾߵǴµ�..

                                // ������ CALL ����� ����ƾ���, CALL ���ʿ� �����
                                // ���ϱ� �ٷ� 0xFF 0x25 JMP ����� ��Ƽ�� �ִٸ� �̰�
                                // ��κ� ����Ʈ �Լ� ȣ���� ��Ȳ��. ������ CALL memset
                                // ���� �η��� ȣ��� ��Ȳ��. �׷��� esp ���ÿ��� ���� �ϳ�
                                // �̾ƺ��� �����ּҰ� �� ���̰�, ���� memset �������� ���
                                // ���� �귣ġ ó���� �� ������ ���� ������ ���� �ּ�
                                // �ʿ��ٰ� �ζ��� ��ġ�� �ɾ�ѷ��� ����. memset �� �� ȣ��
                                // �Ǽ� ó���ϰ� �ǵ��ƿ��� ��ŷ ��ƾ���� �ٽ� Ÿ�� ��������
                                // �ϰڴٴ� �����.
                                if (dbg.reg.call) {
                                    // �� �κ��� �Ʒ��� ���� �������ϰ� �������
                                    dbg.reg.ret = *((DWORD *)(dbg.reg.esp));
                                }
                                else {
                                    // ����, ������ CALL �� ȣ��� ��Ȳ�� �ƴ϶��, ����
                                    // �� �Žñ� ������ ������ �̷� ��쿡�� ����Ʈ ���̺�
                                    // �Լ��� ȣ���ϴ� ��Ȳ��.
                                    // ������� �̷��� �ΰ����� ����.
/*
CASE 1:  ������ ���� memset �� ȣ���ϸ� �ȿ� ���� 0xFF 0x25 (JMP) �� �����ϴ� ��Ȳ.
         �׷��� �� ���ʱ��� �����ؼ� �� �ʿ䰡 ����. ���� �������� ���ξ�� ��.
         ����, ������ ����ؼ� ó���ϸ� ����ؼ� ��ģ���� �������ٰ� �عٴڱ���
         �������� �ϸ鼭 ������ �Ұ����� ������ ���� ���� ������. �޸� ������ ����
         ���ֵ��� �� ���� ������, �ִ��� �ϵ��ڵ��� ���� ����ڿ��� ������ �� �ִ�
         ��Ȳ���� ���������ϱ� ������ �ϴ�, ����� �غ����ϰ� ����� ���α��� ����
         �ؼ� ���� ���ϰ� ������ ���������� �ҷ��� ��. ��, �Ϲ� �ν�Ʈ���� ó��
         ó���ϵ��� �ҷ��� ��. (���߿� �ɺ� ó�� �κи� �߰��� �����صѷ��� ��)
         �׷��ٸ� 0xFF 0x25 ��ɿ��� +6 ����Ʈ�� ���ָ� �ɱ�? ���� �ȵ�. �׷��� ��
         ��쿡�� �Ʒ��� jmp ds:__imp_memset �� ���� JMP �� �����ϰ� �ְ� ���� ���
         ��ü�� ����. �׷��� ������ ���� �ν�Ʈ���� �κп� �ζ��� ��ġ�� �ɸ� �ٸ�
         �Լ��� �Ӹ����� �� ����. ���� �ζ��� ��ġ�� �������� �������� ����.
         �� ���� memset �Լ��� �����Ѵٴ� �ǹ���. �׷��Ƿ� ���� �ܰ迡�� ����, CALL
         ����� ����Ǿ��ٸ� dbg.reg.call �� �����صξ��� ������ ���簡 0xFF 0x25 ����
         �� ��쿡�� dbg.reg.esp ���� �ּҸ� �̾Ƽ� �ش� ���� ��巹�� ��ġ�� �ζ���
         ��ġ�� �ɾ�� �ٽ� ��ŷ��ƾ���� �������� ����. �� �ּҴ� �Ʒ����� 6C1A37E2
         �ּҰ� �� ����.
----------------------------------------------------------------------------------------------------------
.text:6C1A37DC 56                                                  push    esi             ; Dst
.text:6C1A37DD E8 09 00 00 00   [Import Table's function!!] =>     call    memset
.text:6C1A37E2 83 4E 14 FF                                         or      dword ptr [esi+14h], 0FFFFFFFFh
----------------------------------------------------------------------------------------------------------
.text:6C1A37D2                                     ; int __thiscall sub_6C1A37D2(void *Dst)
.text:6C1A37D2                                     sub_6C1A37D2    proc near       
.text:6C1A37EB FF 25 C8 27 1A 6C                                   jmp     ds:__imp_memset
.text:6C1A37EB                                     memset          endp
----------------------------------------------------------------------------------------------------------

CASE 1:  �ι�° ���� �Ʒ��� ���� �η���. ������ CALL ����� ȣ����� �ʾ���.
         �ܼ��� ����Ʈ ���̺� �ִ� �Լ��� ȣ���ϴ� ����. �� ��쿡�� memset
         ó�� CRT �Լ��� �ƴ϶� MS ���ǽ��� �����Ƽ ���̺귯�� DLL �ȿ� �ִ�
         API ó�� �����Լ��� ȣ���� �����. �� ��쿡�� �������� ������ �����
         ������ �� �� �ֵ��� ����� ��. �ٸ�, ����� �������ϱ� ������ ������
         �����Ƿ� �Ϲ� ���ó�� ó�����ٷ��� ��. �׷����� ���ÿ��� ���� �̾Ƽ���
         �ȵǰ� ���� 0xFF 0x25 JMP ���� �ν�Ʈ���� �����ʿ� ��ġ�� �ɾ��־�� ��.
         ��, �Ϲ� ��� ó�� ���� ó���ؾߵ�. (������ ���⼭ �߻���. ������ �κ�
         ���� �����ϰԵǸ� JMP ���� ������ �������� ������. ������ ����. �Ʒ���
         JMP ����� ����� ������ �ι��ٽ� �������� ��� �ȵ��ƿ�. ��ŷ ����
         ���������� ��ġ�������� ������ �ȵȴ� �����. ������ �˾Ƴ����� �������
         �õ��ߴµ� ���� �κп��� ��� �ͼ����� �������� ����Ȯ���� �Ұ�����.
         ����ŷ� ������ ������ advapi32.dll �ȿ��� ��� ���̳��� �ɸ�. ������
         ������ ���ĸ� ���α׷��� ������ �ʰ� �߸� ����ǰ� �ִµ� ����ŷ� ������
         ���� ���ٴ� ����. �׷��� �Ʒ��� JMP ���� �� ����ǰ��� ������ �ߴܵǴ�
         ��Ȳ�� �߻��ϰ� ���α׷��� �ƹ� �������� �߸� ����ǰ� ����. �ƹ��� ����
         ������� �� �����. ����ŷ� �� ������ �ȵǴ��� Ȯ���ҷ��� �Ҷ��� advapi32.dll
         �ȿ��� ������ ���̻� ������ ���ϰ� �Ѵٴ� ����.. ��ġ, ���ڿ����� �����ϰ�
         �ִ� �� ���� ������. Ȯ���غ����� �����ڰ� ������ ���ڰ� ���ڷ� �ٲ�
         �����̷� �����µ�, Ȯ�ξ��ϸ� �����ڰ� �����ϱ� ���ڰ� �ƴ� �ĵ����� ����
         ���̸� ����� �׷� �����̶���? ���� ���ڿ��е� �ƴϰ� ����ŷ� Ȯ���ҷ���
         �������� ���� 0 �̵Ǹ鼭 �ͼ����� �߻��ؼ� ������ ���� ���ܳ��� �׳� ����
         ��쿡�� �ƹ��� ������ ���� �߸� ����Ǵµ� ������ �ߴܵǴ� ��Ȳ. �ᱹ,
         ��û�� ��� ���� �ϴ� ��������� GG ����. ���� �� �̷����� �� ���װ� �ִٸ�
         ����ָ� ��������.. �ϴ�, ������ �̷��ٴ� ��.

.text:6C1AFC4B 0F 84 13 21 00 00                                   jz      loc_6C1B1D64
.text:6C1AFC51 5D                                                  pop     ebp
.text:6C1AFC52 FF 25 00 10 FE 6C                                   jmp     _MsoFreePv@4    ; MsoFreePv(x)
.text:6C1AFC52                                     sub_6C1AFC44    endp
.text:6C1AFC52
*/

                                    // �׷��� dbg.reg.eip �� +6 �� ���Ѵ�. �Ϲ�����
                                    // ��� ó�� ó���ҷ���..
                                    dbg.reg.ret = dbg.reg.eip + 6;
                                }

                                dna.branch_jump = false;
                                dna.SavedPatchSize = dna.PatchSize;
                                dna.PatchSize = 0;
                                SizeNextInst = 0;

                                // 0xFF 0x25 �� ��쿡�� IMM ���� �ƴ϶� DISP ���� �ּҺκ��̴�
                                cs_x86_op *op = &(x86->operands[0]);
                                dbg.reg.eip = *((DWORD *)(op->mem.disp));
                            }
                            break;
                        }
                    }
                    break;
                case 0xC2:  // retn
                    {
                        dna.branch_jump = true;
                        dna.SavedPatchSize = dna.PatchSize;
                        dna.PatchSize = 0;
                        SizeNextInst = 0;
                        // ex) retn 10h
                        // 
                        // retn instruction is get the Saved Return Address and
                        // and It is plus 0x04 of the esp.
                        // retn 10h (esp + 0x04 and esp + 0x10)
                        // dbg.reg.esp is 0x04 + 0x10.
                        // Do You Understand of My Explain? ������
                        // dumpcode((unsigned char *)(dbg.reg.esp), 200);

                        // �ȵǴ� ����� ���� ������ �ߴµ�, �ѱ۷� �ٽ� �����ϸ�
                        // ���� ����� ������ esp ���� ���� ����. �׸���, eip ��
                        // ���� �ּ� ������ �ٲ��ִ� ����.
                        // �̶�, 0x04 �� �����ִ� ���� ret ����� ���� esp ����
                        // ���� ������ pop ��Ű�� ����̱� ������ +4 �� ���� ����.
                        // �׸��� retn 10h ��� �Ҷ� 10h �� x86->operands[index].imm
                        // ���̶�.. �� ���� ���ÿ��� ���� �����־�� ��. ��������
                        // ���̱� ������. ��.. ����?
                        dbg.reg.eip = *((DWORD *)(dbg.reg.esp));
                        dbg.reg.esp += 0x04 + x86->operands[index].imm;
                    }
                    break;
                case 0xC3:  // ret
                    {
                        dna.branch_jump = true;
                        dna.SavedPatchSize = dna.PatchSize;
                        dna.PatchSize = 0;
                        SizeNextInst = 0;

                        // ����� �� ����. ������ �͵� ���� �׳� ret �� ���� popping
                        // +4 ó���� ���ָ� ��.
                        dbg.reg.eip = *((DWORD *)(dbg.reg.esp));
                        dbg.reg.esp += 0x04;
                    }
                    break;
                }
            }
		}

		// free memory allocated by cs_disasm()
		cs_free(insn, count);
	} else {
#ifdef _DEBUG
		DBGMSG.Format("[+][IMATINIB] ****************\n");
        OutputDebugString(DBGMSG);
		DBGMSG.Format("[+][IMATINIB] ERROR: Failed to disasm given code!\n");
        OutputDebugString(DBGMSG);
#endif
	}

#ifdef _DEBUG
	DBGMSG.Format("[+][IMATINIB] \n");
    OutputDebugString(DBGMSG);
#endif

    return SizeNextInst;
}

void RecoveryInst(FINGERPRINTSTRUCT &dna)
{
    // �� �Լ��� ��ŷ�ɶ� ��ġ�� �κ��� ������Ų��.

    // ���� �귣ġ�� ��쿡�� ���� ��ɾ�� ��������ִ°� �ƴ϶� ���� ����
    // ������ ���־��� ������ ��ġ ����� ������ ��. �׷��� ��ġ �����
    // �̸� ����ص� ������ dna.SavedPatchSize ����. �׷��� �� ������ dna.PatchSize
    // ������ �־��־ �ϴ� �ڵ带 ������Ű�� �ٽ� dna.PatchSize ���� 0 ����
    // �������. �� �̷��� �ϳĸ� �𽺾������ ���Ѽ� �������� ��ġ�� ��ġ��
    // ������ Ȯ���ϴ� �Լ����� dna.PatchSize ���� 0 �̾�� ��. ������ ������
    // ��ġ ������� �������־�� �ϴ°� �ƴ϶� �帧�� ���� �ٲ�� ������ ����
    // ������ ��ġ ����� ���������� �ʴ� ����. �ֳĸ�, dna.PatchSize ����
    // ��ɾ �������� ���յ� ���¶��, ���� ��ɾ� �����ŭ ���ְ� ������
    // ���� �⺻���� �ΰ� �߰����� ���� ����� ���ϴ� ��Ȳ�ε�, �� ��ġ��
    // dbg.reg.eip �ε� �̳��� ����ó�� ������ �ּ� ��ü�� ���Ӱ� ������ ��
    // ��Ȳ���� ������ ���� ���ϴ� �� ��ü�� �ǹ̵� ���� ���ؼ��� �ȵ�.
    // �׷��� dna.PatchSize ���� ���� ���������� �ݵ�� 0 �̾�� ��. �׷��� 0 ��
    // ����� ������ ���� �ٱ� ������ ������ ��� ���� �ڵ�� ���������ֳ�..
    // �׷��� ������ 0 ���� ����� ���� ���� �̸� ������ ���� dna.SavedPatchSize
    // ���� ���� �ٱ����� ��ġ�Ǿ� �ִ� ������ �ڵ� ������ ���ؼ� ����س���
    // ����. ������ �ϴ��� �ڵ�� ���� ���ѳ��ƾ� �ϴϱ� �̳��� �ٽ� ������
    // ���� ������ų ������ ��ġ�Ϸ��� �ǵ���. �̶�, dbg.reg.ret �� ��쵵 ����
    // ������ ó���� ����. �׷���, dbg.reg.ret ���� 0xFF 0x25 ����� �� �����ϴ�
    // ����. 0xFF 0x25 �� �귣ġ ��������� ó���ߴٰ��� ���ʵǴ� ��Ȳ�̹Ƿ�,
    // �귣ġ ó�� ó���� �ؼ� �ڵ� ������ ��Ű����, ������ ������ ��ġ�� �ɾ
    // ��ŷ��ƾ���� Ÿ������� ó���� �������ϰ� ������ ��. ����� �ϴ� �ڵ带
    // ������Ű�� ��ƾ�̱� ������ ���⼭�� �׳� �귣ġ ó���ϵ��� ó���� ������
    // ����.
    if (dna.branch_jump || dbg.reg.ret) {
        dna.PatchSize = dna.SavedPatchSize;
        RecoveryCode(dna.AddressFound, dna);
        dna.PatchSize = 0;
    }
    else {
        // �Ϲ����� ���� ��� ������ ��ġ�ɱ� ���� ���� �ڵ� ������ �ڵ带 ������Ŵ
        RecoveryCode(dna.AddressFound, dna);
    }

    // ���� ��Ų �������� ĳ���� ����־�� ���ŵȴ�. �׷���, �� ȿ�� ������.
    /*
    FlushInstructionCache(GetCurrentThread(),
                          (LPCVOID)GetBaseAddress(dna.ModuleName),
                          GetImageSize(dna.ModuleName));
    */
}

void ChainRecoveryInst(FINGERPRINTSTRUCT &dna)
{
    // �� �Լ��� �ν�Ʈ������̼��� �䳻���� ���ؼ� ���� �ζ��� ��ġ�� �ؼ� ��ŷ��
    // �ϴ� ���� �߿��� ������ �ϴ� �ٽɷ�ƾ�̴�.

    // ���� �ν�Ʈ���� ������ ���
    DWORD SizeNextInst = GetNextInst(dna);
    
    // ENG: Restore Original Codes
    // KOR: �ζ��� ��ġ�� ������ �ٽ� ���� ��Ŵ
    RecoveryInst(dna);

    DWORD SizeNextFetchInst;

    // �� �κ��� ��ŷ�� �ϱ����ؼ� ã�� ������ �𽺾������ ������ ���� ���� ��ġ�� ����
    // ù��° ���� ����� ����� ���Ѵ�. ������Ű�� �ٽ� �������� �̾ ���� ������ ��ġ��
    // �ɱ� ���ؼ��̴�.

    // �귣ġ�� ���
    if (dna.branch_jump) {
        // �������� ��ġ�� ���� ������ ���
        SizeNextFetchInst = GetSizeNextFetchInst(dna, SizeNextInst);
        dna.AddressFound = dbg.reg.eip;
        dna.branch_jump = false;
    } // �귣ġ���� �귣ġ�� Ÿ�� �ƵǴ� ��� (\xFF\x25 ��ɿ� ���� ó���� �ϱ�����.)
    else if (dbg.reg.ret) { // (��κ� �ּҰ� ����Ʈ �Լ� �ּҵ��̱� ������)
        // ���� dbg.reg.eip �� �̹� 0xFF 0x25 ������ disp �ּ���. ��, ����Ʈ �Լ� �ּ�
        DWORD EIP = dbg.reg.eip;
        // 0xFF 0x25 �� �ΰ��� ��찡 �ִµ� CALL �ȿ� ���� ���� �ƴ� ����.
        // ���� �ƴϸ� �Ϲ� �ν�Ʈ���� ó�� ó���ϰ� �´ٸ� CALL ������ ����
        // �ּҷ� �ǵ����ߵ�. dbg.reg.ret ���� 0xFF 0x25 ����� CALL ������
        // ����� ������ ��쿡�� CALL �� �����ּ��̰�, �Ϲ� ���¿��� �����
        // ���¶�� �� ���� ���� �ν�Ʈ���� �κ��� �ζ��� ��ġ�ϱ� ���ؼ� +6
        // Byte ��ŭ ������ ����.
        dbg.reg.eip = dbg.reg.ret;
        // ���� dbg.reg.eip �� + 6 (0xFF 0x25 �� 6 Byte ��) �� �� ������.
        // �� ��ġ���� �𽺾���� ��Ų �Ŀ� ��ɾ� ����� ���س�.
        SizeNextFetchInst = GetSizeNextFetchInst(dna, SizeNextInst);
        // dna.AddressFound �� ��ĸ�, �귣ġ�� ������ ���������� �ν�Ʈ����
        // ��� ��ŭ�� ������Ű�� �������� ����ϱ� ���ؼ� ���� ����. ����,
        // ���ʿ� �ζ��� ��ġ������ ã���� ������ ������. dbg.reg.eip �� ����
        // �������ִ� ������ �̹� 0xFF 0x25 ó���Ҷ� dbg.reg.eip �� +6 �� �߱�
        // ������. ����, CALL �ȿ��� 0xFF 0x25 ����� ����� ����� esp ����
        // ������ ������ �� ��ġ�� �����ּҰ� �ְ� �� �ּ� ���� ��ġ�ؾ��� ������.
        dna.AddressFound = dbg.reg.eip;
        // �� ������ ����� ���� ��츦 ����ؼ� call ǥ�ø� �ʱ�ȭ ��.
        dbg.reg.call = false;
        // dbg.reg.eip ���� �ٽ� ����ص� ������ �ǵ���. ���⼭ ����ص� ����
        // 0xFF 0x25 ����� ���ڰ�(disp ��) �ּ���. ��κ� import �ּҷ� Ȯ����
        // �Ǿ���. ���߿� �ּҸ� ����Ʈ ���̺��� ���� ã�Ƽ� �Լ� �̸����� �ٲ�
        // �ɺ�ó���� ���ٷ��� ��. ��ư, dna.AddressFound �� ���� �ּҷ� �����ؼ�
        // �귣ġ�� �ƴ� ���¸� ó���ϵ��� �س��� dbg.reg.eip �� 0xFF 0x25 �����
        // ���� �ּҷ� ��������. ��, dbg.reg.eip �������� ���� ����ǰ� ���� �ǵ�
        // �� ���� ���� �߻��ϸ� �ζ��� ��ġ�� �ɸ� ������ dna.AdddressFound ����
        // ���� �ٽ� ��ŷ�Լ� ������ ��� ������ �� ����.
        // (Fix: ���� �� �κ��� ��Ӹ��� ��� ����. ������ �ڿ� �ȵ��ƿ��� ������
        //       ����. �������� �ȵ����� ���� ó�� �ȵ��ƿ��� �κ��� ���ظ� ����
        //       ���ؼ� ���׸� ����� ����. �� �ߵǴµ� Ư�� �κп��� �ȵ�.)
        dbg.reg.eip = EIP;
        // dbg.reg.ret ���� �ʱ�ȭ ���Ѽ� �������� �� �κ����� �ȵ����� ��.
        dbg.reg.ret = 0;
    }
    else {
        // �� �κ��� �Ϲ� �ν�Ʈ���� ó���� �ϱ� ���ؼ� ���������� ���� �ν�Ʈ����
        // ������ ��ŭ �ǳʶ�� ���� �κ��� �ν�Ʈ���� ����� ���ؼ� SizeNextFetchInst
        // ������ �������ִ� ����. �׷��� �ؾ� ���� �ν�Ʈ���� ��ŭ �޺κп� �����
        // ��ġ������ �ִ��� Ȯ���ϰ� DNA_Injector �Լ��� ��ġ�� �� �� �ֱ� ������.
        SizeNextFetchInst = GetSizeNextFetchInst(dna, SizeNextInst);
        // ���� �ν�Ʈ���� �κ� ��ŭ �ǳʶ�. ������ ������ �ζ��� ��ġ�� ���
        // dna.AddressFound ���� �������� ��ġ��. dbg.reg.eip �� �귣ġ ó��
        // �ް��ϰ� ������ �ּҰ� �޶����� ����� ���� �س��ٸ� �� dna.AddressFound
        // ���� �⺻ ��尡 �������� ��ġ��. �׷��� ���� ����� ���� ���� ���� ��Ȳ��
        // ó���� ������ �ξ dna.AddressFound �� �ް��ϰ� �ٲ� �� �ִ� ��Ȳ���� ����
        // ���̰� ���⼭�� ���� ��� ��ġ�̴ϱ� SizeNextInst ó�� ���� ��ɾ� �����
        // ���ؼ� ������. �׷��� �� ��ġ�� ��ġ�� �Ŵµ� ����� ��ġ ������ �ִ��� �˾ƾ�
        // �ϱ� ������ Capstone �� Disassembly �ɷ��� ��� ��ġ ���� ����� ���ϴ� ����.
        // SizeNextInst(���� ��� ��, �ǳʶ� ������) �̰� SizeNextFetchInst �� ������ ��ġ��
        // ������ ����ϳĿ� ����ϸ� ����� ���̳Ķ�� �����ϼ�.
        dna.AddressFound += SizeNextInst;
        // ���ó� ���������� �Ϲ� ��ɾ ����� ���̸�, CALL ȣ���� �־�ٰ� �ϴ���
        // ����� �Ϲ� �ν�Ʈ������ ȣ��� ���̴ϱ� CALL ǥ���� �ʱ�ȭ �����־����.
        // �̷��� ���ϸ� 0xFF 0x25 ���� ���ù����� ���� ������ ������ ��.
        dbg.reg.call = false;
    }

    // ������ ������ �κ��̴�. �𽺾������ ������ ����� ����� ���õǸ� �ش� ����� ����
    // �ϴ� �Լ��� �����Ͽ���. �� �Լ��� ���ϰ��� ������ ��� ��ġ���� ��ġ�Ҷ� �װ��� ��ġ��
    // ������ �� �����Ƿ�, �󸶸�ŭ�� ��ɵ��� ��ġ�ؾ� ����� �������ΰ��� �ǹ��Ѵ�. �� �Լ���
    // ���ؼ� ����� ������ ������ ���� �� ���� �������� ��ġ�� ��Ȳ���� �� ��ġ ������ ũ���
    // �������ش�.
    dna.PatchSize = SizeNextFetchInst;

    // ó���� ���� ��ŷ�� �ɾ��� ���� �Ȱ��� �Լ��� ȣ���Ͽ� ���� ��� ��ġ�� ��ŷ�ɸ� ���¿���
    // ��ġ��Ų��. �̹� �ڵ�� ������ ������Ų ��Ȳ�̴�. ������ ���� ���ϰ� �ڵ带 �� ������ ��
    // �ֱ�� ������ ũ�� �ӵ����� ������ ������ �����Ƿ� �׳� ���� ��Ű�� ��ġ�ϰ� �ߴ�.
    DNA_Injector(INST_CALL, (DWORD)&Imatinib_STUB, dna);

    // ĳ���� �����ִ� ����� �÷��� ���Ѽ� ���ŵ� �̹����� �ڵ尡 �ݿ��ǰ� �Ѵ�.
    // �̰� ���� �ݿ� �ȵǴ� �ǰ�. ��ġ�ϸ� �ٷιٷ� ������ ��. �̰� ���� ���ص�
    // ���� ���°� ������, ���߿� �����Ǹ� �ּ� Ǯ���� ������.. �ϴ� �̰� �ּ���
    // ó���س��� ������ �ƹ� ������ ������ �ӵ� �� �� ������ �÷������� �Ѱ���.
    /*
    FlushInstructionCache(GetCurrentThread(),
                          (LPCVOID)GetBaseAddress(dna.ModuleName),
                          GetImageSize(dna.ModuleName));
    */
}

// �ν�Ʈ������̼� ���� �ڵ� (Ȱ���ϴ� ����� �����ֱ� ���� ÷���� ������)
void __fastcall DNA_Instrument(DWORD EIP)
{
    if (EIP == dna->DNA.Imatinib.AddressFound)
    {
        // �ν�Ʈ������̼� ����. �տ��� ������ �Լ����� ����.
        ChainRecoveryInst(dna->DNA.Imatinib);
    }
}

///////////////////////////////////////////////////////////////////////
// Instrument()
///////////////////////////////////////////////////////////////////////
void __fastcall Instrument(DWORD EIP)
{
    ////////////////////////////////////////////
    // Instruction Instrumentation START
    ////////////////////////////////////////////
    
    // KOR: ũ��Ƽ���� �ɾ��ִ°� ������ �ȸ�����
    //      �𸣰���. ���α׷��� ���߿� �ڲٸ� ��
    //      ���� ���� ���ܼ� �����״µ� ����ȭ
    //      ������ �ƴϾ���. �ڵ尡 �Ʊ���� �غ�
    //      �س���.

    // EnterCriticalSection(&cs);

    // ENG: Instrumentation Sample - 1 (Instruction Tracing)
    // KOR: �ν�Ʈ������̼� ���� 1 �� - (�ν�Ʈ���� �����ϱ�)
    DNA_Instrument(EIP);

    // LeaveCriticalSection(&cs);
    ////////////////////////////////////////////
    // Instruction Instrumentation END
    ////////////////////////////////////////////
}

//////////////////////////////////////////////////////////////////////
// Imatinib_STUB()
// Description: Imatinib_STUB trampoline function stub
// -------------------------------------------------------------------
void __declspec(naked) Imatinib_STUB()
{
    __asm {

        // ENG: pushfd and pop before dirty of stack.
        // KOR: ������ �����Ǵ� ���� �����ϱ� ���ؼ� ���� pushfd �� ó������� ��
        pushfd
        pop    dbg.reg.eflags

        // ENG: Get Saved Return Address & Delete CALL Stack Gap (translate CALL to JMP)
        // KOR: ���� �ڵ���ġ�� EIP ���� ���, �� ��ŷ�� �ɾ��� ������ �߻��� 4 ����Ʈ��
        //      POP ������ ���ŵ�. �̰��� CALL ȣ���� JMP ������ ó���ϱ� ����.
        pop    dbg.reg.eip

        // ENG: Get Registers
        // KOR: naked �Լ��̱� ������ ���⼭ ��� �������͵��� ��� ������ ������ �����.
        //      �ٸ�, EIP �� ESP �� �ణ ���̰� �߻��ϱ� ������ ��������� ��.
        mov    dbg.reg.eax, eax
        mov    dbg.reg.ecx, ecx
        mov    dbg.reg.edx, edx
        mov    dbg.reg.ebx, ebx
        mov    dbg.reg.esp, esp
        mov    dbg.reg.ebp, ebp
        mov    dbg.reg.esi, esi
        mov    dbg.reg.edi, edi

        // ENG: Adjust EIP (This EIP have the size of added 5 on CALL hooked routine.)
        // KOR: ����, EIP ���� ��������. ���� ���� EIP �� CALL ����� �ζ��� ��ġ��
        //      ���¿��� �Լ��ȿ� ���ͼ� �� ���̹Ƿ� ���� ��巹���� �Ǿ�����.
        //      �׷��Ƿ� ���Ͼ�巹���� �ƴ϶� ���� EIP ���� ���� �ϹǷ� -5 ��ŭ��
        //      ���־�� ��.

        push   eax
        mov    eax, dbg.reg.eip
        sub    eax, 5
        mov    dbg.reg.eip, eax
        pop    eax
    
        // ENG: Backup registers
        // KOR: �̰� �����ָ� ����. �ڿ��� �и� �������͸� 0x20 ����Ʈ ��� ��
        //      �������ְ� �ִµ��� �ұ��ϰ� �����ָ� ���̳�.
        pushad
    }

    // ENG: Instrument the instructions by current EIP.
    // KOR: EIP ���� �ĺ��ڷ� ���Ͽ� �ν�Ʈ������̼� ��ƾ�� ȣ����.
    //      ������ �ν�Ʈ������̼� �Լ����� �ڱⰡ �۾��� ��Ȳ��
    //      �´��� EIP ���� Ȯ���ؼ� ������ �ڽ��� ��ƾ�� ������.
    Instrument(dbg.reg.eip);

    __asm {

        // ENG: The pushfd & popfd or push & popfd or pushfd & pop makes dirty the top stack.
        //      It must use bitween pushad and popad. Current DNA_Instrument function translate
        //      instruction the CALL to the JMP therefore if current instruction is the CALL,
        //      esp != dbg.reg.esp. Do you understand of my explains? If push & popfd is used
        //      after DNA_Instrument, top stack is dirty.
        // KOR: push �� popfd �Ǵ� pushfd �� pop �Ǵ� push �� popfd ��� ���� ���� ���� ������
        //      �� �ִ�. ���� CALL �� JMP �� �ٲ� �����̹Ƿ�, DNA_Instrument �Լ��� ���ٰ�
        //      �������� ������ 4 ����Ʈ�� ���̰� ���� �����̴�. �ֳĸ�, ���� ���� �ڵ尡 CALL
        //      ��� ó���ϰ� �Ҷ� ���õ�, ���� ���� ��ü ���� ó���� �ٲ㼭 ó���ϰ� �ֱ� ����
        //      �� ���ÿ� 4 ��ŭ�� ó���� ������ ���� �Ͼ�� �ִٴ� ����̴�. ��, ���� ����
        //      esp �� dbg.reg.esp �� 4 ����Ʈ ��ŭ�� ���̰� ���µ� push �ߴٰ� popfd �� �ع�����
        //      ���� �ּҰ� �־�� �� ���� eflag ���� ���Եȴ�. �ֳĸ� �� �� �κп��� ������
        //      mov esp, dbg.reg.esp �� ������ ������ �������� �ʳ�. ��, ������ ������ ��������
        //      ���ϸ� �򰥸� �� �ۿ� ����. �����δ� ������ 4 ��ŭ ���̰� ���� ������ Instrument
        //      �Լ� ���ʿ����� CALL ����� JMP ������� ó�����ָ鼭 ������ ���ÿ� ���� ���
        //      ���������� �������ְ� �ִ� ��Ȳ�̴�. �׷���, ���� ���� ���κ� ��� ó���� �ϴ�
        //      ��Ȳ������ push dbg.reg.eflags �� popfd ���� ����Ǹ� ���� esp �� �ǵ帰�ٴ� ����
        //      ��� ����̴�. �׷��� �Ǹ� 4 ����Ʈ ��ŭ�� �ǵ���´ٴ� ����̴�. �׷��� ������
        //      Instrument �Լ����ʿ��� �ƹ��� ����ε� ���� �־��൵ �� push popfd ��� ����
        //      ������ �������� ������ �� �ٷ� ���� mov esp, dbg.reg.esp ����� ����Ǳ� ����
        //      �������� ������ �����ϰ� �ȴ�. �׷� �翬�� eflags ���� �ּҷ� �����ϰ� �����Ϸ���
        //      ���״� ���� ���̴�. �׷��Ƿ� pushad �� popad �� ���� �ڿ� �� ���ʿ��� ������Ѿ߸�
        //      �Ѵ�. �׷��� ���������� ����ȴ�.
        //
        push   dbg.reg.eflags
        popfd

        // ENG: Restore registers
        // KOR: �������� ����
        popad

        // ENG: Overwrite Registers
        // KOR: ���� Instrument �Լ����� �������͸� �������ְų� �� ��쿡��
        //      ���⼭ ���Ӱ� ��������Ʈ ��Ŵ.

        mov    eax, dbg.reg.eax
        mov    ecx, dbg.reg.ecx
        mov    edx, dbg.reg.edx
        mov    ebx, dbg.reg.ebx
        mov    esp, dbg.reg.esp
        mov    ebp, dbg.reg.ebp
        mov    esi, dbg.reg.esi
        mov    edi, dbg.reg.edi

        // ENG: JUMP EIP
        // KOR: EIP �� �����ϵ��� �ٲ�. ��� �귣ġ �ν�Ʈ���ǵ��� ���� ����
        //      �ڵ�� ����Ǵ°� �ƴ϶� �� ��ŷ DLL �ȿ��� ó����. ������
        //      �ν�Ʈ�������� �ǵ����� ���� �ν�Ʈ������ ����Ǿ� �����ϴ�
        //      ������ �ƴ϶� ���� �ν�Ʈ������ �Ǵ��ؼ� ���ο��� ������ ���
        //      ���� ��Ʈ���ϵ��� �ɾ���� ������. �̷��� �ؾ��� ���߿� Basic
        //      Block ���� ó���� �� ���� �� ���Ƽ� �Ϻη� �׷��� �س�����.
        jmp    dbg.reg.eip
    }
}

/* ���� ����� ��Ʈ�ѷ��� �����ų ����� �����غ����� ������ �� ����
�ڵ� �����ε�, ���� ������ �����Ǿ� �۵��� ���������� �̷��� �����ϴ�
���� ȿ���� ���� �ʴٴ� �� ������ ������ ����� ���� ���� �������Ѿߵ�.
//////////////////////////////////////////////////////////////////////
// Pseudo Codes for communications with external debugger controller.
//////////////////////////////////////////////////////////////////////

extern bool is_Listen;
extern bool is_StartDebugger;
extern LPBYTE pMemoryMap;

///////////////////////////////////////
// InprocServer
///////////////////////////////////////
DWORD WINAPI InprocServer(LPVOID lpARG)
{
    LRESULT hr = S_OK;
    HANDLE  hConn = (HANDLE)lpARG;

    DWORD retCode;
    DWORD bytesRead;
    DWORD lastError;

	IMATINIB_DATA packet;

    while (is_StartDebugger)
    {
		memset(&packet, 0, sizeof(_IMATINIB_DATA));

		retCode = ReadFile(hConn, &packet, sizeof(_IMATINIB_DATA), &bytesRead, NULL);
		if (!retCode)
		{
			lastError = GetLastError();
			switch (lastError)
			{
			  case ERROR_BROKEN_PIPE:
			  default:
				is_StartDebugger = FALSE;
				break;
			}
		}

        if (retCode)
        {
 			if(bytesRead > 0)
			{
				switch (packet.dwState)
				{
					case IMATINIB_GET_REG:
						SendToDebugger(DBG_CONTROL_DUMP, (const char *)&dbg, sizeof(_DBGDATA));
						break;

					case IMATINIB_GET_IMM:
						break;

					case IMATINIB_GET_DWORD:
						break;

					case IMATINIB_GET_STRING:
						break;

                    case IMATINIB_GET_DUMP:
					{
                        DWORD addr = GetBaseAddress(MODULE_NAME);
                        DWORD size = GetImageSize(MODULE_NAME);

                        SendToDebugger(DBG_CONTROL_NORMAL, (char *)addr, size);
						break;
					}

                    case IMATINIB_GET_GETFINGERPRINT:
                    {
						DNA_FingerPrintList(0, 0, dna->DNA.Imatinib);
                        packet.Address = dna->DNA.Imatinib.AddressFound;
                        packet.Offset = dna->DNA.Imatinib.PatchSize;
                        break;
                    }

                    case IMATINIB_GET_INTERCEPT:
                    {
                        if (dna->DNA.Imatinib.AddressFound)
                        {
                            DNA_Injector(INST_CALL, (DWORD)&Imatinib_STUB, dna->DNA.Imatinib);
                        }
                        break;
                    }

					case IMATINIB_GET_STOP:
						is_StartDebugger = FALSE;
						break;
				}
			}
        }

        Sleep(1);
    }

    FlushFileBuffers(hConn);
    CloseHandle(hConn);
    DisconnectNamedPipe(hConn);

    return hr;
}

///////////////////////////////////////////////////////////////////////////
// SendToDebugger
///////////////////////////////////////////////////////////////////////////
BOOL WINAPI SendToDebugger(DWORD CtrlMode, const char *Data, DWORD dwBytes)
{
    LRESULT bSend;
    PVOID lpData;
    
    COPYDATASTRUCT cpStructData;

    cpStructData.dwData = CtrlMode;
    cpStructData.cbData = dwBytes;

    __try {

        lpData = LocalAlloc(LPTR, cpStructData.cbData);
    
        DWORD oldSourceProt = 0;
        VirtualProtect((void*)Data, cpStructData.cbData, PAGE_EXECUTE_READWRITE, &oldSourceProt);
          memcpy((void *)lpData, (const void*)Data, (size_t)cpStructData.cbData);
        VirtualProtect((void*)Data, cpStructData.cbData, oldSourceProt, &oldSourceProt);

        cpStructData.lpData = (void *)lpData;

		if (dna->hProcess)
		{
			switch(CtrlMode)
			{
				case DBG_CONTROL_START:

					if (!is_Listen)
					{
						is_Listen = TRUE;
						is_StartDebugger = TRUE;

                        // cpStructData.dwData = DBG_CONTROL_START;
                        // bSend = ::SendMessage(psp->hProcess, WM_COPYDATA, (WPARAM)psp->hProcess, (LPARAM)&cpStructData);

                        // char PIPE_NAME[] = "\\\\.\\PIPE\\IDAIMATINIB";

                        // HANDLE PIPE_HANDLE = CreateFile(PIPE_NAME, GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
                        // if (PIPE_HANDLE != INVALID_HANDLE_VALUE)
                        // {
                               // DWORD dwThread;
                               // CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)InprocServer, (LPVOID)PIPE_HANDLE, NULL, &dwThread);
                        // }
					}

					break;

				case DBG_CONTROL_STOP:

					if (is_Listen)
					{
						is_Listen = FALSE;
						is_StartDebugger = FALSE;

						cpStructData.dwData = DBG_CONTROL_STOP;
						bSend = ::SendNotifyMessage(dna->hProcess, WM_COPYDATA, (WPARAM)dna->hProcess, (LPARAM)&cpStructData);
					}

					break;

				case DBG_CONTROL_NORMAL:

					if (is_Listen)
					{
						cpStructData.dwData = DBG_CONTROL_NORMAL;
						bSend = ::SendNotifyMessage(dna->hProcess, WM_COPYDATA, (WPARAM)dna->hProcess, (LPARAM)&cpStructData);
					}

					break;

				case DBG_CONTROL_DUMP:

					if (is_Listen)
					{
						cpStructData.dwData = DBG_CONTROL_DUMP;
						bSend = ::SendNotifyMessage(dna->hProcess, WM_COPYDATA, (WPARAM)dna->hProcess, (LPARAM)&cpStructData);
					}

					break;

				default: break;
			}
		}
    }
    __finally {
        LocalFree(lpData);
    }

    return(bSend);
}

///////////////////////////////////////////////////
// CheckTimeOver
///////////////////////////////////////////////////
BOOL CheckTimeOver(time_t tTime, DWORD dwCheckTime)
{
	time_t tCurrentTime = time(0);

	if(tCurrentTime >= tTime)
	{
		return ((tCurrentTime-tTime) >= dwCheckTime) ? TRUE : FALSE;
	}

	return ((tTime-((((time_t)(-1))-tTime)+tCurrentTime)) >= dwCheckTime) ? TRUE : FALSE;
}

////////////////////////////////////////
// DBG_CONNECT
////////////////////////////////////////
DWORD WINAPI DBG_CONNECT(LPVOID lpParam)
{
    static time_t tCheckT = time(0);

    while (TRUE)
    {
        if(CheckTimeOver(tCheckT, 1))
        {
			dna->hProcess = FindWindowEx(NULL, NULL, "TFormImatinibCenter", "IDAImatinib");
            if (dna->hProcess)
            {
				CString CtrlMsg = "IMATINIB INIT..";
				SendToDebugger(DBG_CONTROL_START, CtrlMsg, CtrlMsg.GetLength());
            }
            else
            {
                is_Listen = FALSE;
				is_StartDebugger = FALSE;
            }

            tCheckT = time(0);
        }

        Sleep(1);
    }

    return 0;
}

/////////////////////////////////////////////////////////////////
// GetRemoteProcAddress
/////////////////////////////////////////////////////////////////
PVOID GetRemoteProcAddress(PVOID ModuleBase, PCHAR pFunctionName)
{
    PVOID pFunctionAddress = NULL;
    
    __try
    {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ModuleBase;
        PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)((ULONG) ModuleBase + dos->e_lfanew);
        PIMAGE_DATA_DIRECTORY expdir = (PIMAGE_DATA_DIRECTORY)(nt->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_EXPORT);
        ULONG addr = expdir->VirtualAddress;
        PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)((ULONG)ModuleBase + addr);
        PULONG functions = (PULONG)((ULONG)ModuleBase + exports->AddressOfFunctions);
        PSHORT ordinals  = (PSHORT)((ULONG)ModuleBase + exports->AddressOfNameOrdinals);
        PULONG names     = (PULONG)((ULONG)ModuleBase + exports->AddressOfNames);
        ULONG  max_name  = exports->NumberOfNames;
        ULONG  max_func  = exports->NumberOfFunctions;

        ULONG i;

        for (i = 0; i < max_name; i++)
        {
            ULONG ord = ordinals[i];

            if(i >= max_name || ord >= max_func) {
                return NULL;
            }

            if (functions[ord] < addr || functions[ord] >= addr)
            {
                if (strcmp((PCHAR)ModuleBase + names[i], pFunctionName) == 0)
                {
                    // pFunctionAddress = (PVOID)((PCHAR)ModuleBase + functions[ord]);
					pFunctionAddress = (PVOID)functions[ord];
                    break;
                }
            }
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        pFunctionAddress = NULL;
    }

    return pFunctionAddress;
}

/////////////////////////////////////////////////////////////////
// GetRemoteCallBack
/////////////////////////////////////////////////////////////////
PVOID GetRemoteCallBack(HANDLE process_handle,
                        DWORD lpProcessId,
                        LPCSTR lpBuffer,
                        LPCSTR lpModule,
                        PCHAR pFunctionName)
{
	PVOID pFunctionAddress = NULL;

    HANDLE hSnapshot;
    MODULEENTRY32 me32;

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, lpProcessId);
    if (hSnapshot != INVALID_HANDLE_VALUE)
    {
        me32.dwSize = sizeof(MODULEENTRY32);
        if (Module32First(hSnapshot, &me32))
        {
            do
            {
				if (!stricmp(me32.szModule, lpModule))
				{
					__try {
						lpBuffer = (LPCSTR)malloc(me32.modBaseSize);
						ReadProcessMemory(process_handle, (void *)me32.modBaseAddr, (PVOID)lpBuffer, me32.modBaseSize, 0);
						pFunctionAddress = (PVOID)((DWORD)GetRemoteProcAddress((PVOID)lpBuffer, pFunctionName) + (DWORD)me32.modBaseAddr);
					}
					__finally {
						free((PVOID)lpBuffer);
					}
					
					break;
				}
            }
            while (Module32Next(hSnapshot, &me32));
        }
        CloseHandle(hSnapshot);
    }
    return pFunctionAddress;
}

///////////////////////////////////
// Imatinib
///////////////////////////////////
void __fastcall Imatinib(char *ecx)
{
	PDBGDATA mem = (PDBGDATA)pMemoryMap;
	memcpy(mem, &dbg, sizeof(_DBGDATA));

	MEMORY_BASIC_INFORMATION MemInfo = {0,};

	SIZE_T nResult = 0;

	nResult = VirtualQuery((const void *)mem->reg.eax, &MemInfo, sizeof(MemInfo));

	if (MemInfo.State & MEM_COMMIT)
		memcpy(mem->mem.eax, (const void *)mem->reg.eax, 1024);
	else
		memset(mem->mem.eax, 0x00, 1024);

	nResult = VirtualQuery((const void *)mem->reg.ebx, &MemInfo, sizeof(MemInfo));

	if (MemInfo.State & MEM_COMMIT)
		memcpy(mem->mem.ebx, (const void *)mem->reg.ebx, 1024);
	else
		memset(mem->mem.ebx, 0x00, 1024);
	
	nResult = VirtualQuery((const void *)mem->reg.ecx, &MemInfo, sizeof(MemInfo));

	if (MemInfo.State & MEM_COMMIT)
		memcpy(mem->mem.ecx, (const void *)mem->reg.ecx, 1024);
	else
		memset(mem->mem.ecx, 0x00, 1024);

	nResult = VirtualQuery((const void *)mem->reg.edx, &MemInfo, sizeof(MemInfo));

	if (MemInfo.State & MEM_COMMIT)
		memcpy(mem->mem.edx, (const void *)mem->reg.edx, 1024);
	else
		memset(mem->mem.edx, 0x00, 1024);

	nResult = VirtualQuery((const void *)mem->reg.esi, &MemInfo, sizeof(MemInfo));

	if (MemInfo.State & MEM_COMMIT)
		memcpy(mem->mem.esi, (const void *)mem->reg.esi, 1024);
	else
		memset(mem->mem.esi, 0x00, 1024);

	nResult = VirtualQuery((const void *)mem->reg.edi, &MemInfo, sizeof(MemInfo));

	if (MemInfo.State & MEM_COMMIT)
		memcpy(mem->mem.edi, (const void *)mem->reg.edi, 1024);
	else
		memset(mem->mem.edi, 0x00, 1024);

	nResult = VirtualQuery((const void *)mem->reg.ebp, &MemInfo, sizeof(MemInfo));

	if (MemInfo.State & MEM_COMMIT)
		memcpy(mem->mem.ebp, (const void *)mem->reg.ebp, 1024);
	else
		memset(mem->mem.ebp, 0x00, 1024);

	nResult = VirtualQuery((const void *)mem->reg.esp, &MemInfo, sizeof(MemInfo));

	if (MemInfo.State & MEM_COMMIT)
		memcpy(mem->mem.esp, (const void *)mem->reg.esp, 1024);
	else
		memset(mem->mem.esp, 0x00, 1024);

	DWORD dwProcessId;
	GetWindowThreadProcessId(dna->hProcess, &dwProcessId);
	HANDLE process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
	if (process_handle)
	{
        LPCSTR lpBuffer = NULL;
        LPTHREAD_START_ROUTINE RemoteCallBack = (LPTHREAD_START_ROUTINE)GetRemoteCallBack(process_handle,
                                                                                          dwProcessId,
                                                                                          lpBuffer,
                                                                                          "IDAServ.exe",
                                                                                          "IoCompleteRemoteCallBackForSharedMemory");
		if (RemoteCallBack)
		{
			DWORD thread_id = 0;
			HANDLE thread = CreateRemoteThread(process_handle, NULL, 0, RemoteCallBack, NULL, 0, &thread_id);

			if (thread != NULL && thread_id != 0) {
				WaitForSingleObject(thread, INFINITE);
				DWORD exit_code = 0;
				GetExitCodeThread(thread, &exit_code);
			}
		}
	}
}
*/