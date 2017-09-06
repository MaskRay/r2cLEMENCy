#include <errno.h>
#include <r_types.h>

#include "include/disasm.h"
#include "include/opfield-inc.h"

#define FIELD(name, offset, count) inst->name = (inst->code >> bit_size-count-offset) & ((1 << count) - 1);
#define SIGN_EXTEND(name, count) do { inst->name = ((st32)inst->name << (32 - count)) >> (32 - count); } while (0)

const char *conditions[16] = {
  "n", "e", "l", "le", "g", "ge", "no", "o",
  "ns", "s", "sl", "sle", "sg", "sge", NULL, ""
};

const char *regs[32] = {
	"r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8",
	"r9", "r10", "r11", "r12", "r13", "r14", "r15", "r16",
	"r17", "r18", "r19", "r20", "r21", "r22", "r23", "r24",
	"r25", "r26", "r27", "r28", "st", "ra", "pc"
};

static const char *mnemonics[] = {
	"invalid",
#define INS(ins, opcode) #ins,
#include "include/opcode-inc.h"
#undef FORMAT
#undef INS
#undef INS_1
#undef INS_2
#undef INS_3
#undef INS_4
};

static ut64 read_18(const ut16 *src) {
  return (ut64)src[1] << 9 | src[0];
}

static ut64 read_27(const ut16 *src) {
  return (ut64)src[1] << 18 | (ut64)src[0] << 9 | src[2];
}

static ut64 read_36(const ut16 *src) {
  return (ut64)src[1] << 27 | (ut64)src[0] << 18 | (ut64)src[2] << 9 | src[3];
}

static ut64 read_54(const ut16 *src) {
  return (ut64)src[1] << 45 | (ut64)src[0] << 36 | (ut64)src[2] << 27 | (ut64)src[4] << 18 | (ut64)src[3] << 9 | src[5];
}

#define DEFINE_DECODE(type, bits) \
  bool decode_##type(inst_t *inst, const ut16 *src, int len) \
  { \
    int bit_size = bits; \
    if ((inst->size = bits / 9) > len) return false; \
    inst->code = read_##bits (src); \
		FORM_##type; \
		return true; \
  }

DEFINE_DECODE (R, 27)
DEFINE_DECODE (R_IMM, 27)
DEFINE_DECODE (U, 27)
DEFINE_DECODE (BIN_R, 18)
DEFINE_DECODE (BIN_R_IMM, 27)
DEFINE_DECODE (MOV_LOW_HI, 27)
DEFINE_DECODE (B_CC_R, 18)
DEFINE_DECODE (B_LOC, 36)
DEFINE_DECODE (N, 18)
DEFINE_DECODE (FLAGS_INTS, 18)
DEFINE_DECODE (U_EXTEND, 27)
DEFINE_DECODE (RANDOM, 27)
DEFINE_DECODE (MP, 27)

#undef DEFINE_DECODE

bool decode_MOV_LOW_SIGNED(inst_t *inst, const ut16 *src, int len)
{
  int bit_size = 27;
  if ((inst->size = 3) > len) return false;
  inst->code = read_27 (src);
	FORM_MOV_LOW_SIGNED;
  SIGN_EXTEND(imm, 17);
	return true;
}

bool decode_B_CC_OFF(inst_t *inst, const ut16 *src, int len)
{
  int bit_size = 27;
  if ((inst->size = 3) > len) return false;
  inst->code = read_27 (src);
	FORM_B_CC_OFF;
  SIGN_EXTEND (imm, 17);
	return true;
}

bool decode_B_OFF(inst_t *inst, const ut16 *src, int len)
{
  int bit_size = 36;
  if ((inst->size = 4) > len) return false;
  inst->code = read_36 (src);
	FORM_B_OFF;
  SIGN_EXTEND (imm, 27);
	return true;
}

bool decode_M(inst_t *inst, const ut16 *src, int len)
{
  int bit_size = 54;
  if ((inst->size = 6) > len) return false;
  inst->code = read_54 (src);
	FORM_M;
  SIGN_EXTEND (imm, 27);
  inst->reg_count++;
	return true;
}

int parse_reg(const char **src) {
	static const char *specials[] = {"st", "ra", "pc"};
	char *s = (char *)*src;
	for (int i = 0; i < 3; i++)
		if (!strncasecmp (s, specials[i], 2) && !isalnum (s[2])) {
			*src += 2;
			return 29 + i;
		}
	if (tolower (*s) == 'r') {
		errno = 0;
		int r = strtol (s+1, &s, 10);
		if (errno || s == *src+1) return -1;
		*src = s;
		return r;
	}
	return -1;
}

static void pprint_R(RAsmOp *op, const inst_t *inst) {
	snprintf (op->buf_asm, sizeof op->buf_asm, "%s%s %s, %s, %s", mnemonics[inst->id], inst->uf ? "." : "", regs[inst->rA], regs[inst->rB], regs[inst->rC]);
}

static void pprint_R_IMM(RAsmOp *op, const inst_t *inst) {
	snprintf (op->buf_asm, sizeof op->buf_asm, "%s%s %s, %s, 0x%" PRIx32, mnemonics[inst->id], inst->uf ? "." : "", regs[inst->rA], regs[inst->rB], inst->imm);
}

static void pprint_U(RAsmOp *op, const inst_t *inst) {
	snprintf (op->buf_asm, sizeof op->buf_asm, "%s%s %s, %s", mnemonics[inst->id], inst->uf ? "." : "", regs[inst->rA], regs[inst->rB]);
}

static void pprint_BIN_R(RAsmOp *op, const inst_t *inst) {
	snprintf (op->buf_asm, sizeof op->buf_asm, "%s %s, %s", mnemonics[inst->id], regs[inst->rA], regs[inst->rB]);
}

static void pprint_BIN_R_IMM(RAsmOp *op, const inst_t *inst) {
	snprintf (op->buf_asm, sizeof op->buf_asm, "%s %s, 0x%" PRIx32, mnemonics[inst->id], regs[inst->rA], inst->imm);
}

#define pprint_MOV_LOW_HI pprint_BIN_R_IMM

static void pprint_MOV_LOW_SIGNED(RAsmOp *op, const inst_t *inst) {
	// clemency-emu displays this as 17-bit
	snprintf (op->buf_asm, sizeof op->buf_asm, "%s %s, 0x%" PRIx32, mnemonics[inst->id], regs[inst->rA], inst->imm & MASK_27);
}

static void pprint_B_CC_OFF(RAsmOp *op, const inst_t *inst) {
	if (!conditions[inst->cc])
		strcpy (op->buf_asm, mnemonics[I_invalid]);
	else
		snprintf (op->buf_asm, sizeof op->buf_asm, "%s%s 0x%" PRIx32, mnemonics[inst->id], conditions[inst->cc], inst->pc + inst->imm & MASK_27);
}

static void pprint_B_CC_R(RAsmOp *op, const inst_t *inst) {
	if (!conditions[inst->cc])
		strcpy (op->buf_asm, mnemonics[I_invalid]);
	else
		snprintf (op->buf_asm, sizeof op->buf_asm, "%s%s %s", mnemonics[inst->id], conditions[inst->cc], regs[inst->rA]);
}

static void pprint_B_OFF(RAsmOp *op, const inst_t *inst) {
	snprintf (op->buf_asm, sizeof op->buf_asm, "%s 0x%" PRIx32, mnemonics[inst->id], inst->pc + inst->imm & MASK_27);
}

static void pprint_B_LOC(RAsmOp *op, const inst_t *inst) {
	snprintf (op->buf_asm, sizeof op->buf_asm, "%s 0x%" PRIx32, mnemonics[inst->id], inst->imm);
}

static void pprint_N(RAsmOp *op, const inst_t *inst) {
	snprintf (op->buf_asm, sizeof op->buf_asm, "%s", mnemonics[inst->id]);
}

static void pprint_FLAGS_INTS(RAsmOp *op, const inst_t *inst) {
	snprintf (op->buf_asm, sizeof op->buf_asm, "%s %s", mnemonics[inst->id], regs[inst->rA]);
}

static void pprint_U_EXTEND(RAsmOp *op, const inst_t *inst) {
	snprintf (op->buf_asm, sizeof op->buf_asm, "%s %s, %s", mnemonics[inst->id], regs[inst->rA], regs[inst->rB]);
}

static void pprint_RANDOM(RAsmOp *op, const inst_t *inst) {
	snprintf (op->buf_asm, sizeof op->buf_asm, "%s%s %s", mnemonics[inst->id], inst->uf ? "." : "", regs[inst->rA]);
}

static void pprint_M(RAsmOp *op, const inst_t *inst) {
	static const char *adj[] = {"", "i", "d"};
	if (inst->adj_rb >= R_ARRAY_SIZE (adj))
		strcpy (op->buf_asm, mnemonics[I_invalid]);
	else {
		if (inst->imm >= 0)
			snprintf (op->buf_asm, sizeof op->buf_asm, "%s%s %s, [%s+0x%" PRIx32 ", %" PRIi16 "]", mnemonics[inst->id], adj[inst->adj_rb], regs[inst->rA], regs[inst->rB], inst->imm, inst->reg_count);
		else
			snprintf (op->buf_asm, sizeof op->buf_asm, "%s%s %s, [%s-0x%" PRIx32 ", %" PRIi16 "]", mnemonics[inst->id], adj[inst->adj_rb], regs[inst->rA], regs[inst->rB], -inst->imm, inst->reg_count);
	}
}

static void pprint_MP(RAsmOp *op, const inst_t *inst) {
	static const char *protections[] = {"", "R", "RW", "RE"};
	snprintf (op->buf_asm, sizeof op->buf_asm, "%s %s, %s, %s", mnemonics[inst->id], regs[inst->rA], regs[inst->rB], protections[inst->mem_flags]);
}

int disassemble(RAsm *a, RAsmOp *op, const ut8 *src, int len) {
	inst_t inst = {.pc = a->pc};
	void (*pprint)(RAsmOp *op, const inst_t *inst);
	bool ok;

#define FORMAT(fmt) ok = decode_##fmt (&inst, (const ut16*)src, len/2); pprint = pprint_##fmt;
#define INS(x,opc) do { if (ok && inst.opcode == opc) { inst.id = I_##x; pprint (op, &inst); return op->size = inst.size; } } while (0);
#define INS_1(x,opc,f1,v1) do { if (ok && inst.opcode == opc && inst.f1 == v1) { inst.id = I_##x; pprint (op, &inst); return op->size = inst.size; } } while (0);
#define INS_2(x,opc,f1,v1,f2,v2) do { if (ok && inst.opcode == opc && inst.f1 == v1 && inst.f2 == v2) { inst.id = I_##x; pprint (op, &inst); return op->size = inst.size; } } while (0);
#define INS_3(x,opc,f1,v1,f2,v2,f3,v3) do { if (ok && inst.opcode == opc && inst.f1 == v1 && inst.f2 == v2 && inst.f3 == v3) { inst.id = I_##x; pprint (op, &inst); return op->size = inst.size; } } while (0);
#define INS_4(x,opc,f1,v1,f2,v2,f3,v3,f4,v4) do { if (ok && inst.opcode == opc && inst.f1 == v1 && inst.f2 == v2 && inst.f3 == v3 && inst.f4 == v4) { inst.id = I_##x; pprint (op, &inst); return op->size = inst.size; } } while (0);
#include "include/opcode-inc.h"
#undef FORMAT
#undef INS
#undef INS_1
#undef INS_2
#undef INS_3
#undef INS_4

	strcpy (op->buf_asm, mnemonics[I_invalid]);
	return op->size = 1;
}
