#include <r_asm.h>

typedef ut16 ut9;
typedef ut32 ut18;
typedef ut32 ut27;

enum {
  I_invalid = 0,
#define INS(X, OPC) I_##X,
#include "opcode-inc.h"
#undef FORMAT
#undef INS
#undef INS_1
#undef INS_2
#undef INS_3
#undef INS_4
  I__count
};

enum {
	CC_n,
	CC_e,
	CC_l,
	CC_le,
	CC_g,
	CC_ge,
	CC_no,
	CC_o,
	CC_ns,
	CC_s,
	CC_sl,
	CC_sle,
	CC_sg,
	CC_sge,
	CC_invalid,
	CC_always,
};

static const char *conditions[16] = {
  "n", "e", "l", "le", "g", "ge", "no", "o",
  "ns", "s", "sl", "sle", "sg", "sge", NULL, ""
};

static const char *regs[32] = {
	"r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8",
	"r9", "r10", "r11", "r12", "r13", "r14", "r15", "r16",
	"r17", "r18", "r19", "r20", "r21", "r22", "r23", "r24",
	"r25", "r26", "r27", "r28", "st", "ra", "pc"
};

static ut9 r_read_me9(const ut8* buf, int boff) {
	ut9 ret = 0;
	r_mem_copybits_delta ((ut8*)&ret, 0, buf, boff, 9);
	return ret;
}

static ut18 r_read_me18(const ut8* buf, int boff) {
	ut18 ret = 0;
	r_mem_copybits_delta((ut8*)&ret, 9, buf, boff, 9);
	r_mem_copybits_delta((ut8*)&ret, 0, buf, boff + 9, 9);
	return ret;
}

static ut27 r_read_me27(const ut8* buf, int boff) {
	ut27 ret = 0;
	r_mem_copybits_delta((ut8*)&ret, 18, buf, boff + 18, 9);
	r_mem_copybits_delta((ut8*)&ret, 9, buf, boff, 9);
	r_mem_copybits_delta((ut8*)&ret, 0, buf, boff + 9, 9);
	return ret;
}

static ut27 r_read_plain27(const ut8* buf, int boff) {
	ut27 ret = 0;
	r_mem_copybits_delta((ut8*)&ret, 0, buf, boff, 9);
	r_mem_copybits_delta((ut8*)&ret, 9, buf, boff + 9, 9);
	r_mem_copybits_delta((ut8*)&ret, 18, buf, boff + 18, 9);
	return ret;
}

static void r_write_me9(ut8* buf, ut9 val, int boff) {
	r_mem_copybits_delta (buf, boff, (ut8*)&val, 0, 9);
}

static void r_write_me18(ut8* buf, ut18 val, int boff) {
	r_mem_copybits_delta(buf, boff + 9, (ut8*)&val, 0, 9);
	r_mem_copybits_delta(buf, boff, (ut8*)&val, 9, 9);
}

static void r_write_me27(ut8* buf, ut27 val, int boff) {
	r_mem_copybits_delta(buf, boff + 18, (ut8*)&val, 18, 9);
	r_mem_copybits_delta(buf, boff + 9, (ut8*)&val, 0, 9);
	r_mem_copybits_delta(buf, boff, (ut8*)&val, 9, 9);
}

static void r_write_plain27(ut8* buf, ut27 val, int boff) {
	r_mem_copybits_delta(buf, boff, (ut8*)&val, 0, 9);
	r_mem_copybits_delta(buf, boff + 9, (ut8*)&val, 9, 9);
	r_mem_copybits_delta(buf, boff + 18, (ut8*)&val, 18, 9);
}

typedef struct {
  ut64 code, opcode;
  int id, size;
  ut32 pc, funct;
  st32 imm;
  ut16 cc, reg_count;
  ut8 adj_rb, arith_signed, is_imm, mem_flags, rA, rB, rC, rw, uf;
} inst_t;

#define FIELD(name, offset, count) inst->name = (inst->code >> bit_size-count-offset) & ((1 << count) - 1)
#define SIGN_EXTEND(name, count) do { inst->name = ((st32)inst->name << (32 - count)) >> (32 - count); } while (0)

static ut64 read_18(const ut16 *src) {
  return (ut64)src[1] << 9 | src[0];
}

static ut64 read_27(const ut16 *src) {
  return (ut64)src[1] << 18 | (ut64)src[0] << 9 | src[2];
}

static ut64 read_36(const ut16 *src) {
  return (ut64)src[1] << 27 | (ut64)src[0] << 18 | (ut64)src[2] << 9 | src[3];
}

static ut64 read_45(const ut16 *src) {
  return (ut64)src[1] << 36 | (ut64)src[0] << 27 | (ut64)src[2] << 18 | (ut64)src[4] << 9 | src[3];
}

static ut64 read_54(const ut16 *src) {
  return (ut64)src[1] << 45 | (ut64)src[0] << 36 | (ut64)src[2] << 27 | (ut64)src[4] << 18 | (ut64)src[3] << 9 | src[5];
}

static void decode_R(inst_t *inst, const ut16 *src)
{
  int bit_size = 27;
  inst->size = 3;
  inst->code = read_27 (src);
  FIELD(opcode, 0, 7);
  FIELD(rA, 7, 5);
  FIELD(rB, 12, 5);
  FIELD(rC, 17, 5);
  FIELD(funct, 22, 2);
  FIELD(arith_signed, 24, 1);
  FIELD(is_imm, 25, 1);
  FIELD(uf, 26, 1);
}

static void decode_R_IMM(inst_t *inst, const ut16 *src)
{
  int bit_size = 27;
  inst->size = 3;
  inst->code = read_27 (src);
  FIELD(opcode, 0, 7);
  FIELD(rA, 7, 5);
  FIELD(rB, 12, 5);
  FIELD(imm, 17, 7);
  FIELD(arith_signed, 24, 1);
  FIELD(is_imm, 25, 1);
  FIELD(uf, 26, 1);
}

static void decode_U(inst_t *inst, const ut16 *src)
{
  int bit_size = 27;
  inst->size = 3;
  inst->code = read_27 (src);
  FIELD(opcode, 0, 9);
  FIELD(rA, 9, 5);
  FIELD(rB, 14, 5);
  FIELD(funct, 19, 7);
  FIELD(uf, 26, 1);
}

static void decode_BIN_R(inst_t *inst, const ut16 *src)
{
  int bit_size = 18;
  inst->size = 2;
  inst->code = read_18 (src);
  FIELD(opcode, 0, 8);
  FIELD(rA, 8, 5);
  FIELD(rB, 13, 5);
}

static void decode_BIN_R_IMM(inst_t *inst, const ut16 *src)
{
  int bit_size = 27;
  inst->size = 3;
  inst->code = read_27 (src);
  FIELD(opcode, 0, 8);
  FIELD(rA, 8, 5);
  FIELD(imm, 13, 14);
}

static void decode_MOV_LOW_HI(inst_t *inst, const ut16 *src)
{
  int bit_size = 27;
  inst->size = 3;
  inst->code = read_27 (src);
  FIELD(opcode, 0, 5);
  FIELD(rA, 5, 5);
  FIELD(imm, 10, 17);
}

static void decode_MOV_LOW_SIGNED(inst_t *inst, const ut16 *src)
{
  int bit_size = 27;
  inst->size = 3;
  inst->code = read_27 (src);
  FIELD(opcode, 0, 5);
  FIELD(rA, 5, 5);
  FIELD(imm, 10, 17);
  SIGN_EXTEND(imm, 17);
}

static void decode_B_CC_OFF(inst_t *inst, const ut16 *src)
{
  int bit_size = 27;
  inst->size = 3;
  inst->code = read_27 (src);
  FIELD(opcode, 0, 6);
  FIELD(cc, 6, 4);
  FIELD(imm, 10, 17);
  SIGN_EXTEND(imm, 17);
}

static void decode_B_CC_R(inst_t *inst, const ut16 *src)
{
  int bit_size = 18;
  inst->size = 2;
  inst->code = read_18 (src);
  FIELD(opcode, 0, 6);
  FIELD(cc, 6, 4);
  FIELD(rA, 10, 5);
  FIELD(funct, 15, 3);
}

static void decode_B_OFF(inst_t *inst, const ut16 *src)
{
  int bit_size = 36;
  inst->size = 4;
  inst->code = read_36 (src);
  FIELD(opcode, 0, 9);
  FIELD(imm, 9, 27);
  SIGN_EXTEND(imm, 27);
}

static void decode_B_LOC(inst_t *inst, const ut16 *src)
{
  int bit_size = 36;
  inst->size = 4;
  inst->code = read_36 (src);
  FIELD(opcode, 0, 9);
  FIELD(imm, 9, 27);
}

static void decode_N(inst_t *inst, const ut16 *src)
{
  int bit_size = 18;
  inst->size = 2;
  inst->code = read_18 (src);
  FIELD(opcode, 0, 18);
}

static void decode_FLAGS_INTS(inst_t *inst, const ut16 *src)
{
  int bit_size = 18;
  inst->size = 2;
  inst->code = read_18 (src);
  FIELD(opcode, 0, 12);
  FIELD(rA, 12, 5);
  FIELD(funct, 17, 1);
}

static void decode_U_EXTEND(inst_t *inst, const ut16 *src)
{
  int bit_size = 27;
  inst->size = 3;
  inst->code = read_27 (src);
  FIELD(opcode, 0, 12);
  FIELD(rA, 12, 5);
  FIELD(rB, 17, 5);
  FIELD(funct, 22, 5);
}

static void decode_RANDOM(inst_t *inst, const ut16 *src)
{
  int bit_size = 27;
  inst->size = 3;
  inst->code = read_27 (src);
  FIELD(opcode, 0, 9);
  FIELD(rA, 9, 5);
  FIELD(funct, 14, 12);
  FIELD(uf, 26, 1);
}

static void decode_M(inst_t *inst, const ut16 *src)
{
  int bit_size = 54;
  inst->size = 6;
  inst->code = read_54 (src);
  FIELD(opcode, 0, 7);
  FIELD(rA, 7, 5);
  FIELD(rB, 12, 5);
  FIELD(reg_count, 17, 5);
  FIELD(adj_rb, 22, 2);
  FIELD(imm, 24, 27);
  SIGN_EXTEND(imm, 27);
  FIELD(funct, 51, 3);

  inst->reg_count++;
}

static void decode_MP(inst_t *inst, const ut16 *src)
{
  int bit_size = 27;
  inst->size = 3;
  inst->code = read_27 (src);
  FIELD(opcode, 0, 7);
  FIELD(rA, 7, 5);
  FIELD(rB, 12, 5);
  FIELD(rw, 17, 1);
  FIELD(mem_flags, 18, 2);
  FIELD(funct, 20, 7);
}

#undef FIELD
#undef SIGN_EXTEND
