#pragma once

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

typedef struct {
  ut64 code, opcode;
  int id, size;
  ut32 pc, funct;
  st32 imm;
  ut16 cc, reg_count;
  ut8 adj_rb, arith_signed, is_imm, mem_flags, rA, rB, rC, rw, uf;
} inst_t;
