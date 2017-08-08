#pragma once

#define MASK_9 0x1ff
#define MASK_18 0x3ffff
#define MASK_27 0x7ffffff
#define MASK_54 0x3fffffffffffffull
#define BIT_26 (1L << 26)
#define BIT_53 (1L << 53)

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

typedef struct {
  ut64 code, opcode;
  int id, size;
  ut32 pc, funct;
  st32 imm;
  ut16 cc, reg_count;
  ut8 adj_rb, arith_signed, is_imm, mem_flags, rA, rB, rC, rw, uf;
} inst_t;

extern const char *conditions[16];
extern const char *regs[32];
