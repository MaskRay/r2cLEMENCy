/* radare - LGPL - Copyright 2017 - xvilka */

#include <stdio.h>
#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>

#include "../include/clemency.h"

static const char *mnemonics[] = {
	"invalid",
#define INS(ins, opcode) #ins,
#include "../include/opcode-inc.h"
#undef FORMAT
#undef INS
#undef INS_1
#undef INS_2
#undef INS_3
#undef INS_4
};

static int parse_cc(inst_t *inst, const char **src) {
}

static int parse_comma(inst_t *inst, const char **src) {
	while (isspace (**src)) ++*src;
	if (*(*src)++ != ',') return -1;
	while (isspace (**src)) ++*src;
	return 0;
}

static int parse_imm(inst_t *inst, const char **src) {

}

static int parse_reg(inst_t *inst, const char **src) {
	static const char *specials[] = {"st", "ra", "pc"};
	char *s = (char *)*src;
	for (int i = 0; i < 3; i++)
		if (!strncasecmp (s, specials[i], 2) && !isalnum(s[2])) {
			*src += 2;
			return 29 + i;
		}
	if (islower (*src) == 'r') {
		int r = strtol (s+1, &s, 10);
		*src = s;
		return r;
	}
	return -1;
}

static int parse_rA(inst_t *inst, const char **src) {
	inst->rA = parse_reg (inst, src);
	return 0 <= inst->rA < 32 ? 0 : -1;
}

static int parse_rB(inst_t *inst, const char **src) {
	inst->rB = parse_reg (inst, src);
	return 0 <= inst->rB < 32 ? 0 : -1;
}

static int parse_rC(inst_t *inst, const char **src) {
	inst->rC = parse_reg (inst, src);
	return 0 <= inst->rC < 32 ? 0 : -1;
}

static int parse_space(inst_t *inst, const char **src) {
	const char *s = *src;
	while (isspace (*s)) s++;
	if (s == *src) return -1;
	*src = s;
	return 0;
}

static int parse_uf(inst_t *inst, const char **src) {
	if (**src == '.') {
		inst->uf = 1;
		++*src;
	} else {
		inst->uf = 0;
	}
	return 0;
}

static int assemble_R(inst_t *inst, const char **src) {
	if (parse_uf (inst, src)) return 1;
	if (parse_space (inst, src)) return 1;
	if (parse_rA (inst, src)) return 1;
	if (parse_comma (inst, src)) return -1;
	if (parse_rB (inst, src)) return 2;
	if (parse_comma (inst, src)) return -2;
	if (parse_rC (inst, src)) return 3;
	return 0;
}

static int assemble_R_imm(inst_t *inst, const char **src) {
	if (parse_uf (inst, src)) return 1;
	if (parse_space (inst, src)) return 1;
	if (parse_rA (inst, src)) return 1;
	if (parse_comma (inst, src)) return -1;
	if (parse_rB (inst, src)) return 2;
	if (parse_comma (inst, src)) return -2;
	if (parse_imm (inst, src)) return 3;
	return 0;
}

static int assemble_U(inst_t *inst, const char **src) {
	if (parse_uf (inst, src)) return 1;
	if (parse_space (inst, src)) return 1;
	if (parse_rA (inst, src)) return 1;
	if (parse_comma (inst, src)) return -1;
	if (parse_rB (inst, src)) return 2;
	return 0;
}

static int assemble_BIN_R(inst_t *inst, const char **src) {
	if (parse_space (inst, src)) return 1;
	if (parse_rA (inst, src)) return 1;
	if (parse_comma (inst, src)) return -1;
	if (parse_rB (inst, src)) return 2;
	return 0;
}

static int assemble_BIN_R_IMM(inst_t *inst, const char **src) {
	if (parse_space (inst, src)) return 1;
	if (parse_rA (inst, src)) return 1;
	if (parse_comma (inst, src)) return -1;
	if (parse_imm (inst, src)) return 2;
	return 0;
}

static int assemble_B_CC_OFF(inst_t *inst, const char **src) {
	if (parse_cc (inst, src)) return 1;
	if (parse_space (inst, src)) return 1;
	if (parse_imm (inst, src)) return 1;
	return 0;
}

static int assemble_B_CC_R(inst_t *inst, const char **src) {
	if (parse_cc (inst, src)) return 1;
	if (parse_space (inst, src)) return 1;
	if (parse_rA (inst, src)) return 1;
	return 0;
}

static int assemble_B_OFF(inst_t *inst, const char **src) {
	if (parse_cc (inst, src)) return 1;
	if (parse_space (inst, src)) return 1;
	if (parse_rA (inst, src)) return 1;
	return 0;
}

static int assemble_B_LOC(inst_t *inst, const char **src) {
	if (parse_cc (inst, src)) return 1;
	if (parse_space (inst, src)) return 1;
	if (parse_rA (inst, src)) return 1;
	return 0;
}

static int assemble_N(inst_t *inst, const char **src) {
	return 0;
}

static int assemble_FLAGS_INTS(inst_t *inst, const char **src) {
	if (parse_rA (inst, src)) return 1;
	return 0;
}

static void pprint_R(RAsmOp *op, const inst_t *inst) {
	snprintf (op->buf_asm, sizeof op->buf_asm, "%s%s %s, %s, %s", mnemonics[inst->id], inst->uf ? "." : "", regs[inst->rA], regs[inst->rB], regs[inst->rC]);
}

static void pprint_R_IMM(RAsmOp *op, const inst_t *inst) {
	snprintf (op->buf_asm, sizeof op->buf_asm, "%s%s %s, 0x%" PRIx32, mnemonics[inst->id], inst->uf ? "." : "", regs[inst->rA], inst->imm);
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

#define pprint_MOV_LOW_SIGNED pprint_BIN_R_IMM

static void pprint_B_CC_OFF(RAsmOp *op, const inst_t *inst) {
	if (!conditions[inst->cc])
		strcpy (op->buf_asm, mnemonics[I_invalid]);
	else
		snprintf (op->buf_asm, sizeof op->buf_asm, "%s%s 0x%" PRIx32, mnemonics[inst->id], conditions[inst->cc], inst->pc + inst->imm);
}

static void pprint_B_CC_R(RAsmOp *op, const inst_t *inst) {
	if (!conditions[inst->cc])
		strcpy (op->buf_asm, mnemonics[I_invalid]);
	else
		snprintf (op->buf_asm, sizeof op->buf_asm, "%s%s %s", mnemonics[inst->id], conditions[inst->cc], regs[inst->rA]);
}

static void pprint_B_OFF(RAsmOp *op, const inst_t *inst) {
	snprintf (op->buf_asm, sizeof op->buf_asm, "%s 0x%" PRIx32, mnemonics[inst->id], inst->pc + inst->imm);
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
	if (!conditions[inst->cc])
		strcpy (op->buf_asm, mnemonics[I_invalid]);
	else
		snprintf (op->buf_asm, sizeof op->buf_asm, "%s%s %s", mnemonics[inst->id], conditions[inst->cc], regs[inst->rA]);
}

static void pprint_M(RAsmOp *op, const inst_t *inst) {
	static const char *adj[] = {"", "i", "d"};
	if (inst->adj_rb >= R_ARRAY_SIZE (adj))
		strcpy (op->buf_asm, mnemonics[I_invalid]);
	else {
		if (inst->imm >= 0)
			snprintf (op->buf_asm, sizeof op->buf_asm, "%s%s %s, [%s+0x%" PRIx32 ", %" PRIx32 "]", mnemonics[inst->id], adj[inst->adj_rb], regs[inst->rA], regs[inst->rB], inst->imm, inst->reg_count);
		else
			snprintf (op->buf_asm, sizeof op->buf_asm, "%s%s %s, [%s-0x%" PRIx32 ", %" PRIx32 "]", mnemonics[inst->id], adj[inst->adj_rb], regs[inst->rA], regs[inst->rB], -inst->imm, inst->reg_count);
	}
}

static void pprint_MP(RAsmOp *op, const inst_t *inst) {
	static const char *protections[] = {"", "R", "W", "RE"};
	snprintf (op->buf_asm, sizeof op->buf_asm, "%s %s, %s, %s", mnemonics[inst->id], regs[inst->rA], regs[inst->rB], protections[inst->mem_flags]);
}

static const char *get_reg_name(int reg_index) {
	if (reg_index < sizeof(regs)) {
		return regs[reg_index];
	}
	return NULL;
}

static void asm_clemency_getreg(const ut8 *buf, int index, char *reg_str, int max_len) {
	int reg;
	int byte_off;
	int bit_off;
	const ut8 *c;

	byte_off = index / 8;
	bit_off = index % 8;
	c = &buf[byte_off]; // buf+byte_off;
	reg = (*c >> bit_off) & 0x1f;
	if (bit_off > 3) {
		bit_off = 8 - bit_off;
		c = c + 1;
		reg = reg & (*c << bit_off);
	}
	switch (reg & 0x1f) {
		case 29:
			snprintf(reg_str, max_len, "st");
			break;
		case 30:
			snprintf(reg_str, max_len, "ra");
			break;
		case 31:
			snprintf(reg_str, max_len, "pc");
			break;
		default:
			snprintf(reg_str, max_len, "r%d", buf[0]);
			break;
	}
}

// return new offset
static int dump_9bit(const ut8 *buf, int bitoff) {
	ut9 i;
	int offset = bitoff + 9; // bit level offset
	static char b[16] = { 0 };
	ut9 meint = r_read_me9 (buf, bitoff);
	for (i = 9; i > 0; i--) {
		if ((meint & (1UL << i)) >> i == 1) {
			b[i-1] = '1';
		} else {
			b[i-1] = '0';
		}
	}
	eprintf ("%08d : %s [%08x]\n", bitoff, b, meint);
	return offset;
}

static int dump_27bit(const ut8 *buf, int bitoff) {
	ut27 i;
	int offset = bitoff + 27; // bit level offset
	static char b[32] = { 0 };
	ut27 meint = r_read_me27 (buf, bitoff);
	for (i = 27; i > 0; i--) {
		if ((meint & (1UL << i)) >> i == 1) {
			b[i-1] = '1';
		} else {
			b[i-1] = '0';
		}
	}
	eprintf ("%08d : %s [%08"PFMT32x"]\n", bitoff, b, meint);
	return offset;
}

static int assemble(RAsm *a, RAsmOp *op, const char *buf) {
	return 0;
}

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *src, int len) {
	inst_t inst = {.pc = a->pc};
	void (*pprint)(RAsmOp *op, const inst_t *inst);

#define FORMAT(fmt) decode_##fmt (&inst, (const ut16*)src); pprint = pprint_##fmt;
#define INS(x,opc) do { if (inst.opcode == opc) { inst.id = I_##x; pprint (op, &inst); return op->size = inst.size; } } while (0);
#define INS_1(x,opc,f1,v1) do { if (inst.opcode == opc && inst.f1 == v1) { inst.id = I_##x; pprint (op, &inst); return op->size = inst.size; } } while (0);
#define INS_2(x,opc,f1,v1,f2,v2) do { if (inst.opcode == opc && inst.f1 == v1 && inst.f2 == v2) { inst.id = I_##x; pprint (op, &inst); return op->size = inst.size; } } while (0);
#define INS_3(x,opc,f1,v1,f2,v2,f3,v3) do { if (inst.opcode == opc && inst.f1 == v1 && inst.f2 == v2 && inst.f3 == v3) { inst.id = I_##x; pprint (op, &inst); return op->size = inst.size; } } while (0);
#define INS_4(x,opc,f1,v1,f2,v2,f3,v3,f4,v4) do { if (inst.opcode == opc && inst.f1 == v1 && inst.f2 == v2 && inst.f3 == v3 && inst.f4 == v4) { inst.id = I_##x; pprint (op, &inst); return op->size = inst.size; } } while (0);
#include "../include/opcode-inc.h"
#undef FORMAT
#undef INS
#undef INS_1
#undef INS_2
#undef INS_3
#undef INS_4

	strcpy (op->buf_asm, mnemonics[I_invalid]);
	return op->size = 1;
}

static RAsmPlugin r_asm_plugin_clemency  = {
	.name = "clcy",
	.arch = "clcy",
	.license = "LGPL3",
	.bits = 27,
	.desc = "cLEMENCy disassembler and assembler",
	.disassemble = &disassemble,
	.assemble = &assemble,
};

RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_clemency,
	.version = R2_VERSION,
};
