/* radare - LGPL - Copyright 2017 - xvilka, MaskRay */
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>

#include "../include/clemency.h"
#include "../include/disasm.h"
#include "../include/opfield-inc.h"

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
	for (int i = 0; i < R_ARRAY_SIZE (conditions); i++)
		if (conditions[i]) {
			int l = strlen (conditions[i]);
			if (!strncasecmp (*src, conditions[i], l) && !isalnum ((*src)[l])) {
				*src += l;
				inst->cc = i;
				return 0;
			}
		}
	return -1;
}

static int parse_char(inst_t *inst, const char **src, char c) {
	while (isspace (**src)) ++*src;
	if (*(*src)++ != c) return -1;
	while (isspace (**src)) ++*src;
	return 0;
}

static int parse_comma(inst_t *inst, const char **src) {
	return parse_char (inst, src, ',');
}

static int parse_end(const char **src) {
	while (isspace (**src)) ++*src;
	return **src ? -1 : 0;
}

static int parse_imm_st(inst_t *inst, const char **src, int bits) {
	char *s = (char *)*src;
	errno = 0;
	inst->imm = strtol (s, &s, 0);
	if (errno || s == *src || !(-1 << bits-1 <= inst->imm && inst->imm < 1 << bits-1)) return -1;
	*src = s;
	return 0;
}

static int parse_imm_ut(inst_t *inst, const char **src, int bits) {
	char *s = (char *)*src;
	errno = 0;
	inst->imm = strtol (s, &s, 0);
	if (errno || s == *src || !(0 <= inst->imm && inst->imm < 1 << bits)) return -1;
	*src = s;
	return 0;
}

static int parse_rA(inst_t *inst, const char **src) {
	inst->rA = parse_reg (src);
	return 0 <= inst->rA < 32 ? 0 : -1;
}

static int parse_rB(inst_t *inst, const char **src) {
	inst->rB = parse_reg (src);
	return 0 <= inst->rB < 32 ? 0 : -1;
}

static int parse_rC(inst_t *inst, const char **src) {
	inst->rC = parse_reg (src);
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

#define FIELD(name, offset, count) | ((ut64)inst->name << bit_size-count-offset)

static int assemble_R(inst_t *inst, const char **src) {
	int bit_size = 27;
	if (parse_uf (inst, src)) return 1;
	if (parse_space (inst, src)) return 1;
	if (parse_rA (inst, src)) return 1;
	if (parse_comma (inst, src)) return -1;
	if (parse_rB (inst, src)) return 2;
	if (parse_comma (inst, src)) return -2;
	if (parse_rC (inst, src)) return 3;
	if (parse_end (src)) return 3;
	inst->size = 3;
	inst->code = 0 FORM_R;
	return 0;
}

static int assemble_R_IMM(inst_t *inst, const char **src) {
	int bit_size = 27;
	if (parse_uf (inst, src)) return 1;
	if (parse_space (inst, src)) return 1;
	if (parse_rA (inst, src)) return 1;
	if (parse_comma (inst, src)) return -1;
	if (parse_rB (inst, src)) return 2;
	if (parse_comma (inst, src)) return -2;
	if (parse_imm_st (inst, src, 28)) return 3; // TODO differentiate st/ut e.g. dvi/dvis
	inst->imm &= MASK_27;
	if (parse_end (src)) return 3;
	inst->size = 3;
	inst->code = 0 FORM_R_IMM;
	return 0;
}

static int assemble_U(inst_t *inst, const char **src) {
	int bit_size = 27;
	if (parse_uf (inst, src)) return 1;
	if (parse_space (inst, src)) return 1;
	if (parse_rA (inst, src)) return 1;
	if (parse_comma (inst, src)) return -1;
	if (parse_rB (inst, src)) return 2;
	if (parse_end (src)) return 2;
	inst->size = 3;
	inst->code = 0 FORM_U;
	return 0;
}

static int assemble_BIN_R(inst_t *inst, const char **src) {
	int bit_size = 18;
	if (parse_space (inst, src)) return 1;
	if (parse_rA (inst, src)) return 1;
	if (parse_comma (inst, src)) return -1;
	if (parse_rB (inst, src)) return 2;
	if (parse_end (src)) return 2;
	inst->size = 2;
	inst->code = 0 FORM_BIN_R;
	return 0;
}

static int assemble_BIN_R_IMM(inst_t *inst, const char **src) {
	int bit_size = 27;
	if (parse_space (inst, src)) return 1;
	if (parse_rA (inst, src)) return 1;
	if (parse_comma (inst, src)) return -1;
	if (parse_imm_st (inst, src, 14)) return 2;
	inst->imm &= (1 << 14) - 1;
	if (parse_end (src)) return 2;
	inst->size = 3;
	inst->code = 0 FORM_BIN_R_IMM;
	return 0;
}

static int assemble_MOV_LOW_HI(inst_t *inst, const char **src) {
	int bit_size = 27;
	if (parse_space (inst, src)) return 1;
	if (parse_rA (inst, src)) return 1;
	if (parse_comma (inst, src)) return -1;
	if (parse_imm_ut (inst, src, 17)) return 2;
	if (parse_end (src)) return 2;
	inst->size = 3;
	inst->code = 0 FORM_MOV_LOW_HI;
	return 0;
}

static int assemble_MOV_LOW_SIGNED(inst_t *inst, const char **src) {
	int bit_size = 27;
	if (parse_space (inst, src)) return 1;
	if (parse_rA (inst, src)) return 1;
	if (parse_comma (inst, src)) return -1;
	if (parse_imm_st (inst, src, 17)) return 2;
	inst->imm &= (1 << 17) - 1;
	if (parse_end (src)) return 2;
	inst->size = 3;
	inst->code = 0 FORM_MOV_LOW_HI;
	return 0;
}

static int assemble_B_CC_OFF(inst_t *inst, const char **src) {
	int bit_size = 27;
	if (parse_cc (inst, src)) return 1;
	if (parse_space (inst, src)) return 1;
	if (parse_imm_ut (inst, src, 17)) return 1;
	inst->imm = inst->imm - inst->pc & (1 << 17) - 1;
	if (parse_end (src)) return 1;
	inst->size = 3;
	inst->code = 0 FORM_B_CC_OFF;
	return 0;
}

static int assemble_B_CC_R(inst_t *inst, const char **src) {
	int bit_size = 18;
	if (parse_cc (inst, src)) return 1;
	if (parse_space (inst, src)) return 1;
	if (parse_rA (inst, src)) return 1;
	if (parse_end (src)) return 1;
	inst->size = 2;
	inst->code = 0 FORM_B_CC_R;
	return 0;
}

static int assemble_B_OFF(inst_t *inst, const char **src) {
	int bit_size = 36;
	if (parse_space (inst, src)) return 1;
	if (parse_imm_ut (inst, src, 27)) return 1;
	inst->imm = inst->imm - inst->pc & MASK_27;
	if (parse_end (src)) return 1;
	inst->size = 4;
	inst->code = 0 FORM_B_OFF;
	return 0;
}

static int assemble_B_LOC(inst_t *inst, const char **src) {
	int bit_size = 36;
	if (parse_cc (inst, src)) return 1;
	if (parse_imm_ut (inst, src, 27)) return 1;
	if (parse_end (src)) return 1;
	inst->size = 4;
	inst->code = 0 FORM_B_LOC;
	return 0;
}

static int assemble_N(inst_t *inst, const char **src) {
	int bit_size = 18;
	if (parse_end (src)) return 1;
	inst->size = 2;
	inst->code = 0 FORM_N;
	return 0;
}

static int assemble_FLAGS_INTS(inst_t *inst, const char **src) {
	int bit_size = 18;
	if (parse_space (inst, src)) return 1;
	if (parse_rA (inst, src)) return 1;
	if (parse_end (src)) return 1;
	inst->size = 2;
	inst->code = 0 FORM_FLAGS_INTS;
	return 0;
}

static int assemble_U_EXTEND(inst_t *inst, const char **src) {
	int bit_size = 27;
	if (parse_space (inst, src)) return 1;
	if (parse_rA (inst, src)) return 1;
	if (parse_comma (inst, src)) return -1;
	if (parse_rB (inst, src)) return 2;
	if (parse_end (src)) return 2;
	inst->size = 3;
	inst->code = 0 FORM_U_EXTEND;
	return 0;
}

static int assemble_RANDOM(inst_t *inst, const char **src) {
	int bit_size = 27;
	if (parse_uf (inst, src)) return 1;
	if (parse_space (inst, src)) return 1;
	if (parse_rA (inst, src)) return 1;
	if (parse_end (src)) return 1;
	inst->size = 3;
	inst->code = 0 FORM_RANDOM;
	return 0;
}

static int assemble_M(inst_t *inst, const char **src) {
	int bit_size = 54;
	if (**src == 'i') {
		++*src;
		inst->adj_rb = 1;
	} else if (**src == 'd') {
		++*src;
		inst->adj_rb = 2;
	} else {
		inst->adj_rb = 0;
	}
	if (parse_space (inst, src)) return 1;
	if (parse_rA (inst, src)) return 1;
	if (parse_comma (inst, src)) return 1;
	if (parse_char (inst, src, '[')) return 1;
	if (parse_rB (inst, src)) return 2;
	if (**src == ',')
		inst->imm = 0;
	else {
		if (parse_imm_st (inst, src, 27)) return 3;
		inst->imm &= MASK_27;
	}
	if (parse_comma (inst, src)) return -3;
	char *s = (char *)*src;
	errno = 0;
	inst->reg_count = strtol (s, &s, 0);
	if (errno || !(0 < inst->reg_count && inst->reg_count <= 32)) return 4;
	*src = s;
	inst->reg_count--;
	if (parse_char (inst, src, ']')) return 4;
	if (parse_end (src)) return 4;
	inst->size = 6;
	inst->code = 0 FORM_M;
	return 0;
}

static int assemble_MP(inst_t *inst, const char **src) {
	int bit_size = 27;
	if (parse_space (inst, src)) return 1;
	if (parse_rA (inst, src)) return 1;
	if (parse_comma (inst, src)) return 1;
	if (parse_rB (inst, src)) return 2;
	if (parse_comma (inst, src)) return 1;
	char *s = (char *)*src;
	if (tolower (s[0]) == 'r') {
		if (tolower (s[1]) == 'w') {
			inst->mem_flags = 2;
			s += 2;
		} else if (tolower (s[1]) == 'e') {
			inst->mem_flags = 3;
			s += 2;
		} else {
			inst->mem_flags = 1;
			s++;
		}
	} else if ('0' <= s[0] && s[0] <= '4') {
		inst->mem_flags = s[0] - '0';
		s++;
	} else {
		inst->mem_flags = 0;
	}
	*src = s;
	if (parse_end (src)) return 3;
	inst->size = 3;
	inst->code = 0 FORM_MP;
	return 0;
}

#undef FIELD

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

static int assemble(RAsm *a, RAsmOp *op, const char *src) {
	static const char *bc[] = {"br", "b", "cr", "c"};
	static const char *adj[] = {"lds", "ldt", "ldw", "sts", "stt", "stw"};

	char buf[4096];
	int mnemlen = 0;
	snprintf (buf, sizeof buf, "%s", src);
	for (int i = 0; i < R_ARRAY_SIZE (bc); i++) {
		int l = strlen (bc[i]), ll;
		if (!strncasecmp (buf, bc[i], l)) {
			for (int j = 0; j < R_ARRAY_SIZE (conditions); j++)
				if (conditions[j] && (ll = strlen (conditions[j]), !strncasecmp (buf+l, conditions[j], ll) && !isalnum (buf[l+ll]))) {
					mnemlen = l;
					break;
				}
			break;
		}
	}
	if (!mnemlen) {
		for (int i = 0; i < R_ARRAY_SIZE (adj); i++) {
			if (!strncasecmp (buf, adj[i], 3)) {
				mnemlen = 3;
				break;
			}
		}
	}
	if (!mnemlen) {
		while (buf[mnemlen] && buf[mnemlen] != '.' && !isspace (buf[mnemlen])) {
			mnemlen++;
		}
	}

	int (*assem)(inst_t *inst, const char **src);
	inst_t inst;
	char saved = buf[mnemlen];
	buf[mnemlen] = '\0';
	inst.pc = a->pc;

#define FORMAT(fmt) assem = assemble_##fmt;
#define INS(x,opc) if (!strcmp (buf, #x)) { buf[mnemlen] = saved; src = buf+mnemlen; inst.opcode = opc; break; }
#define INS_1(x,opc,f1,v1) inst.f1 = v1; INS(x, opc)
#define INS_2(x,opc,f1,v1,f2,v2) inst.f1 = v1; inst.f2 = v2; INS(x, opc)
#define INS_3(x,opc,f1,v1,f2,v2,f3,v3) inst.f1 = v1; inst.f2 = v2; inst.f3 = v3; INS(x, opc)
#define INS_4(x,opc,f1,v1,f2,v2,f3,v3,f4,v4) inst.f1 = v1; inst.f2 = v2; inst.f3 = v3; inst.f4 = v4; INS(x, opc)
	do {
#include "../include/opcode-inc.h"
#undef FORMAT
#undef INS
#undef INS_1
#undef INS_2
#undef INS_3
#undef INS_4
		return -1;
	} while (0);

	if (assem (&inst, &src)) return -1;
	for (int i = 0; i < inst.size; i++) {
		ut64 t = inst.code >> (inst.size-1-i)*9;
		op->buf[i * 2] = t & 255;
		op->buf[i * 2 + 1] = t >> 8 & 1;
	}
	// middle-endian swap
	for (int i = 0; i + 1 < inst.size; i += 3) {
		char t0 = op->buf[i * 2], t1 = op->buf[i * 2 + 1];
		op->buf[i * 2] = op->buf[i * 2 + 2];
		op->buf[i * 2 + 1] = op->buf[i * 2 + 3];
		op->buf[i * 2 + 2] = t0;
		op->buf[i * 2 + 3] = t1;
	}
	return inst.size * 2;
}

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *src, int len) {
	inst_t inst = {.pc = a->pc};
	void (*pprint)(RAsmOp *op, const inst_t *inst);
	bool ok;

#define FORMAT(fmt) ok = decode_##fmt (&inst, (const ut16*)src, len/2); pprint = pprint_##fmt;
#define INS(x,opc) do { if (ok && inst.opcode == opc) { inst.id = I_##x; pprint (op, &inst); return op->size = inst.size; } } while (0);
#define INS_1(x,opc,f1,v1) do { if (ok && inst.opcode == opc && inst.f1 == v1) { inst.id = I_##x; pprint (op, &inst); return op->size = inst.size; } } while (0);
#define INS_2(x,opc,f1,v1,f2,v2) do { if (ok && inst.opcode == opc && inst.f1 == v1 && inst.f2 == v2) { inst.id = I_##x; pprint (op, &inst); return op->size = inst.size; } } while (0);
#define INS_3(x,opc,f1,v1,f2,v2,f3,v3) do { if (ok && inst.opcode == opc && inst.f1 == v1 && inst.f2 == v2 && inst.f3 == v3) { inst.id = I_##x; pprint (op, &inst); return op->size = inst.size; } } while (0);
#define INS_4(x,opc,f1,v1,f2,v2,f3,v3,f4,v4) do { if (ok && inst.opcode == opc && inst.f1 == v1 && inst.f2 == v2 && inst.f3 == v3 && inst.f4 == v4) { inst.id = I_##x; pprint (op, &inst); return op->size = inst.size; } } while (0);
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

static RAsmPlugin r_asm_plugin_clcy  = {
	.name = "clcy",
	.arch = "clcy",
	.license = "LGPL3",
	.bits = 64, // in accordance with r_anal_plugin_clcy
	.desc = "cLEMENCy disassembler and assembler",
	.disassemble = &disassemble,
	.assemble = &assemble,
};

RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_clcy,
	.version = R2_VERSION,
};
