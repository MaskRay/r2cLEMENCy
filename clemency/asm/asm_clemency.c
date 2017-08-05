/* radare - LGPL - Copyright 2017 - xvilka */

#include <stdio.h>
#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>

#include "../anal/decode.h"

#include "../include/clemency.h"

static const char *get_reg_name(int reg_index) {
	if (reg_index < sizeof(regs)) {
		return regs[reg_index];
	}
	return NULL;
}

static int assemble(RAsm *a, RAsmOp *op, const char *buf) {
	op->size = 1;
	op->buf[0] = 0x90;
	return op->size;
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

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *src, int len) {
	char *rA, *rB, *rC;
	ut16 tmp;
	st64 imm = 0;
	const char *c;
	int cond = 0;
	int opcode = 0;
	int count = 0;
	char *buf = malloc (len);
	
	int i, d = 0;
	for (i = 0; i < len; i += 16) {
		r_mem_copybits_delta (buf, d, src, i, 9);
		d += 9;
	}

	decode_result_t inst;
	dump_9bit (buf, 0);
	op->bitsize = decode_byte (buf, a->bitshift, &inst);
	// op->size = op->bitsize / 9;
	op->size = op->bitsize / 8;
	op->bitsize = 0;
	opcode = inst.mnemonic;
	rA = get_reg_name(inst.rA);
	rB = get_reg_name(inst.rB);
	rC = get_reg_name(inst.rC);
	imm = inst.Immediate_unsigned;
	cond = inst.Condition;
	count = inst.Register_Count;

	if (op->bitsize >= 27) {
		dump_27bit(buf, a->bitshift);
	} else {
		dump_9bit(buf, a->bitshift);
	}

	switch (opcode) {
	case CLCY_AD: // Add
		snprintf(op->buf_asm, 64, "add %s, %s, %s", rA, rB, rC);
		break;
	case CLCY_ADC: // Add with curry
		snprintf(op->buf_asm, 64, "adc %s, %s, %s", rA, rB, rC);
		break;
	case CLCY_ADCI: // Add immediate with curry
		snprintf(op->buf_asm, 64, "adc %s, %s, %"PFMT64x"", rA, rB, imm);
		break;
	case CLCY_ADCIM: // Add immediate multi reg with curry
		snprintf(op->buf_asm, 64, "adcim %s, %s, %"PFMT64x"", rA, rB, imm);
		break;
	case CLCY_ADCM: // Add multi reg with curry
		snprintf(op->buf_asm, 64, "adcm %s, %s, %s", rA, rB, rC);
		break;
	case CLCY_ADF: // Add floating point
		snprintf(op->buf_asm, 64, "adf %s, %s, %s", rA, rB, rC);
		break;
	case CLCY_ADFM: // Add floating point multi reg
		snprintf(op->buf_asm, 64, "adfm %s, %s, %s", rA, rB, rC);
		break;
	case CLCY_ADI: // Add immediate
		snprintf(op->buf_asm, 64, "adi %s, %s, %"PFMT64x"", rA, rB, imm);
		break;
	case CLCY_ADIM: // Add immediate multi reg
		snprintf(op->buf_asm, 64, "adim %s, %s, %"PFMT64x"", rA, rB, imm);
		break;
	case CLCY_ADM: // Add multi reg
		snprintf(op->buf_asm, 64, "adm %s, %s, %s", rA, rB, rC);
		break;
	case CLCY_AN: // And
		snprintf(op->buf_asm, 64, "an %s, %s, %s", rA, rB, rC);
		break;
	case CLCY_ANI: // And immediate
		snprintf(op->buf_asm, 64, "ani %s, %s, %"PFMT64x"", rA, rB, imm);
		break;
	case CLCY_ANM: // And multi reg
		snprintf(op->buf_asm, 64, "anm %s, %s, %s", rA, rB, rC);
		break;
	case CLCY_B: // Branch conditional
		switch(cond) {
			case 0: // Not equal / not zero
				snprintf(op->buf_asm, 64, "b.ne %"PFMT64x"", imm);
				break;
			case 1: // Equal / Zero
				snprintf(op->buf_asm, 64, "b.eq %"PFMT64x"", imm);
				break;
			case 2: // Less Than
				snprintf(op->buf_asm, 64, "b.lt %"PFMT64x"", imm);
				break;
			case 3: // Less Than or Equal
				snprintf(op->buf_asm, 64, "b.lte %"PFMT64x"", imm);
				break;
			case 4: // Greater Than
				snprintf(op->buf_asm, 64, "b.gt %"PFMT64x"", imm);
				break;
			case 5: // Greater Than or Equal
				snprintf(op->buf_asm, 64, "b.gte %"PFMT64x"", imm);
				break;
			case 6: // Not overflow
				snprintf(op->buf_asm, 64, "b.nof %"PFMT64x"", imm);
				break;
			case 7: // Overflow
				snprintf(op->buf_asm, 64, "b.of %"PFMT64x"", imm);
				break;
			case 8: // Not signed
				snprintf(op->buf_asm, 64, "b.ns %"PFMT64x"", imm);
				break;
			case 9: // Signed
				snprintf(op->buf_asm, 64, "b.s %"PFMT64x"", imm);
				break;
			case 10: // Signed less than
				snprintf(op->buf_asm, 64, "b.slt %"PFMT64x"", imm);
				break;
			case 11: // Signed less than or Equal
				snprintf(op->buf_asm, 64, "b.slte %"PFMT64x"", imm);
				break;
			case 12: // Signed greater than
				snprintf(op->buf_asm, 64, "b.sgt %"PFMT64x"", imm);
				break;
			case 13: // Sined Greater Than or Equal
				snprintf(op->buf_asm, 64, "b.sgte %"PFMT64x"", imm);
				break;
			default: // Always
				snprintf(op->buf_asm, 64, "b %"PFMT64x"", imm);
				break;
		}
		break;
	case CLCY_BF: // Bit flip
		snprintf(op->buf_asm, 64, "bf %s, %s", rA, rB);
		break;
	case CLCY_BFM: // Bit flip multi reg
		snprintf(op->buf_asm, 64, "bfm %s, %s", rA, rB);
		break;
	case CLCY_BR: // Branch register
		switch(cond) {
			case 0: // Not equal / not zero
				snprintf(op->buf_asm, 64, "br.ne %s", rA);
				break;
			case 1: // Equal / Zero
				snprintf(op->buf_asm, 64, "br.eq %s", rA);
				break;
			case 2: // Less Than
				snprintf(op->buf_asm, 64, "br.lt %s", rA);
				break;
			case 3: // Less Than or Equal
				snprintf(op->buf_asm, 64, "br.lte %s", rA);
				break;
			case 4: // Greater Than
				snprintf(op->buf_asm, 64, "br.gt %s", rA);
				break;
			case 5: // Greater Than or Equal
				snprintf(op->buf_asm, 64, "br.gte %s", rA);
				break;
			case 6: // Not overflow
				snprintf(op->buf_asm, 64, "br.nof %s", rA);
				break;
			case 7: // Overflow
				snprintf(op->buf_asm, 64, "br.of %s", rA);
				break;
			case 8: // Not signed
				snprintf(op->buf_asm, 64, "br.ns %s", rA);
				break;
			case 9: // Signed
				snprintf(op->buf_asm, 64, "br.s %s", rA);
				break;
			case 10: // Signed less than
				snprintf(op->buf_asm, 64, "br.slt %s", rA);
				break;
			case 11: // Signed less than or Equal
				snprintf(op->buf_asm, 64, "br.slte %s", rA);
				break;
			case 12: // Signed greater than
				snprintf(op->buf_asm, 64, "br.sgt %s", rA);
				break;
			case 13: // Sined Greater Than or Equal
				snprintf(op->buf_asm, 64, "br.sgte %s", rA);
				break;
			default: // Always
				snprintf(op->buf_asm, 64, "br %s", rA);
				break;
		}
		break;
	case CLCY_BRA: // Branch absolute
		snprintf(op->buf_asm, 64, "bra %"PFMT64x"", imm);
		break;
	case CLCY_BRR: // Branch relative
		snprintf(op->buf_asm, 64, "brr %"PFMT64x"", imm);
		break;
	case CLCY_C: // Call conditional
		switch(cond) {
			case 0: // Not equal / not zero
				snprintf(op->buf_asm, 64, "c.ne %"PFMT64x"", imm);
				break;
			case 1: // Equal / Zero
				snprintf(op->buf_asm, 64, "c.eq %"PFMT64x"", imm);
				break;
			case 2: // Less Than
				snprintf(op->buf_asm, 64, "c.lt %"PFMT64x"", imm);
				break;
			case 3: // Less Than or Equal
				snprintf(op->buf_asm, 64, "c.lte %"PFMT64x"", imm);
				break;
			case 4: // Greater Than
				snprintf(op->buf_asm, 64, "c.gt %"PFMT64x"", imm);
				break;
			case 5: // Greater Than or Equal
				snprintf(op->buf_asm, 64, "c.gte %"PFMT64x"", imm);
				break;
			case 6: // Not overflow
				snprintf(op->buf_asm, 64, "c.nof %"PFMT64x"", imm);
				break;
			case 7: // Overflow
				snprintf(op->buf_asm, 64, "c.of %"PFMT64x"", imm);
				break;
			case 8: // Not signed
				snprintf(op->buf_asm, 64, "c.ns %"PFMT64x"", imm);
				break;
			case 9: // Signed
				snprintf(op->buf_asm, 64, "c.s %"PFMT64x"", imm);
				break;
			case 10: // Signed less than
				snprintf(op->buf_asm, 64, "c.slt %"PFMT64x"", imm);
				break;
			case 11: // Signed less than or Equal
				snprintf(op->buf_asm, 64, "c.slte %"PFMT64x"", imm);
				break;
			case 12: // Signed greater than
				snprintf(op->buf_asm, 64, "c.sgt %"PFMT64x"", imm);
				break;
			case 13: // Sined Greater Than or Equal
				snprintf(op->buf_asm, 64, "c.sgte %"PFMT64x"", imm);
				break;
			default: // Always
				snprintf(op->buf_asm, 64, "c %"PFMT64x"", imm);
				break;
		}
		break;
	case CLCY_CAA: // Call absolute
		snprintf(op->buf_asm, 64, "caa %"PFMT64x"", imm);
		break;
	case CLCY_CAR: // Call relative
		snprintf(op->buf_asm, 64, "car %s", rA);
		break;
	case CLCY_CM: // Compare
		snprintf(op->buf_asm, 64, "cm %s, %s", rA, rB);
		break;
	case CLCY_CMF: // Compare Floating Point
		snprintf(op->buf_asm, 64, "cmf %s, %s", rA, rB);
		break;
	case CLCY_CMFM: // Compare floating point multi reg
		snprintf(op->buf_asm, 64, "cmfm %s, %s", rA, rB);
		break;
	case CLCY_CMI: // Compare immediate
		snprintf(op->buf_asm, 64, "cmi %s, %"PFMT64x"", rA, imm);
		break;
	case CLCY_CMIM: // Compare immediate multi reg
		snprintf(op->buf_asm, 64, "cmim %s, %"PFMT64x"", rA, imm);
		break;
	case CLCY_CMM: // Compare multi reg
		snprintf(op->buf_asm, 64, "cmm %s, %s", rA, rB);
		break;
	case CLCY_CR: // Call register conditional
		switch(cond) {
			case 0: // Not equal / not zero
				snprintf(op->buf_asm, 64, "cr.ne %s", rA);
				break;
			case 1: // Equal / Zero
				snprintf(op->buf_asm, 64, "cr.eq %s", rA);
				break;
			case 2: // Less Than
				snprintf(op->buf_asm, 64, "cr.lt %s", rA);
				break;
			case 3: // Less Than or Equal
				snprintf(op->buf_asm, 64, "cr.lte %s", rA);
				break;
			case 4: // Greater Than
				snprintf(op->buf_asm, 64, "cr.gt %s", rA);
				break;
			case 5: // Greater Than or Equal
				snprintf(op->buf_asm, 64, "cr.gte %s", rA);
				break;
			case 6: // Not overflow
				snprintf(op->buf_asm, 64, "cr.nof %s", rA);
				break;
			case 7: // Overflow
				snprintf(op->buf_asm, 64, "cr.of %s", rA);
				break;
			case 8: // Not signed
				snprintf(op->buf_asm, 64, "cr.ns %s", rA);
				break;
			case 9: // Signed
				snprintf(op->buf_asm, 64, "cr.s %s", rA);
				break;
			case 10: // Signed less than
				snprintf(op->buf_asm, 64, "cr.slt %s", rA);
				break;
			case 11: // Signed less than or Equal
				snprintf(op->buf_asm, 64, "cr.slte %s", rA);
				break;
			case 12: // Signed greater than
				snprintf(op->buf_asm, 64, "cr.sgt %s", rA);
				break;
			case 13: // Sined Greater Than or Equal
				snprintf(op->buf_asm, 64, "cr.sgte %s", rA);
				break;
			default: // Always
				snprintf(op->buf_asm, 64, "cr %s", rA);
				break;
		}
		break;
	case CLCY_DI: // Disable interrupts
		snprintf(op->buf_asm, 64, "di %s", rA);
		break;
	case CLCY_DBRK: // Debug break
		snprintf(op->buf_asm, 64, "dbrk %s", rA);
		break;
	case CLCY_DMT: // Direct memory transfer
		snprintf(op->buf_asm, 64, "dmt %s, %s, %s", rA, rB, rC);
		break;
	case CLCY_DV: // Divide
		snprintf(op->buf_asm, 64, "dv %s, %s, %s", rA, rB, rC);
		break;
	case CLCY_DVF: // Divide floating point
		snprintf(op->buf_asm, 64, "dvf %s, %s, %s", rA, rB, rB);
		break;
	case CLCY_DVFM: // Divide floating point multi reg
		snprintf(op->buf_asm, 64, "dvfm %s, %s, %s", rA, rB, rC);
		break;
	case CLCY_DVI: // Divide immediate
		snprintf(op->buf_asm, 64, "dvi %s, %s, %"PFMT64x"", rA, rB, imm);
		break;
	case CLCY_DVIM: // Divide immediate multi reg
		snprintf(op->buf_asm, 64, "dvim %s, %s, %"PFMT64x"", rA, rB, imm);
		break;
	case CLCY_DVIS: // Divide immediate signed
		snprintf(op->buf_asm, 64, "dvis %s, %s, %"PFMT64x"", rA, rB, imm);
		break;
	case CLCY_DVISM: // Divide immediate signed multi reg
		snprintf(op->buf_asm, 64, "dvism %s, %s, %"PFMT64x"", rA, rB, imm);
		break;
	case CLCY_DVM: // Divide multi reg
		snprintf(op->buf_asm, 64, "dvm %s, %s, %s", rA, rB, rC);
		break;
	case CLCY_DVS: // Divide signed
		snprintf(op->buf_asm, 64, "dvs %s, %s, %s", rA, rB, rC);
		break;
	case CLCY_DVSM: // Divide signed multi reg
		snprintf(op->buf_asm, 64, "dvsm %s, %s, %s", rA, rB, rC);
		break;
	case CLCY_EI: // Enable interrupts
		snprintf(op->buf_asm, 64, "ei %s", rA);
		break;
	case CLCY_FTI: // Float to integer
		snprintf(op->buf_asm, 64, "fti %s, %s", rA, rB);
		break;
	case CLCY_FTIM: // Float to integer multi reg
		snprintf(op->buf_asm, 64, "ftim %s, %s", rA, rB);
		break;
	case CLCY_HT: // Halt
		snprintf(op->buf_asm, 64, "ht");
		break;
	case CLCY_IR: // Interrupt return
		snprintf(op->buf_asm, 64, "ir");
		break;
	case CLCY_ITF: // Integer to float
		snprintf(op->buf_asm, 64, "itf %s, %s", rA, rB);
		break;
	case CLCY_ITFM: // Integer to float multi reg
		snprintf(op->buf_asm, 64, "itfm %s, %s", rA, rB);
		break;
	// Allow only aligned to 32bits access
	case CLCY_LDS: // Load single
		snprintf(op->buf_asm, 64, "lds %s, [%s + %"PFMT64x", %d]", rA, rB, imm, count);
		break;
	// Allow only aligned to 32bits access
	case CLCY_LDT: // Load tri
		snprintf(op->buf_asm, 64, "ldt %s, [%s + %"PFMT64x", %d]", rA, rB, imm, count);
		break;
	// Allow only aligned to 32bits access
	case CLCY_LDW: // Load word
		snprintf(op->buf_asm, 64, "ldw %s, [%s + %"PFMT64x", %d]", rA, rB, imm, count);
		break;
	case CLCY_MD: // Modulus
		snprintf(op->buf_asm, 64, "md %s, %s, %s", rA, rB, rC);
		break;
	case CLCY_MDF: // Modulus floating point
		snprintf(op->buf_asm, 64, "mdf %s, %s, %s", rA, rB, rC);
		break;
	case CLCY_MDFM: // Modulus floating point multi reg
		snprintf(op->buf_asm, 64, "mdfm %s, %s, %s", rA, rB, rC);
		break;
	case CLCY_MDI: // Modulus immediate
		snprintf(op->buf_asm, 64, "mdi %s, %s, %"PFMT64x"", rA, rB, imm);
		break;
	case CLCY_MDIM: // Modulus immediate multi reg
		snprintf(op->buf_asm, 64, "mdim %s, %s, %"PFMT64x"", rA, rB, imm);
		break;
	case CLCY_MDIS: // Modulus immediate signed
		snprintf(op->buf_asm, 64, "mdis %s, %s, %"PFMT64x"", rA, rB, imm);
		break;
	case CLCY_MDISM: // Modulus immediate signed multi reg
		snprintf(op->buf_asm, 64, "mdism %s, %s, %"PFMT64x"", rA, rB, imm);
		break;
	case CLCY_MDM: // Modulus multi reg
		snprintf(op->buf_asm, 64, "mdm %s, %s, %s", rA, rB, rC);
		break;
	case CLCY_MDS: // Modulus signed
		snprintf(op->buf_asm, 64, "mds %s, %s, %s", rA, rB, rC);
		break;
	case CLCY_MDSM: // Modulus signed multi reg
		snprintf(op->buf_asm, 64, "mdsm %s, %s, %s", rA, rB, rC);
		break;
	case CLCY_MH: // Move high
		snprintf(op->buf_asm, 64, "mh %s, %"PFMT64x"", rA, imm);
		break;
	case CLCY_ML: // Move low
		snprintf(op->buf_asm, 64, "ml %s, %"PFMT64x"", rA, imm);
		break;
	case CLCY_MS: // Move low signed
		snprintf(op->buf_asm, 64, "ms %s, %"PFMT64x"", rA, imm);
		break;
	case CLCY_MU: // Multiply
		snprintf(op->buf_asm, 64, "mu %s, %s, %s", rA, rB, rC);
		break;
	case CLCY_MUF: // Multiply floating point
		snprintf(op->buf_asm, 64, "muf %s, %s, %s", rA, rB, rC);
		break;
	case CLCY_MUFM: // Multiply floating point multi reg
		snprintf(op->buf_asm, 64, "mufm %s, %s, %s", rA, rB, rC);
		break;
	case CLCY_MUI: // Multiply immediate
		snprintf(op->buf_asm, 64, "mui %s, %s, %"PFMT64x"", rA, rB, imm);
		break;
	case CLCY_MUIM: // Multiply immediate multi reg
		snprintf(op->buf_asm, 64, "muim %s, %s, %"PFMT64x"", rA, rB, imm);
		break;
	case CLCY_MUIS: // Multiply immediate signed
		snprintf(op->buf_asm, 64, "muis %s, %s, %"PFMT64x"", rA, rB, imm);
		break;
	case CLCY_MUISM: // Multiply immediate signed multi reg
		snprintf(op->buf_asm, 64, "muism %s, %s, %"PFMT64x"", rA, rB, imm);
		break;
	case CLCY_MUM: // Multiply multi reg
		snprintf(op->buf_asm, 64, "mum %s, %s, %s", rA, rB, rC);
		break;
	case CLCY_MUS: // Multiply signed
		snprintf(op->buf_asm, 64, "mus %s, %s, %s", rA, rB, rC);
		break;
	case CLCY_MUSM: // Multiply signed multi reg
		snprintf(op->buf_asm, 64, "musm %s, %s, %s", rA, rB, rC);
		break;
	case CLCY_NG: // Negate (nougat)
		snprintf(op->buf_asm, 64, "ng %s, %s", rA, rB);
		break;
	case CLCY_NGF: // Negate floating point
		snprintf(op->buf_asm, 64, "ngf %s, %s", rA, rB);
		break;
	case CLCY_NGFM: // Negate floating point multi reg
		snprintf(op->buf_asm, 64, "ngfm %s, %s", rA, rB);
		break;
	case CLCY_NGM: // Negate multi reg
		snprintf(op->buf_asm, 64, "ngm %s, %s", rA, rB);
		break;
	case CLCY_NT: // Nooooooooooooooooot
		snprintf(op->buf_asm, 64, "nt %s, %s", rA, rB);
		break;
	case CLCY_NTM: // Not multi reg
		snprintf(op->buf_asm, 64, "ntm %s, %s", rA, rB);
		break;
	case CLCY_OR: // Or
		snprintf(op->buf_asm, 64, "or %s, %s, %s", rA, rB, rC);
		break;
	case CLCY_ORI: // Ori
		snprintf(op->buf_asm, 64, "ori %s, %s, %"PFMT64x"", rA, rB, imm);
		break;
	case CLCY_ORM: // Or multi reg
		snprintf(op->buf_asm, 64, "orm %s, %s, %s", rA, rB, rC);
		break;
	case CLCY_RE: // Return
		snprintf(op->buf_asm, 64, "re");
		break;
	case CLCY_RF: // Read flags
		snprintf(op->buf_asm, 64, "rf %s", rA);
		break;
	case CLCY_RL: // Rotate left
		snprintf(op->buf_asm, 64, "rl %s, %s, %s", rA, rB, rC);
		break;
	case CLCY_RLI: // Rotate left immediate
		snprintf(op->buf_asm, 64, "rli %s, %s, %"PFMT64x"", rA, rB, imm);
		break;
	case CLCY_RLIM: // Rotate left immediate multi reg
		snprintf(op->buf_asm, 64, "rlim %s, %s, %"PFMT64x"", rA, rB, imm);
		break;
	case CLCY_RLM: // Rotate left multi reg
		snprintf(op->buf_asm, 64, "rlm %s, %s, %s", rA, rB, rC);
		break;
	case CLCY_RMP: // Read memory protection
		snprintf(op->buf_asm, 64, "rmp %s, %s", rA, rB);
		break;
	case CLCY_RND: // Random
		snprintf(op->buf_asm, 64, "rnd %s", rA);
		break;
	case CLCY_RNDM: // Random multi reg
		snprintf(op->buf_asm, 64, "rndm %s", rA);
		break;
	case CLCY_RR: // Rotate right
		snprintf(op->buf_asm, 64, "rr %s, %s, %s", rA, rB, rC);
		break;
	case CLCY_RRI: // Rotate right immediate
		snprintf(op->buf_asm, 64, "rri %s, %s, %"PFMT64x"", rA, rB, imm);
		break;
	case CLCY_RRIM: // Rotate right immediate multi reg
		snprintf(op->buf_asm, 64, "rrim %s, %s, %"PFMT64x"", rA, rB, imm);
		break;
	case CLCY_RRM: // Rotate right multi reg
		snprintf(op->buf_asm, 64, "rrm %s, %s, %s", rA, rB, rC);
		break;
	case CLCY_SA: // Shift arithmetic right
		snprintf(op->buf_asm, 64, "sa %s, %s, %s", rA, rB, rC);
		break;
	case CLCY_SAI: // Shift arithmetic right immediate
		snprintf(op->buf_asm, 64, "sai %s, %s, %"PFMT64x"", rA, rB, imm);
		break;
	case CLCY_SAIM: // Shift arithmetic right immediate multi reg
		snprintf(op->buf_asm, 64, "saim %s, %s, %"PFMT64x"", rA, rB, imm);
		break;
	case CLCY_SAM: // Shift arithmetic right multi reg
		snprintf(op->buf_asm, 64, "sam %s, %s, %s", rA, rB, rC);
		break;
	case CLCY_SB: // Subtract
		snprintf(op->buf_asm, 64, "sb %s, %s, %s", rA, rB, rC);
		break;
	case CLCY_SBC: // Subtract with carry
		snprintf(op->buf_asm, 64, "sbc %s, %s, %s", rA, rB, rC);
		break;
	case CLCY_SBCI: // Subtract immediate with carry
		snprintf(op->buf_asm, 64, "sbci %s, %s, %"PFMT64x"", rA, rB, imm);
		break;
	case CLCY_SBCIM: // Subtract immediate multi reg with carry
		snprintf(op->buf_asm, 64, "sbcim %s, %s, %"PFMT64x"", rA, rB, imm);
		break;
	case CLCY_SBCM: // Subtract multi reg with carry
		snprintf(op->buf_asm, 64, "sbcm %s, %s, %s", rA, rB, rC);
		break;
	case CLCY_SBF: // Subtract floating point
		snprintf(op->buf_asm, 64, "sbf %s, %s, %s", rA, rB, rC);
		break;
	case CLCY_SBFM: // Subtract floating point multi reg
		snprintf(op->buf_asm, 64, "sbfm %s, %s, %s", rA, rB, rC);
		break;
	case CLCY_SBI: // Subtract immediate
		snprintf(op->buf_asm, 64, "sbi %s, %s, %"PFMT64x"", rA, rB, imm);
		break;
	case CLCY_SBIM: // Subtract immediate multi reg;
		snprintf(op->buf_asm, 64, "sbim %s, %s, %"PFMT64x"", rA, rB, imm);
		break;
	case CLCY_SBM: // Subtract multi reg
		snprintf(op->buf_asm, 64, "sbm %s, %s, %s", rA, rB, rC);
		break;
	case CLCY_SES: // Sign extend single
		snprintf(op->buf_asm, 64, "ses %s, %s", rA, rB);
		break;
	case CLCY_SEW: // Sign extend word
		snprintf(op->buf_asm, 64, "sew %s, %s", rA, rB);
		break;
	case CLCY_SF: // Set flags
		snprintf(op->buf_asm, 64, "ss %s", rA);
		break;
	case CLCY_SL: // Shift left
		snprintf(op->buf_asm, 64, "sl %s, %s, %s", rA, rB, rC);
		break;
	case CLCY_SLI: // Shift left immediate
		snprintf(op->buf_asm, 64, "sli %s, %s, %"PFMT64x"", rA, rB, imm);
		break;
	case CLCY_SLIM: // Shift left immediate multi reg
		snprintf(op->buf_asm, 64, "slim %s, %s, %"PFMT64x"", rA, rB, imm);
		break;
	case CLCY_SLM: // Shift left multi reg
		snprintf(op->buf_asm, 64, "slm %s, %s, %s", rA, rB, rC);
		break;
	case CLCY_SMP: // Set memory protection
		snprintf(op->buf_asm, 64, "smp %s, %s, %"PFMT64x"", rA, rB, inst.Memory_Flags);
		break;
	case CLCY_SR: // Shift right
		snprintf(op->buf_asm, 64, "sr %s, %s, %s", rA, rB, rC);
		break;
	case CLCY_SRI: // Shift right immediate
		snprintf(op->buf_asm, 64, "sri %s, %s, %"PFMT64x"", rA, rB, imm);
		break;
	case CLCY_SRIM: // Shift right immediate multi reg
		snprintf(op->buf_asm, 64, "srim %s, %s, %"PFMT64x"", rA, rB, imm);
		break;
	case CLCY_SRM: // Shift right multi reg
		snprintf(op->buf_asm, 64, "srm %s, %s, %s", rA, rB, rC);
		break;
	// It aligns the storage to 32bits
	case CLCY_STS: // Store single
		snprintf(op->buf_asm, 64, "sts %s, [%s + %"PFMT64x", %d]", rA, rB, imm, count);
		break;
	// It aligns the storage to 32bits
	case CLCY_STT: // Store tri
		snprintf(op->buf_asm, 64, "stt %s, [%s + %"PFMT64x", %d]", rA, rB, imm, count);
		break;
	// It aligns the storage to 32bits
	case CLCY_STW: // Store word
		snprintf(op->buf_asm, 64, "stw %s, [%s + %"PFMT64x", %d]", rA, rB, imm, count);
		break;
	case CLCY_WT: // Wait
		snprintf(op->buf_asm, 64, "wt");
		break;
	case CLCY_XR: // Xor
		snprintf(op->buf_asm, 64, "xr %s, %s, %s", rA, rB, rC);
		break;
	case CLCY_XRI: // Xor immediate
		snprintf(op->buf_asm, 64, "xri %s, %s, %"PFMT64x"", rA, rB, imm);
		break;
	case CLCY_XRM: // Xor multi reg
		snprintf(op->buf_asm, 64, "xrm %s, %s, %s", rA, rB, rC);
		break;
	case CLCY_ZES: // Zero extend single
		snprintf(op->buf_asm, 64, "zes %s, %s", rA, rB);
		break;
	case CLCY_ZEW: // Zero extend word
		snprintf(op->buf_asm, 64, "zes %s, %s", rA, rB);
		break;
	default:
		snprintf(op->buf_asm, 64, "invalid");
		break;
	}
	free (buf);
	eprintf("{OLD} bitshift = %d ; bitsize = %d\n", a->bitshift, op->bitsize);
	a->bitshift = (op->bitsize + a->bitshift) % 8;
	eprintf("{NEW} bitshift = %d ; size = %d\n", a->bitshift, op->size);
	return op->size;
}

static RAsmPlugin r_asm_plugin_clemency  = {
	.name = "clcy",
	.arch = "clcy",
	.license = "LGPL3",
	.bits = 27,
	.desc = "clemency disassembler and assembler plugin",
	.disassemble = &disassemble,
	.assemble = &assemble
};

RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_clemency
};
