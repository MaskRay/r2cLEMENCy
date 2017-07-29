/* radare2 - LGPL - Copyright 2017 - xvilka */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>
#include <stdio.h>
#include <fcntl.h>

#include "decode.h"

#include "../include/clcy_mem.h"

char* regs[] = {
	"r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8",
	"r9", "r10", "r11", "r12", "r13", "r14", "r15", "r16",
	"r17", "r18", "r19", "r20", "r21", "r22", "r23", "r24",
	"r25", "r26", "r27", "r28", "st", "ra", "pc"
};

static int reg_read(RAnalEsil *esil, const char *regname, ut64 *num) {
	RRegItem *reg = r_reg_get (esil->anal->reg, regname, -1);
	if (reg) {
		if (num)
			*num = r_reg_get_value (esil->anal->reg, reg);
		return 1;
	}
	return 0;
}

static int reg_write(RAnalEsil *esil, const char *regname, ut64 num) {
	RRegItem *reg = r_reg_get (esil->anal->reg, regname, -1);
	if (reg) {
		if (num)
			r_reg_set_value (esil->anal->reg, reg,num);
		return 1;
	}
	return 0;

}

char *get_reg_name(int reg_index)
{
	if (reg_index < sizeof(regs)) {
		return regs[reg_index];
	}
	return NULL;
}

static int clemency_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len) {
	char *rA, *rB, *rC;
	st32 imm = 0;
	ut8 opcode = 0;
	decode_result_t inst;
	int cond = 0;

	if (op == NULL) {
		return 1;
	}

	memset (op, 0, sizeof (RAnalOp));
	op->type = R_ANAL_OP_TYPE_NULL;
	op->delay = 0;
	op->jump = op->fail = -1;
	op->ptr = op->val = -1;
	op->addr = addr;
	op->refptr = 0;
	r_strbuf_init (&op->esil);
	// Wrong - it also has subopcode
	// or run decode function here?
	op->size = decode_byte (buf, anal->bitshift, &inst) / 9;
	opcode = inst.mnemonic;
	rA = get_reg_name(inst.rA);
	rB = get_reg_name(inst.rB);
	rC = get_reg_name(inst.rC);
	imm = inst.Immediate_unsigned;
	cond = inst.Condition;

	switch (opcode) {
	case CLCY_AD: // Add
		op->type = R_ANAL_OP_TYPE_ADD;
		op->size = 3;
		r_strbuf_setf (&op->esil, "%s,%s,+,%s,=",rC,rB,rA);
		break;
	case CLCY_ADC: // Add with curry
		op->type = R_ANAL_OP_TYPE_ADD;
		op->size = 3;
		r_strbuf_setf (&op->esil, "%s,%s,+,cf,+,%s,=",rC,rB,rA);
		break;
	case CLCY_ADCI: // Add immediate with curry
		op->type = R_ANAL_OP_TYPE_ADD;
		op->size = 3;
		r_strbuf_setf (&op->esil, "%s,%"PFMT64x",+,cf,+,%s,=",rB,imm,rA);
		break;
	// XXX
	case CLCY_ADCIM: // Add immediate multi reg with curry
		op->type = R_ANAL_OP_TYPE_ADD;
		op->size = 3;
		r_strbuf_setf (&op->esil, "%s,%"PFMT64x",+,%s,=",rB,imm,rA);
		break;
	// XXX
	case CLCY_ADCM: // Add multi reg with curry
		op->type = R_ANAL_OP_TYPE_ADD;
		op->size = 3;
		r_strbuf_setf (&op->esil, "%s,%s,+,%s,=",rC,rB,rA);
		break;
	case CLCY_ADF: // Add floating point
		op->size = 3;
		break;
	case CLCY_ADFM: // Add floating point multi reg
		op->size = 3;
		break;
	case CLCY_ADI: // Add immediate
		op->type = R_ANAL_OP_TYPE_ADD;
		op->size = 3;
		r_strbuf_setf (&op->esil, "%s,%"PFMT64x",+,%s,=",rB,imm,rA);
		break;
	// XXX
	case CLCY_ADIM: // Add immediate multi reg
		op->type = R_ANAL_OP_TYPE_ADD;
		op->size = 3;
		break;
	// XXX
	case CLCY_ADM: // Add multi reg
		op->type = R_ANAL_OP_TYPE_ADD;
		op->size = 3;
		break;
	case CLCY_AN: // And
		op->type = R_ANAL_OP_TYPE_AND;
		op->size = 3;
		r_strbuf_setf (&op->esil, "%s,%s,&,%s,=,",rC,rB,rA);
		break;
	case CLCY_ANI: // And immediate
		op->type = R_ANAL_OP_TYPE_AND;
		op->size = 3;
		r_strbuf_setf (&op->esil, "%s,%"PFMT64x",&,%s,=,",rB,imm,rA);
		break;
	// XXX
	case CLCY_ANM: // And multi reg
		op->type = R_ANAL_OP_TYPE_AND;
		op->size = 3;
		break;
	case CLCY_B: // Branch conditional
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->size = 3;
		op->jump = imm;
		op->fail = addr + op->size;
		int cond = ((buf[0] & 0xc0) >> 6) | ((buf[1] & 3) << 2);
		switch(cond) {
			case 0: // Not equal / not zero
				r_strbuf_setf(&op->esil, "zf,!,?{,%"PFMT64d",pc,+=,}",imm);
				break;
			case 1: // Equal / Zero
				r_strbuf_setf(&op->esil, "zf,?{,%"PFMT64d",pc,+=,}",imm);
				break;
			case 2: // Less Than
				r_strbuf_setf(&op->esil, "zf,!,cf,&,?{,%"PFMT64d",pc,+=,}",imm);
				break;
			case 3: // Less Than or Equal
				r_strbuf_setf(&op->esil, "zf,cf,|,?{,%"PFMT64d",pc,+=,}", imm);
				break;
			case 4: // Greater Than
				r_strbuf_setf(&op->esil, "zf,cf,&,!,?{,%"PFMT64d",pc,+=,}", imm);
				break;
			case 5: // Greater Than or Equal
				r_strbuf_setf(&op->esil, "cf,!,zf,|,?{,%"PFMT64d",pc,+=,}", imm);
				break;
			case 6: // Not overflow
				r_strbuf_setf(&op->esil, "of,!,?{,%"PFMT64d",pc,+=,}", imm);
				break;
			case 7: // Overflow
				r_strbuf_setf(&op->esil, "of,?{,%"PFMT64d",pc,+=,}", imm);
				break;
			case 8: // Not signed
				r_strbuf_setf(&op->esil, "sf,!,?{,%"PFMT64d",pc,+=,}", imm);
				break;
			case 9: // Signed
				r_strbuf_setf(&op->esil, "sf,?{,%"PFMT64d",pc,+=,}", imm);
				break;
			case 10: // Signed less than
				r_strbuf_setf(&op->esil, "of,sf,==,!,?{,%"PFMT64d",pc,+=,}", imm);
				break;
			case 11: // Signed less than or Equal
				r_strbuf_setf(&op->esil, "of,sf,==,!,zf,|,?{,%"PFMT64d",pc,+=,}", imm);
				break;
			case 12: // Signed greater than
				r_strbuf_setf(&op->esil, "zf,!,of,sf,==,&,?{,%"PFMT64d",pc,+=,}", imm);
				break;
			case 13: // Sined Greater Than or Equal
				r_strbuf_setf(&op->esil, "of,sf,==,?{,%"PFMT64d",pc,+=,}", imm);
				break;
			default: // Always
				r_strbuf_setf(&op->esil, "%"PFMT64d",pc,+=,", imm);
				break;
		}
		break;
	case CLCY_BF: // Bit flip
		op->type = R_ANAL_OP_TYPE_NOT;
		op->size = 3;
		r_strbuf_setf(&op->esil,"%s,%s,!=,",rB, rA);
		break;
	// XXX
	case CLCY_BFM: // Bit flip multi reg
		op->type = R_ANAL_OP_TYPE_NOT;
		op->size = 3;
		break;
	case CLCY_BR: // Branch register
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->size = 2;
		op->jump = UT64_MAX;
		op->fail = addr + op->size;
		switch(cond) {
			case 0: // Not equal / not zero
				r_strbuf_setf(&op->esil, "zf,!,?{,%s,pc,=,}", rA);
				break;
			case 1: // Equal / Zero
				r_strbuf_setf(&op->esil, "zf,?{,%s,pc,=,}", rA);
				break;
			case 2: // Less Than
				r_strbuf_setf(&op->esil, "zf,!,cf,&,?{,%s,pc,=,}", rA);
				break;
			case 3: // Less Than or Equal
				r_strbuf_setf(&op->esil, "zf,cf,|,?{,%s,pc,=,}", rA);
				break;
			case 4: // Greater Than
				r_strbuf_setf(&op->esil, "zf,cf,&,!,?{,%s,pc,=,}", rA);
				break;
			case 5: // Greater Than or Equal
				r_strbuf_setf(&op->esil, "cf,!,zf,|,?{,%s,pc,=,}", rA);
				break;
			case 6: // Not overflow
				r_strbuf_setf(&op->esil, "of,!,?{,%s,pc,=,}", rA);
				break;
			case 7: // Overflow
				r_strbuf_setf(&op->esil, "of,?{,%s,pc,=,}", rA);
				break;
			case 8: // Not signed
				r_strbuf_setf(&op->esil, "sf,!,?{,%s,pc,=,}", rA);
				break;
			case 9: // Signed
				r_strbuf_setf(&op->esil, "sf,?{,%s,pc,=,}", rA);
				break;
			case 10: // Signed less than
				r_strbuf_setf(&op->esil, "of,sf,==,!,?{,%s,pc,=,}", rA);
				break;
			case 11: // Signed less than or Equal
				r_strbuf_setf(&op->esil, "of,sf,==,!,zf,|,?{,%s,pc,=,}", rA);
				break;
			case 12: // Signed greater than
				r_strbuf_setf(&op->esil, "zf,!,of,sf,==,&,?{,%s,pc,=,}", rA);
				break;
			case 13: // Sined Greater Than or Equal
				r_strbuf_setf(&op->esil, "of,sf,==,?{,%s,pc,=,}", rA);
				break;
			default: // Always
				r_strbuf_setf(&op->esil, "%s,pc,=,", rA);
				break;
		}
		break;
	case CLCY_BRA: // Branch absolute
		op->type = R_ANAL_OP_TYPE_JMP;
		op->size = 4;
		op->jump = imm;
		op->fail = addr + op->size;
		r_strbuf_setf(&op->esil, "%"PFMT64x",pc,=,",imm);
		break;
	case CLCY_BRR: // Branch relative
		op->type = R_ANAL_OP_TYPE_JMP;
		op->size = 4;
		op->jump = imm;
		op->fail = addr + op->size;
		r_strbuf_setf(&op->esil, "%"PFMT64x",pc,+=,",imm);
		break;
	case CLCY_C: // Call conditional
		op->type = R_ANAL_OP_TYPE_CCALL;
		op->size = 3;
		op->jump = imm;
		op->fail = addr + op->size;
		switch(cond) {
			case 0: // Not equal / not zero
				r_strbuf_setf(&op->esil, "zf,!,?{,pc,3,+,%s,=,%"PFMT64d",pc,+=,}",rA, imm);
				break;
			case 1: // Equal / Zero
				r_strbuf_setf(&op->esil, "zf,?{,pc,3,+,%s,=,%"PFMT64d",pc,+=,}",rA, imm);
				break;
			case 2: // Less Than
				r_strbuf_setf(&op->esil, "zf,!,cf,&,?{,pc,3,+,%s,=,%"PFMT64d",pc,+=,}",rA, imm);
				break;
			case 3: // Less Than or Equal
				r_strbuf_setf(&op->esil, "zf,cf,|,?{,pc,3,+,%s,=,%"PFMT64d",pc,+=,}", rA, imm);
				break;
			case 4: // Greater Than
				r_strbuf_setf(&op->esil, "zf,cf,&,!,?{,pc,3,+,%s,=,%"PFMT64d",pc,+=,}", rA, imm);
				break;
			case 5: // Greater Than or Equal
				r_strbuf_setf(&op->esil, "cf,!,zf,|,?{,pc,3,+,%s,=,%"PFMT64d",pc,+=,}", rA, imm);
				break;
			case 6: // Not overflow
				r_strbuf_setf(&op->esil, "of,!,?{,pc,3,+,%s,=,%"PFMT64d",pc,+=,}", rA, imm);
				break;
			case 7: // Overflow
				r_strbuf_setf(&op->esil, "of,?{,pc,3,+,%s,=,%"PFMT64d",pc,+=,}", rA, imm);
				break;
			case 8: // Not signed
				r_strbuf_setf(&op->esil, "sf,!,?{,pc,3,+,%s,=,%"PFMT64d",pc,+=,}", rA, imm);
				break;
			case 9: // Signed
				r_strbuf_setf(&op->esil, "sf,?{,pc,3,+,%s,=,%"PFMT64d",pc,+=,}", rA, imm);
				break;
			case 10: // Signed less than
				r_strbuf_setf(&op->esil, "of,sf,==,!,?{,pc,3,+,%s,=,%"PFMT64d",pc,+=,}", rA, imm);
				break;
			case 11: // Signed less than or Equal
				r_strbuf_setf(&op->esil, "of,sf,==,!,zf,|,?{,pc,3,+,%s,=,%"PFMT64d",pc,+=,}", rA, imm);
				break;
			case 12: // Signed greater than
				r_strbuf_setf(&op->esil, "zf,!,of,sf,==,&,?{,pc,3,+,%s,=,%"PFMT64d",pc,+=,}", rA, imm);
				break;
			case 13: // Sined Greater Than or Equal
				r_strbuf_setf(&op->esil, "of,sf,==,?{,pc,3,+,%s,=,%"PFMT64d",pc,+=,}", rA, imm);
				break;
			default: // Always
				r_strbuf_setf(&op->esil, "pc,3,+,%s,=,%"PFMT64d",pc,+=,", rA, imm);
				break;
		}
		break;
	case CLCY_CAA: // Call absolute
		op->type = R_ANAL_OP_TYPE_CALL;
		op->size = 4;
		op->jump = imm;
		op->fail = addr + op->size;
		r_strbuf_setf (&op->esil, "pc,4,+,ra,=,%"PFMT64x",pc,=,",imm);
		break;
	case CLCY_CAR: // Call relative
		op->type = R_ANAL_OP_TYPE_CALL;
		op->size = 4;
		op->jump = imm;
		op->fail = addr + op->size;
		r_strbuf_setf (&op->esil, "pc,4,+,ra,=,%"PFMT64x",pc,+=,",imm);
		break;
	// XXX
	case CLCY_CM: // Compare
		op->type = R_ANAL_OP_TYPE_CMP;
		op->size = 2;
		r_strbuf_setf (&op->esil, "%s,%s,==,", rA, rB);
		break;
	case CLCY_CMF: // Compare Floating Point
		op->size = 2;
		break;
	case CLCY_CMFM: // Compare floating point multi reg
		op->size = 2;
		break;
	case CLCY_CMI: // Compare immediate
		op->type = R_ANAL_OP_TYPE_CMP;
		op->size = 3;
		r_strbuf_setf (&op->esil, "%s,%"PFMT64d",==,", rA, imm);
		break;
	// XXX
	case CLCY_CMIM: // Compare immediate multi reg
		op->type = R_ANAL_OP_TYPE_CMP;
		op->size = 3;
		break;
	// XXX
	case CLCY_CMM: // Compare multi reg
		op->type = R_ANAL_OP_TYPE_CMP;
		op->size = 2;
		break;
	// XX
	case CLCY_CR: // Call register conditional
		op->type = R_ANAL_OP_TYPE_CCALL;
		op->size = 2;
		switch(cond) {
			case 0: // Not equal / not zero
				r_strbuf_setf(&op->esil, "zf,!,?{,pc,2,+,%s,=,%s,pc,=,}",rA, rA);
				break;
			case 1: // Equal / Zero
				r_strbuf_setf(&op->esil, "zf,?{,pc,2,+,%s,=,%s,pc,=,}",rA, rA);
				break;
			case 2: // Less Than
				r_strbuf_setf(&op->esil, "zf,!,cf,&,?{,pc,2,+,%s,=,%s,pc,=,}",rA, rA);
				break;
			case 3: // Less Than or Equal
				r_strbuf_setf(&op->esil, "zf,cf,|,?{,pc,2,+,%s,=,%s,pc,=,}", rA, rA);
				break;
			case 4: // Greater Than
				r_strbuf_setf(&op->esil, "zf,cf,&,!,?{,pc,2,+,%s,=,%s,pc,=,}", rA, rA);
				break;
			case 5: // Greater Than or Equal
				r_strbuf_setf(&op->esil, "cf,!,zf,|,?{,pc,2,+,%s,=,%s,pc,=,}", rA, rA);
				break;
			case 6: // Not overflow
				r_strbuf_setf(&op->esil, "of,!,?{,pc,2,+,%s,=,%s,pc,=,}", rA, rA);
				break;
			case 7: // Overflow
				r_strbuf_setf(&op->esil, "of,?{,pc,2,+,%s,=,%s,pc,=,}", rA, rA);
				break;
			case 8: // Not signed
				r_strbuf_setf(&op->esil, "sf,!,?{,pc,2,+,%s,=,%s,pc,=,}", rA, rA);
				break;
			case 9: // Signed
				r_strbuf_setf(&op->esil, "sf,?{,pc,2,+,%s,=,%s,pc,=,}", rA, rA);
				break;
			case 10: // Signed less than
				r_strbuf_setf(&op->esil, "of,sf,==,!,?{,pc,2,+,%s,=,%s,pc,=,}", rA, rA);
				break;
			case 11: // Signed less than or Equal
				r_strbuf_setf(&op->esil, "of,sf,==,!,zf,|,?{,pc,2,+,%s,=,%s,pc,=,}", rA, rA);
				break;
			case 12: // Signed greater than
				r_strbuf_setf(&op->esil, "zf,!,of,sf,==,&,?{,pc,2,+,%s,=,%s,pc,=,}", rA, rA);
				break;
			case 13: // Sined Greater Than or Equal
				r_strbuf_setf(&op->esil, "of,sf,==,?{,pc,2,+,%s,=,%s,pc,=,}", rA, rA);
				break;
			default: // Always
				r_strbuf_setf(&op->esil, "pc,2,+,%s,=,%s,pc,=,", rA, rA);
				break;
		}

		break;
	case CLCY_DI: // Disable interrupts
		op->size = 2;
		break;
	case CLCY_DBRK: // Debug break
		op->type = R_ANAL_OP_TYPE_TRAP;
		op->size = 2;
		break;
	// XXX
	case CLCY_DMT: // Direct memory transfer
		op->type = R_ANAL_OP_TYPE_MOV;
		op->size = 3;
		break;
	case CLCY_DV: // Divide
		op->type = R_ANAL_OP_TYPE_DIV;
		op->size = 3;
		r_strbuf_setf (&op->esil, "%s,%s,/,%s,=,",rC,rB,rA);
		break;
	case CLCY_DVF: // Divide floating point
		op->size = 3;
		break;
	case CLCY_DVFM: // Divide floating point multi reg
		op->size = 3;
		break;
	case CLCY_DVI: // Divide immediate
		op->type = R_ANAL_OP_TYPE_DIV;
		op->size = 3;
		r_strbuf_setf (&op->esil, "%"PFMT64d",%s,/,%s,=,",imm,rB,rA);
		break;
	case CLCY_DVIM: // Divide immediate multi reg
		op->type = R_ANAL_OP_TYPE_DIV;
		op->size = 3;
		break;
	case CLCY_DVIS: // Divide immediate signed
		op->type = R_ANAL_OP_TYPE_DIV;
		op->size = 3;
		r_strbuf_setf (&op->esil, "%"PFMT64d",%s,/,%s,=,",imm,rB,rA);
		break;
	case CLCY_DVISM: // Divide immediate signed multi reg
		op->type = R_ANAL_OP_TYPE_DIV;
		op->size = 3;
		break;
	case CLCY_DVM: // Divide multi reg
		op->type = R_ANAL_OP_TYPE_DIV;
		op->size = 3;
		break;
	case CLCY_DVS: // Divide signed
		op->type = R_ANAL_OP_TYPE_DIV;
		op->size = 3;
		r_strbuf_setf (&op->esil, "%s,%s,/,%s,=,",rC,rB,rA);
		break;
	case CLCY_DVSM: // Divide signed multi reg
		op->type = R_ANAL_OP_TYPE_DIV;
		op->size = 3;
		break;
	case CLCY_EI: // Enable interrupts
		op->size = 2;
		break;
	case CLCY_FTI: // Float to integer
		op->type = R_ANAL_OP_TYPE_MOV;
		op->size = 3;
		break;
	case CLCY_FTIM: // Float to integer multi reg
		op->type = R_ANAL_OP_TYPE_MOV;
		op->size = 3;
		break;
	case CLCY_HT: // Halt
		op->type = R_ANAL_OP_TYPE_TRAP;
		op->size = 2;
		break;
	case CLCY_IR: // Interrupt return
		op->size = 2;
		break;
	case CLCY_ITF: // Integer to float
		op->type = R_ANAL_OP_TYPE_MOV;
		op->size = 3;
		break;
	case CLCY_ITFM: // Integer to float multi reg
		op->type = R_ANAL_OP_TYPE_MOV;
		op->size = 3;
		break;
	// Allow only aligned to 32bits access
	case CLCY_LDS: // Load single
		op->type = R_ANAL_OP_TYPE_LOAD;
		op->size = 6;
		op->refptr = 6;
		r_strbuf_setf (&op->esil, "%s,%"PFMT64d",+,[4],0x1f,&,%s,=,", rB, imm, rA);
		break;
	// Allow only aligned to 32bits access
	case CLCY_LDT: // Load tri
		op->type = R_ANAL_OP_TYPE_LOAD;
		op->size = 6;
		r_strbuf_setf (&op->esil, "%s,%"PFMT64d",+,[4],0xffffff,&,%s,=,", rB, imm, rA);
		break;
	// Allow only aligned to 32bits access
	case CLCY_LDW: // Load word
		op->type = R_ANAL_OP_TYPE_LOAD;
		op->size = 6;
		r_strbuf_setf (&op->esil, "%s,%"PFMT64d",+,[4],0x3ffff,&,%s,=,", rB, imm, rA);
		break;
	case CLCY_MD: // Modulus
		op->type = R_ANAL_OP_TYPE_MOD;
		op->size = 3;
		r_strbuf_setf (&op->esil, "%s,%s,%c,%s,=,",rC,rB,'%',rA);
		break;
	case CLCY_MDF: // Modulus floating point
		op->size = 3;
		break;
	case CLCY_MDFM: // Modulus floating point multi reg
		op->size = 3;
		break;
	case CLCY_MDI: // Modulus immediate
		op->type = R_ANAL_OP_TYPE_MOD;
		op->size = 3;
		r_strbuf_setf (&op->esil, "%"PFMT64d",%s,%c,%s,=,",imm,rB,'%',rA);
		break;
	case CLCY_MDIM: // Modulus immediate multi reg
		op->type = R_ANAL_OP_TYPE_MOD;
		op->size = 3;
		break;
	case CLCY_MDIS: // Modulus immediate signed
		op->type = R_ANAL_OP_TYPE_MOD;
		op->size = 3;
		r_strbuf_setf (&op->esil, "%"PFMT64d",%s,%c,%s,=,",imm,rB,'%',rA);
		break;
	case CLCY_MDISM: // Modulus immediate signed multi reg
		op->type = R_ANAL_OP_TYPE_MOD;
		op->size = 3;
		break;
	case CLCY_MDM: // Modulus multi reg
		op->type = R_ANAL_OP_TYPE_MOD;
		op->size = 3;
		break;
	case CLCY_MDS: // Modulus signed
		op->type = R_ANAL_OP_TYPE_MOD;
		op->size = 3;
		r_strbuf_setf (&op->esil, "%s,%s,%c,%s,=,",rC,rB,'%',rA);
		break;
	case CLCY_MDSM: // Modulus signed multi reg
		op->type = R_ANAL_OP_TYPE_REG;
		op->size = 3;
		break;
	case CLCY_MH: // Move high
		op->type = R_ANAL_OP_TYPE_MOV;
		op->size = 3;
		r_strbuf_setf (&op->esil, "%"PFMT64d",10,<<,%s,0x3ff,&,|,%s,=,", imm, rA, rA);
		break;
	case CLCY_ML: // Move low
		op->type = R_ANAL_OP_TYPE_MOV;
		op->size = 3;
		r_strbuf_setf (&op->esil, "%"PFMT64d",%s,=,", imm, rA);
		break;
	case CLCY_MS: // Move low signed
		op->type = R_ANAL_OP_TYPE_MOV;
		op->size = 3;
		r_strbuf_setf (&op->esil, "%"PFMT64d",%s,=,", imm, rA);
		break;
	case CLCY_MU: // Multiply
		op->type = R_ANAL_OP_TYPE_MUL;
		op->size = 3;
		r_strbuf_setf (&op->esil, "%s,%s,*,%s,=,",rC,rB,rA);
		break;
	case CLCY_MUF: // Multiply floating point
		op->size = 3;
		break;
	case CLCY_MUFM: // Multiply floating point multi reg
		op->size = 3;
		break;
	case CLCY_MUI: // Multiply immediate
		op->type = R_ANAL_OP_TYPE_MUL;
		op->size = 3;
		r_strbuf_setf (&op->esil, "%"PFMT64d",%s,*,%s,=,",imm,rB,rA);
		break;
	case CLCY_MUIM: // Multiply immediate multi reg
		op->type = R_ANAL_OP_TYPE_MUL;
		op->size = 3;
		break;
	case CLCY_MUIS: // Multiply immediate signed
		op->type = R_ANAL_OP_TYPE_MUL;
		op->size = 3;
		r_strbuf_setf (&op->esil, "%s,%"PFMT64d",*,%s,=,",rB, imm, rA);
		break;
	case CLCY_MUISM: // Multiply immediate signed multi reg
		op->type = R_ANAL_OP_TYPE_MUL;
		op->size = 3;
		break;
	case CLCY_MUM: // Multiply multi reg
		op->type = R_ANAL_OP_TYPE_MUL;
		op->size = 3;
		break;
	case CLCY_MUS: // Multiply signed
		op->type = R_ANAL_OP_TYPE_MUL;
		op->size = 3;
		r_strbuf_setf (&op->esil, "%s,%s,*,%s,=,",rC,rB,rA);
		break;
	case CLCY_MUSM: // Multiply signed multi reg
		op->type = R_ANAL_OP_TYPE_MUL;
		op->size = 3;
		break;
	case CLCY_NG: // Negate (nougat)
		op->type = R_ANAL_OP_TYPE_NOT;
		op->size = 3;
		r_strbuf_setf (&op->esil, "%s,0,-,%s,=,", rB, rA);
		break;
	case CLCY_NGF: // Negate floating point
		op->size = 3;
		break;
	case CLCY_NGFM: // Negate floating point multi reg
		op->size = 3;
		break;
	case CLCY_NGM: // Negate multi reg
		op->type = R_ANAL_OP_TYPE_NOT;
		op->size = 3;
		break;
	case CLCY_NT: // Nooooooooooooooooot
		op->type = R_ANAL_OP_TYPE_NOT;
		op->size = 3;
		r_strbuf_setf (&op->esil, "%s,!,%s,=,", rB, rA);
		break;
	case CLCY_NTM: // Not multi reg
		op->type = R_ANAL_OP_TYPE_NOT;
		op->size = 3;
		break;
	case CLCY_OR: // Or
		op->type = R_ANAL_OP_TYPE_OR;
		op->size = 3;
		r_strbuf_setf (&op->esil, "%s,%s,|,%s,=,",rC,rB,rA);
		break;
	case CLCY_ORI: // Ori
		op->type = R_ANAL_OP_TYPE_OR;
		op->size = 3;
		r_strbuf_setf (&op->esil, "%s,%"PFMT64x",|,%s,=,",rB,imm,rA);
		break;
	case CLCY_ORM: // Or multi reg
		op->type = R_ANAL_OP_TYPE_OR;
		op->size = 3;
		break;
	case CLCY_RE: // Return
		op->type = R_ANAL_OP_TYPE_RET;
		op->size = 2;
		break;
	case CLCY_RF: // Read flags
		op->type = R_ANAL_OP_TYPE_MOV;
		op->size = 2;
		break;
	// XXX - be careful with rotation - may be use not embeded commands?
	case CLCY_RL: // Rotate left
		op->type = R_ANAL_OP_TYPE_ROL;
		op->size = 3;
		r_strbuf_setf (&op->esil, "%s,%s,<<<,%s,=",rC,rB,rA);
		break;
	case CLCY_RLI: // Rotate left immediate
		op->type = R_ANAL_OP_TYPE_ROL;
		op->size = 3;
		r_strbuf_setf (&op->esil, "%"PFMT64d",%s,<<<,%s,=",imm, rB, rA);
		break;
	case CLCY_RLIM: // Rotate left immediate multi reg
		op->type = R_ANAL_OP_TYPE_ROL;
		op->size = 3;
		break;
	case CLCY_RLM: // Rotate left multi reg
		op->type = R_ANAL_OP_TYPE_ROL;
		op->size = 3;
		break;
	case CLCY_RMP: // Read memory protection
		op->size = 3;
		break;
	case CLCY_RND: // Random
		op->size = 3;
		break;
	case CLCY_RNDM: // Random multi reg
		op->size = 3;
		break;
	case CLCY_RR: // Rotate right
		op->type = R_ANAL_OP_TYPE_ROR;
		op->size = 3;
		r_strbuf_setf (&op->esil, "%s,%s,>>>,%s,=",rC,rB,rA);
		break;
	case CLCY_RRI: // Rotate right immediate
		op->type = R_ANAL_OP_TYPE_ROR;
		op->size = 3;
		r_strbuf_setf (&op->esil, "%"PFMT64d",%s,>>>,%s,=",imm, rB, rA);
		break;
	case CLCY_RRIM: // Rotate right immediate multi reg
		op->type = R_ANAL_OP_TYPE_ROR;
		op->size = 3;
		break;
	case CLCY_RRM: // Rotate right multi reg
		op->type = R_ANAL_OP_TYPE_ROR;
		op->size = 3;
		break;
	case CLCY_SA: // Shift arithmetic right
		op->type = R_ANAL_OP_TYPE_SAR;
		op->size = 3;
		break;
	case CLCY_SAI: // Shift arithmetic right immediate
		op->type = R_ANAL_OP_TYPE_SAR;
		op->size = 3;
		break;
	case CLCY_SAIM: // Shift arithmetic right immediate multi reg
		op->type = R_ANAL_OP_TYPE_SAR;
		op->size = 3;
		break;
	case CLCY_SAM: // Shift arithmetic right multi reg
		op->type = R_ANAL_OP_TYPE_SAR;
		op->size = 3;
		break;
	case CLCY_SB: // Subtract
		op->type = R_ANAL_OP_TYPE_SUB;
		op->size = 3;
		r_strbuf_setf (&op->esil, "%s,%s,-,%s,=",rC,rB,rA);
		break;
	case CLCY_SBC: // Subtract with carry
		op->type = R_ANAL_OP_TYPE_SUB;
		op->size = 3;
		r_strbuf_setf (&op->esil, "%s,%s,-,%s,=",rC,rB,rA);
		break;
	case CLCY_SBCI: // Subtract immediate with carry
		op->type = R_ANAL_OP_TYPE_SUB;
		op->size = 3;
		r_strbuf_setf (&op->esil, "%"PFMT64d",%s,-,%s,=",imm,rB,rA);
		break;
	case CLCY_SBCIM: // Subtract immediate multi reg with carry
		op->type = R_ANAL_OP_TYPE_SUB;
		op->size = 3;
		break;
	case CLCY_SBCM: // Subtract multi reg with carry
		op->type = R_ANAL_OP_TYPE_SUB;
		op->size = 3;
		break;
	case CLCY_SBF: // Subtract floating point
		op->size = 3;
		break;
	case CLCY_SBFM: // Subtract floating point multi reg
		op->size = 3;
		break;
	case CLCY_SBI: // Subtract immediate
		op->type = R_ANAL_OP_TYPE_SUB;
		op->size = 3;
		r_strbuf_setf (&op->esil, "%"PFMT64d",%s,-,%s,=",imm,rB,rA);
		break;
	case CLCY_SBIM: // Subtract immediate multi reg;
		op->type = R_ANAL_OP_TYPE_SUB;
		op->size = 3;
		break;
	case CLCY_SBM: // Subtract multi reg
		op->type = R_ANAL_OP_TYPE_SUB;
		op->size = 3;
		break;
	case CLCY_SES: // Sign extend single
		op->size = 3;
		break;
	case CLCY_SEW: // Sign extend word
		op->size = 3;
		break;
	case CLCY_SF: // Set flags
		op->type = R_ANAL_OP_TYPE_MOV;
		op->size = 3;
		break;
	case CLCY_SL: // Shift left
		op->type = R_ANAL_OP_TYPE_SHL;
		op->size = 3;
		r_strbuf_setf (&op->esil, "%s,%s,<<,%s,=",rC,rB,rA);
		break;
	case CLCY_SLI: // Shift left immediate
		op->type = R_ANAL_OP_TYPE_SHL;
		op->size = 3;
		r_strbuf_setf (&op->esil, "%"PFMT64d",%s,<<,%s,=,",imm,rB,rA);
		break;
	case CLCY_SLIM: // Shift left immediate multi reg
		op->type = R_ANAL_OP_TYPE_SHL;
		op->size = 3;
		break;
	case CLCY_SLM: // Shift left multi reg
		op->type = R_ANAL_OP_TYPE_SHL;
		op->size = 3;
		break;
	case CLCY_SMP: // Set memory protection
		op->size = 3;
		break;
	case CLCY_SR: // Shift right
		op->type = R_ANAL_OP_TYPE_SHR;
		op->size = 3;
		r_strbuf_setf (&op->esil, "%s,%s,>>,%s,=",rC,rB,rA);
		break;
	case CLCY_SRI: // Shift right immediate
		op->type = R_ANAL_OP_TYPE_SHR;
		op->size = 3;
		r_strbuf_setf (&op->esil, "%"PFMT64d",%s,>>,%s,=,",imm,rB,rA);
		break;
	case CLCY_SRIM: // Shift right immediate multi reg
		op->type = R_ANAL_OP_TYPE_SHR;
		op->size = 3;
		break;
	case CLCY_SRM: // Shift right multi reg
		op->type = R_ANAL_OP_TYPE_SHR;
		op->size = 3;
		break;
	// It aligns the storage to 32bits
	case CLCY_STS: // Store single
		op->type = R_ANAL_OP_TYPE_STORE;
		op->size = 6;
		r_strbuf_setf (&op->esil, ",%s,0x1f,&,%"PFMT64d",%s,+,=[4],", rA, imm, rB);
		break;
	// It aligns the storage to 32bits
	case CLCY_STT: // Store tri
		op->type = R_ANAL_OP_TYPE_STORE;
		op->size = 6;
		r_strbuf_setf (&op->esil, ",%s,0xfffffff,&,%"PFMT64d",%s,+,=[4],", rA, imm, rB);
		break;
	// It aligns the storage to 32bits
	case CLCY_STW: // Store word
		op->type = R_ANAL_OP_TYPE_STORE;
		op->size = 6;
		r_strbuf_setf (&op->esil, ",%s,0x3ff,&,%"PFMT64d",%s,+,=[4],", rA, imm, rB);
		break;
	case CLCY_WT: // Wait
		op->size = 2;
		break;
	case CLCY_XR: // Xor
		op->type = R_ANAL_OP_TYPE_XOR;
		op->size = 3;
		r_strbuf_setf (&op->esil, "%s,%s,^,%s,=,",rC,rB,rA);
		break;
	case CLCY_XRI: // Xor immediate
		op->type = R_ANAL_OP_TYPE_XOR;
		op->size = 3;
		r_strbuf_setf (&op->esil, "%s,%"PFMT64x",^,%s,=,",rB,imm,rA);
		break;
	case CLCY_XRM: // Xor multi reg
		op->type = R_ANAL_OP_TYPE_XOR;
		op->size = 3;
		break;
	case CLCY_ZES: // Zero extend single
		op->size = 3;
		break;
	case CLCY_ZEW: // Zero extend word
		op->size = 3;
		break;
	default:
		op->type = R_ANAL_OP_TYPE_NOP;
		op->size = 1;
		r_strbuf_setf (&op->esil, "nop");
		break;
	}
	anal->bitshift = (op->size * 9 + anal->bitshift) % 8;
	return op->size;
}

static void *  internalMemory = NULL;
static int indicememoria = 0;
static ut32 vtmp = 0;
static ut32 idxInputText = 0;
static char texto[] ="packers_and_vms_and_xors_oh_my\n";

static int esil_clemency_intr (RAnalEsil *esil, int intr) {
	ut64 valor1;
	if (!esil)
		return false;
	if (intr==0) {
		reg_read(esil,"r_00",&valor1);
		eprintf("%c\n",(ut32)valor1);
	} else if (intr==0x4) {
		eprintf("Leido %c\n",texto[idxInputText]);
		reg_write(esil,"r_00",(ut64)((char) texto[idxInputText++]));
	}
	else if (intr==0x11) {
		ut64 basedata=0;
		reg_read(esil,"r_00",&valor1);
		reg_read(esil,"r_data",&basedata);
		int  v1=indicememoria;
		indicememoria+= valor1;

		reg_write(esil,"r_00",(ut64) basedata+v1);
	}
	else
		eprintf ("INTERRUPT 0x%02x \n", intr);
	return true;
}

static int set_reg_profile(RAnal *anal) {
	const char *p = \
		"=PC    pc\n"
		"=SP    st\n"
		"=BP    st\n"
		//"=RA    ra\n"
		"=A0	r0\n"
		"=A1    r1\n"
		"=A2    r2\n"
		"=A3    r3\n"
		"gpr	r0	.27	0	0\n"
		"gpr	r1	.27	4	0\n"
		"gpr	r2	.27	8	0\n"
		"gpr	r3	.27	12	0\n"
		"gpr	r4	.27	16	0\n"
		"gpr	r5	.27	20	0\n"
		"gpr	r6	.27	24	0\n"
		"gpr	r7	.27	28	0\n"
		"gpr	r8	.27	32	0\n"
		"gpr	r9	.27	36	0\n"
		"gpr	r10	.27	40	0\n"
		"gpr	r11	.27	44	0\n"
		"gpr	r12	.27	48	0\n"
		"gpr	r13	.27	52	0\n"
		"gpr	r14	.27	56	0\n"
		"gpr	r15	.27	60	0\n"
		"gpr	r16	.27	64	0\n"
		"gpr	r17	.27	68	0\n"
		"gpr	r18	.27	72	0\n"
		"gpr	r19	.27	76	0\n"
		"gpr	r20	.27	80	0\n"
		"gpr	r21	.27	84	0\n"
		"gpr	r22	.27	88	0\n"
		"gpr	r23	.27	92	0\n"
		"gpr	r24	.27	96	0\n"
		"gpr	r25	.27	100	0\n"
		"gpr	r26	.27	104	0\n"
		"gpr	r27	.27	108	0\n"
		"gpr	r28	.27	112	0\n"
		"gpr	st	.27	116	0\n"
		"gpr	ra	.27	120	0\n"
		"gpr	pc	.27	124	0\n"
		"flg	fl	.27	128	0 zcos\n"
		"flg	zf	.1	128.0	0\n"
		"flg	cf	.1	128.1	0\n"
		"flg	of	.1	128.2	0\n"
		"flg	sf	.1	128.3	0\n";

	return r_reg_set_profile_string (anal->reg, p);
}
static int esil_clemency_init (RAnalEsil *esil) {
	if (!esil) return false;
	return true;
}

static int esil_clemency_fini (RAnalEsil *esil) {
	return true;
}

static RAnalPlugin r_anal_plugin_clemency = {
	.name = "clcy",
	.desc = "clemency code analysis plugin",
	.license = "LGPL3",
	.arch = "clcy",
	.bits = 27,
	.esil_init = esil_clemency_init,
	.esil_fini = esil_clemency_fini,
	.esil_intr = esil_clemency_intr,
	.esil = true,
	.op = &clemency_op,
	.set_reg_profile = set_reg_profile,
};

RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_clemency,
	.version = R2_VERSION
};
