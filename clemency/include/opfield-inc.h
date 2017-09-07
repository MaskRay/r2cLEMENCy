#define FORM_R \
	FIELD(opcode, 0, 7) \
	FIELD(rA, 7, 5) \
	FIELD(rB, 12, 5) \
	FIELD(rC, 17, 5) \
	FIELD(funct, 22, 2) \
	FIELD(arith_signed, 24, 1) \
	FIELD(is_imm, 25, 1) \
	FIELD(uf, 26, 1) \

#define FORM_R_IMM \
	FIELD(opcode, 0, 7) \
	FIELD(rA, 7, 5) \
	FIELD(rB, 12, 5) \
	FIELD(imm, 17, 7) \
	FIELD(arith_signed, 24, 1) \
	FIELD(is_imm, 25, 1) \
	FIELD(uf, 26, 1) \

#define FORM_U \
	FIELD(opcode, 0, 9) \
	FIELD(rA, 9, 5) \
	FIELD(rB, 14, 5) \
	FIELD(funct, 19, 7) \
	FIELD(uf, 26, 1) \

#define FORM_BIN_R \
	FIELD(opcode, 0, 8) \
	FIELD(rA, 8, 5) \
	FIELD(rB, 13, 5) \

#define FORM_BIN_R_IMM \
	FIELD(opcode, 0, 8) \
	FIELD(rA, 8, 5) \
	FIELD(imm, 13, 14) \

#define FORM_MOV_LOW_HI \
	FIELD(opcode, 0, 5) \
	FIELD(rA, 5, 5) \
	FIELD(imm, 10, 17) \

#define FORM_MOV_LOW_SIGNED \
	FIELD(opcode, 0, 5) \
	FIELD(rA, 5, 5) \
	FIELD(imm, 10, 17) \

#define FORM_B_CC_OFF \
	FIELD(opcode, 0, 6) \
	FIELD(cc, 6, 4) \
	FIELD(imm, 10, 17) \

#define FORM_B_CC_R \
	FIELD(opcode, 0, 6) \
	FIELD(cc, 6, 4) \
	FIELD(rA, 10, 5) \
	FIELD(funct, 15, 3) \

#define FORM_B_OFF \
	FIELD(opcode, 0, 9) \
	FIELD(imm, 9, 27) \

#define FORM_B_LOC \
	FIELD(opcode, 0, 9) \
	FIELD(imm, 9, 27) \

#define FORM_N \
	FIELD(opcode, 0, 18) \

#define FORM_FLAGS_INTS \
	FIELD(opcode, 0, 12) \
	FIELD(rA, 12, 5) \
	FIELD(funct, 17, 1) \

#define FORM_U_EXTEND \
	FIELD(opcode, 0, 12) \
	FIELD(rA, 12, 5) \
	FIELD(rB, 17, 5) \
	FIELD(funct, 22, 5) \

#define FORM_RANDOM \
	FIELD(opcode, 0, 9) \
	FIELD(rA, 9, 5) \
	FIELD(funct, 14, 12) \
	FIELD(uf, 26, 1) \

#define FORM_M \
	FIELD(opcode, 0, 7) \
	FIELD(rA, 7, 5) \
	FIELD(rB, 12, 5) \
	FIELD(reg_count, 17, 5) \
	FIELD(adj_rb, 22, 2) \
	FIELD(imm, 24, 27) \
	FIELD(funct, 51, 3) \

#define FORM_MP \
	FIELD(opcode, 0, 7) \
	FIELD(rA, 7, 5) \
	FIELD(rB, 12, 5) \
	FIELD(rw, 17, 1) \
	FIELD(mem_flags, 18, 2) \
	FIELD(funct, 20, 7) \

