#pragma once
void decode_R(inst_t *inst, const ut16 *src);
void decode_R_IMM(inst_t *inst, const ut16 *src);
void decode_U(inst_t *inst, const ut16 *src);
void decode_BIN_R(inst_t *inst, const ut16 *src);
void decode_BIN_R_IMM(inst_t *inst, const ut16 *src);
void decode_MOV_LOW_HI(inst_t *inst, const ut16 *src);
void decode_MOV_LOW_SIGNED(inst_t *inst, const ut16 *src);
void decode_B_CC_OFF(inst_t *inst, const ut16 *src);
void decode_B_CC_R(inst_t *inst, const ut16 *src);
void decode_B_OFF(inst_t *inst, const ut16 *src);
void decode_B_LOC(inst_t *inst, const ut16 *src);
void decode_N(inst_t *inst, const ut16 *src);
void decode_FLAGS_INTS(inst_t *inst, const ut16 *src);
void decode_U_EXTEND(inst_t *inst, const ut16 *src);
void decode_RANDOM(inst_t *inst, const ut16 *src);
void decode_M(inst_t *inst, const ut16 *src);
void decode_MP(inst_t *inst, const ut16 *src);
