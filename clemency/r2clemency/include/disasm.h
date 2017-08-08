#pragma once
bool decode_R(inst_t *inst, const ut16 *src, int len);
bool decode_R_IMM(inst_t *inst, const ut16 *src, int len);
bool decode_U(inst_t *inst, const ut16 *src, int len);
bool decode_BIN_R(inst_t *inst, const ut16 *src, int len);
bool decode_BIN_R_IMM(inst_t *inst, const ut16 *src, int len);
bool decode_MOV_LOW_HI(inst_t *inst, const ut16 *src, int len);
bool decode_MOV_LOW_SIGNED(inst_t *inst, const ut16 *src, int len);
bool decode_B_CC_OFF(inst_t *inst, const ut16 *src, int len);
bool decode_B_CC_R(inst_t *inst, const ut16 *src, int len);
bool decode_B_OFF(inst_t *inst, const ut16 *src, int len);
bool decode_B_LOC(inst_t *inst, const ut16 *src, int len);
bool decode_N(inst_t *inst, const ut16 *src, int len);
bool decode_FLAGS_INTS(inst_t *inst, const ut16 *src, int len);
bool decode_U_EXTEND(inst_t *inst, const ut16 *src, int len);
bool decode_RANDOM(inst_t *inst, const ut16 *src, int len);
bool decode_M(inst_t *inst, const ut16 *src, int len);
bool decode_MP(inst_t *inst, const ut16 *src, int len);

int parse_reg(const char **src);
