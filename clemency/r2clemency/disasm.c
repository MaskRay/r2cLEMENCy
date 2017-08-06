#include <r_types.h>
#include "include/clemency.h"
#include "include/opfield-inc.h"

#define FIELD(name, offset, count) inst->name = (inst->code >> bit_size-count-offset) & ((1 << count) - 1);
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

void decode_R(inst_t *inst, const ut16 *src)
{
  int bit_size = 27;
  inst->size = 3;
  inst->code = read_27 (src);
	FORM_R;
}

void decode_R_IMM(inst_t *inst, const ut16 *src)
{
  int bit_size = 27;
  inst->size = 3;
  inst->code = read_27 (src);
	FORM_R_IMM;
}

void decode_U(inst_t *inst, const ut16 *src)
{
  int bit_size = 27;
  inst->size = 3;
  inst->code = read_27 (src);
	FORM_U;
}

void decode_BIN_R(inst_t *inst, const ut16 *src)
{
  int bit_size = 18;
  inst->size = 2;
  inst->code = read_18 (src);
	FORM_BIN_R;
}

void decode_BIN_R_IMM(inst_t *inst, const ut16 *src)
{
  int bit_size = 27;
  inst->size = 3;
  inst->code = read_27 (src);
	FORM_BIN_R_IMM;
}

void decode_MOV_LOW_HI(inst_t *inst, const ut16 *src)
{
  int bit_size = 27;
  inst->size = 3;
  inst->code = read_27 (src);
	FORM_MOV_LOW_HI;
}

void decode_MOV_LOW_SIGNED(inst_t *inst, const ut16 *src)
{
  int bit_size = 27;
  inst->size = 3;
  inst->code = read_27 (src);
	FORM_MOV_LOW_SIGNED;
  SIGN_EXTEND(imm, 17);
}

void decode_B_CC_OFF(inst_t *inst, const ut16 *src)
{
  int bit_size = 27;
  inst->size = 3;
  inst->code = read_27 (src);
	FORM_B_CC_OFF;
  SIGN_EXTEND(imm, 17);
}

void decode_B_CC_R(inst_t *inst, const ut16 *src)
{
  int bit_size = 18;
  inst->size = 2;
  inst->code = read_18 (src);
	FORM_B_CC_R;
}

void decode_B_OFF(inst_t *inst, const ut16 *src)
{
  int bit_size = 36;
  inst->size = 4;
  inst->code = read_36 (src);
	FORM_B_OFF;
  SIGN_EXTEND(imm, 27);
}

void decode_B_LOC(inst_t *inst, const ut16 *src)
{
  int bit_size = 36;
  inst->size = 4;
  inst->code = read_36 (src);
	FORM_B_LOC;
}

void decode_N(inst_t *inst, const ut16 *src)
{
  int bit_size = 18;
  inst->size = 2;
  inst->code = read_18 (src);
	FORM_N;
}

void decode_FLAGS_INTS(inst_t *inst, const ut16 *src)
{
  int bit_size = 18;
  inst->size = 2;
  inst->code = read_18 (src);
	FORM_FLAGS_INTS;
}

void decode_U_EXTEND(inst_t *inst, const ut16 *src)
{
  int bit_size = 27;
  inst->size = 3;
  inst->code = read_27 (src);
	FORM_U_EXTEND;
}

void decode_RANDOM(inst_t *inst, const ut16 *src)
{
  int bit_size = 27;
  inst->size = 3;
  inst->code = read_27 (src);
	FORM_RANDOM;
}

void decode_M(inst_t *inst, const ut16 *src)
{
  int bit_size = 54;
  inst->size = 6;
  inst->code = read_54 (src);
	FORM_M;
  SIGN_EXTEND(imm, 27);

  inst->reg_count++;
}

void decode_MP(inst_t *inst, const ut16 *src)
{
  int bit_size = 27;
  inst->size = 3;
  inst->code = read_27 (src);
	FORM_MP;
}
