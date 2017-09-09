/* radare - LGPL - Copyright 2017 - xvilka, MaskRay */
#include <r_lib.h>

#include "../include/disasm.h"

static int _assemble(RAsm *a, RAsmOp *op, const char *src) {
	return assemble (a->pc, op, src);
}

static int _disassemble(RAsm *a, RAsmOp *op, const ut8 *src, int len) {
	return disassemble (a->pc, op, src, len, false);
}

static RAsmPlugin r_asm_plugin_clcy  = {
	.name = "clcy",
	.desc = "cLEMENCy asm",
	.arch = "clcy",
	.license = "LGPL3",
	.bits = 64, // in accordance with r_anal_plugin_clcy
	.disassemble = _disassemble,
	.assemble = _assemble,
};

RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_clcy,
	.version = R2_VERSION,
};
