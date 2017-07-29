/* radare - LGPL - Copyright 2017 - pancake */

#include <r_types.h>
#include <r_lib.h>
#include <r_cmd.h>
#include <r_core.h>
#include <r_cons.h>
#include <string.h>
#include <r_anal.h>

#include "../include/clcy_mem.h"

#undef R_API
#define R_API static
#undef R_IPI
#define R_IPI static

static void clemency_help(RCore *core) {
	eprintf ("Clemency command:\n");
	eprintf ("_s addr   seek to nth 9bit byte\n");
	eprintf ("_x        9bit hexdump\n");
	eprintf ("_xw       18bit hexdump\n");
	eprintf ("_xt       27bit hexdump\n");
}

static void hexdump_9byte(RCore *core, const char *arg) {
	int i, offset = 0; // bit level offset
	for (i = 0; i < core->blocksize - 1; i++) {
		ut9 byte9 = r_read_me9 (core->block, (i * 8) + offset);
		r_cons_printf ("0x%08"PFMT64x" + %d  %03x\n",
			core->offset + i, offset, byte9);
		offset = (offset + 1) % 8;
	}
}

static void hexdump_18word(RCore *core, const char *arg) {
	int i, offset = 0; // bit level offset
	for (i = 0; i < core->blocksize - 1 ; i++) {
		ut18 word18 = r_read_me18 (core->block, (i * 8) + offset);
		r_cons_printf ("0x%08"PFMT64x" + %d  %06"PFMT32x"\n",
			core->offset + i, offset, word18);
		offset = (offset + 1) % 8;
	}
}

static void hexdump_27tri(RCore *core, const char *arg) {
	int i, offset = 0; // bit level offset
	for (i = 0; i < core->blocksize -1 ; i++) {
		ut27 word27 = r_read_me27 (core->block, (i * 8) + offset);
		r_cons_printf ("0x%08"PFMT64x" + %d  %09"PFMT32x"\n",
			core->offset + i, offset, word27);
		offset = (offset + 1) % 8;
	}
}

static int r_cmd_clemency(struct r_core_t *core, const char *str) {
	if (*str == '_') {
		switch (str[1]) {
		case 's':
			{
				ut64 addr = r_num_math (core->num, str + 2);
				if (addr % 9) {
					eprintf ("Unaligned seek for %d bits\n", addr % 9);
				}
				r_core_cmdf (core, "s 0x%08"PFMT64x, addr * 9 / 8);
			}
			break;
		case 'x':
			switch (str[2]) {
			case 'b':
			case 'x':
				hexdump_9byte (core, str);
				break;
			case 'w':
				hexdump_18word (core, str);
				break;
			case 't':
				hexdump_18word (core, str);
				break;
			default:
				hexdump_9byte (core, str);
			}
			break;
		case 'p':
			switch (str[2]) {
			case 'b':
			case 'x':
				hexdump_9byte (core, str);
				break;
			case 'w':
				hexdump_18word (core, str);
				break;
			case 't':
				hexdump_18word (core, str);
				break;
			}
			break;
		case 'w':
			eprintf ("Bit level writes using 9 bit bytes because FUCK YOU\n");
			break;
		default:
			clemency_help (core);
			break;
		}
		return true;
	}
	return false;
}

RCorePlugin r_core_plugin_clemency = {
	.name = "cm",
	.desc = "cLEMENCy core plugin",
	.license = "MIT",
	.call = (void*)r_cmd_clemency,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CORE,
	.data = &r_core_plugin_clemency,
	.version = R2_VERSION
};
#endif
