/* radare - LGPL - Copyright 2017 - pancake */

#include <r_types.h>
#include <r_lib.h>
#include <r_cmd.h>
#include <r_core.h>
#include <r_cons.h>
#include <string.h>
#include <r_anal.h>

#include "../include/clemency.h"

static void clemency_help(RCore *core) {
	eprintf ("Clemency command:\n");
	eprintf ("_x        9bit hexdump\n");
	eprintf ("_xw       18bit hexdump\n");
	eprintf ("_xt       27bit hexdump\n");
}

static void hexdump_9byte(RCore *core, const char *arg, int len) {
	// TODO > blocksize
	ut16 *buf = malloc (len);
	r_io_read_at (core->io, core->offset, buf, len);
	for (int i = 0; (i + 1) * 2 <= len; i++) {
		if (i % 16 == 0) {
			if (i) r_cons_newline ();
			r_cons_printf ("0x%08"PFMT64x":", core->offset + i);
		}
		r_cons_printf (" %03x", buf[i]);
	}
	r_cons_newline ();
	free (buf);
}

static void hexdump_18word(RCore *core, const char *arg, int len) {
	// TODO > blocksize
	ut16 *buf = malloc (len);
	r_io_read_at (core->io, core->offset, buf, len);
	for (int i = 0; (i + 1) * 4 <= len; i++) {
		if (i % 8 == 0) {
			if (i) r_cons_newline ();
			r_cons_printf ("0x%08"PFMT64x":", core->offset + i * 2);
		}
		r_cons_printf (" %05x", buf[i*2] << 9 | buf[i*2+1]);
	}
	r_cons_newline ();
	free (buf);
}

static void hexdump_27tri(RCore *core, const char *arg, int len) {
	// TODO > blocksize
	ut16 *buf = malloc (len);
	r_io_read_at (core->io, core->offset, buf, len);
	for (int i = 0; (i + 1) * 6 <= len; i++) {
		if (i % 8 == 0) {
			if (i) r_cons_newline ();
			r_cons_printf ("0x%08"PFMT64x":", core->offset + i * 3);
		}
		r_cons_printf (" %07x", buf[i*2+2] << 18 | buf[i*2] << 9 | buf[i*2+1]);
	}
	r_cons_newline ();
	free (buf);
}

static int r_cmd_clemency(struct r_core_t *core, const char *input) {
	if (input[0] == '_') {
		switch (input[1]) {
		case 'x': // "_x"
			switch (input[2]) {
			case '\0':
			case ' ':
				r_core_cmdf (core, "_p %s", input[2] ? input + 3 : "");
				break;
			case 't':
				r_core_cmdf (core, "_pt %s", input[2] ? input + 3 : "");
				break;
			case 'w':
				r_core_cmdf (core, "_pw %s", input[2] ? input + 3 : "");
				break;
			default:
				clemency_help (core);
				break;
			}
			break;
		case 'p': // "_p"
			switch (input[2]) {
			case '\0':
			case ' ':
			case 'x': {
				int l = input[3] == ' ' ? (int) r_num_math (core->num, input + 4) * 2
					: core->blocksize;
				hexdump_9byte (core, input, l);
				break;
			}
			case 't': {
				int l = input[3] == ' ' ? (int) r_num_math (core->num, input + 4) * 6
					: core->blocksize;
				hexdump_27tri (core, input, l);
				break;
			}
			case 'w': {
				int l = input[3] == ' ' ? (int) r_num_math (core->num, input + 4) * 4
					: core->blocksize;
				hexdump_18word (core, input, l);
				break;
			}
			default:
				clemency_help (core);
				break;
			}
			break;
		case 'w': // "_w"
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
	.name = "clemency",
	.desc = "cLEMENCy core plugin",
	.license = "LGPL3",
	.call = (void*)r_cmd_clemency,
};

RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CORE,
	.data = &r_core_plugin_clemency,
	.version = R2_VERSION
};
