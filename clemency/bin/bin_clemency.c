/* radare - LGPL - Copyright 2017 - xvilka */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>

#include "../include/clemency.h"

static bool use_9bit = false;

static bool check_bytes(const ut8 *buf, ut64 length) {
	if (buf[0] == 0x2c && buf[1] == 0x31) {
		// using 9bit io
		use_9bit = true;
		return true;
	}
	use_9bit = false;
	// using plain io
	return (buf[0] == 0x20 && buf[1] == 0x56);
}

static void *load_bytes(RBinFile *arch, const ut8 *buf, ut64 sz, ut64 loadaddr, Sdb *sdb) {
	if (!check_bytes (buf, sz)) {
		return NULL;
	}
	return R_NOTNULL;
}

static bool load(RBinFile *arch) {
	const ut8 *bytes = arch? r_buf_buffer (arch->buf): NULL;
	ut64 sz = arch? r_buf_size (arch->buf): 0;
	return check_bytes (bytes, sz);
}

static int destroy(RBinFile *arch) {
	return true;
}

static ut64 baddr(RBinFile *arch) {
	return 0;
}

/* accelerate binary load */
static RList *strings(RBinFile *arch) {
	return NULL;
}

static RBinInfo *info(RBinFile *arch) {
	RBinInfo *ret = NULL;
	if (!(ret = R_NEW0 (RBinInfo))) {
		return NULL;
	}
	ret->lang = NULL;
	ret->file = arch->file? strdup (arch->file): NULL;
	ret->type = strdup ("clcy");
	ret->bclass = strdup ("0.1");
	ret->rclass = strdup ("clcy");
	ret->os = strdup ("any");
	ret->subsystem = strdup ("unknown");
	ret->machine = strdup ("pc");
	ret->arch = strdup ("clcy");
	ret->has_va = 1;
	ret->bits = 27;
	ret->big_endian = 0;
	ret->dbg_info = 0;
	return ret;
}

static int dump_27bit(ut8 *buf, int bitoff) {
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

static RList *sections(RBinFile *arch) {
	RList *ret = NULL;
	RBinSection *ptr = NULL;

	if (!(ret = r_list_newf ((RListFree) free))) {
		return NULL;
	}
	if (!(ptr = R_NEW0 (RBinSection))) {
		return ret;
	}

	// There are also a files with offset 0x66 * 9 bits
	ut16 hdr_bitptr = 0x57 * 9;
	dump_27bit(arch->buf->buf, hdr_bitptr);
	ut27 code = r_read_me27(arch->buf->buf, hdr_bitptr);
	dump_27bit(arch->buf->buf, hdr_bitptr + 27);
	ut27 data = r_read_me27(arch->buf->buf, hdr_bitptr + 27);
	dump_27bit(arch->buf->buf, hdr_bitptr + 54);
	ut27 bss = r_read_me27(arch->buf->buf, hdr_bitptr + 54);
	eprintf("code: 0x%"PFMT32x" data: 0x%"PFMT32x" bss: 0x%"PFMT32x"\n", code, data, bss);

	strcpy (ptr->name, "code");
	ptr->vsize = ptr->size = code * 1024;
	ptr->paddr = 0;
	ptr->vaddr = 0;
	ptr->srwx = R_BIN_SCN_READABLE | R_BIN_SCN_WRITABLE |
	            R_BIN_SCN_EXECUTABLE | R_BIN_SCN_MAP;
	ptr->add = true;
	r_list_append (ret, ptr);

	if (!(ptr = R_NEW0 (RBinSection))) {
		return ret;
	}
	strcpy (ptr->name, "data");
	ptr->vsize = ptr->size = data * 1024;
	ptr->paddr = code * 1024;
	ptr->vaddr = code * 1024;
	ptr->srwx = R_BIN_SCN_READABLE | R_BIN_SCN_WRITABLE |
	            R_BIN_SCN_EXECUTABLE | R_BIN_SCN_MAP;
	ptr->add = true;
	r_list_append (ret, ptr);
	if (!(ptr = R_NEW0 (RBinSection))) {
		return ret;
	}
	strcpy (ptr->name, "bss");
	ptr->vsize = ptr->size = bss * 1024;
	ptr->paddr = code * 1024 + data * 1024;
	ptr->vaddr = code * 1024 + data * 1024;
	ptr->srwx = R_BIN_SCN_READABLE | R_BIN_SCN_WRITABLE |
	            R_BIN_SCN_EXECUTABLE | R_BIN_SCN_MAP;
	ptr->add = true;
	r_list_append (ret, ptr);

	return ret;
}

static RList *entries(RBinFile *arch) {
	RList *ret;
	RBinAddr *ptr = NULL;
	if (!(ret = r_list_new ())) {
		return NULL;
	}
	ret->free = free;
	if (!(ptr = R_NEW0 (RBinAddr))) {
		return ret;
	}
	ptr->paddr = 0;
	ptr->vaddr = 0;
	r_list_append (ret, ptr);
	return ret;
}

RBinPlugin r_bin_plugin_clcy = {
	.name = "clemency",
	.desc = "cLEMENCy bin plugin",
	.license = "LGPL3",
	.load = &load,
	.load_bytes = &load_bytes,
	.destroy = &destroy,
	.check_bytes = &check_bytes,
	.baddr = &baddr,
	.entries = entries,
	.sections = sections,
	.strings = &strings,
	.info = &info,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_clcy,
	.version = R2_VERSION
};
#endif
