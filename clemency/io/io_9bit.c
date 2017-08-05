/* radare - LGPL - Copyright 2017 - pancake */
#include <r_io.h>
#include <r_lib.h>

typedef struct r_io_mmo_t {
	char *filename;
	int flags;
	int mode;
	RBuffer *buf;
} RIOMMapFileObj;

extern RIOPlugin r_io_plugin_9bit;

static bool check_default(const char *filename) {
	return !strncmp (filename, "9bit://", 7);
}

static bool check(RIO *io, const char *filename, bool many) {
	return check_default (filename);
}

static int __close(RIODesc *fd) {
	if (!fd || !fd->data) return -1;
	RIOMMapFileObj *mmo = fd->data;
	r_buf_free (mmo->buf);
	free (mmo->filename);
	free (mmo);
	fd->data = NULL;
	return 0;
}

static ut64 __lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	RIOMMapFileObj *mmo = fd->data;
	ut64 seek_val;
	switch (whence) {
	case SEEK_SET: seek_val = R_MIN (mmo->buf->length / 2, offset); break;
	case SEEK_CUR: seek_val = R_MIN (mmo->buf->length / 2, io->off + offset); break;
	case SEEK_END: seek_val = mmo->buf->length / 2; break;
	}
	return mmo->buf->cur = io->off = seek_val;
}

static RIODesc *__open(RIO *io, const char *filename, int flags, int mode) {
	if (!check_default (filename)) return NULL;
	RBuffer *b = r_buf_new_slurp (filename + 7);
	if (!b) {
		eprintf ("Can't open %s\n", filename + 7);
		return NULL;
	}

	RIOMMapFileObj *mmo = R_NEW (RIOMMapFileObj);
	mmo->filename = strdup (filename);
	mmo->flags = flags;
	mmo->mode = mode;
	mmo->buf = r_buf_new_empty (b->length * 8 / 9 * 2);

	if (flags & R_IO_WRITE) {
		eprintf ("Write mode not supported\n");
	}
	if (!mmo->buf) {
		free (mmo->filename);
		free (mmo->buf);
		free (mmo);
		return NULL;
	}
	ut64 size = r_buf_size (b), x = 0, l = 0, n_buf = 0, i;
	for (i = 0; i < size; i++) {
		x = x << 8 | b->buf[i];
		l += 8;
		if (l >= 9) {
			l -= 9;
			mmo->buf->buf[n_buf++] = x >> l & 255;
			mmo->buf->buf[n_buf++] = x >> l >> 8;
			x &= (1L << l) - 1;
		}
	}
	r_buf_free (b);
	return r_io_desc_new (&r_io_plugin_9bit, -1, mmo->filename, flags, mode, mmo);
}

static int __read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
	RIOMMapFileObj *mmo = fd->data;
	return r_buf_read_at (mmo->buf, io->off * 2, buf, count);
}

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int len) {
	return -1;
}

RIOPlugin r_io_plugin_9bit = {
	.name = "9bit",
	.desc = "open files mapping 9bit on 16bit words",
	.license = "LGPL3",
	.check = check,
	.close = __close,
	.lseek = __lseek,
	.open = __open,
	.read = __read,
	.write = __write,
};

RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_9bit,
	.version = R2_VERSION,
};
