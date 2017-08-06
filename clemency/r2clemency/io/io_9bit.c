/* radare - LGPL - Copyright 2017 - pancake */
#include <errno.h>
#include <sys/mman.h>
#include <r_io.h>
#include <r_lib.h>

typedef struct r_io_mmo_t {
	char *filename;
	int flags;
	int mode;
	RBuffer *buf;
	bool dirty;
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
	if (mmo->dirty) {
		RBuffer *b = mmo->buf;
		ut64 size = r_buf_size (b), x = 0, l = 0, n_buf = 0, i;
		bool ok = true;
		for (i = 0; i < size; i += 2) {
			if (b->buf[i + 1] > 1) {
				ok = false;
				eprintf ("io_9bit: 16-bit at offset %"PFMT64x" exceeds 512", i / 2);
				break;
			}
			x = x << 9 | b->buf[i + 1] << 8 | b->buf[i];
			l += 9;
			while (l >= 8) {
				l -= 8;
				b->buf[n_buf++] = x >> l;
				x &= (1LL << l) - 1;
			}
		}
		if (ok) {
			ssize_t t;
			if (l) {
				b->buf[n_buf++] = x << 8-l;
			}
			if (lseek (fd->fd, 0, SEEK_SET) == -1) {
				eprintf ("io_9bit lseek: %s\n", strerror (errno));
			} else if ((t = write (fd->fd, b->buf, n_buf)) != n_buf) {
				eprintf ("io_9bit: written %zd bytes, %s\n", t, strerror (errno));
			} else if (ftruncate (fd->fd, n_buf) == -1) {
				eprintf ("io_9bit ftruncate: %s\n", strerror (errno));
			}
		}
	}
	close (fd->fd);
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
	filename += 7;
	int fd = r_sandbox_open (filename, flags & R_IO_WRITE ? O_CREAT | O_RDWR : O_RDONLY, mode);
	if (fd == -1) return NULL;
	off_t len = lseek (fd, 0, SEEK_END);
	if (len < 0) goto err_lseek;
	ut8 *buf = mmap (NULL, len, PROT_READ, MAP_SHARED, fd, 0);
	if (buf == (ut8 *)-1) goto err_lseek;

	RIOMMapFileObj *mmo = R_NEW (RIOMMapFileObj);
	if (!mmo) goto err_mmo;
	mmo->filename = strdup (filename);
	if (!mmo->filename) goto err_strdup;
	mmo->flags = flags;
	mmo->mode = mode;
	if (len >= 2) {
		mmo->buf = r_buf_new_empty (len * 8 / 9 * 2);
		if (!mmo->buf) goto err_mmo_buf;
	} else
		mmo->buf = NULL;
	mmo->dirty = false;

	ut64 x = 0, l = 0, n_buf = 0, i;
	for (i = 0; i < len; i++) {
		x = x << 8 | buf[i];
		l += 8;
		if (l >= 9) {
			l -= 9;
			mmo->buf->buf[n_buf++] = x >> l & 255;
			mmo->buf->buf[n_buf++] = x >> l >> 8;
			x &= (1L << l) - 1;
		}
	}
	return r_io_desc_new (&r_io_plugin_9bit, fd, mmo->filename, flags, mode, mmo);

 err_mmo_buf:
	free (mmo->filename);
 err_strdup:
	free (mmo);
 err_mmo:
	munmap (buf, len);
 err_lseek:
	r_sandbox_close (fd);
}

static int __read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
	RIOMMapFileObj *mmo = fd->data;
	return r_buf_read_at (mmo->buf, io->off * 2, buf, count);
}

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int len) {
	RIOMMapFileObj *mmo = fd->data;
	if (io->off * 2 + len > r_buf_size (mmo->buf)) return -1;
	mmo->dirty = true;
	return r_buf_write_at (mmo->buf, io->off * 2, buf, len);
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
