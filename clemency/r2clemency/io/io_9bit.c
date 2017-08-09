/* radare - LGPL - Copyright 2017 - pancake */
#include <errno.h>
#include <sys/mman.h>
#include <r_core.h>
#include <r_io.h>
#include <r_lib.h>

typedef struct r_io_mmo_t {
	char *filename;
	ut16 *buf;
	ut64 size;
	int flags;
	int mode;
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
		ut64 x = 0, l = 0, n_buf = 0, i;
		bool ok = true;
		for (i = 0; i < mmo->size; i++) {
			if (mmo->buf[i] >= 512) {
				ok = false;
				eprintf ("io_9bit: 16-bit at offset %"PFMT64x" >= 512", i);
				break;
			}
			x = x << 9 | mmo->buf[i];
			l += 9;
			while (l >= 8) {
				l -= 8;
				mmo->buf[n_buf++] = x >> l;
				x &= (1LL << l) - 1;
			}
		}
		if (ok) {
			ssize_t t;
			if (l)
				mmo->buf[n_buf++] = x << 8-l;
			if (lseek (fd->fd, 0, SEEK_SET) == -1) {
				eprintf ("io_9bit lseek: %s\n", strerror (errno));
			} else if ((t = write (fd->fd, mmo->buf, n_buf)) != n_buf) {
				eprintf ("io_9bit: written %zd bytes, %s\n", t, strerror (errno));
			} else if (ftruncate (fd->fd, n_buf) == -1) {
				eprintf ("io_9bit ftruncate: %s\n", strerror (errno));
			}
		}
	}
	close (fd->fd);
	free (mmo->buf);
	free (mmo->filename);
	free (mmo);
	fd->data = NULL;
	return 0;
}

static int extend(RIO *io, RIODesc *fd, ut64 extend) {
	RIOMMapFileObj *mmo = fd->data;
	ut64 addr = io->off, size = mmo->size;
	mmo->buf = realloc (mmo->buf, (size + extend) * 2);
	if (!mmo->buf) return -1;
	memmove (&mmo->buf[addr + extend], &mmo->buf[addr], (size - addr) * 2);
	memset (&mmo->buf[addr], 0, extend * 2);
	return extend;
}

static ut64 __lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	RIOMMapFileObj *mmo = fd->data;
	ut64 seek_val;
	switch (whence) {
	case SEEK_SET: seek_val = R_MIN (mmo->size, offset); break;
	case SEEK_CUR: seek_val = R_MIN (mmo->size, io->off + offset); break;
	case SEEK_END: seek_val = mmo->size; break;
	}
	return io->off = seek_val;
}

static RIODesc *__open(RIO *io, const char *filename, int flags, int mode) {
	if (!check_default (filename)) return NULL;
	filename += 7;
	int fd = r_sandbox_open (filename, flags & R_IO_WRITE ? O_CREAT | O_RDWR : O_RDONLY, mode);
	if (fd == -1) return NULL;
	off_t len = lseek (fd, 0, SEEK_END);
	if (len < 0) goto err_lseek;
	ut8 *buf = len > 0 ? mmap (NULL, len, PROT_READ, MAP_SHARED, fd, 0) : NULL;
	if (buf == (ut8 *)-1) goto err_lseek;

	RIOMMapFileObj *mmo = R_NEW (RIOMMapFileObj);
	if (!mmo) goto err_mmo;
	mmo->filename = strdup (filename);
	if (!mmo->filename) goto err_strdup;
	mmo->flags = flags;
	mmo->mode = mode;
	if (len >= 2) {
		mmo->size = len * 8 / 9;
		mmo->buf = malloc (mmo->size * 2);
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
			mmo->buf[n_buf++] = x >> l;
			x &= (1L << l) - 1;
		}
	}
	r_config_set_i (((RCore *)io->user)->config, "asm.addrbytes", 2);
	return r_io_desc_new (&r_io_plugin_9bit, fd, mmo->filename, flags, mode, mmo);

 err_mmo_buf:
	free (mmo->filename);
 err_strdup:
	free (mmo);
 err_mmo:
	if (buf)
		munmap (buf, len);
 err_lseek:
	r_sandbox_close (fd);
	return NULL;
}

static int __read(RIO *io, RIODesc *fd, ut8 *buf, int len) {
	RIOMMapFileObj *mmo = fd->data;
	if (len <= (mmo->size - io->off) * 2)
		memcpy (buf, &mmo->buf[io->off], len);
	else {
		memcpy (buf, &mmo->buf[io->off], (mmo->size - io->off) * 2);
		memset (&buf[(mmo->size - io->off) * 2], 0xff, io->off * 2 + len - mmo->size * 2);
	}
	return len;
}

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int len) {
	RIOMMapFileObj *mmo = fd->data;
	if (io->off * 2 + len > mmo->size * 2) return -1;
	mmo->dirty = true;
	memcpy (mmo->buf + io->off * 2, buf, len);
	return len;
}

RIOPlugin r_io_plugin_9bit = {
	.name = "9bit",
	.desc = "open files mapping 9bit on 16bit words",
	.license = "LGPL3",
	.check = check,
	.close = __close,
	.extend = extend,
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
