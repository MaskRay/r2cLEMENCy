/* radare - LGPL - Copyright 2017 - pancake, MaskRay */
#include <errno.h>
#include <sys/mman.h>

#include <r_core.h>
#include <r_io.h>
#include <r_lib.h>

typedef struct r_io_mmo_t {
	char *filename;
	ut16 *buf;
	ut64 size;
	int fd;
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

static int _close(RIODesc *fd) {
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
				((ut8 *)mmo->buf)[n_buf++] = x >> l;
				x &= (1LL << l) - 1;
			}
		}
		if (ok) {
			ssize_t t;
			if (l)
				mmo->buf[n_buf++] = x << 8-l;
			if (lseek (mmo->fd, 0, SEEK_SET) == -1) {
				eprintf ("io_9bit lseek: %s\n", strerror (errno));
			} else if ((t = write (mmo->fd, mmo->buf, n_buf)) != n_buf) {
				eprintf ("io_9bit: written %zd bytes, %s\n", t, strerror (errno));
			} else if (ftruncate (mmo->fd, n_buf) == -1) {
				eprintf ("io_9bit ftruncate: %s\n", strerror (errno));
			}
		}
	}
	close (mmo->fd);
	free (mmo->buf);
	free (mmo->filename);
	free (mmo);
	fd->data = NULL;
	return 0;
}

static int _extend(RIO *io, RIODesc *fd, ut64 extend) {
	RIOMMapFileObj *mmo = fd->data;
	ut64 addr = io->off, size = mmo->size;
	mmo->buf = realloc (mmo->buf, (size + extend) * 2);
	if (!mmo->buf) return -1;
	memmove (&mmo->buf[addr + extend], &mmo->buf[addr], (size - addr) * 2);
	memset (&mmo->buf[addr], 0, extend * 2);
	return extend;
}

static ut64 _lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	RIOMMapFileObj *mmo = fd->data;
	ut64 seek_val;
	switch (whence) {
	case SEEK_SET: seek_val = R_MIN (mmo->size, offset); break;
	case SEEK_CUR: seek_val = R_MIN (mmo->size, io->off + offset); break;
	case SEEK_END:
		if ((st64)offset <= 0) {
			seek_val = mmo->size + offset;
		}
		break;
	}
	return io->off = seek_val;
}

static RIODesc *_open(RIO *io, const char *filename, int flags, int mode) {
	if (!check_default (filename)) return NULL;
	filename += 7;
	RIOMMapFileObj *mmo;
	ut8 *buf;
	off_t len;
	int fd;

	if ((fd = r_sandbox_open (filename, flags & R_IO_WRITE ? O_CREAT | O_RDWR : O_RDONLY, mode)) < 0) {
		return NULL;
	}
	if ((len = lseek (fd, 0, SEEK_END)) < 0) {
		goto out_sandbox;
	}
	buf = len > 0 ? mmap (NULL, len, PROT_READ, MAP_SHARED, fd, 0) : NULL;
	if (buf == (ut8 *)-1) {
		goto out_sandbox;
	}

	if (!(mmo = R_NEW (RIOMMapFileObj))) {
		goto out_mmo;
	}
	if (!(mmo->filename = strdup (filename))) {
		goto out_mmo;
	}
	mmo->fd = fd;
	mmo->flags = flags;
	mmo->mode = mode;
	if (len >= 2) {
		mmo->size = len * 8 / 9;
		if (!(mmo->buf = malloc (mmo->size * 2))) {
			goto out_mmo;
		}
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
	return r_io_desc_new (io, &r_io_plugin_9bit, mmo->filename, flags, mode, mmo);

 out_mmo:
	if (mmo) {
		free (mmo->filename);
		free (mmo);
	}
	if (buf)
		munmap (buf, len);
 out_sandbox:
	r_sandbox_close (fd);
	return NULL;
}

static int _read(RIO *io, RIODesc *fd, ut8 *buf, int len) {
	RIOMMapFileObj *mmo = fd->data;
	if (len <= (mmo->size - io->off) * 2)
		memcpy (buf, &mmo->buf[io->off], len);
	else {
		memcpy (buf, &mmo->buf[io->off], (mmo->size - io->off) * 2);
		memset (&buf[(mmo->size - io->off) * 2], 0xff, io->off * 2 + len - mmo->size * 2);
	}
	return len;
}

static int _write(RIO *io, RIODesc *fd, const ut8 *buf, int len) {
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
	.close = _close,
	.extend = _extend,
	.lseek = _lseek,
	.open = _open,
	.read = _read,
	.write = _write,
};

RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_9bit,
	.version = R2_VERSION,
};
