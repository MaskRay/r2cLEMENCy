/* radare - LGPL - Copyright 2017 - pancake */

#include <r_userconf.h>
#include <r_io.h>
#include <r_lib.h>

typedef struct r_io_mmo_t {
	char * filename;
	int mode;
	int flags;
	int fd;
	int opened;
	bool nocache;
	ut8 modified;
	RBuffer *buf;
	RIO * io_backref;
	int rawio;
} RIOMMapFileObj;

static void r_io_def_mmap_free (RIOMMapFileObj *mmo) {
	free (mmo->filename);
	r_buf_free (mmo->buf);
	if (mmo->fd != -1) {
		close (mmo->fd);
	}
	free (mmo);
}

RIOMMapFileObj *r_io_def_mmap_create_new_file(RIO  *io, const char *filename, int mode, int flags) {
	if (!io) {
		return NULL;
	}
	RIOMMapFileObj *mmo = R_NEW0 (RIOMMapFileObj);
	if (!mmo) {
		return NULL;
	}
	filename += 7;
	mmo->filename = strdup (filename);
	mmo->mode = mode;
	mmo->flags = flags;
	mmo->io_backref = io;

	RBuffer *data = r_buf_new_slurp (filename);
	mmo->buf = r_buf_new_empty (data->length * 2);

	if (flags & R_IO_WRITE) {
		eprintf ("Write mode not supported\n");
	}

	if (!mmo->buf) {
		free (mmo->filename);
		free (mmo);
		return NULL;
	}
	ut8 *ptr = r_buf_get_at (data, 0, NULL);
	const ut64 totalBits = r_buf_size (data) * 9;
	ut64 at = 0;
	int i;
	for (i = 0; i < totalBits; i += 9) {
		r_mem_copybits_delta (mmo->buf->buf, at, ptr, i, 9);
		at += 2;
	} 
	r_buf_free (data);

	return mmo;
}

static int r_io_def_mmap_close(RIODesc *fd) {
	if (!fd || !fd->data) return -1;
	r_io_def_mmap_free ((RIOMMapFileObj *) fd->data);
	fd->data = NULL;
	return 0;
}

static bool r_io_def_mmap_check_default (const char *filename) {
	return !strncmp (filename, "9bit://", 7);
}

static int r_io_def_mmap_read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
	RIOMMapFileObj *mmo = fd->data;
	return r_buf_read_at (mmo->buf, io->off, buf, count);
}

static RIODesc *r_io_def_mmap_open(RIO *io, const char *file, int flags, int mode) {
	RIOMMapFileObj *mmo = r_io_def_mmap_create_new_file (io, file, mode, flags);
	return (mmo)
		? r_io_desc_new (&r_io_plugin_default, mmo->fd, mmo->filename, flags, mode, mmo)
		: NULL;
}

static bool check(RIO *io, const char *file, bool many) {
	return r_io_def_mmap_check_default (file);
}

// default open should permit opening 
static RIODesc *__open(RIO *io, const char *file, int flags, int mode) {
	if (r_io_def_mmap_check_default (file)) {
		return r_io_def_mmap_open (io, file, flags, mode);
	}
	return NULL;
}

static int __read(RIO *io, RIODesc *fd, ut8 *buf, int len) {
	return r_io_def_mmap_read (io, fd, buf, len);
}

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int len) {
	return -1;
}

static ut64 __lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	RIOMMapFileObj *mmo = fd->data;
	return r_buf_seek (mmo->buf, offset, whence);
}

static int __close(RIODesc *fd) {
	return r_io_def_mmap_close (fd);
}

RIOPlugin r_io_plugin_default = {
	.name = "9bit",
	.desc = "open files mapping 9bit on 16bit words",
	.license = "LGPL3",
	.open = __open,
	.close = __close,
	.read = __read,
	.check = check,
	.lseek = __lseek,
	.write = __write,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_default,
	.version = R2_VERSION
};
#endif
