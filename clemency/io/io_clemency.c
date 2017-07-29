/* radare - LGPL - Copyright 2017 - pancake */

#include "r_io.h"
#include "r_lib.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include "../io/clcy.c"

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int count) {
	if (!fd || !fd->data) {
		return -1;
	}
	RIOClcy *riom = fd->data;
	int i;
	int blocks = count / 18;
	if (blocks == 0) {
		blocks++;
	}
	char cmd[128];
	for (i = 0; i < blocks; i++) {
		ut64 off = io->off * 8 / 9;
		ut32 val = buf[i]; // XXX
		snprintf (cmd, sizeof (cmd) - 1, "wb %"PFMT64x" %x", off, val);
		eprintf ("%s\n", cmd);
		free (runcmd (riom->rs, cmd));
	}
	return count;
}

static int read9bytedump (char *res, ut8 *buf, int bufsz) {
	int col = 0;
	int mode = 0;
	int bi = 0;
	bool data = false;
	char word[16] = {0};
	int i = 0;
	int wi = 0;
	int bits = 0;

	for (i = 0; res[i]; i++) {
		if ((bits / 8) >= bufsz) {
			break;
		}
		col++;
		switch (res[i]) {
		case ' ':
			if (data && wi > 0 && wi < 5) {
				int n = 0;
				sscanf (word, "%x", &n);
// only works in little endian
				r_mem_copybits_delta (buf, bits, (ut8*)&n, 0, 9);
				bits += 9;
//				buf[bi++] = n;
				if (bi == bufsz) {
					return bufsz;
				}
			}
			wi = 0;
			word[wi] = 0;
			break;
		case '-':
			res[i] = ' ';
			break;
		case ':':
			data = true;
			break;
		case '\r':
		case '\n':
			col = 0;
			data = false;
			break;
		default:
			if (wi > 14) {
				wi = -1;
			}
			word[wi++] = res[i];
			word[wi] = 0;
			break;
		}
	}
	return bi;
}

static int __read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
	unsigned int sz;
	if (!fd || !fd->data) {
		return -1;
	}
	RIOClcy *riom = fd->data;
	if (count > 256) {
		count = 256;
		eprintf ("Wrap from %d to 128\n", count);
	}
	int mbs = 18; // 18 9bit bytes are 16 9bit bytes
	int blocks = count / mbs;
	int last = count % mbs;
	int i;
	int maxbits = count * 8;
	int bits = 0;
	if (last) {
		eprintf ("Unaligned 9bit-byte read for %d\n", last);
	}
	for (i = 0; i < blocks ; i++) {
		char cmd[128];
		// XXX should be aligned to mbs to read proper 9bit bytes
		ut64 off = io->off * 8 / 9;
		int offi = off + (i * mbs);
		snprintf (cmd, sizeof (cmd) - 1, "db %"PFMT64x" %x", off, count);
		char *res = runcmd (riom->rs, cmd);
		// eprintf ("RES (%s))\n", res);
		if ((bits + mbs) >= maxbits) {
			break;
		}
		read9bytedump (res, buf + (i * mbs), count);
		bits += (9 * count);
		free (res);
	}
	// TODO : use last here
/*
	sz = RIOTCP_SZ (fd);
	if (io->off >= sz) {
		return -1;
	}
	if (io->off + count >= sz) {
		count = sz - io->off;
	}
	memcpy (buf, RIOTCP_BUF (fd) + io->off, count);
*/
	return count;
}

static int __close(RIODesc *fd) {
	if (!fd || !fd->data) {
		return -1;
	}
	RIOClcy *riom = fd->data;
	r_socket_close (riom->rs);
	r_socket_free (riom->rs);
	free (riom->buf);
	riom->buf = NULL;
	free (fd->data);
	fd->data = NULL;
	fd->state = R_IO_DESC_TYPE_CLOSED;
	return 0;
}

static ut64 __lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	switch (whence) {
	case SEEK_SET: return offset;
	case SEEK_CUR: return io->off + offset;
	case SEEK_END: return UT64_MAX;
	}
	return offset;
}

static bool __plugin_open(RIO *io, const char *pathname, bool many) {
	return (!strncmp (pathname, "clcy://", 7));
}

static inline int getmalfd (RIOClcy *mal) {
	return (UT32_MAX >> 1) & (int)(size_t)mal->buf;
}

static RSocket *tcpme (const char *pathname, int *code, int *len) {
	pathname += strlen ("clcy://");
	*code = 404;
#if __UNIX__
	signal (SIGINT, 0);
#endif
	/* connect and slurp the end point */
	char *host = strdup (pathname);
	if (!host) {
		return NULL;
	}
	char *port = strchr (host, ':');
	if (port) {
		*port++ = 0;
		RSocket *s = r_socket_new (false);
		if (r_socket_connect (s, host, port, R_SOCKET_PROTO_TCP, 0)) {
			eprintf ("Connected!\n");
			/* read until prompt */
			free (runcmd (s, NULL));
			free (host);
			return s;
		}
		r_socket_free (s);
	} else {
		eprintf ("Missing port.\n");
	}
	free (host);
	return NULL;
}

static RIODesc *__open(RIO *io, const char *pathname, int rw, int mode) {
	int rlen, code;
	if (__plugin_open (io, pathname, 0)) {
		RSocket *rs = tcpme (pathname, &code, &rlen);
		if (rs) {
			RIOClcy *mal = R_NEW0 (RIOClcy);
			if (!mal) {
				r_socket_close (rs);
				return NULL;
			}
			mal->rs = rs;
			mal->size = rlen;
			mal->buf = malloc (mal->size + 1);
			if (!mal->buf) {
				free (mal);
				r_socket_close (rs);
				return NULL;
			}
			mal->fd = getmalfd (mal);
			// memcpy (mal->buf, out, mal->size);
			// free (out);
			rw = 7;
			return r_io_desc_new (&r_io_plugin_clcy,
				mal->fd, pathname, rw, mode, mal);
		}
	}
	return NULL;
}

static int __system(RIO *io, RIODesc *fd, const char *cmd) {
	RIOClcy *riom = fd->data;
	if (!strncmp (cmd, "pid", 3)) {
		int pid = fd->fd;
		if (!cmd[3]) {
			io->cb_printf ("%d\n", pid);
		}
		return pid;
	}
	char *res = runcmd (riom->rs, cmd);
	eprintf ("RES = %s\n", res);
	free (res);
	return 0;
}

RIOPlugin r_io_plugin_clcy = {
	.name = "clcy",
        .desc = "Clemency debugger shell IO plugin",
	.license = "MIT",
        .open = __open,
        .close = __close,
	.read = __read,
        .check = __plugin_open,
	.lseek = __lseek,
	.write = __write,
	.system = __system,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_clcy,
	.version = R2_VERSION
};
#endif
