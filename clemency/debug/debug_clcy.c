/* radare - LGPL - Copyright 2017 - pancake */

#include <r_asm.h>
#include <r_debug.h>

#include "../io/clcy.c"

#define UNKNOWN -1
#define UNSUPPORTED 0
#define SUPPORTED 1

// static libgdbr_t *desc = NULL;
static void *desc = NULL;
static ut8* reg_buf = NULL;
static int buf_size = 0;
static int support_sw_bp = UNKNOWN;
static int support_hw_bp = UNKNOWN;

static int r_debug_clcy_attach(RDebug *dbg, int pid);
static void check_connection (RDebug *dbg) {
	if (!desc) {
		r_debug_clcy_attach (dbg, -1);
	}
}

static int r_debug_clcy_step(RDebug *dbg) {
	RIODesc *d = dbg->iob.io->desc;
	RIOClcy *riom = d->data;
eprintf ("LETs go step\n");
	char * res = runcmd (riom->rs, "t");
eprintf ("STEP %s\n", res);
	free (res);
	// gdbr_step (desc, -1); // TODO handle thread specific step?
	return true;
}

static RList* r_debug_clcy_threads(RDebug *dbg, int pid) {
/*
	RList *list;
	if ((list = gdbr_threads_list (desc, pid))) {
		list->free = (RListFree) &r_debug_pid_free;
	}
	return list;
*/
	return NULL;
}

static int r_debug_clcy_reg_read(RDebug *dbg, int type, ut8 *buf, int size) {
	memset (buf, 0, size);
	return size;
/*
	int copy_size;
	int buflen = 0;
	check_connection (dbg);
	gdbr_read_registers (desc);
	if (!desc) {
		return -1;
	}
	// read the len of the current area
	free (r_reg_get_bytes (dbg->reg, type, &buflen));
	if (size < desc->data_len) {
		eprintf ("r_debug_clcy_reg_read: small buffer %d vs %d\n",
			(int)size, (int)desc->data_len);
		//	return -1;
	}
	copy_size = R_MIN (desc->data_len, size);
	buflen = R_MAX (desc->data_len, buflen);
	if (reg_buf) {
		// if (buf_size < copy_size) { //desc->data_len) {
		if (buflen > buf_size) { //copy_size) {
			ut8* new_buf = realloc (reg_buf, buflen);
			if (!new_buf) {
				return -1;
			}
			reg_buf = new_buf;
			buf_size = buflen;
		}
	} else {
		reg_buf = calloc (buflen, 1);
		if (!reg_buf) {
			return -1;
		}
		buf_size = buflen;
	}
	memset ((void*)(volatile void*)buf, 0, size);
	memcpy ((void*)(volatile void*)buf, desc->data, R_MIN (copy_size, size));
	memset ((void*)(volatile void*)reg_buf, 0, buflen);
	memcpy ((void*)(volatile void*)reg_buf, desc->data, copy_size);
#if 0
	int i;
	//for(i=0;i<168;i++) {
	for(i=0;i<copy_size;i++) {
		if (!(i%16)) printf ("\n0x%08x  ", i);
		printf ("%02x ", buf[i]); //(ut8)desc->data[i]);
	}
	printf("\n");
#endif
*/
}

static RList *r_debug_clcy_map_get(RDebug* dbg) { //TODO
	return 0;
#if 0
	check_connection (dbg);
	if (desc->pid <= 0) {
		return NULL;
	}
	RList *retlist = NULL;

	// Get file from GDB
	char path[128];
	ut8 *buf;
	int ret;
	// TODO don't hardcode buffer size, get from remote target
	// (I think gdb doesn't do that, it just keeps reading till EOF)
	// fstat info can get file size, but it doesn't work for /proc/pid/maps
	ut64 buflen = 16384;
	// If /proc/%d/maps is not valid for gdbserver, we return NULL, as of now
	snprintf (path, sizeof (path) - 1, "/proc/%d/maps", desc->pid);
	if (gdbr_open_file (desc, path, O_RDONLY, S_IRUSR | S_IWUSR | S_IXUSR) < 0) {
		return NULL;
	}
	if (!(buf = malloc (buflen))) {
		gdbr_close_file (desc);
		return NULL;
	}
	if ((ret = gdbr_read_file (desc, buf, buflen - 1)) <= 0) {
		gdbr_close_file (desc);
		free (buf);
		return NULL;
	}
	buf[ret] = '\0';

	// Get map list
	int unk = 0, perm, i;
	char *ptr, *pos_1;
	size_t line_len;
	char name[1024], region1[100], region2[100], perms[5];
	RDebugMap *map = NULL;
	region1[0] = region2[0] = '0';
	region1[1] = region2[1] = 'x';
	if (!(ptr = strtok ((char*) buf, "\n"))) {
		gdbr_close_file (desc);
		free (buf);
		return NULL;
	}
	if (!(retlist = r_list_new ())) {
		gdbr_close_file (desc);
		free (buf);
		return NULL;
	}
	while (ptr) {
		ut64 map_start, map_end, offset;
		bool map_is_shared = false;
		line_len = strlen (ptr);
		// maps files should not have empty lines
		if (line_len == 0) {
			break;
		}
		// We assume Linux target, for now, so -
		// 7ffff7dda000-7ffff7dfd000 r-xp 00000000 08:05 265428 /usr/lib/ld-2.25.so
		ret = sscanf (ptr, "%s %s %"PFMT64x" %*s %*s %[^\n]", &region1[2],
			      perms, &offset, name);
		if (ret == 3) {
			name[0] = '\0';
		} else if (ret != 4) {
			eprintf ("%s: Unable to parse \"%s\"\nContent:\n%s\n", __func__, path, buf);
			gdbr_close_file (desc);
			free (buf);
			r_list_free (retlist);
			return NULL;
		}
		if (!(pos_1 = strchr (&region1[2], '-'))) {
			ptr = strtok (NULL, "\n");
			continue;
		}
		strncpy (&region2[2], pos_1 + 1, sizeof (region2) - 2 - 1);
		if (!*name) {
			snprintf (name, sizeof (name), "unk%d", unk++);
		}
		perm = 0;
		for (i = 0; perms[i] && i < 5; i++) {
			switch (perms[i]) {
			case 'r': perm |= R_IO_READ; break;
			case 'w': perm |= R_IO_WRITE; break;
			case 'x': perm |= R_IO_EXEC; break;
			case 'p': map_is_shared = false; break;
			case 's': map_is_shared = true; break;
			}
		}
		map_start = r_num_get (NULL, region1);
		map_end = r_num_get (NULL, region2);
		if (map_start == map_end || map_end == 0) {
			eprintf ("%s: ignoring invalid map size: %s - %s\n",
				 __func__, region1, region2);
			ptr = strtok (NULL, "\n");
			continue;
		}
		if (!(map = r_debug_map_new (name, map_start, map_end, perm, 0))) {
			break;
		}
		map->offset = offset;
		map->shared = map_is_shared;
		map->file = strdup (name);
		r_list_append (retlist, map);
		ptr = strtok (NULL, "\n");
	}
	gdbr_close_file (desc);
	free (buf);
	return retlist;
#endif
}

static int r_debug_clcy_reg_write(RDebug *dbg, int type, const ut8 *buf, int size) {
eprintf ("write\n");
	return -1;
#if 0
	check_connection (dbg);
	if (!reg_buf) {
		// we cannot write registers before we once read them
		return -1;
	}
	int buflen = 0;
	int bits = dbg->anal->bits;
	const char *pcname = r_reg_get_name (dbg->anal->reg, R_REG_NAME_PC);
	RRegItem *reg = r_reg_get (dbg->anal->reg, pcname, 0);
	if (reg) {
		if (dbg->anal->bits != reg->size)
			bits = reg->size;
	}
	free (r_reg_get_bytes (dbg->reg, type, &buflen));
	// some implementations of the gdb protocol are acting weird.
	// so winedbg is not able to write registers through the <G> packet
	// and also it does not return the whole gdb register profile after
	// calling <g>
	// so this workaround resizes the small register profile buffer
	// to the whole set and fills the rest with 0
	if (buf_size < buflen) {
		ut8* new_buf = realloc (reg_buf, buflen * sizeof (ut8));
		if (!new_buf) {
			return -1;
		}
		reg_buf = new_buf;
		memset (new_buf + buf_size, 0, buflen - buf_size);
	}

	RRegItem* current = NULL;
	for (;;) {
		current = r_reg_next_diff (dbg->reg, type, reg_buf, buflen, current, bits);
		if (!current) break;
		ut64 val = r_reg_get_value (dbg->reg, current);
		int bytes = bits / 8;
		gdbr_write_reg (desc, current->name, (char*)&val, bytes);
	}
	return true;
#endif
}

static int r_debug_clcy_continue(RDebug *dbg, int pid, int tid, int sig) {
	// check_connection (dbg);
	//gdbr_continue (desc, pid, tid, sig);
	return true;
}

static RDebugReasonType r_debug_clcy_wait(RDebug *dbg, int pid) {
eprintf ("wait\n");
#if 0
	check_connection (dbg);
	if (!desc->stop_reason.is_valid) {
		if (gdbr_stop_reason (desc) < 0) {
			dbg->reason.type = R_DEBUG_REASON_UNKNOWN;
			return R_DEBUG_REASON_UNKNOWN;
		}
	}
	desc->stop_reason.is_valid = false;
	if (desc->stop_reason.thread.present) {
		dbg->reason.tid = desc->stop_reason.thread.tid;
	}
	dbg->reason.signum = desc->stop_reason.signum;
	dbg->reason.type = desc->stop_reason.reason;
#endif
	return 0; //desc->stop_reason.reason;
}

static int r_debug_clcy_attach(RDebug *dbg, int pid) {
	RIODesc *d = dbg->iob.io->desc;
	RIOClcy *riom = d->data;
	char * res = runcmd (riom->rs, "t");
eprintf ("attach %s\n", res);
	free (res);
	return true;
}

static int r_debug_clcy_detach(RDebug *dbg, int pid) {
//	return gdbr_detach_pid (desc, pid);
	return true;
}

static const char *r_debug_clcy_reg_profile(RDebug *dbg) {
	int arch = r_sys_arch_id (dbg->arch);
	int bits = dbg->anal->bits;
	return strdup (
		"=PC    pc\n"
		"=SP    st\n"
		"=BP    st\n"
		"=A0    r0\n"
		"=A1    r1\n"
		"=A2    r2\n"
		"=A3    r3\n"
		"gpr	r0	.27	0	0\n"
		"gpr	r1	.27	4	0\n"
		"gpr	r2	.27	8	0\n"
		"gpr	r3	.27	12	0\n"
		"gpr	r4	.27	16	0\n"
		"gpr	r5	.27	20	0\n"
		"gpr	r6	.27	24	0\n"
		"gpr	r7	.27	28	0\n"
		"gpr	r8	.27	32	0\n"
		"gpr	r9	.27	36	0\n"
		"gpr	r10	.27	40	0\n"
		"gpr	r11	.27	44	0\n"
		"gpr	r12	.27	48	0\n"
		"gpr	r13	.27	52	0\n"
		"gpr	r14	.27	56	0\n"
		"gpr	r15	.27	60	0\n"
		"gpr	r16	.27	64	0\n"
		"gpr	r17	.27	68	0\n"
		"gpr	r18	.27	72	0\n"
		"gpr	r19	.27	76	0\n"
		"gpr	r20	.27	80	0\n"
		"gpr	r21	.27	84	0\n"
		"gpr	r22	.27	88	0\n"
		"gpr	r23	.27	92	0\n"
		"gpr	r24	.27	96	0\n"
		"gpr	r25	.27	100	0\n"
		"gpr	r26	.27	104	0\n"
		"gpr	r27	.27	108	0\n"
		"gpr	r28	.27	112	0\n"
		"gpr	st	.27	116	0\n"
		"gpr	ra	.27	120	0\n"
		"gpr	pc	.27	124	0\n"
		"gpr	fl	.27	128	0\n"
	);
}

static int r_debug_clcy_breakpoint (RBreakpointItem *bp, int set, void *user) {
#if 0
	int ret;
	if (!bp) {
		return false;
	}
	// TODO handle rwx and conditions
	if (set)
		ret = bp->hw?
			gdbr_set_hwbp (desc, bp->addr, ""):
			gdbr_set_bp (desc, bp->addr, "");
	else
		ret = bp->hw?
			gdbr_remove_hwbp (desc, bp->addr):
			gdbr_remove_bp (desc, bp->addr);
	return !ret;
#endif
	// runcmd ("b");
	return false;
}

static bool r_debug_clcy_kill(RDebug *dbg, int pid, int tid, int sig) {
dbg->reason.type = 0;
	return true;
}

static RDebugInfo* r_debug_clcy_info(RDebug *dbg, const char *arg) {
	RDebugInfo *rdi;
	if (!(rdi = R_NEW0 (RDebugInfo))) {
		return NULL;
	}
	RList *th_list;
	bool list_alloc = false;
	if (dbg->threads) {
		th_list = dbg->threads;
	} else {
		th_list = r_debug_clcy_threads (dbg, dbg->pid);
		list_alloc = true;
	}
	RDebugPid *th;
	RListIter *it;
	bool found = false;
	r_list_foreach (th_list, it, th) {
		if (th->pid == dbg->pid) {
			found = true;
			break;
		}
	}
	rdi->pid = dbg->pid;
	rdi->tid = dbg->tid;
	// rdi->exe = gdbr_exec_file_read (desc, dbg->pid);
	rdi->status = found ? th->status : R_DBG_PROC_STOP;
	rdi->uid = found ? th->uid : -1;
	rdi->gid = found ? th->gid : -1;
#if 0
	if (gdbr_stop_reason (desc) >= 0) {
		eprintf ("signal: %d\n", desc->stop_reason.signum);
		rdi->signum = desc->stop_reason.signum;
	}
#endif
	if (list_alloc) {
		r_list_free (th_list);
	}
	return rdi;
}

RDebugPlugin r_debug_plugin_clcy = {
	.name = "clcy",
	/* TODO: Add support for more architectures here */
	.license = "LGPL3",
	.arch = "clcy",
	.bits = 27,
	.step = r_debug_clcy_step,
	.cont = r_debug_clcy_continue,

	.attach = &r_debug_clcy_attach,
	.detach = &r_debug_clcy_detach,
	.threads = &r_debug_clcy_threads,
	.canstep = 1,
	.wait = &r_debug_clcy_wait,
	.map_get = r_debug_clcy_map_get,
	.breakpoint = &r_debug_clcy_breakpoint,

	.reg_read = &r_debug_clcy_reg_read,
	.reg_write = &r_debug_clcy_reg_write,
	.reg_profile = (void *)r_debug_clcy_reg_profile,

	.kill = &r_debug_clcy_kill,
	.info = &r_debug_clcy_info,
	//.bp_write = &r_debug_clcy_bp_write,
	//.bp_read = &r_debug_clcy_bp_read,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_DBG,
	.data = &r_debug_plugin_clcy,
	.version = R2_VERSION
};
#endif
