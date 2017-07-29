typedef struct {
	int fd;
	ut8 *buf;
	ut32 size;
	RSocket *rs;
} RIOClcy;
RIOPlugin r_io_plugin_clcy;

#define RIOTCP_FD(x) (((RIOClcy*)x->data)->fd)
#define RIOTCP_SZ(x) (((RIOClcy*)x->data)->size)
#define RIOTCP_BUF(x) (((RIOClcy*)x->data)->buf)

static char *runcmd(RSocket *fd, const char *cmd) {
	int buf_sz = 40960;
	char *buf = malloc (buf_sz);
	int i = 0;
	if (cmd) {
		r_socket_write (fd, (void*)cmd, strlen (cmd));
		r_socket_write (fd, "\n", 1);
	}
	const char *prompt = "\n> ";
	int prompt_idx = 0;
	do {
		int ret = r_socket_read (fd, (ut8*)buf + i, 1);
		if (ret != 1) {
			eprintf ("Read error %d\n", ret);
			break;
		}
		if (buf[i] == prompt[prompt_idx]) {
			prompt_idx ++;
		} else {
			prompt_idx = 0;
			if (buf[i] == prompt[prompt_idx]) {
				prompt_idx ++;
			}
		}
		i++;
		if (prompt_idx == strlen (prompt)) {
			break;
		}
	} while (i < buf_sz);
	if (i > 2) {
		buf[i - 2] = 0;
	} else {
		buf[i] = 0;
	}
	return buf;
}

