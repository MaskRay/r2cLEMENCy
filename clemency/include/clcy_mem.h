#define MASK_9BIT 0x1ff
#define MASK_18BIT 0x3ffff
#define MASK_27BIT 0x7ffffff

typedef ut16 ut9;
typedef ut32 ut18;
typedef ut32 ut27;
// void r_mem_copybits_delta(ut8 *dst, int doff, const ut8 *src, int soff, int bits);

static ut9 r_read_me9(const ut8* buf, int boff) {
	ut9 ret = 0;
	r_mem_copybits_delta ((ut8*)&ret, 0, buf, boff, 9);
	return ret;
}

static ut18 r_read_me18(const ut8* buf, int boff) {
	ut18 ret = 0;
	r_mem_copybits_delta((ut8*)&ret, 9, buf, boff, 9);
	r_mem_copybits_delta((ut8*)&ret, 0, buf, boff + 9, 9);
	return ret;
}

static ut27 r_read_me27(const ut8* buf, int boff) {
	ut27 ret = 0;
	r_mem_copybits_delta((ut8*)&ret, 18, buf, boff + 18, 9);
	r_mem_copybits_delta((ut8*)&ret, 9, buf, boff, 9);
	r_mem_copybits_delta((ut8*)&ret, 0, buf, boff + 9, 9);
	return ret;
}

static ut27 r_read_plain27(const ut8* buf, int boff) {
	ut27 ret = 0;
	r_mem_copybits_delta((ut8*)&ret, 0, buf, boff, 9);
	r_mem_copybits_delta((ut8*)&ret, 9, buf, boff + 9, 9);
	r_mem_copybits_delta((ut8*)&ret, 18, buf, boff + 18, 9);
	return ret;
}

static void r_write_me9(ut8* buf, ut9 val, int boff) {
	r_mem_copybits_delta (buf, boff, (ut8*)&val, 0, 9);
}

static void r_write_me18(ut8* buf, ut18 val, int boff) {
	r_mem_copybits_delta(buf, boff + 9, (ut8*)&val, 0, 9);
	r_mem_copybits_delta(buf, boff, (ut8*)&val, 9, 9);
}

static void r_write_me27(ut8* buf, ut27 val, int boff) {
	r_mem_copybits_delta(buf, boff + 18, (ut8*)&val, 18, 9);
	r_mem_copybits_delta(buf, boff + 9, (ut8*)&val, 0, 9);
	r_mem_copybits_delta(buf, boff, (ut8*)&val, 9, 9);
}

static void r_write_plain27(ut8* buf, ut27 val, int boff) {
	r_mem_copybits_delta(buf, boff, (ut8*)&val, 0, 9);
	r_mem_copybits_delta(buf, boff + 9, (ut8*)&val, 9, 9);
	r_mem_copybits_delta(buf, boff + 18, (ut8*)&val, 18, 9);
}
