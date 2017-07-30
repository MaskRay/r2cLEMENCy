#include <r_util.h>

void test(const char *a, const char *b, int as, int bs) {
	char out[32];
	ut8 buf[32] = {0};
	
	ut8 in[32] = {0};
	ut32 num = r_num_get (NULL, a);
	memcpy (in, &num, sizeof (num));

	int max = strlen (a) - 1;
	r_mem_copybits_delta (buf, as, in, bs, max - R_MAX (bs, as));
	out[0] = 0;
	int *ias = &in;
	int *ibs = &buf;
	r_str_bits (out, buf, max, NULL);
	r_str_reverse (out);
// eprintf ("((%s)((%s))   (%s)\n", a, b, out);
	if (!strncmp (out, b, strlen (b) - 2)) {
		eprintf ("[OK]  ");
		eprintf ("%s %s %d %d\n", a, out, as, bs);
	} else {
		eprintf ("[XX]  ");
		eprintf ("%s %s (%s) %d %d\n", a, out, b, as, bs);
	}
}

main() {
	test ("10101111b", "10101111b", 0, 0);
	test ("10101111b", "01011110b", 1, 0);
	test ("10101111b", "10101110b", 1, 1);
	test ("10101111b", "11110000b", 4, 0);
	test ("10101111b", "00001010b", 0, 4);

	// testing 9bit and beyond
	test ("110101111b", "110101111b", 0, 0);
	//test ("10010101111b", "10010101111b", 0, 0);
	test ("10000000000b", "10000000000b", 0, 0);
	test ("10000000000b", "00001000000b", 0, 4);
	test ("10000000000b", "00000000000b", 4, 0);

	// test ("10101111b", "10101111b", 0, 0);
	// test ("10101111b", "10101111b", 0, 0);
}
