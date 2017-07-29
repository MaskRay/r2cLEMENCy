LIBEXT=$(shell r2 -H LIBEXT)

R2_CFLAGS+=$(shell pkg-config --cflags r_core r_asm r_anal r_util)
R2_LDFLAGS+=$(shell pkg-config --libs r_core r_asm r_anal r_util)

CFLAGS+=-g

R2_CFLAGS+=-fPIC
R2_LDFLAGS+=-shared
R2PM_PLUGDIR=$(shell r2 -H RHOMEDIR)/plugins

DEPS+=asm/asm_clemency.$(LIBEXT)
DEPS+=anal/anal_clemency.$(LIBEXT)
DEPS+=bin/bin_clemency.$(LIBEXT)
DEPS+=core/core_clemency.$(LIBEXT)
DEPS+=io/io_clemency.$(LIBEXT)
DEPS+=debug/debug_clcy.$(LIBEXT)

all: $(DEPS)
	$(MAKE) install

asm/asm_clemency.$(LIBEXT): asm/asm_clemency.c asm/asm-desc.kv
	$(CC) $(CFLAGS) $(LDFLAGS) $(R2_CFLAGS) $(R2_LDFLAGS) -o asm/asm_clemency.$(LIBEXT) asm/asm_clemency.c

anal/anal_clemency.$(LIBEXT): anal/anal_clemency.c
	$(CC) $(CFLAGS) $(LDFLAGS) $(R2_CFLAGS) $(R2_LDFLAGS) -o anal/anal_clemency.$(LIBEXT) anal/anal_clemency.c

bin/bin_clemency.$(LIBEXT): bin/bin_clemency.c
	$(CC) $(CFLAGS) $(LDFLAGS) $(R2_CFLAGS) $(R2_LDFLAGS) -o bin/bin_clemency.$(LIBEXT) bin/bin_clemency.c

core/core_clemency.$(LIBEXT): core/core_clemency.c
	$(CC) $(CFLAGS) $(LDFLAGS) $(R2_CFLAGS) $(R2_LDFLAGS) -o core/core_clemency.$(LIBEXT) core/core_clemency.c

io/io_clemency.$(LIBEXT): io/io_clemency.c
	$(CC) $(CFLAGS) $(LDFLAGS) $(R2_CFLAGS) $(R2_LDFLAGS) -o io/io_clemency.$(LIBEXT) io/io_clemency.c

debug/debug_clcy.$(LIBEXT): debug/debug_clcy.c
	$(CC) $(CFLAGS) $(LDFLAGS) $(R2_CFLAGS) $(R2_LDFLAGS) -o debug/debug_clcy.$(LIBEXT) debug/debug_clcy.c

asm/specs.json:
	node asm/pdf2specs.js > asm/specs.json

asm/asm-desc.kv: asm/specs.json
	node asm/specs2desc.js > asm/asm-desc.kv

clean:
	rm -f */*.$(LIBEXT) */*.dll */*.so */*.dylib

install:
	cp -f */*.$(LIBEXT) $(R2PM_PLUGDIR)
#	cp -rf */*.$(LIBEXT).dSYM $(R2PM_PLUGDIR)

uninstall:
	rm -f ${R2PM_PLUGDIR}/*clemency*
