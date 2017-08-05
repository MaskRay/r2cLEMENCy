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
DEPS+=io/io_9bit.$(LIBEXT)
DEPS+=debug/debug_clcy.$(LIBEXT)

all: $(DEPS)
	#r2 -a clemency -b 27 ../third_party/clemency/hello.bin
	r2 -a clemency -e asm.addrbytes=2 9bit://../third_party/clemency/hello.bin

%.$(LIBEXT): %.c include/*.h
	$(LINK.c) $(R2_CFLAGS) $(R2_LDFLAGS) $^ $(LDLIBS) -o $@

asm/specs.json:
	node asm/pdf2specs.js > asm/specs.json

asm/asm-desc.kv: asm/specs.json
	node asm/specs2desc.js > asm/asm-desc.kv

clean:
	rm -f $(DEPS)

install: $(DEPS)
	cp -f $(DEPS) $(R2PM_PLUGDIR)/
#	cp -rf */*.$(LIBEXT).dSYM $(R2PM_PLUGDIR)

symstall: $(DEPS)
	ln -sfr $(DEPS) $(R2PM_PLUGDIR)/

uninstall:
	rm -f ${R2PM_PLUGDIR}/*clemency*
