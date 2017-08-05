INSTALL := install
LIBEXT := $(shell r2 -H LIBEXT)
SDB ?= @echo 'Please set SDB to the path of radare2/shlr/sdb/sdb' \#

R2_CFLAGS+=$(shell pkg-config --cflags r_core r_asm r_anal r_util)
R2_LDFLAGS+=$(shell pkg-config --libs r_core r_asm r_anal r_util)

CFLAGS+=-g

R2_CFLAGS+=-fPIC
R2_LDFLAGS+=-shared
R2PM_PLUGDIR=$(shell r2 -H RHOMEDIR)/plugins
R2PM_SHAREDIR = $(dir $(shell r2 -H MAGICPATH))

SO := anal/anal_clcy.$(LIBEXT) asm/asm_clcy.$(LIBEXT) debug/debug_clcy.$(LIBEXT) \
	core/core_clcy.$(LIBEXT) io/io_clcy.$(LIBEXT) io/io_9bit.$(LIBEXT)

DEPS := $(SO) asm/d/clcy.sdb syscall/d/linux-clcy-27.sdb

all: $(DEPS)
	#r2 -a clcy -b 27 ../third_party/clemency/hello.bin
	r2 -a clcy -b 27 -e asm.addrbytes=2 9bit://../third_party/clemency/hello.bin

%.$(LIBEXT): %.c include/*.h
	$(LINK.c) $(R2_CFLAGS) $(R2_LDFLAGS) $^ $(LDLIBS) -o $@

%.sdb: %
	$(SDB) $@ = < $^

clean:
	rm -f $(DEPS)

install: $(DEPS)
	$(INSTALL) $(SO) $(R2PM_PLUGDIR)/
	$(INSTALL) asm/d/clcy.sdb $(R2PM_SHAREDIR)/opcodes/
	$(INSTALL) syscall/d/linux-clcy-27.sdb $(R2PM_SHAREDIR)/syscall/

symstall: $(DEPS)
	ln -sfr $(SO) $(R2PM_PLUGDIR)/
	ln -sfr asm/d/clcy.sdb  $(R2PM_SHAREDIR)/opcodes/
	ln -sfr syscall/d/linux-clcy-27.sdb $(R2PM_SHAREDIR)/syscall/

uninstall:
	rm -f ${R2PM_PLUGDIR}/*clcy* $(R2PM_SHAREDIR)/opcodes/clcy.sdb $(R2PM_SHAREDIR)/syscall/linux-clcy-27.sdb

.PHONY: all clean install symstall uninstall
