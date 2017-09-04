INSTALL := install
LIBEXT := $(shell r2 -H LIBEXT)
SDB ?= @echo 'Please set SDB to the path of radare2/shlr/sdb/sdb' \#

R2_CFLAGS+=$(shell pkg-config --cflags r_core r_asm r_anal r_util)
R2_LDFLAGS+=$(shell pkg-config --libs r_core r_asm r_anal r_util)

CFLAGS+=-g -std=gnu11

R2_CFLAGS+=-fPIC
R2_LDFLAGS+=-shared
R2PM_PLUGDIR := $(shell r2 -H RHOMEDIR)/plugins
R2PM_SHAREDIR = $(dir $(shell r2 -H MAGICPATH))

SO := anal/anal_clcy.$(LIBEXT) asm/asm_clcy.$(LIBEXT) debug/debug_clcy.$(LIBEXT) \
	core/core_clcy.$(LIBEXT) io/io_clcy.$(LIBEXT) io/io_9bit.$(LIBEXT)

DEPS := $(SO) anal/d/cc-clcy-64.sdb asm/d/clcy.sdb syscall/d/linux-clcy-64.sdb

all: $(DEPS)

run: $(DEPS)
	r2 -a clcy $(RUNFLAGS) 9bit://../third_party/clemency/hello.bin

%.o: %.c include/*.h
	$(COMPILE.c) $(R2_CFLAGS) $(R2_LDFLAGS) $< -o $@

%.$(LIBEXT): %.o
	$(LINK.c) $(R2_CFLAGS) $(R2_LDFLAGS) $^ $(LDLIBS) -o $@

anal/anal_clcy.$(LIBEXT): disasm.o
asm/asm_clcy.$(LIBEXT): disasm.o

%.sdb: %
	$(SDB) $@ = < $^

clean:
	$(RM) $(DEPS)

$(R2PM_PLUGDIR):
	mkdir $@

install: $(DEPS) | $(R2PM_PLUGDIR)
	$(INSTALL) $(SO) $(R2PM_PLUGDIR)/
	$(INSTALL) asm/d/clcy.sdb $(R2PM_SHAREDIR)/opcodes/
	$(INSTALL) syscall/d/linux-clcy-64.sdb $(R2PM_SHAREDIR)/syscall/

symstall: $(DEPS) | $(R2PM_PLUGDIR)
	ln -sfr $(SO) $(R2PM_PLUGDIR)/
	ln -sfr asm/d/clcy.sdb  $(R2PM_SHAREDIR)/opcodes/
	ln -sfr syscall/d/linux-clcy-64.sdb $(R2PM_SHAREDIR)/syscall/
	ln -sfr anal/d/cc-clcy-64.sdb $(R2PM_SHAREDIR)/fcnsign/

uninstall:
	$(RM) $(foreach i,$(SO),${R2PM_PLUGDIR}/$(notdir $i)) $(R2PM_SHAREDIR)/fcnsign/cc-clcy-64.sdb $(R2PM_SHAREDIR)/opcodes/clcy.sdb $(R2PM_SHAREDIR)/syscall/linux-clcy-64.sdb

.PHONY: all clean install run symstall uninstall
