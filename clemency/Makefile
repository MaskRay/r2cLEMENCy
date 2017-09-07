R2_LIBS := r_anal r_asm r_bin r_core r_io r_parse
R2_CFLAGS ?= $(shell pkg-config --cflags $(R2_LIBS))
R2_LDFLAGS ?= $(shell pkg-config --libs $(R2_LIBS))
R2PM_PLUGDIR ?= $(shell r2 -H RHOMEDIR)/plugins
R2PM_SHAREDIR ?= $(dir $(shell r2 -H MAGICPATH))

INSTALL := install
LIBEXT ?= $(shell r2 -H LIBEXT)
SDB ?= @echo 'Please set SDB to the path of `sdb` executable e.g. radare2/shlr/sdb/sdb' \#

CFLAGS += -g -fPIC -std=gnu11
LDFLAGS += -shared

SO := anal/anal_clcy.$(LIBEXT) asm/asm_clcy.$(LIBEXT) bin/bin_clcy.$(LIBEXT) \
	core/core_clcy.$(LIBEXT) io/io_clcy.$(LIBEXT) parse/parse_clcy.$(LIBEXT) #debug/debug_clcy.$(LIBEXT)

DEPS := $(SO) anal/d/cc-clcy-64.sdb asm/d/clcy.sdb syscall/d/linux-clcy-64.sdb

all: $(DEPS)

info:
	@$(foreach i,R2_LIBS R2_CFLAGS R2_LDFLAGS R2PM_PLUGDIR R2PM_SHAREDIR,echo $(i)=$($i);)

run: $(DEPS)
	r2 -a clcy $(RUNFLAGS) clcy://../third_party/clemency/hello.bin

%.o: %.c include/*.h
	$(COMPILE.c) $(R2_CFLAGS) $(R2_LDFLAGS) $< -o $@

%.$(LIBEXT): %.o
	$(LINK.c) $(R2_CFLAGS) $(R2_LDFLAGS) $^ $(LDLIBS) -o $@

anal/anal_clcy.$(LIBEXT): disasm.o
asm/asm_clcy.$(LIBEXT): disasm.o
parse/parse_clcy.$(LIBEXT): disasm.o

%.sdb: %
	$(SDB) $@ = < $^

clean:
	$(RM) $(DEPS) disasm.o

$(R2PM_PLUGDIR):
	mkdir $@

install: $(DEPS) | $(R2PM_PLUGDIR)
	$(INSTALL) $(SO) $(R2PM_PLUGDIR)/
	$(INSTALL) anal/d/cc-clcy-64.sdb $(R2PM_SHAREDIR)/fcnsign/
	$(INSTALL) asm/d/clcy.sdb $(R2PM_SHAREDIR)/opcodes/
	$(INSTALL) syscall/d/linux-clcy-64.sdb $(R2PM_SHAREDIR)/syscall/

symstall: $(DEPS) | $(R2PM_PLUGDIR)
	ln -sfr $(SO) $(R2PM_PLUGDIR)/
	ln -sfr anal/d/cc-clcy-64.sdb $(R2PM_SHAREDIR)/fcnsign/
	ln -sfr asm/d/clcy.sdb $(R2PM_SHAREDIR)/opcodes/
	ln -sfr syscall/d/linux-clcy-64.sdb $(R2PM_SHAREDIR)/syscall/

uninstall:
	$(RM) $(foreach i,$(SO),${R2PM_PLUGDIR}/$(notdir $i)) $(R2PM_SHAREDIR)/fcnsign/cc-clcy-64.sdb $(R2PM_SHAREDIR)/opcodes/clcy.sdb $(R2PM_SHAREDIR)/syscall/linux-clcy-64.sdb

.PHONY: all clean install run symstall uninstall
