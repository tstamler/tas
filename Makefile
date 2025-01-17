-include Makefile.local

PREFIX ?= /usr/local
SBINDIR ?= $(PREFIX)/sbin
LIBDIR ?= $(PREFIX)/lib
INCDIR ?= $(PREFIX)/include

CFLAGS += -std=gnu99 -O3 -g -Wall -Werror -I. -Iinclude/ -march=native -fno-omit-frame-pointer
LDFLAGS += -pthread -g

RTE_SDK ?= $(HOME)/dpdk/x86_64-native-linuxapp-gcc
DPDK_PMDS ?= ixgbe i40e

CFLAGS+= -I$(RTE_SDK)/include -I$(RTE_SDK)/include/dpdk
LDFLAGS+= -L$(RTE_SDK)/lib/

LIBS_DPDK= -Wl,--whole-archive
LIBS_DPDK+= $(addprefix -lrte_pmd_,$(DPDK_PMDS))
LIBS_DPDK+= -lrte_eal -lrte_mempool -lrte_mempool_ring \
	    -lrte_hash -lrte_ring -lrte_kvargs -lrte_ethdev \
	    -lrte_mbuf -lnuma -lrte_bus_pci -lrte_pci \
	    -lrte_cmdline -lrte_timer -lrte_net \
	    -Wl,--no-whole-archive -ldl $(EXTRA_LIBS_DPDK)

LDLIBS += -lm -lpthread -lrt -ldl

UTILS_OBJS = $(addprefix lib/utils/,utils.o rng.o timeout.o)
TASCOMMON_OBJS = $(addprefix tas/,tas.o config.o shm.o)
SLOWPATH_OBJS = $(addprefix tas/slow/,kernel.o packetmem.o appif.o appif_ctx.o \
	nicif.o cc.o tcp.o arp.o routing.o)
FASTPATH_OBJS = $(addprefix tas/fast/,fastemu.o network.o \
		    qman.o trace.o fast_kernel.o fast_appctx.o fast_flows.o)
STACK_OBJS = $(addprefix lib/tas/,init.o kernel.o conn.o connect.o)
SOCKETS_OBJS = $(addprefix lib/sockets/,control.o transfer.o context.o manage_fd.o \
	epoll.o)
INTERPOSE_OBJS = $(addprefix lib/sockets/,interpose.o)
CFLAGS += -I. -Ilib/tas/include -Ilib/sockets/include

shared_objs = $(patsubst %.o,%.shared.o,$(1))


TESTS= \
	tests/lowlevel \
	tests/lowlevel_echo \
	tests/usocket_accept \
	tests/usocket_connect \
	tests/usocket_accrx \
	tests/usocket_conntx \
	tests/usocket_conntx_large \
	tests/usocket_move \
	tests/usocket_epoll_eof \
	tests/usocket_shutdown \
	tests/bench_ll_echo


all: lib/libtas_sockets.so lib/libtas_interpose.so \
	lib/libtas.so \
	tools/tracetool tools/statetool tools/scaletool \
	tas/tas

tests: $(TESTS)

docs:
	cd doc && doxygen

tas/%.o: CFLAGS+=-Itas/include
tas/tas: LDLIBS+=$(LIBS_DPDK)
tas/tas: $(TASCOMMON_OBJS) $(FASTPATH_OBJS) $(SLOWPATH_OBJS) $(UTILS_OBJS)

flexnic/tests/tcp_common: flexnic/tests/tcp_common.o

tests/lowlevel: tests/lowlevel.o lib/libtas.so
tests/lowlevel_echo: tests/lowlevel_echo.o lib/libtas.so

tests/usocket_accept: tests/usocket_accept.o lib/libtas_sockets.so
tests/usocket_connect: tests/usocket_connect.o lib/libtas_sockets.so
tests/usocket_accrx: tests/usocket_accrx.o lib/libtas_sockets.so
tests/usocket_conntx: tests/usocket_conntx.o lib/libtas_sockets.so
tests/usocket_conntx_large: tests/usocket_conntx_large.o \
	lib/libtas_sockets.so
tests/usocket_move: tests/usocket_move.o lib/libtas_sockets.so
tests/usocket_epoll_eof: tests/usocket_epoll_eof.o
tests/usocket_shutdown: tests/usocket_shutdown.o
tests/bench_ll_echo: tests/bench_ll_echo.o lib/libtas.so

tools/tracetool: tools/tracetool.o
tools/statetool: tools/statetool.o lib/libtas.so
tools/scaletool: tools/scaletool.o lib/libtas.so

lib/libtas_sockets.so: $(call shared_objs, \
	$(SOCKETS_OBJS) $(STACK_OBJS) $(UTILS_OBJS))

lib/libtas_interpose.so: $(call shared_objs, \
	$(INTERPOSE_OBJS) $(SOCKETS_OBJS) $(STACK_OBJS) $(UTILS_OBJS))

lib/libtas.so: $(call shared_objs, $(UTILS_OBJS) $(STACK_OBJS))

%.shared.o: %.c
	$(CC) $(CFLAGS) -fPIC -c -o $@ $<

%.so:
	$(CC) $(LDFLAGS) -shared $^ $(LOADLIBES) $(LDLIBS) -o $@


clean:
	rm -f *.o tas/*.o tas/fast/*.o tas/slow/*.o lib/utils/*.o \
	  lib/tas/*.o lib/sockets/*.o tests/*.o tools/*.o \
	  lib/libtas_sockets.so lib/libtas_interpose.so \
	  lib/libtas.so \
	  $(TESTS) \
	  tools/tracetool tools/statetool tools/scaletool \
	  tas/tas

install: tas/tas lib/libtas_sockets.so lib/libtas_interpose.so \
  lib/libtas.so tools/statetool
	mkdir -p $(DESTDIR)$(SBINDIR)
	cp tas/tas $(DESTDIR)$(SBINDIR)/tas
	cp tools/statetool $(DESTDIR)$(SBINDIR)/tas-statetool
	mkdir -p $(DESTDIR)$(LIBDIR)
	cp lib/libtas_interpose.so $(DESTDIR)$(LIBDIR)/libtas_interpose.so
	cp lib/libtas_sockets.so $(DESTDIR)$(LIBDIR)/libtas_sockets.so
	cp lib/libtas.so $(DESTDIR)$(LIBDIR)/libtas.so

uninstall:
	rm -f $(DESTDIR)$(SBINDIR)/tas
	rm -f $(DESTDIR)$(SBINDIR)/tas-statetool
	rm -f $(DESTDIR)$(LIBDIR)/libtas_interpose.so
	rm -f $(DESTDIR)$(LIBDIR)/libtas_sockets.so
	rm -f $(DESTDIR)$(LIBDIR)/libtas.so

.PHONY: all tests clean docs install uninstall
