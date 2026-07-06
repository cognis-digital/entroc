# entroc - Makefile (C99, stdlib + libm only)
CC      ?= cc
CFLAGS  ?= -O2 -std=c99 -Wall -Wextra
LDLIBS  ?= -lm
PREFIX  ?= /usr/local
BINDIR   = $(PREFIX)/bin

all: entroc

entroc: entroc.c
	$(CC) $(CFLAGS) -o $@ entroc.c $(LDLIBS)

# Strict build used in CI.
strict: entroc.c
	$(CC) $(CFLAGS) -Werror -o entroc entroc.c $(LDLIBS)

test: entroc
	CC="$(CC)" bash tests/run_tests.sh
	CC="$(CC)" bash examples/run_all.sh

bench: entroc
	CC="$(CC)" bash bench/bench.sh

install: entroc
	mkdir -p $(DESTDIR)$(BINDIR)
	cp entroc $(DESTDIR)$(BINDIR)/entroc
	@echo "installed entroc to $(DESTDIR)$(BINDIR)/entroc"

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/entroc

clean:
	rm -f entroc entroc.exe tests/entroc.test tests/unit_entropy.test *.o
	rm -f *.bin *.sarif

.PHONY: all strict test bench install uninstall clean
