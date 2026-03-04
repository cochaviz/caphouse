ifeq ($(shell id -u),0)
PREFIX  ?= /usr/local
else
PREFIX  ?= $(HOME)/.local
endif
BINDIR  := $(PREFIX)/bin
MANDIR  := $(PREFIX)/share/man/man1
ZSHDIR  := $(PREFIX)/share/zsh/site-functions
FISHDIR := $(PREFIX)/share/fish/vendor_completions.d

# Homebrew on macOS uses etc/bash_completion.d; Linux uses share/bash-completion/completions.
ifeq ($(shell uname),Darwin)
BASHDIR := $(PREFIX)/etc/bash_completion.d
else
BASHDIR := $(PREFIX)/share/bash-completion/completions
endif

BIN     := caphouse
MONITOR := caphouse-monitor
BUILDDIR := build

.PHONY: all build man completions install uninstall clean

all: build man completions

build:
	mkdir -p $(BUILDDIR)
	go build -o $(BUILDDIR)/$(BIN) ./cmd/caphouse

man: build
	./$(BUILDDIR)/$(BIN) gen-man man/man1

completions: build
	mkdir -p completions
	./$(BUILDDIR)/$(BIN) completion bash > completions/$(BIN).bash
	./$(BUILDDIR)/$(BIN) completion zsh  > completions/_$(BIN)
	./$(BUILDDIR)/$(BIN) completion fish > completions/$(BIN).fish

install: build man completions
	install -d $(DESTDIR)$(BINDIR)
	install -m755 $(BUILDDIR)/$(BIN) $(DESTDIR)$(BINDIR)/$(BIN)
	install -m755 scripts/$(MONITOR) $(DESTDIR)$(BINDIR)/$(MONITOR)
	install -d $(DESTDIR)$(MANDIR)
	install -m644 man/man1/*.1 $(DESTDIR)$(MANDIR)/
	install -d $(DESTDIR)$(BASHDIR)
	install -m644 completions/$(BIN).bash $(DESTDIR)$(BASHDIR)/$(BIN)
	install -d $(DESTDIR)$(ZSHDIR)
	install -m644 completions/_$(BIN) $(DESTDIR)$(ZSHDIR)/_$(BIN)
	install -d $(DESTDIR)$(FISHDIR)
	install -m644 completions/$(BIN).fish $(DESTDIR)$(FISHDIR)/$(BIN).fish

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(BIN)
	rm -f $(DESTDIR)$(BINDIR)/$(MONITOR)
	rm -f $(DESTDIR)$(MANDIR)/$(BIN)*.1
	rm -f $(DESTDIR)$(BASHDIR)/$(BIN)
	rm -f $(DESTDIR)$(ZSHDIR)/_$(BIN)
	rm -f $(DESTDIR)$(FISHDIR)/$(BIN).fish

clean:
	rm -rf $(BUILDDIR) man completions
