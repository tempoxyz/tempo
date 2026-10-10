COBC ?= cobc
COBFLAGS ?= -free -Wall -Werror -debug

.PHONY: all test clean
all: build/ledger build/evm

build:
	mkdir -p $@

build/ledger: src/ledger.cob | build
	$(COBC) $(COBFLAGS) -x -o $@ $<

build/evm: src/evm.cob | build
	$(COBC) $(COBFLAGS) -x -o $@ $<

test: all
	uv run python -m unittest discover -s tests -v

clean:
	rm -rf build
