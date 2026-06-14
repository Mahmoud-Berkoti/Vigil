CC      ?= cc
CFLAGS  ?= -std=c11 -Wall -Wextra -Werror -O2 -g
LDLIBS   = -lsqlite3 -lcurl -lpthread

BUILD   := build
BIN     := vigil

# Library sources: everything under src/ except main.c
LIB_SRCS := $(shell find src -name '*.c' ! -name 'main.c' | sort)
LIB_OBJS := $(patsubst src/%.c,$(BUILD)/%.o,$(LIB_SRCS))

TEST_SRCS := $(wildcard tests/test_*.c)
TEST_BINS := $(patsubst tests/%.c,$(BUILD)/tests/%,$(TEST_SRCS))

.PHONY: all clean test fuzz demo run

all: $(BIN)

$(BIN): $(BUILD)/main.o $(LIB_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

$(BUILD)/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD)/tests/%: tests/%.c $(LIB_OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -o $@ $< $(LIB_OBJS) $(LDLIBS)

test: $(TEST_BINS)
	@fail=0; for t in $(TEST_BINS); do \
		printf '%-40s ' $$t; \
		./$$t || fail=1; \
	done; \
	if [ $$fail -ne 0 ]; then echo "TESTS FAILED"; exit 1; fi; \
	echo "ALL TESTS PASSED"

# Download a real RIPE RIS update dump for cross-validation (not
# needed for `make test`; the small carved fixture is checked in).
RIS_URL ?= https://data.ris.ripe.net/rrc00/2026.07/updates.20260706.0000.gz
fetch-data:
	curl -s -o data/fixtures/ris-updates.gz "$(RIS_URL)"
	gunzip -kf data/fixtures/ris-updates.gz

# Cross-validate replay counts against mrtparse (pip3 install mrtparse)
crosscheck: $(BIN)
	python3 tools/crosscheck.py data/fixtures/updates-sample.mrt
	@if [ -f data/fixtures/ris-updates ]; then \
		python3 tools/crosscheck.py data/fixtures/ris-updates; \
	fi

fuzz: $(LIB_SRCS) tests/fuzz_main.c
	@mkdir -p $(BUILD)
	$(CC) -std=c11 -Wall -Wextra -O1 -g -fsanitize=address,undefined \
		-o $(BUILD)/fuzz tests/fuzz_main.c $(LIB_SRCS) $(LDLIBS)
	./$(BUILD)/fuzz

demo: $(BIN)
	./tools/demo.sh

clean:
	rm -rf $(BUILD) $(BIN)
