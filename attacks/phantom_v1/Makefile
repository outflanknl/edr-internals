SOURCES := $(wildcard *.c)
EXECUTABLE_SOURCES := $(filter-out shared.c,$(SOURCES))
EXECUTABLES := $(EXECUTABLE_SOURCES:.c=)
BINARIES := $(addprefix bin/,$(EXECUTABLES))

all: $(BINARIES)

bin/%: %.c
	@mkdir -p bin
	gcc -lpthread -o $@ $^

clean:
	rm -f $(BINARIES)

.PHONY: all clean
