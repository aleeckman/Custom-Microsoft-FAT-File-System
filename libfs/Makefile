# Target library
lib  := libfs.a
objs := disk.o fs.o

all: $(lib)

## TODO: Phase 1
CC     := gcc 
CFLAGS := -Wall -Wextra -Werror -MMD

# Optimization
CFLAGS += -O2

# Dependence Traking
deps := $(patsubst %.o,%.d,$(objs))
-include deps

# Rule for compiling the library
libfs.a: $(objs)
	ar rcs $@ $^

# Generic rule for compiling objs
%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Rule for removing all generated files
clean:
	rm -f $(lib) $(objs) $(deps)

