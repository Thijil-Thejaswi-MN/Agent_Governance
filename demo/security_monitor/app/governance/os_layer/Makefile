CC ?= gcc
CFLAGS ?= -O2 -Wall
LDLIBS ?= -lseccomp

TARGETS = landlock_enforcer seccomp_filter sensor

all: $(TARGETS)

landlock_enforcer: landlock_enforcer.c
	$(CC) $(CFLAGS) $< -o $@

seccomp_filter: seccomp_filter.c
	$(CC) $(CFLAGS) $< $(LDLIBS) -o $@

sensor: sensor.c
	$(CC) $(CFLAGS) $< $(LDLIBS) -o $@

clean:
	rm -f $(TARGETS)

.PHONY: all clean
