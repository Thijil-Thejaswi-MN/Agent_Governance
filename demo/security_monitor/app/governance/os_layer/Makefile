CC ?= gcc
CFLAGS ?= -O2 -Wall

TARGETS = landlock_enforcer seccomp_filter sensor

all: $(TARGETS)

landlock_enforcer: landlock_enforcer.c
	$(CC) $(CFLAGS) $< -o $@

seccomp_filter: seccomp_filter.c
	$(CC) $(CFLAGS) $< -o $@

sensor: sensor.c
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f $(TARGETS)

.PHONY: all clean
