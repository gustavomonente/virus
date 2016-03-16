CFLAGS ?= -O3
CFLAGS += -std=gnu11 -Wall -Wextra -Werror -pedantic
VIRUS_SIZE := $(shell ([ -f virus ] && stat -c %s virus) || echo 1)
CPPFLAGS += -DVIRUS_SIZE=$(VIRUS_SIZE)

check: virus
	$(eval ACTUAL_VIRUS_SIZE := $(shell stat -c %s $^))
	[ $(VIRUS_SIZE) = $(ACTUAL_VIRUS_SIZE) ] \
	|| $(MAKE) -W virus.c $@

virus: virus.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	$(RM) virus

.PHONY: check clean
