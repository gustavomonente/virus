CFLAGS += -std=gnu11 -Wall -Wextra -Werror -pedantic

virus: virus.c compute-virus-size-32.c compute-virus-size-64.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $< $(LDFLAGS)

compute-virus-size-%.c: compute-virus-size.c
	echo 'DEFINE_COMPUTE_VIRUS_SIZE($*)' | cat $< - | $(CC) -E -x c -P -CC - > $@

compute-virus-size.c: compute-virus-size.template.c
	sed 's,$$, /*\n*/\\,' < $< > $@
	echo >> $@

clean:
	$(RM) virus compute-virus-size-*.c compute-virus-size.c

.PHONY: check clean
