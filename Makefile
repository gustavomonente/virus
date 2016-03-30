CFLAGS += -std=gnu11 -Wall -Wextra -Werror -pedantic

virus: virus.c compute-virus-info-32.c compute-virus-info-64.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $< $(LDFLAGS)

compute-virus-info-%.c: compute-virus-info.c
	echo 'DEFINE_COMPUTE_VIRUS_INFO($*)' | cat $< - | $(CC) -E -x c -P -CC - > $@

compute-virus-info.c: compute-virus-info.template.c
	sed 's,$$, /*\n*/\\,' < $< > $@
	echo >> $@

clean:
	$(RM) virus compute-virus-info-*.c compute-virus-info.c

.PHONY: check clean
