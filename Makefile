CFLAGS += -std=gnu11 -Wall -Wextra -Werror -pedantic
LDFLAGS += -Wl,--defsym,elf_headers=__executable_start \
           -Wl,--defsym,mutable_data_init_begin=_binary_data2_bin_start \
           -Wl,--defsym,mutable_data_init_end=_binary_data2_bin_end

virus: data2.x virus.o empty-victim.o data2.o
	$(CC) -T $< -o $@ virus.o empty-victim.o data2.o $(LDFLAGS)

data2.o: data2.bin objcopy-args
	objcopy @objcopy-args --input-format=binary --rename-section .data=.data2 $< $@

objcopy-args: define-objcopy-args.sh
	ld --verbose | sh $< > $@

data2.bin: virus.got.plt virus.data virus.data1
	cat $^ > $@

virus.got.plt: virus.elf
	objcopy --output-format=binary --only-section=.got.plt $< $@

virus.data: virus.elf
	objcopy --output-format=binary --only-section=.data $< $@

virus.data1: virus.elf
	objcopy --output-format=binary --only-section=.data1 $< $@

virus.elf: LDFLAGS += -Wl,--defsym,_binary_data2_bin_start=0 \
                      -Wl,--defsym,_binary_data2_bin_end=0
virus.elf: common.x virus.o empty-victim.o
	$(CC) -T $< -o $@ virus.o empty-victim.o $(LDFLAGS)

data2.x: common.x

virus.o: virus.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $<

empty-victim.o: empty-victim.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $<

virus.c empty-victim.c: victim.h

clean:
	$(RM) virus virus.elf virus.got.plt virus.data virus.data1 data2.bin objcopy-args *.o

.PHONY: check clean
