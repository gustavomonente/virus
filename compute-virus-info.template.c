#define DEFINE_COMPUTE_VIRUS_INFO(N)

static virus_info_t compute_virus_info_##N(FILE *file) {
    int fd = fileno(file);
    assert(fd != -1);

    virus_info_t info = { .size = 0, .id_offset = -1 };

    Elf##N##_Ehdr header;
    if (fread(&header, sizeof(header), 1, file) == 0) {
        info.size = -errno;
        assert(ferror(file));
        goto exit;
    }
    assert(header.e_type == ET_EXEC);
    assert(header.e_phentsize == sizeof(Elf##N##_Phdr));
    assert(header.e_shentsize == sizeof(Elf##N##_Shdr));

    info.size = header.e_ehsize;

    off_t num_segments = 0;
    off_t num_sections = 0;
    off_t section_name_table_index = SHN_UNDEF;
    if (header.e_shoff > 0) {
        int result = fseeko(file, header.e_shoff, SEEK_SET);
        assert(!result);

        Elf##N##_Shdr section_header;
        if (fread(&section_header, sizeof(section_header), 1, file) == 0) {
            info.size = -errno;
            assert(ferror(file));
            goto exit;
        }
        num_segments = section_header.sh_info;
        num_sections = section_header.sh_size;
        section_name_table_index = section_header.sh_link;
    }

    if (header.e_phnum < PN_XNUM) {
        num_segments = header.e_phnum;
    }
    if (header.e_shnum < SHN_LORESERVE) {
        num_sections = header.e_shnum;
    }
    if (header.e_shstrndx != SHN_XINDEX) {
        section_name_table_index = header.e_shstrndx;
    }

    off_t segment_header_table_size = num_sections * sizeof(Elf##N##_Shdr);
    off_t segment_header_table_end = header.e_shoff + segment_header_table_size;
    if (info.size < segment_header_table_end) {
        info.size = segment_header_table_end;
    }

    off_t program_header_table_size = num_segments * sizeof(Elf##N##_Phdr);
    off_t program_header_table_end = header.e_phoff + program_header_table_size;
    if (info.size < program_header_table_end) {
        info.size = program_header_table_end;
    }

    char *section_names = NULL;
    off_t section_name_table_size = 0;
    assert(section_name_table_index != SHN_UNDEF);
    {
        int result = fseeko(
            file,
            header.e_shoff + section_name_table_index * sizeof(Elf##N##_Shdr),
            SEEK_SET);
        assert(!result);
    }

    Elf##N##_Shdr section_header;
    if (fread(&section_header, sizeof(section_header), 1, file) == 0) {
        info.size = -errno;
        assert(ferror(file));
        goto exit;
    }
    assert(section_header.sh_type == SHT_STRTAB);
    section_name_table_size = section_header.sh_size;
    assert(section_name_table_size > 0);
    section_names = malloc(section_name_table_size);
    if (!section_names) {
        info.size = -errno;
        goto exit;
    }

    {
        int result = fseeko(file, section_header.sh_offset, SEEK_SET);
        assert(!result);
    }

    if (fread(section_names, section_name_table_size, 1, file) == 0) {
        info.size = -errno;
        assert(ferror(file));
        goto free_section_names;
    }

    if (num_segments > 0) {
        int result = fseeko(file, header.e_phoff, SEEK_SET);
        assert(!result);
        posix_fadvise(fd, header.e_phoff, program_header_table_size,
                      POSIX_FADV_SEQUENTIAL);
        for (off_t i = 0; i < num_segments; ++i) {
            Elf##N##_Phdr program_header;
            if (fread(&program_header, sizeof(program_header), 1, file) == 0) {
                info.size = -errno;
                assert(ferror(file));
                goto free_section_names;
            }
            switch (program_header.p_type) {
                case PT_NULL:
                /* already included in file; only specified if also in memory */
                case PT_PHDR:
                    break;
                default: {
                    off_t segment_end = program_header.p_offset + (off_t) program_header.p_filesz;
                    if (info.size < segment_end) {
                        info.size = segment_end;
                    }
                    break;
                }
            }
        }
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
                info.size = -errno;
                assert(ferror(file));
                goto free_section_names;
            }
            switch (section_header.sh_type) {
                case SHT_NULL:
                case SHT_NOBITS:
                    break;
                default: {
                    off_t section_end = section_header.sh_offset + (off_t) section_header.sh_size;
                    if (info.size < section_end) {
                        info.size = section_end;
                    }

                    assert(section_header.sh_name < (size_t) section_name_table_size);
                    static const char rodata_name[] = ".rodata";
                    if (strncmp(rodata_name,
                                section_names + section_header.sh_name,
                                sizeof(rodata_name)) == 0) {
                        assert((uintptr_t) &virus_id >= section_header.sh_addr);
                        off_t diff = ((uintptr_t) &virus_id) - section_header.sh_addr;
                        info.id_offset = section_header.sh_offset + diff;
                    }
                    break;
                }
            }
        }
    }
    assert(info.id_offset >= 0);

free_section_names:
    free(section_names);

exit:
    return info;
}
