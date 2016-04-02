#ifndef CS458_VIRUS_VICTIM_H
#define CS458_VIRUS_VICTIM_H

#include <sys/types.h>

struct virus_victim {
    off_t size;
    char content[];
};

extern const struct virus_victim virus_victim;

#endif // CS458_VIRUS_VICTIM_H
