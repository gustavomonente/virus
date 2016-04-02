INCLUDE "common.x";
SECTIONS
{
    .data2 :
    {
        *(.data2)
    }
}
INSERT AFTER .data1;
