#include <stdio.h>
#include <sys/types.h>
#include "data_format.h"
int main() {
    for (u_short uc = 0; uc < (unsigned) 256; uc++) printf("%s %s\n", byte_to_hex_str(uc), byte_to_bin_str(uc));
}
