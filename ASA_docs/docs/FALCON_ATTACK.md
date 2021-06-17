# Toward the Detection of Algorithm Substitution Attacks in Post Quantum Cryptography
## Falcon Implementation

Directory: `src/sig/falcon`
To implement the attack, we modified:
- `/pqclean_falcon-512_clean/pqclean.c` for Falcon-512 attack
- `/pqclean_falcon-1024_clean/pqclean.c` for Falcon-1024 attack


First, we include our forked CECIES lib, and declare global variables:
- ciphertext_counter: Ranging between 0 and 1. 0 means that we need to encrypt the seed for transmission, while 1 means that the seed
has already been encrypted, thus it won't need to be encrypted again.
- start
```
#include "cecies/encrypt.h"
#include "cecies/types.h"
#include "cecies/util.h"
#include <stdio.h>

int ciphertext_counter, start, ct_buffer_malloc = 0;
uint8_t *ciphertext_buffer;
unsigned char keygen_seed[32];
```