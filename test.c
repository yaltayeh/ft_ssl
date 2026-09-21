#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include "ft_ssl.h"


int main()
{
    uint64_t key = 0x133457799BBCDFF1ULL;
    uint64_t plaintext = 0x0123456789ABCDEFULL;

    uint64_t subkeys[16];
    

    uint64_t ciphertext = des_process_block(plaintext, subkeys, 0);
    printf("cipher   = %llx (expected 85e813540f0ab405)\n", ciphertext);

    uint64_t decrypted = des_process_block(ciphertext, subkeys, 1);
    printf("decrypted = %llx (expected 123456789abcdef)\n", decrypted);

    return 0;
}
