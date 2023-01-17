#include "headers.h"

void allocateBuffers(struct dataStruct *st)
{
    st->cryptSt.evpKey = calloc(EVP_MAX_KEY_LENGTH, sizeof(*st->cryptSt.evpKey));
    if (st->cryptSt.evpKey == NULL) {
        printSysError(errno);
        printError("Could not allocate evpKey buffer");
        exit(EXIT_FAILURE);
    }
    st->cryptSt.evpSalt = calloc(EVP_SALT_SIZE, sizeof(*st->cryptSt.evpSalt));
    if (st->cryptSt.evpSalt == NULL) {
        printSysError(errno);
        printError("Could not allocate evpSalt buffer");
        exit(EXIT_FAILURE);
    }

    st->cryptSt.hmacKey = calloc(HMAC_KEY_SIZE, sizeof(*st->cryptSt.hmacKey));
    if (st->cryptSt.hmacKey == NULL) {
        printSysError(errno);
        printError("Could not allocate hmacKey buffer");
        exit(EXIT_FAILURE);
    }
}

void cleanUpBuffers(struct dataStruct *st)
{
    OPENSSL_cleanse(st->cryptSt.evpKey, EVP_MAX_KEY_LENGTH);
    free(st->cryptSt.evpKey);
    OPENSSL_cleanse(st->cryptSt.hmacKey, HMAC_KEY_SIZE);
    free(st->cryptSt.hmacKey);

    OPENSSL_cleanse(st->cryptSt.userPass, strlen(st->cryptSt.userPass));
    OPENSSL_cleanse(st->cryptSt.userPassToVerify, strlen(st->cryptSt.userPassToVerify));

    OPENSSL_cleanse(st->cryptSt.keyFileHash, sizeof(st->cryptSt.keyFileHash));

    free(st->cryptSt.evpSalt);
}
