#include "headers.h"

void doCrypt(FILE *inFile, FILE *outFile, uint64_t fileSize, struct dataStruct *st)
{
    #ifdef gui
    *(st->guiSt.progressFraction) = 0.0;
    #endif

    uint8_t *inBuffer = calloc(st->cryptSt.msgBufSize + EVP_MAX_BLOCK_LENGTH, sizeof(*inBuffer)), *outBuffer = calloc(st->cryptSt.msgBufSize + EVP_MAX_BLOCK_LENGTH, sizeof(*outBuffer));
    if (inBuffer == NULL || outBuffer == NULL) {
        printSysError(errno);
        printError("Could not allocate memory for doCrypt buffers");
        exit(EXIT_FAILURE);
    }

    EVP_CIPHER_CTX *evp_ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(evp_ctx);

    HMAC_CTX *hmac_ctx = HMAC_CTX_new();
    HMAC_Init_ex(hmac_ctx, st->cryptSt.hmacKey, HMAC_KEY_SIZE, EVP_get_digestbyname(st->cryptSt.mdAlgorithm), NULL);

    HMAC_Update(hmac_ctx, st->cryptSt.evpSalt, sizeof(*st->cryptSt.evpSalt) * EVP_SALT_SIZE);
    HMAC_Update(hmac_ctx, st->cryptSt.passKeyedHash, sizeof(*st->cryptSt.passKeyedHash) * PASS_KEYED_HASH_SIZE);

    if (st->optSt.encrypt) {
        EVP_EncryptInit_ex(evp_ctx, st->cryptSt.evpCipher, NULL, st->cryptSt.evpKey, st->cryptSt.evpSalt);
    } else if (st->optSt.decrypt) {
        EVP_DecryptInit_ex(evp_ctx, st->cryptSt.evpCipher, NULL, st->cryptSt.evpKey, st->cryptSt.evpSalt);
    }

    uint64_t bytesWritten = 0;
    uint64_t remainingBytes = fileSize;
    uint32_t evpOutputLength = 0;

    uint64_t i;
    uint64_t loopIterations = 0;
    for (i = 0; remainingBytes; i += st->cryptSt.msgBufSize) {

        #ifdef gui
        st->guiSt.startLoop = clock();
        st->guiSt.startBytes = (fileSize - remainingBytes);
        #endif

        if (st->cryptSt.msgBufSize > remainingBytes) {
            st->cryptSt.msgBufSize = remainingBytes;
        }

        if (freadWErrCheck(inBuffer, sizeof(*inBuffer) * st->cryptSt.msgBufSize, 1, inFile, st) != 0) {
            printSysError(st->miscSt.returnVal);
            printError("Could not read file for encryption/decryption");
            exit(EXIT_FAILURE);
        }

        if (st->optSt.encrypt) {
            if (!EVP_EncryptUpdate(evp_ctx, outBuffer, &evpOutputLength, inBuffer, st->cryptSt.msgBufSize)) {
                fprintf(stderr, "EVP_EncryptUpdate failed\n");
                ERR_print_errors_fp(stderr);
                EVP_CIPHER_CTX_cleanup(evp_ctx);

                exit(EXIT_FAILURE);
            }
        } else if (st->optSt.decrypt) {
            if (!EVP_DecryptUpdate(evp_ctx, outBuffer, &evpOutputLength, inBuffer, st->cryptSt.msgBufSize)) {
                fprintf(stderr, "EVP_DecryptUpdate failed\n");
                ERR_print_errors_fp(stderr);
                EVP_CIPHER_CTX_cleanup(evp_ctx);

                exit(EXIT_FAILURE);
            }
        }

        if (fwriteWErrCheck(outBuffer, sizeof(*outBuffer), evpOutputLength, outFile, st) != 0) {
            printSysError(st->miscSt.returnVal);
            printError("Could not write file for encryption/decryption");
            exit(EXIT_FAILURE);
        }
        bytesWritten += evpOutputLength;

        HMAC_Update(hmac_ctx, outBuffer, (sizeof(*outBuffer) * evpOutputLength));

        remainingBytes -= st->cryptSt.msgBufSize;

        #ifdef gui
        *(st->guiSt.progressFraction) = (double)i / (double)fileSize;

        st->guiSt.endLoop = clock();
        st->guiSt.endBytes = (fileSize - remainingBytes);

        st->guiSt.loopTime = (double)(st->guiSt.endLoop - st->guiSt.startLoop) / CLOCKS_PER_SEC;
        st->guiSt.totalTime = (double)(st->guiSt.endLoop - st->guiSt.startTime) / CLOCKS_PER_SEC;
        st->guiSt.totalBytes = st->guiSt.endBytes - st->guiSt.startBytes;

        double dataRate = (double)((double)st->guiSt.totalBytes / (double)st->guiSt.loopTime) / (1024 * 1024);
        sprintf(st->guiSt.statusMessage, "%s %0.0f Mb/s, %0.0fs elapsed", st->optSt.encrypt ? "Encrypting..." : "Decrypting...", dataRate, st->guiSt.totalTime);
        st->guiSt.averageRate += dataRate;
        #endif
        loopIterations++;
    }
    #ifdef gui
    st->guiSt.averageRate /= loopIterations;
    #endif

    if (st->optSt.encrypt) {
        if (!EVP_EncryptFinal_ex(evp_ctx, outBuffer, &evpOutputLength)) {
            fprintf(stderr, "EVP_EncryptFinal_ex failed\n");
            ERR_print_errors_fp(stderr);
            EVP_CIPHER_CTX_cleanup(evp_ctx);
            exit(EXIT_FAILURE);
        }
        bytesWritten += evpOutputLength;
        HMAC_Update(hmac_ctx, outBuffer, (sizeof(*outBuffer) * evpOutputLength));
    } else if (st->optSt.decrypt) {
        if (!EVP_DecryptFinal_ex(evp_ctx, outBuffer, &evpOutputLength)) {
            fprintf(stderr, "EVP_DecryptFinal_ex failed \n");
            ERR_print_errors_fp(stderr);
            EVP_CIPHER_CTX_cleanup(evp_ctx);
            exit(EXIT_FAILURE);
        }
    }

    EVP_CIPHER_CTX_free(evp_ctx);

    if (fwriteWErrCheck(outBuffer, sizeof(*outBuffer), evpOutputLength, outFile, st) != 0) {
        printSysError(st->miscSt.returnVal);
        printError("Could not write file for encryption/decryption");
        exit(EXIT_FAILURE);
    }

    bytesWritten += EVP_SALT_SIZE + PASS_KEYED_HASH_SIZE;

    HMAC_Final(hmac_ctx, st->cryptSt.generatedMAC, (unsigned int *)&bytesWritten);
    HMAC_CTX_free(hmac_ctx);

    free(inBuffer);
    free(outBuffer);
}

void genKeyFileHash(FILE *dataFile, uint64_t fileSize, struct dataStruct *st)
{
    #ifdef gui
    *(st->guiSt.progressFraction) = 0.0;
    #endif

    uint8_t *keyFileHashBuffer = malloc(st->cryptSt.genHmacBufSize * sizeof(*keyFileHashBuffer));
    if (keyFileHashBuffer == NULL) {
        printSysError(errno);
        printError("Could not allocate memory for keyFileHashBuffer");
        exit(EXIT_FAILURE);
    }
    uint64_t remainingBytes = fileSize;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_get_digestbyname(st->cryptSt.mdAlgorithm), NULL);

    uint64_t i;
    for (i = 0; remainingBytes; i += st->cryptSt.genHmacBufSize) {

        #ifdef gui
        st->guiSt.startLoop = clock();
        st->guiSt.startBytes = (fileSize - remainingBytes);
        #endif

        if (st->cryptSt.genHmacBufSize > remainingBytes) {
            st->cryptSt.genHmacBufSize = remainingBytes;
        }

        if (freadWErrCheck(keyFileHashBuffer, sizeof(*keyFileHashBuffer) * st->cryptSt.genHmacBufSize, 1, dataFile, st) != 0) {
            printSysError(st->miscSt.returnVal);
            printError("Could not generate keyFile Hash");
            exit(EXIT_FAILURE);
        }
        EVP_DigestUpdate(ctx, keyFileHashBuffer, sizeof(*keyFileHashBuffer) * st->cryptSt.genHmacBufSize);

        remainingBytes -= st->cryptSt.genHmacBufSize;
        #ifdef gui
        *(st->guiSt.progressFraction) = (double)i / (double)fileSize;

        st->guiSt.endLoop = clock();
        st->guiSt.endBytes = (fileSize - remainingBytes);

        st->guiSt.loopTime = (double)(st->guiSt.endLoop - st->guiSt.startLoop) / CLOCKS_PER_SEC;
        st->guiSt.totalTime = (double)(st->guiSt.endLoop - st->guiSt.startTime) / CLOCKS_PER_SEC;
        st->guiSt.totalBytes = st->guiSt.endBytes - st->guiSt.startBytes;

        double dataRate = (double)((double)st->guiSt.totalBytes / (double)st->guiSt.loopTime) / (1024 * 1024);
        sprintf(st->guiSt.statusMessage, "%s %0.0f Mb/s, %0.0fs elapsed", "Hashing keyfile...", dataRate, st->guiSt.totalTime);
        #endif
    }
    EVP_DigestFinal_ex(ctx, st->cryptSt.keyFileHash, NULL);
    EVP_MD_CTX_free(ctx);
    free(keyFileHashBuffer);
}

void genHMAC(FILE *dataFile, uint64_t fileSize, struct dataStruct *st)
{
    #ifdef gui
    *(st->guiSt.progressFraction) = 0.0;
    #endif

    uint8_t *genHmacBuffer = malloc(st->cryptSt.genHmacBufSize * sizeof(*genHmacBuffer));
    if (genHmacBuffer == NULL) {
        printSysError(errno);
        printError("Could not allocate memory for genHmacBuffer");
        exit(EXIT_FAILURE);
    }
    uint64_t remainingBytes = fileSize;

    HMAC_CTX *ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, st->cryptSt.hmacKey, HMAC_KEY_SIZE, EVP_get_digestbyname(st->cryptSt.mdAlgorithm), NULL);

    uint64_t i;
    for (i = 0; remainingBytes; i += st->cryptSt.genHmacBufSize) {

    #ifdef gui
        st->guiSt.startLoop = clock();
        st->guiSt.startBytes = (fileSize - remainingBytes);
    #endif

        if (st->cryptSt.genHmacBufSize > remainingBytes) {
            st->cryptSt.genHmacBufSize = remainingBytes;
        }

        if (freadWErrCheck(genHmacBuffer, sizeof(*genHmacBuffer) * st->cryptSt.genHmacBufSize, 1, dataFile, st) != 0) {
            printSysError(st->miscSt.returnVal);
            printError("Could not generate HMAC");
            exit(EXIT_FAILURE);
        }
        HMAC_Update(ctx, genHmacBuffer, sizeof(*genHmacBuffer) * st->cryptSt.genHmacBufSize);

        remainingBytes -= st->cryptSt.genHmacBufSize;
    #ifdef gui
        *(st->guiSt.progressFraction) = (double)i / (double)fileSize;

        st->guiSt.endLoop = clock();
        st->guiSt.endBytes = (fileSize - remainingBytes);

        st->guiSt.loopTime = (double)(st->guiSt.endLoop - st->guiSt.startLoop) / CLOCKS_PER_SEC;
        st->guiSt.totalTime = (double)(st->guiSt.endLoop - st->guiSt.startTime) / CLOCKS_PER_SEC;
        st->guiSt.totalBytes = st->guiSt.endBytes - st->guiSt.startBytes;

        double dataRate = (double)((double)st->guiSt.totalBytes / (double)st->guiSt.loopTime) / (1024 * 1024);
        sprintf(st->guiSt.statusMessage, "%s %0.0f Mb/s, %0.0fs elapsed", "Authenticating data...", dataRate, st->guiSt.totalTime);
    #endif
    }
    HMAC_Final(ctx, st->cryptSt.generatedMAC, (unsigned int *)&fileSize);
    HMAC_CTX_free(ctx);
    free(genHmacBuffer);
}

void genHMACKey(struct dataStruct *st)
{

    #ifdef gui
    strcpy(st->guiSt.statusMessage, "Deriving auth key...");
    #endif

    EVP_PKEY_CTX *pctx;
    size_t outlen = sizeof(*st->cryptSt.hmacKey) * HMAC_KEY_SIZE;
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);

    if (EVP_PKEY_derive_init(pctx) <= 0) {
        printError("HKDF failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_get_digestbyname(st->cryptSt.mdAlgorithm)) <= 0) {
        printError("HKDF failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, st->cryptSt.evpKey, sizeof(*st->cryptSt.evpKey) * EVP_MAX_KEY_LENGTH) <= 0) {
        printError("HKDF failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, "authkey", strlen("authkey")) <= 0) {
        printError("HKDF failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_derive(pctx, st->cryptSt.hmacKey, &outlen) <= 0) {
        printError("HKDF failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    EVP_PKEY_CTX_free(pctx);
}

void genPassTag(struct dataStruct *st)
{

    #ifdef gui
    *(st->guiSt.progressFraction) = 0;
    #endif

    if (HMAC(EVP_get_digestbyname(st->cryptSt.mdAlgorithm), st->cryptSt.hmacKey, HMAC_KEY_SIZE, (const unsigned char *)st->cryptSt.userPass, strlen(st->cryptSt.userPass), st->cryptSt.passKeyedHash, st->cryptSt.HMACLengthPtr) == NULL) {
        printError("Password keyed-hash failure");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    #ifdef gui
    *(st->guiSt.progressFraction) = 1;
    #endif
}

void genEvpKey(struct dataStruct *st)
{
    EVP_PKEY_CTX *pctx;

    size_t outlen = sizeof(*st->cryptSt.evpKey) * EVP_MAX_KEY_LENGTH;
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SCRYPT, NULL);

    if (EVP_PKEY_derive_init(pctx) <= 0) {
        printError("scrypt failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_set1_pbe_pass(pctx, st->cryptSt.userPass, strlen(st->cryptSt.userPass)) <= 0) {
        printError("scrypt failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_set1_scrypt_salt(pctx, st->cryptSt.evpSalt, sizeof(*st->cryptSt.evpSalt) * EVP_SALT_SIZE) <= 0) {
        printError("scrypt failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_set_scrypt_N(pctx, st->cryptSt.nFactor) <= 0) {
        printError("scrypt failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_set_scrypt_r(pctx, st->cryptSt.rFactor) <= 0) {
        printError("scrypt failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_set_scrypt_p(pctx, st->cryptSt.pFactor) <= 0) {
        printError("scrypt failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_derive(pctx, st->cryptSt.evpKey, &outlen) <= 0) {
        printError("scrypt failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    EVP_PKEY_CTX_free(pctx);
}

void HKDFKeyFile(struct dataStruct *st)
{

    #ifdef gui
    strcpy(st->guiSt.statusMessage, "Deriving key from keyfile and password...");
    #endif

    EVP_PKEY_CTX *pctx;
    size_t outlen = sizeof(*st->cryptSt.evpKey) * EVP_MAX_KEY_LENGTH;
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);

    if (EVP_PKEY_derive_init(pctx) <= 0) {
        printError("HKDF failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_get_digestbyname(st->cryptSt.mdAlgorithm)) <= 0) {
        printError("HKDF failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, st->cryptSt.evpKey, sizeof(st->cryptSt.evpKey)) <= 0) {
        printError("HKDF failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, st->cryptSt.keyFileHash, sizeof(st->cryptSt.keyFileHash)) <= 0) {
        printError("HKDF failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_derive(pctx, st->cryptSt.evpKey, &outlen) <= 0) {
        printError("HKDF failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    EVP_PKEY_CTX_free(pctx);
}

void genEvpSalt(struct dataStruct *st)
{

    #ifdef gui
    double saltSizeFloat = EVP_SALT_SIZE;
    *(st->guiSt.progressFraction) = 0;
    #endif

    unsigned char b;

    for (int i = 0; i < EVP_SALT_SIZE; i++) {
        if (!RAND_bytes(&b, 1)) {
            printError("Aborting: CSPRNG bytes may not be unpredictable");
            exit(EXIT_FAILURE);
        }
        st->cryptSt.evpSalt[i] = b;
        #ifdef gui
        *(st->guiSt.progressFraction) = (double)i / saltSizeFloat;
        #endif
    }
}
