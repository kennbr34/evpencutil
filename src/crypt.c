#include "lib.h"
#include <assert.h>
#include <errno.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

void doEncrypt(FILE *inFile, FILE *outFile, uint64_t fileSize, struct dataStruct *st)
{
#ifdef gui
    *(st->guiSt.progressFraction) = 0.0;
#endif

    struct timespec begin, end;
    st->timeSt.totalTime = 0;

    uint64_t bytesWritten = 0, bytesRead = 0, amountReadLast = 0;
    uint64_t remainingBytes = fileSize;

    uint64_t loopIterations = 0;

    uint8_t *inBuffer = calloc(st->cryptSt.fileBufSize + EVP_MAX_BLOCK_LENGTH, sizeof(*inBuffer)), *outBuffer = calloc(st->cryptSt.fileBufSize + EVP_MAX_BLOCK_LENGTH, sizeof(*outBuffer));
    if (inBuffer == NULL || outBuffer == NULL) {
        PRINT_SYS_ERROR(errno);
        PRINT_ERROR("Could not allocate memory input/output buffers");
        remove(st->fileNameSt.outputFileName);
        exit(EXIT_FAILURE);
    }

    size_t HMACLengthPtr = 0;

    EVP_CIPHER_CTX *evp_ctx = evp_ctx = EVP_CIPHER_CTX_new();
    if (evp_ctx == NULL) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    OSSL_PARAM params[2];

    params[0] = OSSL_PARAM_construct_utf8_string("digest", (char*)st->cryptSt.mdAlgorithm, 0);
    params[1] = OSSL_PARAM_construct_end();

    EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (mac == NULL) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    EVP_MAC_CTX *mac_ctx = EVP_MAC_CTX_new(mac);
    if (mac_ctx == NULL) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    while (remainingBytes) {

        clock_gettime(CLOCK_REALTIME, &begin);
        st->timeSt.startLoop = begin.tv_nsec / 1000000000.0 + begin.tv_sec;

        st->timeSt.startBytes = bytesWritten;

        if (loopIterations) {
            if (!EVP_CIPHER_CTX_reset(evp_ctx)) {
                ERR_print_errors_fp(stderr);
                exit(EXIT_FAILURE);
            }
        }

        EVP_EncryptInit_ex(evp_ctx, st->cryptSt.evpCipher, NULL, st->cryptSt.evpKey, st->cryptSt.hmacKey);
        EVP_CIPHER_CTX_set_padding(evp_ctx, 0);

        if(!EVP_MAC_init(mac_ctx, st->cryptSt.hmacKey, HMAC_KEY_SIZE, params)) {
			ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }

        if (freadWErrCheck(inBuffer, sizeof(*inBuffer), st->cryptSt.fileBufSize, inFile, st) != 0) {
            PRINT_SYS_ERROR(st->miscSt.returnVal);
            PRINT_ERROR("Could not read file for encryption/decryption");
            OPENSSL_cleanse(inBuffer, sizeof(*inBuffer) * (st->cryptSt.fileBufSize + EVP_MAX_BLOCK_LENGTH));
            OPENSSL_cleanse(outBuffer, sizeof(*outBuffer) * (st->cryptSt.fileBufSize + EVP_MAX_BLOCK_LENGTH));
            remove(st->fileNameSt.outputFileName);
            exit(EXIT_FAILURE);
        }

        amountReadLast = st->miscSt.freadAmt;
        bytesRead += amountReadLast;

        uint8_t paddingAmount = 0;

        uint8_t cipherBlockSize = EVP_CIPHER_CTX_get_block_size(evp_ctx);

        if (amountReadLast < st->cryptSt.fileBufSize) {
            remainingBytes = 0;
            st->cryptSt.fileBufSize = amountReadLast;

            if (cipherBlockSize > 1) {
                if (bytesRead % cipherBlockSize) {
                    paddingAmount = cipherBlockSize - (bytesRead % cipherBlockSize);
                } else if (bytesRead % cipherBlockSize == 0) {
                    paddingAmount = cipherBlockSize;
                }

                uint8_t *paddingArray = calloc(paddingAmount, sizeof(*paddingArray));
                memset(paddingArray, paddingAmount, sizeof(paddingAmount) * paddingAmount);

                memcpy(inBuffer + amountReadLast, paddingArray, sizeof(*paddingArray) * paddingAmount);

                DDFREE(free, paddingArray);
            }

        } else {
            remainingBytes -= st->cryptSt.fileBufSize;
        }

        uint32_t evpOutputLength = 0;

        if (!EVP_EncryptUpdate(evp_ctx, outBuffer, &evpOutputLength, inBuffer, st->cryptSt.fileBufSize + paddingAmount)) {
            fprintf(stderr, "EVP_EncryptUpdate failed\n");
            ERR_print_errors_fp(stderr);
            EVP_CIPHER_CTX_cleanup(evp_ctx);

            OPENSSL_cleanse(inBuffer, sizeof(*inBuffer) * (st->cryptSt.fileBufSize + EVP_MAX_BLOCK_LENGTH));
            OPENSSL_cleanse(outBuffer, sizeof(*outBuffer) * (st->cryptSt.fileBufSize + EVP_MAX_BLOCK_LENGTH));

            remove(st->fileNameSt.outputFileName);

            exit(EXIT_FAILURE);
        }

        EVP_MAC_update(mac_ctx, (const unsigned char *)&st->cryptoHeader, sizeof(st->cryptoHeader));
        EVP_MAC_update(mac_ctx, st->cryptSt.passKeyedHash, sizeof(*st->cryptSt.passKeyedHash) * PASS_KEYED_HASH_SIZE);
        EVP_MAC_update(mac_ctx, outBuffer, sizeof(*outBuffer) * evpOutputLength);

        if (paddingAmount) {
            st->cryptSt.fileBufSize += paddingAmount;
        }

        EVP_MAC_update(mac_ctx, (const unsigned char *)&st->cryptSt.fileBufSize, sizeof(st->cryptSt.fileBufSize));

        EVP_MAC_final(mac_ctx, st->cryptSt.generatedMAC, &HMACLengthPtr, EVP_MAC_CTX_get_mac_size(mac_ctx));

        if (fwriteWErrCheck(outBuffer, sizeof(*outBuffer), evpOutputLength, outFile, st) != 0) {
            PRINT_SYS_ERROR(st->miscSt.returnVal);
            PRINT_ERROR("Could not write file for encryption/decryption");

            OPENSSL_cleanse(inBuffer, sizeof(*inBuffer) * (st->cryptSt.fileBufSize + EVP_MAX_BLOCK_LENGTH));
            OPENSSL_cleanse(outBuffer, sizeof(*outBuffer) * (st->cryptSt.fileBufSize + EVP_MAX_BLOCK_LENGTH));

            remove(st->fileNameSt.outputFileName);

            exit(EXIT_FAILURE);
        }

        bytesWritten += evpOutputLength;

        if (fwriteWErrCheck(st->cryptSt.generatedMAC, sizeof(*st->cryptSt.generatedMAC), HMACLengthPtr, outFile, st) != 0) {
            PRINT_SYS_ERROR(st->miscSt.returnVal);
            PRINT_ERROR("Could not write MAC");
            remove(st->fileNameSt.outputFileName);
            exit(EXIT_FAILURE);
        }

        bytesWritten += HMACLengthPtr;

        genHMACKey(st, st->cryptSt.generatedMAC, HMACLengthPtr);
        genChunkKey(st);

        if (st->optSt.benchmark) {
            if (st->optSt.benchmarkTime && st->timeSt.totalTime >= st->timeSt.benchmarkTime) {
                remainingBytes = 0;
            }
        }

        loopIterations++;

#ifdef gui
        *(st->guiSt.progressFraction) = (double)bytesWritten / (double)fileSize;
#endif

        st->timeSt.endBytes = bytesWritten;
        st->timeSt.totalBytes = st->timeSt.endBytes;

        clock_gettime(CLOCK_REALTIME, &end);
        st->timeSt.endLoop = end.tv_nsec / 1000000000.0 + end.tv_sec;

        st->timeSt.loopTime = st->timeSt.endLoop - st->timeSt.startLoop;
        st->timeSt.totalTime += st->timeSt.loopTime;

        double dataRate = (double)((double)st->timeSt.totalBytes / (double)st->timeSt.totalTime) / (1024 * 1024);
#ifdef gui
        sprintf(st->guiSt.statusMessage, "%s %0.0f Mb/s, %0.0fs elapsed", "Encrypting...", dataRate, st->timeSt.totalTime);
#endif
        st->timeSt.averageRate = dataRate;
        
    }

    OPENSSL_cleanse(inBuffer, sizeof(*inBuffer) * (st->cryptSt.fileBufSize + EVP_MAX_BLOCK_LENGTH));
    OPENSSL_cleanse(outBuffer, sizeof(*outBuffer) * (st->cryptSt.fileBufSize + EVP_MAX_BLOCK_LENGTH));

    DDFREE(free, inBuffer);
    DDFREE(free, outBuffer);

    DDFREE(EVP_CIPHER_CTX_free, evp_ctx);
    DDFREE(EVP_MAC_free, mac);
    DDFREE(EVP_MAC_CTX_free, mac_ctx);
}

void doDecrypt(FILE *inFile, FILE *outFile, uint64_t fileSize, struct dataStruct *st)
{
#ifdef gui
    *(st->guiSt.progressFraction) = 0.0;
#endif

    struct timespec begin, end;
    st->timeSt.totalTime = 0;

    uint64_t bytesWritten = 0, bytesRead = 0, amountReadLast = 0;
    uint64_t remainingBytes = fileSize;

    uint64_t loopIterations = 0;

    uint64_t origFileBufSize = st->cryptSt.fileBufSize;

    uint8_t *inBuffer = calloc(st->cryptSt.fileBufSize + EVP_MAX_BLOCK_LENGTH + EVP_MAX_MD_SIZE, sizeof(*inBuffer)), *outBuffer = calloc(st->cryptSt.fileBufSize + EVP_MAX_BLOCK_LENGTH, sizeof(*outBuffer));
    if (inBuffer == NULL || outBuffer == NULL) {
        PRINT_SYS_ERROR(errno);
        PRINT_ERROR("Could not allocate memory for input/output buffers");
        remove(st->fileNameSt.outputFileName);
        exit(EXIT_FAILURE);
    }
    size_t HMACLengthPtr = 0;

    EVP_CIPHER_CTX *evp_ctx = evp_ctx = EVP_CIPHER_CTX_new();
    if (evp_ctx == NULL) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    OSSL_PARAM params[2];

    params[0] = OSSL_PARAM_construct_utf8_string("digest", (char*)st->cryptSt.mdAlgorithm, 0);
    params[1] = OSSL_PARAM_construct_end();

    EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (mac == NULL) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    EVP_MAC_CTX *mac_ctx = EVP_MAC_CTX_new(mac);
    if (mac_ctx == NULL) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    while (remainingBytes) {

        clock_gettime(CLOCK_REALTIME, &begin);
        st->timeSt.startLoop = begin.tv_nsec / 1000000000.0 + begin.tv_sec;
        st->timeSt.startBytes = bytesWritten;

        if (loopIterations) {
            if (!EVP_CIPHER_CTX_reset(evp_ctx)) {
                ERR_print_errors_fp(stderr);
                exit(EXIT_FAILURE);
            }
        }

        EVP_DecryptInit_ex(evp_ctx, st->cryptSt.evpCipher, NULL, st->cryptSt.evpKey, st->cryptSt.hmacKey);
        uint8_t cipherBlockSize = EVP_CIPHER_CTX_get_block_size(evp_ctx);
        EVP_CIPHER_CTX_set_padding(evp_ctx, 0);

        if(!EVP_MAC_init(mac_ctx, st->cryptSt.hmacKey, HMAC_KEY_SIZE, params)) {
			ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }

        if (freadWErrCheck(inBuffer, sizeof(*inBuffer), st->cryptSt.fileBufSize + EVP_MAX_MD_SIZE, inFile, st) != 0) {
            PRINT_SYS_ERROR(st->miscSt.returnVal);
            PRINT_ERROR("Could not read file for encryption/decryption");
            OPENSSL_cleanse(inBuffer, sizeof(*inBuffer) * (st->cryptSt.fileBufSize + EVP_MAX_BLOCK_LENGTH));
            OPENSSL_cleanse(outBuffer, sizeof(*outBuffer) * (st->cryptSt.fileBufSize + EVP_MAX_BLOCK_LENGTH));
            remove(st->fileNameSt.outputFileName);
            exit(EXIT_FAILURE);
        }

        amountReadLast = st->miscSt.freadAmt;
        bytesRead += amountReadLast;

        if (amountReadLast < (st->cryptSt.fileBufSize + EVP_MAX_MD_SIZE)) {
            remainingBytes = 0;

            uint32_t cipherTextEnd = amountReadLast - (EVP_MAX_MD_SIZE);

            st->cryptSt.fileBufSize = amountReadLast - (EVP_MAX_MD_SIZE);

            memcpy(st->cryptSt.fileMAC, inBuffer + cipherTextEnd, EVP_MAX_MD_SIZE);
        } else {
            remainingBytes -= (st->cryptSt.fileBufSize + EVP_MAX_MD_SIZE);

            memcpy(st->cryptSt.fileMAC, inBuffer + st->cryptSt.fileBufSize, EVP_MAX_MD_SIZE);
        }

        uint32_t evpOutputLength = 0;

        EVP_MAC_update(mac_ctx, (const unsigned char *)&st->cryptoHeader, sizeof(st->cryptoHeader));
        EVP_MAC_update(mac_ctx, st->cryptSt.passKeyedHash, sizeof(*st->cryptSt.passKeyedHash) * PASS_KEYED_HASH_SIZE);
        EVP_MAC_update(mac_ctx, inBuffer, sizeof(*inBuffer) * st->cryptSt.fileBufSize);
        EVP_MAC_update(mac_ctx, (const unsigned char *)&st->cryptSt.fileBufSize, sizeof(st->cryptSt.fileBufSize));

        EVP_MAC_final(mac_ctx, st->cryptSt.generatedMAC, &HMACLengthPtr, EVP_MAC_CTX_get_mac_size(mac_ctx));

        if (CRYPTO_memcmp(st->cryptSt.fileMAC, st->cryptSt.generatedMAC, HMACLengthPtr) != 0) {
            printf("Message authentication failed\n");
#ifdef gui
            strcpy(st->guiSt.statusMessage, "Authentication failure");
#endif
            remove(st->fileNameSt.outputFileName);
            exit(EXIT_FAILURE);
        }

        if (!EVP_DecryptUpdate(evp_ctx, outBuffer, &evpOutputLength, inBuffer, st->cryptSt.fileBufSize)) {
            fprintf(stderr, "EVP_DecryptUpdate failed\n");
            ERR_print_errors_fp(stderr);
            EVP_CIPHER_CTX_cleanup(evp_ctx);

            OPENSSL_cleanse(inBuffer, sizeof(*inBuffer) * (st->cryptSt.fileBufSize + EVP_MAX_BLOCK_LENGTH));
            OPENSSL_cleanse(outBuffer, sizeof(*outBuffer) * (st->cryptSt.fileBufSize + EVP_MAX_BLOCK_LENGTH));

            remove(st->fileNameSt.outputFileName);

            exit(EXIT_FAILURE);
        }

        uint8_t paddingAmount = 0;
        if (st->cryptSt.fileBufSize < origFileBufSize) {
            if (cipherBlockSize > 1) {
                paddingAmount = outBuffer[evpOutputLength - 1];
            }

            if (paddingAmount) {
                uint8_t *paddingArray = calloc(paddingAmount, sizeof(*paddingArray));
                memset(paddingArray, paddingAmount, sizeof(*paddingArray) * paddingAmount);

                if (CRYPTO_memcmp((outBuffer + evpOutputLength) - paddingAmount, paddingArray, sizeof(*paddingArray) * paddingAmount) != 0) {
                    printf("Bad padding\n");
#ifdef gui
                    strcpy(st->guiSt.statusMessage, "Bad padding");
#endif
                    remove(st->fileNameSt.outputFileName);
                    exit(EXIT_FAILURE);
                }

                DDFREE(free, paddingArray);
            }
        }

        if (fwriteWErrCheck(outBuffer, sizeof(*outBuffer), evpOutputLength - paddingAmount, outFile, st) != 0) {
            PRINT_SYS_ERROR(st->miscSt.returnVal);
            PRINT_ERROR("Could not write file for encryption/decryption");

            OPENSSL_cleanse(inBuffer, sizeof(*inBuffer) * (st->cryptSt.fileBufSize + EVP_MAX_BLOCK_LENGTH));
            OPENSSL_cleanse(outBuffer, sizeof(*outBuffer) * (st->cryptSt.fileBufSize + EVP_MAX_BLOCK_LENGTH));

            remove(st->fileNameSt.outputFileName);

            exit(EXIT_FAILURE);
        }

        bytesWritten += evpOutputLength;

        genHMACKey(st, st->cryptSt.fileMAC, HMACLengthPtr);
        genChunkKey(st);

#ifdef gui
        *(st->guiSt.progressFraction) = (double)bytesWritten / (double)fileSize;
#endif

        st->timeSt.endBytes = bytesWritten;
        st->timeSt.totalBytes = st->timeSt.endBytes;

        clock_gettime(CLOCK_REALTIME, &end);
        st->timeSt.endLoop = end.tv_nsec / 1000000000.0 + end.tv_sec;

        st->timeSt.loopTime = st->timeSt.endLoop - st->timeSt.startLoop;
        st->timeSt.totalTime += st->timeSt.loopTime;

        double dataRate = (double)((double)st->timeSt.totalBytes / (double)st->timeSt.totalTime) / (1024 * 1024);
#ifdef gui
        sprintf(st->guiSt.statusMessage, "%s %0.0f Mb/s, %0.0fs elapsed", "Decrypting...", dataRate, st->timeSt.totalTime);
#endif
        st->timeSt.averageRate = dataRate;
        loopIterations++;
        
    }

    OPENSSL_cleanse(inBuffer, sizeof(*inBuffer) * (st->cryptSt.fileBufSize + EVP_MAX_BLOCK_LENGTH));
    OPENSSL_cleanse(outBuffer, sizeof(*outBuffer) * (st->cryptSt.fileBufSize + EVP_MAX_BLOCK_LENGTH));

    DDFREE(free, inBuffer);
    DDFREE(free, outBuffer);

    DDFREE(EVP_CIPHER_CTX_free, evp_ctx);
    DDFREE(EVP_MAC_CTX_free, mac_ctx);
    DDFREE(EVP_MAC_free, mac);
}

void genKeyFileHash(FILE *dataFile, uint64_t fileSize, struct dataStruct *st)
{
#ifdef gui
    *(st->guiSt.progressFraction) = 0.0;
#endif

    uint8_t *keyFileHashBuffer = calloc(st->cryptSt.fileBufSize, sizeof(*keyFileHashBuffer));
    if (keyFileHashBuffer == NULL) {
        PRINT_SYS_ERROR(errno);
        PRINT_ERROR("Could not allocate memory for keyFileHashBuffer");
        remove(st->fileNameSt.outputFileName);
        exit(EXIT_FAILURE);
    }
    uint64_t remainingBytes = fileSize;
    uint64_t bytesRead = 0, amountReadLast = 0;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_get_digestbyname(st->cryptSt.mdAlgorithm), NULL);
    
    uint64_t bufferSize = st->cryptSt.fileBufSize;

    uint64_t i;
    for (i = 0; remainingBytes; i += bufferSize) {

#ifdef gui
        struct timespec begin, end;
        clock_gettime(CLOCK_REALTIME, &begin);
        st->guiSt.startLoop = begin.tv_nsec / 1000000000.0 + begin.tv_sec;

        st->guiSt.startBytes = bytesRead;
#endif

        if (bufferSize > remainingBytes) {
            bufferSize = remainingBytes;
        }

        if (freadWErrCheck(keyFileHashBuffer, sizeof(*keyFileHashBuffer), bufferSize, dataFile, st) != 0) {
            PRINT_SYS_ERROR(st->miscSt.returnVal);
            PRINT_ERROR("Could not generate keyFile Hash");

            OPENSSL_cleanse(keyFileHashBuffer, sizeof(*keyFileHashBuffer) * bufferSize);

            remove(st->fileNameSt.outputFileName);

            exit(EXIT_FAILURE);
        }

        amountReadLast = st->miscSt.freadAmt;
        bytesRead += amountReadLast;

        if (amountReadLast < bufferSize) {
            remainingBytes = 0;
            bufferSize = amountReadLast;
        } else {
            remainingBytes -= bufferSize;
        }

        EVP_DigestUpdate(ctx, keyFileHashBuffer, sizeof(*keyFileHashBuffer) * bufferSize);

        bytesRead += bufferSize;
        remainingBytes -= bufferSize;

#ifdef gui
        *(st->guiSt.progressFraction) = (double)i / (double)fileSize;

        st->guiSt.endBytes = bytesRead;
        st->guiSt.totalBytes = st->guiSt.endBytes;

        clock_gettime(CLOCK_REALTIME, &end);
        st->guiSt.endLoop = end.tv_nsec / 1000000000.0 + end.tv_sec;

        st->guiSt.loopTime = st->guiSt.endLoop - st->guiSt.startLoop;
        st->guiSt.totalTime += st->guiSt.loopTime;

        double dataRate = (double)((double)st->guiSt.totalBytes / (double)st->guiSt.totalTime) / (1024 * 1024);
        sprintf(st->guiSt.statusMessage, "%s %0.0f Mb/s, %0.0fs elapsed", "Hashing keyfile...", dataRate, st->guiSt.totalTime);
#endif
    }
    EVP_DigestFinal_ex(ctx, st->cryptSt.keyFileHash, NULL);
    DDFREE(EVP_MD_CTX_free, ctx);
    OPENSSL_cleanse(keyFileHashBuffer, sizeof(*keyFileHashBuffer) * bufferSize);
    DDFREE(free, keyFileHashBuffer);
}

void genChunkKey(struct dataStruct *st)
{
    EVP_PKEY_CTX *pctx;
    size_t outlen = sizeof(*st->cryptSt.evpKey) * EVP_MAX_KEY_LENGTH;
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);

    if (EVP_PKEY_derive_init(pctx) <= 0) {
        PRINT_ERROR("EVP_PKEY_derive_init failed\n");
        ERR_print_errors_fp(stderr);
        remove(st->fileNameSt.outputFileName);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, st->cryptSt.evpDigest) <= 0) {
        PRINT_ERROR("EVP_PKEY_CTX_set_hkdf_md\n");
        ERR_print_errors_fp(stderr);
        remove(st->fileNameSt.outputFileName);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, st->cryptSt.evpKey, sizeof(*st->cryptSt.evpKey) * EVP_MAX_KEY_LENGTH) <= 0) {
        PRINT_ERROR("EVP_PKEY_CTX_set1_hkdf_key\n");
        ERR_print_errors_fp(stderr);
        remove(st->fileNameSt.outputFileName);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, st->cryptSt.evpSalt, sizeof(*st->cryptSt.evpSalt) * EVP_SALT_SIZE) <= 0) {
        PRINT_ERROR("EVP_PKEY_CTX_set1_hkdf_salt failed\n");
        ERR_print_errors_fp(stderr);
        remove(st->fileNameSt.outputFileName);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, "chunkkey", strlen("chunkkey")) <= 0) {
        PRINT_ERROR("EVP_PKEY_CTX_add1_hkdf_info failed\n");
        ERR_print_errors_fp(stderr);
        remove(st->fileNameSt.outputFileName);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_derive(pctx, st->cryptSt.evpKey, &outlen) <= 0) {
        PRINT_ERROR("EVP_PKEY_derive failed\n");
        ERR_print_errors_fp(stderr);
        remove(st->fileNameSt.outputFileName);
        exit(EXIT_FAILURE);
    }

    DDFREE(EVP_PKEY_CTX_free, pctx);
}

void genHMACKey(struct dataStruct *st, uint8_t *lastChunk, uint32_t chunkSize)
{
    EVP_PKEY_CTX *pctx;
    size_t outlen = sizeof(*st->cryptSt.hmacKey) * HMAC_KEY_SIZE;
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);

    if (EVP_PKEY_derive_init(pctx) <= 0) {
        PRINT_ERROR("EVP_PKEY_derive_init failed\n");
        ERR_print_errors_fp(stderr);
        remove(st->fileNameSt.outputFileName);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, st->cryptSt.evpDigest) <= 0) {
        PRINT_ERROR("EVP_PKEY_CTX_set_hkdf_md failed\n");
        ERR_print_errors_fp(stderr);
        remove(st->fileNameSt.outputFileName);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, st->cryptSt.evpKey, sizeof(*st->cryptSt.evpKey) * EVP_MAX_KEY_LENGTH) <= 0) {
        PRINT_ERROR("EVP_PKEY_CTX_set1_hkdf_key failed\n");
        ERR_print_errors_fp(stderr);
        remove(st->fileNameSt.outputFileName);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, st->cryptSt.evpSalt, sizeof(*st->cryptSt.evpSalt) * EVP_SALT_SIZE) <= 0) {
        PRINT_ERROR("EVP_PKEY_CTX_set1_hkdf_salt failed\n");
        ERR_print_errors_fp(stderr);
        remove(st->fileNameSt.outputFileName);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, "authkey", strlen("authkey")) <= 0) {
        PRINT_ERROR("EVP_PKEY_CTX_add1_hkdf_info failed\n");
        ERR_print_errors_fp(stderr);
        remove(st->fileNameSt.outputFileName);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, lastChunk, chunkSize) <= 0) {
        PRINT_ERROR("EVP_PKEY_CTX_add1_hkdf_info failed\n");
        ERR_print_errors_fp(stderr);
        remove(st->fileNameSt.outputFileName);
    }
    if (EVP_PKEY_derive(pctx, st->cryptSt.hmacKey, &outlen) <= 0) {
        PRINT_ERROR("EVP_PKEY_derive failed\n");
        ERR_print_errors_fp(stderr);
        remove(st->fileNameSt.outputFileName);
        exit(EXIT_FAILURE);
    }

    DDFREE(EVP_PKEY_CTX_free, pctx);
}

void genPassTag(struct dataStruct *st)
{

#ifdef gui
    *(st->guiSt.progressFraction) = 0;
#endif

    if (HMAC(EVP_get_digestbyname(st->cryptSt.mdAlgorithm), st->cryptSt.hmacKey, HMAC_KEY_SIZE, (const unsigned char *)st->cryptSt.userPass, strlen(st->cryptSt.userPass), st->cryptSt.passKeyedHash, st->cryptSt.HMACLengthPtr) == NULL) {
        PRINT_ERROR("Password keyed-hash failure");
        ERR_print_errors_fp(stderr);
        remove(st->fileNameSt.outputFileName);
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
        PRINT_ERROR("EVP_PKEY_derive_init failed\n");
        ERR_print_errors_fp(stderr);
        remove(st->fileNameSt.outputFileName);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_set1_pbe_pass(pctx, st->cryptSt.userPass, strlen(st->cryptSt.userPass)) <= 0) {
        PRINT_ERROR("EVP_PKEY_CTX_set1_pbe_pass failed\n");
        ERR_print_errors_fp(stderr);
        remove(st->fileNameSt.outputFileName);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_set1_scrypt_salt(pctx, st->cryptSt.evpSalt, sizeof(*st->cryptSt.evpSalt) * EVP_SALT_SIZE) <= 0) {
        PRINT_ERROR("EVP_PKEY_CTX_set1_scrypt_salt failed\n");
        ERR_print_errors_fp(stderr);
        remove(st->fileNameSt.outputFileName);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_set_scrypt_N(pctx, st->cryptSt.nFactor) <= 0) {
        PRINT_ERROR("EVP_PKEY_CTX_set_scrypt_N failed\n");
        ERR_print_errors_fp(stderr);
        remove(st->fileNameSt.outputFileName);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_set_scrypt_r(pctx, st->cryptSt.rFactor) <= 0) {
        PRINT_ERROR("EVP_PKEY_CTX_set_scrypt_r failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_set_scrypt_p(pctx, st->cryptSt.pFactor) <= 0) {
        PRINT_ERROR("EVP_PKEY_CTX_set_scrypt_p failed\n");
        ERR_print_errors_fp(stderr);
        remove(st->fileNameSt.outputFileName);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_derive(pctx, st->cryptSt.evpKey, &outlen) <= 0) {
        PRINT_ERROR("EVP_PKEY_derive failed\n");
        ERR_print_errors_fp(stderr);
        remove(st->fileNameSt.outputFileName);
        exit(EXIT_FAILURE);
    }

    DDFREE(EVP_PKEY_CTX_free, pctx);
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
        PRINT_ERROR("EVP_PKEY_derive_init failed\n");
        ERR_print_errors_fp(stderr);
        remove(st->fileNameSt.outputFileName);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, st->cryptSt.evpDigest) <= 0) {
        PRINT_ERROR("EVP_PKEY_CTX_set_hkdf_md failed\n");
        ERR_print_errors_fp(stderr);
        remove(st->fileNameSt.outputFileName);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, st->cryptSt.evpKey, sizeof(st->cryptSt.evpKey)) <= 0) {
        PRINT_ERROR("EVP_PKEY_CTX_set1_hkdf_ke failed\n");
        ERR_print_errors_fp(stderr);
        remove(st->fileNameSt.outputFileName);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, st->cryptSt.keyFileHash, sizeof(st->cryptSt.keyFileHash)) <= 0) {
        PRINT_ERROR("EVP_PKEY_CTX_set1_hkdf_saltfailed\n");
        ERR_print_errors_fp(stderr);
        remove(st->fileNameSt.outputFileName);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, "keyfile", strlen("keyfile")) <= 0) {
        PRINT_ERROR("EVP_PKEY_CTX_add1_hkdf_info failed\n");
        ERR_print_errors_fp(stderr);
        remove(st->fileNameSt.outputFileName);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_derive(pctx, st->cryptSt.evpKey, &outlen) <= 0) {
        PRINT_ERROR("EVP_PKEY_derive failed\n");
        ERR_print_errors_fp(stderr);
        remove(st->fileNameSt.outputFileName);
        exit(EXIT_FAILURE);
    }

    DDFREE(EVP_PKEY_CTX_free, pctx);
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
            PRINT_ERROR("Aborting: CSPRNG bytes may not be unpredictable");
            remove(st->fileNameSt.outputFileName);
            exit(EXIT_FAILURE);
        }
        st->cryptSt.evpSalt[i] = b;
#ifdef gui
        *(st->guiSt.progressFraction) = (double)i / saltSizeFloat;
#endif
    }
}
