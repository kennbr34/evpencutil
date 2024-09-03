#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <time.h>
#include "lib.h"

void doEncrypt(FILE *inFile, FILE *outFile, uint64_t fileSize, struct dataStruct *st) 
{
    #ifdef gui
    *(st->guiSt.progressFraction) = 0.0;
    #endif
    
    uint64_t bytesWritten = 0, bytesRead = 0, amountReadLast = 0;
    uint64_t remainingBytes = fileSize;
    uint32_t evpOutputLength = 0;
    
    uint64_t loopIterations = 0;
    
    uint8_t *inBuffer = calloc(st->cryptSt.fileBufSize + EVP_MAX_BLOCK_LENGTH, sizeof(*inBuffer)), *outBuffer = calloc(st->cryptSt.fileBufSize + EVP_MAX_BLOCK_LENGTH, sizeof(*outBuffer));
    if (inBuffer == NULL || outBuffer == NULL) {
        PRINT_SYS_ERROR(errno);
        PRINT_ERROR("Could not allocate memory for doCrypt buffers");
        remove(st->fileNameSt.outputFileName);
        exit(EXIT_FAILURE);
    }
    
    uint32_t hmacBufferSize = sizeof(st->cryptoHeader) + (sizeof(*st->cryptSt.passKeyedHash) * PASS_KEYED_HASH_SIZE) + (sizeof(*outBuffer) * st->cryptSt.fileBufSize);
    uint8_t *hmacBuffer = calloc(hmacBufferSize, sizeof(*hmacBuffer));
    if (hmacBuffer == NULL) {
        PRINT_SYS_ERROR(errno);
        PRINT_ERROR("Could not allocate memory for doCrypt buffers");
        remove(st->fileNameSt.outputFileName);
        exit(EXIT_FAILURE);
    }

    EVP_CIPHER_CTX *evp_ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(evp_ctx);
    EVP_EncryptInit_ex(evp_ctx, st->cryptSt.evpCipher, NULL, st->cryptSt.evpKey, st->cryptSt.hmacKey);
    
    EVP_MD_CTX *md_ctx = NULL;
            
    uint32_t HMACLengthPtr = 0;
    
    #ifdef gui
    st->guiSt.totalTime = 0;
    #endif
    
    while (remainingBytes) {
        
        if(!loopIterations) {
            md_ctx = EVP_MD_CTX_new();
        } else {
            EVP_MD_CTX_reset(md_ctx);
        }
        
        EVP_DigestInit_ex(md_ctx, EVP_get_digestbyname(st->cryptSt.mdAlgorithm), NULL);
        
        #ifdef gui
        struct timespec begin, end;
		clock_gettime(CLOCK_REALTIME, &begin);
		st->guiSt.startLoop = begin.tv_nsec / 1000000000.0 + begin.tv_sec;
		
        st->guiSt.startBytes = bytesWritten;
        #endif

        if (freadWErrCheck(inBuffer, sizeof(*inBuffer), st->cryptSt.fileBufSize, inFile, st) != 0) {
            PRINT_SYS_ERROR(st->miscSt.returnVal);
            PRINT_ERROR("Could not read file for encryption/decryption");
            OPENSSL_cleanse(inBuffer,sizeof(*inBuffer) * (st->cryptSt.fileBufSize + EVP_MAX_BLOCK_LENGTH));
            OPENSSL_cleanse(outBuffer,sizeof(*outBuffer) * (st->cryptSt.fileBufSize + EVP_MAX_BLOCK_LENGTH));
            remove(st->fileNameSt.outputFileName);
            exit(EXIT_FAILURE);
        }
                    
        amountReadLast = st->miscSt.freadAmt;
        bytesRead += amountReadLast;
        
        if(amountReadLast < st->cryptSt.fileBufSize) {
            remainingBytes = 0;
            st->cryptSt.fileBufSize = amountReadLast;
        } else {
            remainingBytes -= st->cryptSt.fileBufSize;
        }
        
        if (!EVP_EncryptUpdate(evp_ctx, outBuffer, &evpOutputLength, inBuffer, st->cryptSt.fileBufSize)) {
            fprintf(stderr, "EVP_EncryptUpdate failed\n");
            ERR_print_errors_fp(stderr);
            EVP_CIPHER_CTX_cleanup(evp_ctx);
            
            OPENSSL_cleanse(inBuffer,sizeof(*inBuffer) * (st->cryptSt.fileBufSize + EVP_MAX_BLOCK_LENGTH));
            OPENSSL_cleanse(outBuffer,sizeof(*outBuffer) * (st->cryptSt.fileBufSize + EVP_MAX_BLOCK_LENGTH));
            
            remove(st->fileNameSt.outputFileName);
            
            exit(EXIT_FAILURE);
        }

        if (fwriteWErrCheck(outBuffer, sizeof(*outBuffer), evpOutputLength, outFile, st) != 0) {
            PRINT_SYS_ERROR(st->miscSt.returnVal);
            PRINT_ERROR("Could not write file for encryption/decryption");
            
            OPENSSL_cleanse(inBuffer,sizeof(*inBuffer) * (st->cryptSt.fileBufSize + EVP_MAX_BLOCK_LENGTH));
            OPENSSL_cleanse(outBuffer,sizeof(*outBuffer) * (st->cryptSt.fileBufSize + EVP_MAX_BLOCK_LENGTH));
            
            remove(st->fileNameSt.outputFileName);
            
            exit(EXIT_FAILURE);
        }
        bytesWritten += evpOutputLength;
        
        EVP_DigestUpdate(md_ctx, &st->cryptoHeader, sizeof(st->cryptoHeader));
        EVP_DigestUpdate(md_ctx, st->cryptSt.passKeyedHash, sizeof(*st->cryptSt.passKeyedHash) * PASS_KEYED_HASH_SIZE);
        EVP_DigestUpdate(md_ctx, outBuffer, sizeof(*outBuffer) * evpOutputLength);
        
        /* Do not write MAC if remainingBytes is zero and the cipher is a block cipher, in order
         * to prevent messing up the padding */
         
        uint8_t cipherNeedsPadding = 0;
        
        if(bytesWritten % EVP_CIPHER_CTX_block_size(evp_ctx) != 0) {
            cipherNeedsPadding = 1;
        }
        
        if(!cipherNeedsPadding) {
            
            EVP_DigestFinal_ex(md_ctx, st->cryptSt.generatedMAC, &HMACLengthPtr);
            
            if (fwriteWErrCheck(st->cryptSt.generatedMAC, sizeof(*st->cryptSt.generatedMAC), HMACLengthPtr, outFile, st) != 0) {
                PRINT_SYS_ERROR(st->miscSt.returnVal);
                PRINT_ERROR("Could not write MAC");
                remove(st->fileNameSt.outputFileName);
                exit(EXIT_FAILURE);
            }
            bytesWritten += HMACLengthPtr;
        }
            
        
        #ifdef gui
        *(st->guiSt.progressFraction) = (double)bytesWritten / (double)fileSize;
        
         st->guiSt.endBytes = bytesWritten;
         st->guiSt.totalBytes = st->guiSt.endBytes;
        
        clock_gettime(CLOCK_REALTIME, &end);
        st->guiSt.endLoop = end.tv_nsec / 1000000000.0 + end.tv_sec;

        st->guiSt.loopTime = st->guiSt.endLoop - st->guiSt.startLoop;
        st->guiSt.totalTime += st->guiSt.loopTime;

        double dataRate = (double)((double)st->guiSt.totalBytes / (double)st->guiSt.totalTime) / (1024 * 1024);
        sprintf(st->guiSt.statusMessage, "%s %0.0f Mb/s, %0.0fs elapsed", "Encrypting...", dataRate, st->guiSt.totalTime);
        st->guiSt.averageRate = dataRate;
        #endif
        loopIterations++;
    }

    if (!EVP_EncryptFinal_ex(evp_ctx, outBuffer, &evpOutputLength)) {
        fprintf(stderr, "EVP_EncryptFinal_ex failed\n");
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_cleanup(evp_ctx);
        
        OPENSSL_cleanse(inBuffer,sizeof(*inBuffer) * (st->cryptSt.fileBufSize + EVP_MAX_BLOCK_LENGTH));
        OPENSSL_cleanse(outBuffer,sizeof(*outBuffer) * (st->cryptSt.fileBufSize + EVP_MAX_BLOCK_LENGTH));
        
        remove(st->fileNameSt.outputFileName);
        
        exit(EXIT_FAILURE);
    }
    
    if(evpOutputLength) {
        
        if (fwriteWErrCheck(outBuffer, sizeof(*outBuffer), evpOutputLength, outFile, st) != 0) {
            PRINT_SYS_ERROR(st->miscSt.returnVal);
            PRINT_ERROR("Could not write file for encryption/decryption");
            
            OPENSSL_cleanse(inBuffer,sizeof(*inBuffer) * (st->cryptSt.fileBufSize + EVP_MAX_BLOCK_LENGTH));
            OPENSSL_cleanse(outBuffer,sizeof(*outBuffer) * (st->cryptSt.fileBufSize + EVP_MAX_BLOCK_LENGTH));
            
            remove(st->fileNameSt.outputFileName);
            
            exit(EXIT_FAILURE);
        }
           
        bytesWritten += evpOutputLength;
                        
        EVP_DigestUpdate(md_ctx, outBuffer, sizeof(*outBuffer) * evpOutputLength);
        EVP_DigestUpdate(md_ctx, &bytesWritten, sizeof(bytesWritten));
        
        EVP_DigestFinal_ex(md_ctx, st->cryptSt.generatedMAC, &HMACLengthPtr);
        
        if (fwriteWErrCheck(st->cryptSt.generatedMAC, sizeof(*st->cryptSt.generatedMAC), HMACLengthPtr, outFile, st) != 0) {
            PRINT_SYS_ERROR(st->miscSt.returnVal);
            PRINT_ERROR("Could not write MAC");
            remove(st->fileNameSt.outputFileName);
            exit(EXIT_FAILURE);
        }
        
        bytesWritten += HMACLengthPtr;
    }
    
    EVP_CIPHER_CTX_free(evp_ctx);
    EVP_MD_CTX_free(md_ctx);
    OPENSSL_cleanse(inBuffer,sizeof(*inBuffer) * (st->cryptSt.fileBufSize + EVP_MAX_BLOCK_LENGTH));
    OPENSSL_cleanse(outBuffer,sizeof(*outBuffer) * (st->cryptSt.fileBufSize + EVP_MAX_BLOCK_LENGTH));

    free(inBuffer);
    free(outBuffer);
    free(hmacBuffer);
}

void doDecrypt(FILE *inFile, FILE *outFile, uint64_t fileSize, struct dataStruct *st)
{
    #ifdef gui
    *(st->guiSt.progressFraction) = 0.0;
    #endif
    
    uint64_t bytesWritten = 0, bytesRead = 0, amountReadLast = 0;
    uint64_t remainingBytes = fileSize;
    uint32_t evpOutputLength = 0;
    
    uint64_t loopIterations = 0;
    
    uint8_t *inBuffer = calloc(st->cryptSt.fileBufSize + EVP_MAX_BLOCK_LENGTH + EVP_MAX_MD_SIZE, sizeof(*inBuffer)), *outBuffer = calloc(st->cryptSt.fileBufSize + EVP_MAX_BLOCK_LENGTH, sizeof(*outBuffer));
    if (inBuffer == NULL || outBuffer == NULL) {
        PRINT_SYS_ERROR(errno);
        PRINT_ERROR("Could not allocate memory for doCrypt buffers");
        remove(st->fileNameSt.outputFileName);
        exit(EXIT_FAILURE);
    }
    
    uint32_t hmacBufferSize = sizeof(st->cryptoHeader) + (sizeof(*st->cryptSt.passKeyedHash) * PASS_KEYED_HASH_SIZE) + (sizeof(*outBuffer) * st->cryptSt.fileBufSize);
    uint8_t *hmacBuffer = calloc(hmacBufferSize, sizeof(*hmacBuffer));
    if (hmacBuffer == NULL) {
        PRINT_SYS_ERROR(errno);
        PRINT_ERROR("Could not allocate memory for doCrypt buffers");
        remove(st->fileNameSt.outputFileName);
        exit(EXIT_FAILURE);
    }

    EVP_CIPHER_CTX *evp_ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(evp_ctx);
    EVP_DecryptInit_ex(evp_ctx, st->cryptSt.evpCipher, NULL, st->cryptSt.evpKey, st->cryptSt.hmacKey);
    
    EVP_MD_CTX *md_ctx = NULL;
    
    uint32_t HMACLengthPtr = 0;
    
    #ifdef gui
    st->guiSt.totalTime = 0;
    #endif
    
    while (remainingBytes) {
        
        if(!loopIterations) {
            md_ctx = EVP_MD_CTX_new();
        } else {
            EVP_MD_CTX_reset(md_ctx);
        }
        
        EVP_DigestInit_ex(md_ctx, EVP_get_digestbyname(st->cryptSt.mdAlgorithm), NULL);
                
        #ifdef gui
        struct timespec begin, end;
		clock_gettime(CLOCK_REALTIME, &begin);
		st->guiSt.startLoop = begin.tv_nsec / 1000000000.0 + begin.tv_sec;
		
        st->guiSt.startBytes = bytesWritten;
        #endif

        if (freadWErrCheck(inBuffer, sizeof(*inBuffer), st->cryptSt.fileBufSize + EVP_MAX_MD_SIZE, inFile, st) != 0) {
            PRINT_SYS_ERROR(st->miscSt.returnVal);
            PRINT_ERROR("Could not read file for encryption/decryption");
            OPENSSL_cleanse(inBuffer,sizeof(*inBuffer) * (st->cryptSt.fileBufSize + EVP_MAX_BLOCK_LENGTH));
            OPENSSL_cleanse(outBuffer,sizeof(*outBuffer) * (st->cryptSt.fileBufSize + EVP_MAX_BLOCK_LENGTH));
            remove(st->fileNameSt.outputFileName);
            exit(EXIT_FAILURE);
        }
        
        amountReadLast = st->miscSt.freadAmt;
        bytesRead += amountReadLast;
        
        if(amountReadLast < (st->cryptSt.fileBufSize + EVP_MAX_MD_SIZE)) {
            remainingBytes = 0;
            
            uint32_t cipherTextEnd = amountReadLast - (EVP_MAX_MD_SIZE);
            
            st->cryptSt.fileBufSize = amountReadLast - (EVP_MAX_MD_SIZE);
            
            memcpy(st->cryptSt.fileMAC,inBuffer + cipherTextEnd, EVP_MAX_MD_SIZE);
        } else {
            remainingBytes -= (st->cryptSt.fileBufSize + EVP_MAX_MD_SIZE);
            
            memcpy(st->cryptSt.fileMAC,inBuffer + st->cryptSt.fileBufSize, EVP_MAX_MD_SIZE);
        }
            EVP_DigestUpdate(md_ctx, &st->cryptoHeader, sizeof(st->cryptoHeader));
            EVP_DigestUpdate(md_ctx, st->cryptSt.passKeyedHash, sizeof(*st->cryptSt.passKeyedHash) * PASS_KEYED_HASH_SIZE);
            EVP_DigestUpdate(md_ctx, inBuffer, sizeof(*inBuffer) * st->cryptSt.fileBufSize);
            EVP_DigestFinal_ex(md_ctx, st->cryptSt.generatedMAC, &HMACLengthPtr);
                        
            if (CRYPTO_memcmp(st->cryptSt.fileMAC, st->cryptSt.generatedMAC, sizeof(*st->cryptSt.generatedMAC) * EVP_MAX_MD_SIZE) != 0) {
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
            
            OPENSSL_cleanse(inBuffer,sizeof(*inBuffer) * (st->cryptSt.fileBufSize + EVP_MAX_BLOCK_LENGTH));
            OPENSSL_cleanse(outBuffer,sizeof(*outBuffer) * (st->cryptSt.fileBufSize + EVP_MAX_BLOCK_LENGTH));
            
            remove(st->fileNameSt.outputFileName);

            exit(EXIT_FAILURE);
        }

        if (fwriteWErrCheck(outBuffer, sizeof(*outBuffer), evpOutputLength, outFile, st) != 0) {
            PRINT_SYS_ERROR(st->miscSt.returnVal);
            PRINT_ERROR("Could not write file for encryption/decryption");
            
            OPENSSL_cleanse(inBuffer,sizeof(*inBuffer) * (st->cryptSt.fileBufSize + EVP_MAX_BLOCK_LENGTH));
            OPENSSL_cleanse(outBuffer,sizeof(*outBuffer) * (st->cryptSt.fileBufSize + EVP_MAX_BLOCK_LENGTH));
            
            remove(st->fileNameSt.outputFileName);
            
            exit(EXIT_FAILURE);
        }
        bytesWritten += evpOutputLength;
        
        #ifdef gui
        *(st->guiSt.progressFraction) = (double)bytesWritten / (double)fileSize;
        
         st->guiSt.endBytes = bytesWritten;
         st->guiSt.totalBytes = st->guiSt.endBytes;
        
        clock_gettime(CLOCK_REALTIME, &end);
        st->guiSt.endLoop = end.tv_nsec / 1000000000.0 + end.tv_sec;

        st->guiSt.loopTime = st->guiSt.endLoop - st->guiSt.startLoop;
        st->guiSt.totalTime += st->guiSt.loopTime;

        double dataRate = (double)((double)st->guiSt.totalBytes / (double)st->guiSt.totalTime) / (1024 * 1024);
        sprintf(st->guiSt.statusMessage, "%s %0.0f Mb/s, %0.0fs elapsed", "Decrypting...", dataRate, st->guiSt.totalTime);
        st->guiSt.averageRate = dataRate;
        #endif
        loopIterations++;
    }

    if (!EVP_DecryptFinal_ex(evp_ctx, outBuffer, &evpOutputLength)) {
        fprintf(stderr, "EVP_DecryptFinal_ex failed \n");
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_cleanup(evp_ctx);
        
        OPENSSL_cleanse(inBuffer,sizeof(*inBuffer) * (st->cryptSt.fileBufSize + EVP_MAX_BLOCK_LENGTH));
        OPENSSL_cleanse(outBuffer,sizeof(*outBuffer) * (st->cryptSt.fileBufSize + EVP_MAX_BLOCK_LENGTH));
        
        remove(st->fileNameSt.outputFileName);
        
        exit(EXIT_FAILURE);
    }

    EVP_CIPHER_CTX_free(evp_ctx);
    EVP_MD_CTX_free(md_ctx);
    
    if(evpOutputLength) {
        
        if (fwriteWErrCheck(outBuffer, sizeof(*outBuffer), evpOutputLength, outFile, st) != 0) {
            PRINT_SYS_ERROR(st->miscSt.returnVal);
            PRINT_ERROR("Could not write file for encryption/decryption");
            
            OPENSSL_cleanse(inBuffer,sizeof(*inBuffer) * (st->cryptSt.fileBufSize + EVP_MAX_BLOCK_LENGTH));
            OPENSSL_cleanse(outBuffer,sizeof(*outBuffer) * (st->cryptSt.fileBufSize + EVP_MAX_BLOCK_LENGTH));
            
            remove(st->fileNameSt.outputFileName);
            
            exit(EXIT_FAILURE);
        }
    }
    
    OPENSSL_cleanse(inBuffer,sizeof(*inBuffer) * (st->cryptSt.fileBufSize + EVP_MAX_BLOCK_LENGTH));
    OPENSSL_cleanse(outBuffer,sizeof(*outBuffer) * (st->cryptSt.fileBufSize + EVP_MAX_BLOCK_LENGTH));

    free(inBuffer);
    free(outBuffer);
    free(hmacBuffer);
}

void genKeyFileHash(FILE *dataFile, uint64_t fileSize, struct dataStruct *st)
{
    #ifdef gui
    *(st->guiSt.progressFraction) = 0.0;
    #endif

    uint8_t *keyFileHashBuffer = calloc(st->cryptSt.genAuthBufSize, sizeof(*keyFileHashBuffer));
    if (keyFileHashBuffer == NULL) {
        PRINT_SYS_ERROR(errno);
        PRINT_ERROR("Could not allocate memory for keyFileHashBuffer");
        remove(st->fileNameSt.outputFileName);
        exit(EXIT_FAILURE);
    }
    uint64_t remainingBytes = fileSize;
    uint64_t bytesRead = 0, amountReadLast =0;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_get_digestbyname(st->cryptSt.mdAlgorithm), NULL);

    uint64_t i;
    for (i = 0; remainingBytes; i += st->cryptSt.genAuthBufSize) {

        #ifdef gui
        struct timespec begin, end;
		clock_gettime(CLOCK_REALTIME, &begin);
		st->guiSt.startLoop = begin.tv_nsec / 1000000000.0 + begin.tv_sec;
		
        st->guiSt.startBytes = bytesRead;
        #endif

        if (st->cryptSt.genAuthBufSize > remainingBytes) {
            st->cryptSt.genAuthBufSize = remainingBytes;
        }

        if (freadWErrCheck(keyFileHashBuffer, sizeof(*keyFileHashBuffer), st->cryptSt.genAuthBufSize, dataFile, st) != 0) {
            PRINT_SYS_ERROR(st->miscSt.returnVal);
            PRINT_ERROR("Could not generate keyFile Hash");
            
            OPENSSL_cleanse(keyFileHashBuffer,sizeof(*keyFileHashBuffer) * st->cryptSt.genAuthBufSize);
            
            remove(st->fileNameSt.outputFileName);
            
            exit(EXIT_FAILURE);
        }
        
        amountReadLast = st->miscSt.freadAmt;
        bytesRead += amountReadLast;
        
        if(amountReadLast < st->cryptSt.genAuthBufSize) {
			remainingBytes = 0;
			st->cryptSt.genAuthBufSize = amountReadLast;
		} else {
			remainingBytes -= st->cryptSt.genAuthBufSize;
		}
        
        EVP_DigestUpdate(ctx, keyFileHashBuffer, sizeof(*keyFileHashBuffer) * st->cryptSt.genAuthBufSize);

		bytesRead += st->cryptSt.genAuthBufSize;
        remainingBytes -= st->cryptSt.genAuthBufSize;
        
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
    EVP_MD_CTX_free(ctx);
    OPENSSL_cleanse(keyFileHashBuffer,sizeof(*keyFileHashBuffer) * st->cryptSt.genAuthBufSize);
    free(keyFileHashBuffer);
}

void genHMAC(FILE *dataFile, uint64_t fileSize, struct dataStruct *st)
{
    #ifdef gui
    *(st->guiSt.progressFraction) = 0.0;
    #endif

    uint8_t *genAuthBuffer = calloc(st->cryptSt.genAuthBufSize, sizeof(*genAuthBuffer));
    if (genAuthBuffer == NULL) {
        PRINT_SYS_ERROR(errno);
        PRINT_ERROR("Could not allocate memory for genAuthBuffer");
        remove(st->fileNameSt.outputFileName);
        exit(EXIT_FAILURE);
    }
    uint64_t remainingBytes = fileSize;
    uint64_t bytesRead = 0;

    HMAC_CTX *ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, st->cryptSt.hmacKey, HMAC_KEY_SIZE, EVP_get_digestbyname(st->cryptSt.mdAlgorithm), NULL);

    uint64_t i;
    for (i = 0; remainingBytes; i += st->cryptSt.genAuthBufSize) {

        #ifdef gui
        struct timespec begin, end;
		clock_gettime(CLOCK_REALTIME, &begin);
		st->guiSt.startLoop = begin.tv_nsec / 1000000000.0 + begin.tv_sec;
		
        st->guiSt.startBytes = bytesRead;
        #endif

        if (st->cryptSt.genAuthBufSize > remainingBytes) {
            st->cryptSt.genAuthBufSize = remainingBytes;
        }

        if (freadWErrCheck(genAuthBuffer, sizeof(*genAuthBuffer), st->cryptSt.genAuthBufSize, dataFile, st) != 0) {
            PRINT_SYS_ERROR(st->miscSt.returnVal);
            PRINT_ERROR("Could not generate HMAC");
            exit(EXIT_FAILURE);
        }
        HMAC_Update(ctx, genAuthBuffer, sizeof(*genAuthBuffer) * st->cryptSt.genAuthBufSize);

		bytesRead += st->cryptSt.genAuthBufSize;
        remainingBytes -= st->cryptSt.genAuthBufSize;
        #ifdef gui
        *(st->guiSt.progressFraction) = (double)i / (double)fileSize;
        
         st->guiSt.endBytes = bytesRead;
         st->guiSt.totalBytes = st->guiSt.endBytes;
        
        clock_gettime(CLOCK_REALTIME, &end);
        st->guiSt.endLoop = end.tv_nsec / 1000000000.0 + end.tv_sec;

        st->guiSt.loopTime = st->guiSt.endLoop - st->guiSt.startLoop;
        st->guiSt.totalTime += st->guiSt.loopTime;

        double dataRate = (double)((double)st->guiSt.totalBytes / (double)st->guiSt.totalTime) / (1024 * 1024);
        sprintf(st->guiSt.statusMessage, "%s %0.0f Mb/s, %0.0fs elapsed", "Authenticating data...", dataRate, st->guiSt.totalTime);
        #endif
    }
    HMAC_Final(ctx, st->cryptSt.generatedMAC, (unsigned int *)&fileSize);
    HMAC_CTX_free(ctx);
    free(genAuthBuffer);
}

void genChunkKey(struct dataStruct *st)
{

    #ifdef gui
    strcpy(st->guiSt.statusMessage, "Deriving chunk key...");
    #endif

    EVP_PKEY_CTX *pctx;
    size_t outlen = sizeof(*st->cryptSt.evpKey) * EVP_MAX_KEY_LENGTH;
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);

    if (EVP_PKEY_derive_init(pctx) <= 0) {
        PRINT_ERROR("HKDF failed\n");
        ERR_print_errors_fp(stderr);
        remove(st->fileNameSt.outputFileName);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_get_digestbyname(st->cryptSt.mdAlgorithm)) <= 0) {
        PRINT_ERROR("HKDF failed\n");
        ERR_print_errors_fp(stderr);
        remove(st->fileNameSt.outputFileName);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, st->cryptSt.evpKey, sizeof(*st->cryptSt.evpKey) * EVP_MAX_KEY_LENGTH) <= 0) {
        PRINT_ERROR("HKDF failed\n");
        ERR_print_errors_fp(stderr);
        remove(st->fileNameSt.outputFileName);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, st->cryptSt.evpSalt, sizeof(*st->cryptSt.evpSalt) * EVP_SALT_SIZE) <= 0) {
        PRINT_ERROR("HKDF failed\n");
        ERR_print_errors_fp(stderr);
        remove(st->fileNameSt.outputFileName);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, "chunkkey", strlen("chunkkey")) <= 0) {
        PRINT_ERROR("HKDF failed\n");
        ERR_print_errors_fp(stderr);
        remove(st->fileNameSt.outputFileName);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_derive(pctx, st->cryptSt.evpKey, &outlen) <= 0) {
        PRINT_ERROR("HKDF failed\n");
        ERR_print_errors_fp(stderr);
        remove(st->fileNameSt.outputFileName);
        exit(EXIT_FAILURE);
    }

    EVP_PKEY_CTX_free(pctx);
}

void genHMACKey(struct dataStruct *st, uint8_t *lastChunk, uint32_t chunkSize)
{

    #ifdef gui
    strcpy(st->guiSt.statusMessage, "Deriving auth key...");
    #endif

    EVP_PKEY_CTX *pctx;
    size_t outlen = sizeof(*st->cryptSt.hmacKey) * HMAC_KEY_SIZE;
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);

    if (EVP_PKEY_derive_init(pctx) <= 0) {
        PRINT_ERROR("HKDF failed\n");
        ERR_print_errors_fp(stderr);
        remove(st->fileNameSt.outputFileName);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_get_digestbyname(st->cryptSt.mdAlgorithm)) <= 0) {
        PRINT_ERROR("HKDF failed\n");
        ERR_print_errors_fp(stderr);
        remove(st->fileNameSt.outputFileName);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, st->cryptSt.evpKey, sizeof(*st->cryptSt.evpKey) * EVP_MAX_KEY_LENGTH) <= 0) {
        PRINT_ERROR("HKDF failed\n");
        ERR_print_errors_fp(stderr);
        remove(st->fileNameSt.outputFileName);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, st->cryptSt.evpSalt, sizeof(*st->cryptSt.evpSalt) * EVP_SALT_SIZE) <= 0) {
        PRINT_ERROR("HKDF failed\n");
        ERR_print_errors_fp(stderr);
        remove(st->fileNameSt.outputFileName);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, "authkey", strlen("authkey")) <= 0) {
        PRINT_ERROR("HKDF failed\n");
        ERR_print_errors_fp(stderr);
        remove(st->fileNameSt.outputFileName);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, lastChunk, chunkSize) <= 0) {
        PRINT_ERROR("HKDF failed\n");
        ERR_print_errors_fp(stderr);
        remove(st->fileNameSt.outputFileName);
    }
    if (EVP_PKEY_derive(pctx, st->cryptSt.hmacKey, &outlen) <= 0) {
        PRINT_ERROR("HKDF failed\n");
        ERR_print_errors_fp(stderr);
        remove(st->fileNameSt.outputFileName);
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
        PRINT_ERROR("scrypt failed\n");
        ERR_print_errors_fp(stderr);
        remove(st->fileNameSt.outputFileName);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_set1_pbe_pass(pctx, st->cryptSt.userPass, strlen(st->cryptSt.userPass)) <= 0) {
        PRINT_ERROR("scrypt failed\n");
        ERR_print_errors_fp(stderr);
        remove(st->fileNameSt.outputFileName);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_set1_scrypt_salt(pctx, st->cryptSt.evpSalt, sizeof(*st->cryptSt.evpSalt) * EVP_SALT_SIZE) <= 0) {
        PRINT_ERROR("scrypt failed\n");
        ERR_print_errors_fp(stderr);
        remove(st->fileNameSt.outputFileName);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_set_scrypt_N(pctx, st->cryptSt.nFactor) <= 0) {
        PRINT_ERROR("scrypt failed\n");
        ERR_print_errors_fp(stderr);
        remove(st->fileNameSt.outputFileName);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_set_scrypt_r(pctx, st->cryptSt.rFactor) <= 0) {
        PRINT_ERROR("scrypt failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_set_scrypt_p(pctx, st->cryptSt.pFactor) <= 0) {
        PRINT_ERROR("scrypt failed\n");
        ERR_print_errors_fp(stderr);
        remove(st->fileNameSt.outputFileName);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_derive(pctx, st->cryptSt.evpKey, &outlen) <= 0) {
        PRINT_ERROR("scrypt failed\n");
        ERR_print_errors_fp(stderr);
        remove(st->fileNameSt.outputFileName);
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
        PRINT_ERROR("HKDF failed\n");
        ERR_print_errors_fp(stderr);
        remove(st->fileNameSt.outputFileName);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_get_digestbyname(st->cryptSt.mdAlgorithm)) <= 0) {
        PRINT_ERROR("HKDF failed\n");
        ERR_print_errors_fp(stderr);
        remove(st->fileNameSt.outputFileName);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, st->cryptSt.evpKey, sizeof(st->cryptSt.evpKey)) <= 0) {
        PRINT_ERROR("HKDF failed\n");
        ERR_print_errors_fp(stderr);
        remove(st->fileNameSt.outputFileName);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, st->cryptSt.keyFileHash, sizeof(st->cryptSt.keyFileHash)) <= 0) {
        PRINT_ERROR("HKDF failed\n");
        ERR_print_errors_fp(stderr);
        remove(st->fileNameSt.outputFileName);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, "keyfile", strlen("keyfile")) <= 0) {
        PRINT_ERROR("HKDF failed\n");
        ERR_print_errors_fp(stderr);
        remove(st->fileNameSt.outputFileName);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_derive(pctx, st->cryptSt.evpKey, &outlen) <= 0) {
        PRINT_ERROR("HKDF failed\n");
        ERR_print_errors_fp(stderr);
        remove(st->fileNameSt.outputFileName);
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
