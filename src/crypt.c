#include "lib.h"
#include <errno.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>

typedef struct {
    uint8_t *inBuffer;
    uint8_t *outBuffer;
    uint8_t paddingAmount;
    uint8_t cipherBlockSize;
    EVP_CIPHER_CTX *evp_ctx;
    EVP_MD_CTX *md_ctx;
    HMAC_CTX *mac_ctx;
    uint8_t *macBuffer;
    uint8_t *hmacKey;
    uint8_t *evpKey;
    FILE *outFile;
    pthread_mutex_t *fileMutex;
    pthread_mutex_t *cryptoMutex;
    uint64_t *bytesWritten;
    uint64_t *remainingBytes;
    uint64_t origFileBufSize;
    struct dataStruct st;
    #ifdef gui
    struct guiStruct guiSt;
    #endif
} thread_data_t;

void *thread_encrypt_chunk(void *arg) {
    thread_data_t *data = (thread_data_t *)arg;
    setvbuf(data->outFile, NULL, _IONBF, 0);
    
    pthread_mutex_lock(data->cryptoMutex);
    uint32_t evpOutputLength = 0;
    uint32_t HMACLengthPtr = 0;
    
    
    if (!EVP_EncryptUpdate(data->evp_ctx, data->outBuffer, &evpOutputLength, data->inBuffer, data->st.cryptSt.fileBufSize + data->paddingAmount)) {
        fprintf(stderr, "EVP_EncryptUpdate failed\n");
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_cleanup(data->evp_ctx);

        OPENSSL_cleanse(data->inBuffer, sizeof(*data->inBuffer) * (data->st.cryptSt.fileBufSize + EVP_MAX_BLOCK_LENGTH));
        OPENSSL_cleanse(data->outBuffer, sizeof(*data->outBuffer) * (data->st.cryptSt.fileBufSize + EVP_MAX_BLOCK_LENGTH));

        remove(data->st.fileNameSt.outputFileName);

        exit(EXIT_FAILURE);
    }

    HMAC_Update(data->mac_ctx, (const unsigned char *)&data->st.cryptoHeader, sizeof(data->st.cryptoHeader));
    HMAC_Update(data->mac_ctx, data->st.cryptSt.passKeyedHash, sizeof(*data->st.cryptSt.passKeyedHash) * PASS_KEYED_HASH_SIZE);
    HMAC_Update(data->mac_ctx, data->outBuffer, sizeof(*data->outBuffer) * evpOutputLength);
        
    if (data->paddingAmount) {
        data->st.cryptSt.fileBufSize += data->paddingAmount;
    }
        
    HMAC_Update(data->mac_ctx, (const unsigned char *)&data->st.cryptSt.fileBufSize, sizeof(data->st.cryptSt.fileBufSize));

    HMAC_Final(data->mac_ctx, data->macBuffer, &HMACLengthPtr);
    pthread_mutex_unlock(data->cryptoMutex);

    pthread_mutex_lock(data->fileMutex);
    if (fwriteWErrCheck(data->outBuffer, sizeof(*data->outBuffer), evpOutputLength, data->outFile, &data->st) != 0) {
        PRINT_SYS_ERROR(data->st.miscSt.returnVal);
        PRINT_ERROR("Could not write file for encryption/decryption");

        OPENSSL_cleanse(data->inBuffer, sizeof(*data->inBuffer) * (data->st.cryptSt.fileBufSize + EVP_MAX_BLOCK_LENGTH));
        OPENSSL_cleanse(data->outBuffer, sizeof(*data->outBuffer) * (data->st.cryptSt.fileBufSize + EVP_MAX_BLOCK_LENGTH));

        remove(data->st.fileNameSt.outputFileName);

        exit(EXIT_FAILURE);
    }
    fflush(data->outFile);
    *(data->bytesWritten) += evpOutputLength;
    
    if (fwriteWErrCheck(data->macBuffer, sizeof(*data->macBuffer), HMACLengthPtr, data->outFile, &data->st) != 0) {
        PRINT_SYS_ERROR(data->st.miscSt.returnVal);
        PRINT_ERROR("Could not write MAC");
        remove(data->st.fileNameSt.outputFileName);
        exit(EXIT_FAILURE);
    }
    fflush(data->outFile);
    *(data->bytesWritten) += HMACLengthPtr;
        
    pthread_mutex_unlock(data->fileMutex);

    return NULL;
}

void *thread_decrypt_chunk(void *arg) {
    thread_data_t *data = (thread_data_t *)arg;
    setvbuf(data->outFile, NULL, _IONBF, 0);
    
    pthread_mutex_lock(data->cryptoMutex);
    uint32_t evpOutputLength = 0;
    uint32_t HMACLengthPtr = 0;
    
    HMAC_Update(data->mac_ctx, (const unsigned char *)&data->st.cryptoHeader, sizeof(data->st.cryptoHeader));
    HMAC_Update(data->mac_ctx, data->st.cryptSt.passKeyedHash, sizeof(*data->st.cryptSt.passKeyedHash) * PASS_KEYED_HASH_SIZE);
    HMAC_Update(data->mac_ctx, data->inBuffer, sizeof(*data->inBuffer) * data->st.cryptSt.fileBufSize);
    HMAC_Update(data->mac_ctx, (const unsigned char *)&data->st.cryptSt.fileBufSize, sizeof(data->st.cryptSt.fileBufSize));

    HMAC_Final(data->mac_ctx, data->macBuffer, &HMACLengthPtr);
    
    if (CRYPTO_memcmp(data->st.cryptSt.fileMAC, data->macBuffer, sizeof(*data->macBuffer) * EVP_MAX_MD_SIZE) != 0) {
        printf("Message authentication failed\n");
#ifdef gui
        strcpy(data->st.guiSt.statusMessage, "Authentication failure");
#endif
        remove(data->st.fileNameSt.outputFileName);
        exit(EXIT_FAILURE);
    }
    
    if (!EVP_DecryptUpdate(data->evp_ctx, data->outBuffer, &evpOutputLength, data->inBuffer, data->st.cryptSt.fileBufSize)) {
        fprintf(stderr, "EVP_DecryptUpdate failed\n");
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_cleanup(data->evp_ctx);

        OPENSSL_cleanse(data->inBuffer, sizeof(*data->inBuffer) * (data->st.cryptSt.fileBufSize + EVP_MAX_BLOCK_LENGTH));
        OPENSSL_cleanse(data->outBuffer, sizeof(*data->outBuffer) * (data->st.cryptSt.fileBufSize + EVP_MAX_BLOCK_LENGTH));

        remove(data->st.fileNameSt.outputFileName);

        exit(EXIT_FAILURE);
    }
    
    uint8_t paddingAmount = 0;
    if (data->st.cryptSt.fileBufSize < data->origFileBufSize) {
        if (data->cipherBlockSize > 1) {
            paddingAmount = data->outBuffer[evpOutputLength - 1];
        }
        
        if(paddingAmount) {
            uint8_t *paddingArray = calloc(paddingAmount,sizeof(*paddingArray));
            memset(paddingArray,paddingAmount,sizeof(*paddingArray) * paddingAmount);
            
            if (CRYPTO_memcmp((data->outBuffer + evpOutputLength) - paddingAmount, paddingArray, sizeof(*paddingArray) * paddingAmount) != 0) {
                printf("Bad padding\n");
    #ifdef gui
                strcpy(data->st.guiSt.statusMessage, "Bad padding");
    #endif
                remove(data->st.fileNameSt.outputFileName);
                exit(EXIT_FAILURE);
            }
            
            DDFREE(free,paddingArray);
        }
    }
    pthread_mutex_unlock(data->cryptoMutex);
    
    pthread_mutex_lock(data->fileMutex);
    if (fwriteWErrCheck(data->outBuffer, sizeof(*data->outBuffer), evpOutputLength - paddingAmount, data->outFile, &data->st) != 0) {
        PRINT_SYS_ERROR(data->st.miscSt.returnVal);
        PRINT_ERROR("Could not write file for encryption/decryption");

        OPENSSL_cleanse(data->inBuffer, sizeof(*data->inBuffer) * (data->st.cryptSt.fileBufSize + EVP_MAX_BLOCK_LENGTH));
        OPENSSL_cleanse(data->outBuffer, sizeof(*data->outBuffer) * (data->st.cryptSt.fileBufSize + EVP_MAX_BLOCK_LENGTH));

        remove(data->st.fileNameSt.outputFileName);

        exit(EXIT_FAILURE);
    }
    fflush(data->outFile);
    *(data->bytesWritten) += evpOutputLength;
        
    pthread_mutex_unlock(data->fileMutex);

    return NULL;
}

void doEncrypt(FILE *inFile, FILE *outFile, uint64_t fileSize, struct dataStruct *st)
{
#ifdef gui
    *(st->guiSt.progressFraction) = 0.0;
    struct timespec begin, end;
#endif
    
    uint64_t bytesWritten = 0, bytesRead = 0, amountReadLast = 0;
    uint64_t remainingBytes = fileSize;

    uint64_t loopIterations = 0, activeThreads = 0;

    uint8_t *inBuffer = calloc(st->cryptSt.fileBufSize + EVP_MAX_BLOCK_LENGTH, sizeof(*inBuffer)), *outBuffer = calloc(st->cryptSt.fileBufSize + EVP_MAX_BLOCK_LENGTH, sizeof(*outBuffer));
    if (inBuffer == NULL || outBuffer == NULL) {
        PRINT_SYS_ERROR(errno);
        PRINT_ERROR("Could not allocate memory input/output buffers");
        remove(st->fileNameSt.outputFileName);
        exit(EXIT_FAILURE);
    }

    uint32_t HMACLengthPtr = 0;

#ifdef gui
    st->guiSt.totalTime = 0;
#endif

    pthread_t threads[st->cryptSt.threadNumber];
    thread_data_t thread_data[st->cryptSt.threadNumber];
    pthread_mutex_t fileMutex = PTHREAD_MUTEX_INITIALIZER, cryptoMutex = PTHREAD_MUTEX_INITIALIZER;

    while (remainingBytes) {
        
         #ifdef gui
        clock_gettime(CLOCK_REALTIME, &begin);
        st->guiSt.startLoop = begin.tv_nsec / 1000000000.0 + begin.tv_sec;

        st->guiSt.startBytes = bytesWritten;
        #endif
        
        activeThreads = 0;
        
        for (int i = 0; i < st->cryptSt.threadNumber && remainingBytes; i++) {
            
            pthread_mutex_lock(&cryptoMutex);
            thread_data[i].evp_ctx = EVP_CIPHER_CTX_new();
            if(thread_data[i].evp_ctx == NULL) {
                ERR_print_errors_fp(stderr);
                exit(EXIT_FAILURE);
            }
            if(!EVP_CIPHER_CTX_reset(thread_data[i].evp_ctx)) {
                ERR_print_errors_fp(stderr);
                exit(EXIT_FAILURE);
            }
            thread_data[i].mac_ctx = HMAC_CTX_new();
                                        
            EVP_EncryptInit_ex(thread_data[i].evp_ctx, st->cryptSt.evpCipher, NULL, st->cryptSt.evpKey, st->cryptSt.hmacKey);
            EVP_CIPHER_CTX_set_padding(thread_data[i].evp_ctx, 0);
    
            HMAC_Init_ex(thread_data[i].mac_ctx, st->cryptSt.hmacKey, HMAC_KEY_SIZE, EVP_get_digestbyname(st->cryptSt.mdAlgorithm), NULL);
            pthread_mutex_unlock(&cryptoMutex);
    
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
            
            uint8_t cipherBlockSize = EVP_CIPHER_CTX_get_block_size(thread_data[i].evp_ctx);
    
            if (amountReadLast < st->cryptSt.fileBufSize) {
                remainingBytes = 0;
                st->cryptSt.fileBufSize = amountReadLast;
                
                if(cipherBlockSize > 1) {
                if (bytesRead % cipherBlockSize) {
                    paddingAmount = cipherBlockSize - (bytesRead % cipherBlockSize);
                } else if (bytesRead % cipherBlockSize == 0) {
                    paddingAmount = cipherBlockSize;
                }
    
                uint8_t *paddingArray = calloc(paddingAmount, sizeof(*paddingArray));
                memset(paddingArray, paddingAmount, sizeof(paddingAmount) * paddingAmount);
    
                memcpy(inBuffer + amountReadLast, paddingArray, sizeof(*paddingArray) * paddingAmount);
                
                DDFREE(free,paddingArray);
            }
    
            } else {
                remainingBytes -= st->cryptSt.fileBufSize;
            }
            
            thread_data[i].inBuffer = malloc(st->cryptSt.fileBufSize + EVP_MAX_BLOCK_LENGTH);
            memcpy(thread_data[i].inBuffer, inBuffer, st->cryptSt.fileBufSize + paddingAmount);
            thread_data[i].outBuffer = malloc(st->cryptSt.fileBufSize + EVP_MAX_BLOCK_LENGTH);
            thread_data[i].macBuffer = malloc(EVP_MAX_MD_SIZE);
            thread_data[i].outFile = outFile;
            thread_data[i].fileMutex = &fileMutex;
            thread_data[i].cryptoMutex = &cryptoMutex;
            thread_data[i].bytesWritten = &bytesWritten;
            thread_data[i].st.cryptSt.fileBufSize = st->cryptSt.fileBufSize;
            thread_data[i].paddingAmount = paddingAmount;
            #ifdef gui
            memcpy(&thread_data[i].st.guiSt,&st->guiSt,sizeof(st->guiSt));
            #endif
            memcpy(&thread_data[i].st.cryptoHeader,&st->cryptoHeader,sizeof(st->cryptoHeader));
            memcpy(thread_data[i].st.cryptSt.passKeyedHash,st->cryptSt.passKeyedHash,sizeof(*st->cryptSt.passKeyedHash) * PASS_KEYED_HASH_SIZE);

            pthread_create(&threads[i], NULL, thread_encrypt_chunk, &thread_data[i]);
            
            activeThreads++;
            genHMACKey(st, st->cryptSt.generatedMAC, HMACLengthPtr);
            genChunkKey(st);

        }
        
        for (int i = 0; i < activeThreads; i++) {
            if(pthread_join(threads[i], NULL)) {
                PRINT_SYS_ERROR(errno);
                PRINT_ERROR("Could not join threads");
                remove(st->fileNameSt.outputFileName);
                exit(EXIT_FAILURE);
            }
            
            pthread_mutex_lock(&cryptoMutex);
            DDFREE(free,thread_data[i].outBuffer);

            DDFREE(free,thread_data[i].inBuffer);
            
            DDFREE(free,thread_data[i].macBuffer);
            
            DDFREE(EVP_CIPHER_CTX_free,thread_data[i].evp_ctx);
            
            DDFREE(HMAC_CTX_free,thread_data[i].mac_ctx);
            pthread_mutex_unlock(&cryptoMutex);
        }
        
        #ifdef gui
        if (st->optSt.benchmark) {
			if(st->optSt.benchmarkTime && st->guiSt.totalTime >= st->miscSt.benchmarkTime) {
				remainingBytes = 0;
			}
		}
        #endif
        
        loopIterations++;
        
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
    }
    pthread_mutex_destroy(&fileMutex);
    pthread_mutex_destroy(&cryptoMutex);

    OPENSSL_cleanse(inBuffer, sizeof(*inBuffer) * (st->cryptSt.fileBufSize + EVP_MAX_BLOCK_LENGTH));
    OPENSSL_cleanse(outBuffer, sizeof(*outBuffer) * (st->cryptSt.fileBufSize + EVP_MAX_BLOCK_LENGTH));

    DDFREE(free,inBuffer);
    DDFREE(free,outBuffer);
}

void doDecrypt(FILE *inFile, FILE *outFile, uint64_t fileSize, struct dataStruct *st)
{
#ifdef gui
    *(st->guiSt.progressFraction) = 0.0;
    struct timespec end;
#endif

    uint64_t bytesWritten = 0, bytesRead = 0, amountReadLast = 0;
    uint64_t remainingBytes = fileSize;

    uint64_t loopIterations = 0, activeThreads = 0;
    
    uint64_t origFileBufSize = st->cryptSt.fileBufSize;

    uint8_t *inBuffer = calloc(st->cryptSt.fileBufSize + EVP_MAX_BLOCK_LENGTH + EVP_MAX_MD_SIZE, sizeof(*inBuffer)), *outBuffer = calloc(st->cryptSt.fileBufSize + EVP_MAX_BLOCK_LENGTH, sizeof(*outBuffer));
    if (inBuffer == NULL || outBuffer == NULL) {
        PRINT_SYS_ERROR(errno);
        PRINT_ERROR("Could not allocate memory for input/output buffers");
        remove(st->fileNameSt.outputFileName);
        exit(EXIT_FAILURE);
    }

    EVP_CIPHER_CTX *evp_ctx = NULL;

    EVP_MD_CTX *md_ctx = NULL;

    uint32_t HMACLengthPtr = 0;

#ifdef gui
    st->guiSt.totalTime = 0;
#endif

    pthread_t threads[st->cryptSt.threadNumber];
    thread_data_t thread_data[st->cryptSt.threadNumber];
    pthread_mutex_t fileMutex = PTHREAD_MUTEX_INITIALIZER, cryptoMutex = PTHREAD_MUTEX_INITIALIZER;
    
    while (remainingBytes) {
        
        activeThreads = 0;

        for (int i = 0; i < st->cryptSt.threadNumber && remainingBytes; i++) {
            
            pthread_mutex_lock(&cryptoMutex);
            
            thread_data[i].evp_ctx = EVP_CIPHER_CTX_new();
            if(thread_data[i].evp_ctx == NULL) {
                ERR_print_errors_fp(stderr);
                exit(EXIT_FAILURE);
            }
            if(!EVP_CIPHER_CTX_reset(thread_data[i].evp_ctx)) {
                ERR_print_errors_fp(stderr);
                exit(EXIT_FAILURE);
            }
            thread_data[i].mac_ctx = HMAC_CTX_new();

            EVP_DecryptInit_ex(thread_data[i].evp_ctx, st->cryptSt.evpCipher, NULL, st->cryptSt.evpKey, st->cryptSt.hmacKey);
            uint8_t cipherBlockSize = EVP_CIPHER_CTX_get_block_size(thread_data[i].evp_ctx);
            EVP_CIPHER_CTX_set_padding(thread_data[i].evp_ctx, 0);
    
            HMAC_Init_ex(thread_data[i].mac_ctx, st->cryptSt.hmacKey, HMAC_KEY_SIZE, EVP_get_digestbyname(st->cryptSt.mdAlgorithm), NULL);
            pthread_mutex_unlock(&cryptoMutex);
            
    #ifdef gui
            struct timespec begin;
            clock_gettime(CLOCK_REALTIME, &begin);
            st->guiSt.startLoop = begin.tv_nsec / 1000000000.0 + begin.tv_sec;
    
            st->guiSt.startBytes = bytesWritten;
    #endif
    
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
            
            thread_data[i].inBuffer = calloc((st->cryptSt.fileBufSize + EVP_MAX_BLOCK_LENGTH + EVP_MAX_MD_SIZE) * 2,sizeof(*(thread_data[i].inBuffer)));
            if(thread_data[i].inBuffer == NULL) {
                PRINT_SYS_ERROR(errno);
                PRINT_ERROR("Could not allocate thread buffers");
                remove(st->fileNameSt.outputFileName);
                exit(EXIT_FAILURE);
            }
            memcpy(thread_data[i].inBuffer, inBuffer, st->cryptSt.fileBufSize + EVP_MAX_BLOCK_LENGTH);
            thread_data[i].outBuffer = malloc((st->cryptSt.fileBufSize + EVP_MAX_BLOCK_LENGTH) * 2);
            thread_data[i].macBuffer = malloc(EVP_MAX_MD_SIZE);
            thread_data[i].outFile = outFile;
            thread_data[i].fileMutex = &fileMutex;
            thread_data[i].cryptoMutex = &cryptoMutex;
            thread_data[i].bytesWritten = &bytesWritten;
            thread_data[i].remainingBytes = &remainingBytes;
            thread_data[i].origFileBufSize = origFileBufSize;
            thread_data[i].st.cryptSt.fileBufSize = st->cryptSt.fileBufSize;
            thread_data[i].cipherBlockSize = cipherBlockSize;
            #ifdef gui
            memcpy(&thread_data[i].st.guiSt,&st->guiSt,sizeof(st->guiSt));
            #endif
            memcpy(&thread_data[i].st.cryptoHeader,&st->cryptoHeader,sizeof(st->cryptoHeader));
            memcpy(thread_data[i].st.cryptSt.passKeyedHash,st->cryptSt.passKeyedHash,sizeof(*st->cryptSt.passKeyedHash) * PASS_KEYED_HASH_SIZE);
            memcpy(thread_data[i].st.cryptSt.fileMAC,st->cryptSt.fileMAC,sizeof(*st->cryptSt.fileMAC) * EVP_MAX_MD_SIZE);
    
            pthread_create(&threads[i], NULL, thread_decrypt_chunk, &thread_data[i]);
            
            activeThreads++;
            genHMACKey(st, st->cryptSt.generatedMAC, HMACLengthPtr);
            genChunkKey(st);
        }
        
        for (int i = 0; i < activeThreads; i++) {
            if(pthread_join(threads[i], NULL)) {
                PRINT_SYS_ERROR(errno);
                PRINT_ERROR("Could not join threads");
                remove(st->fileNameSt.outputFileName);
                exit(EXIT_FAILURE);
            }
            
            pthread_mutex_lock(&cryptoMutex);
            DDFREE(free,thread_data[i].outBuffer);

            DDFREE(free,thread_data[i].inBuffer);
            
            DDFREE(free,thread_data[i].macBuffer);
            
            DDFREE(EVP_CIPHER_CTX_free,thread_data[i].evp_ctx);
            
            DDFREE(HMAC_CTX_free,thread_data[i].mac_ctx);
            pthread_mutex_unlock(&cryptoMutex);
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
        sprintf(st->guiSt.statusMessage, "%s %0.0f Mb/s, %0.0fs elapsed", "Decrypting...", dataRate, st->guiSt.totalTime);
        st->guiSt.averageRate = dataRate;
#endif
        loopIterations++;
    }
    pthread_mutex_destroy(&fileMutex);

    DDFREE(EVP_CIPHER_CTX_free,evp_ctx);
    DDFREE(EVP_MD_CTX_free,md_ctx);

    OPENSSL_cleanse(inBuffer, sizeof(*inBuffer) * (st->cryptSt.fileBufSize + EVP_MAX_BLOCK_LENGTH));
    OPENSSL_cleanse(outBuffer, sizeof(*outBuffer) * (st->cryptSt.fileBufSize + EVP_MAX_BLOCK_LENGTH));

    DDFREE(free,inBuffer);
    DDFREE(free,outBuffer);
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
    uint64_t bytesRead = 0, amountReadLast = 0;

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

            OPENSSL_cleanse(keyFileHashBuffer, sizeof(*keyFileHashBuffer) * st->cryptSt.genAuthBufSize);

            remove(st->fileNameSt.outputFileName);

            exit(EXIT_FAILURE);
        }

        amountReadLast = st->miscSt.freadAmt;
        bytesRead += amountReadLast;

        if (amountReadLast < st->cryptSt.genAuthBufSize) {
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
    DDFREE(EVP_MD_CTX_free,ctx);
    OPENSSL_cleanse(keyFileHashBuffer, sizeof(*keyFileHashBuffer) * st->cryptSt.genAuthBufSize);
    DDFREE(free,keyFileHashBuffer);
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
    HMAC_Init_ex(ctx, st->cryptSt.hmacKey, HMAC_KEY_SIZE, st->cryptSt.evpDigest, NULL);

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
    DDFREE(HMAC_CTX_free,ctx);
    DDFREE(free,genAuthBuffer);
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

    DDFREE(EVP_PKEY_CTX_free,pctx);
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

    DDFREE(EVP_PKEY_CTX_free,pctx);
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

    DDFREE(EVP_PKEY_CTX_free,pctx);
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

    DDFREE(EVP_PKEY_CTX_free,pctx);
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
