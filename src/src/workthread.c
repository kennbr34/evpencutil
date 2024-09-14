#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdint.h>
#include <time.h>
#include <errno.h>
#include "lib.h"

int workThread(char action, struct dataStruct *st)
{
    pid_t p = fork();
    if (p)
        return 0;
        
    FILE *inFile;
        
    if(st->optSt.readFromStdin) {
		inFile = stdin;
        } else {
            inFile = fopen(st->fileNameSt.inputFileName, "rb");
            if (inFile == NULL) {
                PRINT_FILE_ERROR(st->fileNameSt.inputFileName, errno);
                exit(EXIT_FAILURE);
        }
    }
    
    FILE *outFile;
    
    if(st->optSt.writeToStdout) {
		outFile = stdout;
	} else {    
	    outFile = fopen(st->fileNameSt.outputFileName, "wb+");
	    if (outFile == NULL) {
	        PRINT_FILE_ERROR(st->fileNameSt.outputFileName, errno);
	        exit(EXIT_FAILURE);
	    }
	}

    uint64_t fileSize = 0;

    struct timespec begin;
	clock_gettime(CLOCK_REALTIME, &begin);
    st->timeSt.startTime = begin.tv_nsec / 1000000000.0 + begin.tv_sec;

    if (action == 'e') {
        #ifdef gui
        strcpy(st->guiSt.statusMessage, "Generating salt...");
        *(st->guiSt.overallProgressFraction) = .1;
        #endif
        genEvpSalt(st);
    }

    if (action == 'd') {
        
        parseCryptoHeader(inFile, st);
        
        st->cryptSt.fileBufSize = st->cryptoHeader.fileBufSize;
        
        #ifdef gui
        gtk_combo_box_text_prepend(GTK_COMBO_BOX_TEXT(st->guiSt.fileBufSizeComboBox), 0, "From File");
        gtk_combo_box_set_active(GTK_COMBO_BOX(st->guiSt.fileBufSizeComboBox), 0);
        #endif
        
        #ifdef gui
        strcpy(st->guiSt.statusMessage, "Reading pass keyed-hash...");
        *(st->guiSt.overallProgressFraction) = .2;
        #endif
        
        /*Skip past cryptoHeader since it was parsed prior to now*/
        
        /*Get passKeyedHashFromFile*/
        if (freadWErrCheck(st->cryptSt.passKeyedHashFromFile, sizeof(*st->cryptSt.passKeyedHashFromFile), PASS_KEYED_HASH_SIZE, inFile, st) != 0) {
            PRINT_SYS_ERROR(st->miscSt.returnVal);
            PRINT_ERROR("Could not read password hash");
            remove(st->fileNameSt.outputFileName);
            exit(EXIT_FAILURE);
        }
    }

    if (st->optSt.keyFileGiven) {        
        FILE *keyFile = NULL;
    
	    if(st->optSt.keyFromStdin) {
			keyFile = stdin;
		} else {    
		    keyFile = fopen(st->fileNameSt.keyFileName, "rb");
		    if (keyFile == NULL) {
	            PRINT_FILE_ERROR(st->fileNameSt.keyFileName, errno);
	            remove(st->fileNameSt.outputFileName);
	            exit(EXIT_FAILURE);
	        }
		}

        if (!st->optSt.passWordGiven) {
            if (freadWErrCheck(st->cryptSt.evpKey, sizeof(*st->cryptSt.evpKey), EVP_MAX_KEY_LENGTH, keyFile, st) != 0) {
                PRINT_SYS_ERROR(st->miscSt.returnVal);
                exit(EXIT_FAILURE);
            }

			if(st->optSt.keyFromStdin) {
				genKeyFileHash(keyFile,(uint64_t)~0,st);
			} else {
				genKeyFileHash(keyFile, getFileSize(st->fileNameSt.keyFileName), st);
			}
            fclose(keyFile);

            HKDFKeyFile(st);
        } else {
            #ifdef gui
            strcpy(st->guiSt.statusMessage, "Hashing keyfile...");
            *(st->guiSt.overallProgressFraction) = .2;
            #endif

            if(st->optSt.keyFromStdin) {
				genKeyFileHash(keyFile,(uint64_t)~0,st);
			} else {
				genKeyFileHash(keyFile, getFileSize(st->fileNameSt.keyFileName), st);
			}
            fclose(keyFile);
            fclose(keyFile);

            #ifdef gui
            strcpy(st->guiSt.statusMessage, "Generating encryption key...");
            *(st->guiSt.overallProgressFraction) = .3;
            #endif
            genEvpKey(st);
            HKDFKeyFile(st);
        }

    } else {
        #ifdef gui
        strcpy(st->guiSt.statusMessage, "Generating encryption key...");
        *(st->guiSt.overallProgressFraction) = .2;
        #endif
        genEvpKey(st);
    }

    #ifdef gui
    strcpy(st->guiSt.statusMessage, "Generation auth key...");
    *(st->guiSt.overallProgressFraction) = .3;
    #endif
    genHMACKey(st, st->cryptSt.generatedMAC, HMAC_KEY_SIZE);

    #ifdef gui
    strcpy(st->guiSt.statusMessage, "Password keyed-hash...");
    *(st->guiSt.overallProgressFraction) = .4;
    #endif
    genPassTag(st);

    if (action == 'd') {
        #ifdef gui
        strcpy(st->guiSt.statusMessage, "Verifying password...");
        *(st->guiSt.overallProgressFraction) = .6;
        #endif
        if (CRYPTO_memcmp(st->cryptSt.passKeyedHash, st->cryptSt.passKeyedHashFromFile, sizeof(*st->cryptSt.passKeyedHashFromFile) * PASS_KEYED_HASH_SIZE) != 0) {
            printf("Wrong password\n");
            #ifdef gui
            strcpy(st->guiSt.statusMessage, "Wrong password");
            #endif
            remove(st->fileNameSt.outputFileName);
            exit(EXIT_FAILURE);
        }
    }

    if (action == 'e') {
		if(st->optSt.readFromStdin) {
			fileSize = (uint64_t)~0;
		} else {
			fileSize = getFileSize(st->fileNameSt.inputFileName);
		}

        #ifdef gui
        strcpy(st->guiSt.statusMessage, "Writing salt...");
        *(st->guiSt.overallProgressFraction) = .5;
        #endif
        
        /*Prepare cryptoHeader*/
        strcpy((char * restrict)st->cryptoHeader.evpEncUtilString, "evpencutil");
        snprintf(st->cryptoHeader.algorithmString,ALGORITHM_STRING_SIZE,"%s:%s", st->cryptSt.encAlgorithm, st->cryptSt.mdAlgorithm);
        memcpy(st->cryptoHeader.evpSalt, st->cryptSt.evpSalt, sizeof(*st->cryptSt.evpSalt) * EVP_SALT_SIZE);
        st->cryptoHeader.scryptWorkFactors[0] = st->cryptSt.nFactor;
        st->cryptoHeader.scryptWorkFactors[1] = st->cryptSt.rFactor;
        st->cryptoHeader.scryptWorkFactors[2] = st->cryptSt.pFactor;
        st->cryptoHeader.fileBufSize = st->cryptSt.fileBufSize;
        
        /*Prepend cryptoHeader to head of file*/
        if (fwriteWErrCheck(&st->cryptoHeader, sizeof(st->cryptoHeader), 1, outFile, st) != 0) {
            PRINT_SYS_ERROR(st->miscSt.returnVal);
            PRINT_ERROR("Could not write salt");
            remove(st->fileNameSt.outputFileName);
            exit(EXIT_FAILURE);
        }

        #ifdef gui
        strcpy(st->guiSt.statusMessage, "Writing password keyed-hash...");
        *(st->guiSt.overallProgressFraction) = .6;
        #endif
        /*Write passKeyedHash to head of file next to cryptoHeader*/
        if (fwriteWErrCheck(st->cryptSt.passKeyedHash, sizeof(*st->cryptSt.passKeyedHash), PASS_KEYED_HASH_SIZE, outFile, st) != 0) {
            PRINT_SYS_ERROR(st->miscSt.returnVal);
            PRINT_ERROR("Could not write password hash");
            remove(st->fileNameSt.outputFileName);
            exit(EXIT_FAILURE);
        }

        #ifdef gui
        strcpy(st->guiSt.statusMessage, "Encrypting...");
        *(st->guiSt.overallProgressFraction) = .7;
        #endif
    } else if (action == 'd') {
        
        if(st->optSt.readFromStdin) {
			fileSize = (uint64_t)~0;
		} else {
			/*Get filesize, discounting the cryptoHeader and passKeyedHash*/
            fileSize = getFileSize(st->fileNameSt.inputFileName) - (sizeof(st->cryptoHeader) + PASS_KEYED_HASH_SIZE);
		}

        #ifdef gui
        strcpy(st->guiSt.statusMessage, "Decrypting...");
        *(st->guiSt.overallProgressFraction) = .8;
        #endif
    }

    if (action == 'e') {
        doEncrypt(inFile, outFile, fileSize, st);
    } else if (action == 'd') {
        doDecrypt(inFile, outFile, fileSize, st);
    }

    if (fclose(inFile) != 0) {
        PRINT_SYS_ERROR(errno);
        PRINT_ERROR("Error closing file");
        remove(st->fileNameSt.outputFileName);
        exit(EXIT_FAILURE);
    }

    OPENSSL_cleanse(st->cryptSt.hmacKey, sizeof(*st->cryptSt.hmacKey) * HMAC_KEY_SIZE);
    
    #ifdef gui
    strcpy(st->guiSt.statusMessage, "Saving file...");
    *(st->guiSt.overallProgressFraction) = .9;
    #endif

    if (fclose(outFile) != 0) {
        PRINT_SYS_ERROR(errno);
        PRINT_ERROR("Could not close file");
        remove(st->fileNameSt.outputFileName);
        exit(EXIT_FAILURE);
    }

    #ifdef gui
    if (action == 'e') {
        sprintf(st->guiSt.statusMessage, "File encrypted... %0.2fs elapsed,%0.2f MB/s", st->guiSt.totalTime, st->guiSt.averageRate);
        *(st->guiSt.overallProgressFraction) = 1;
    } else if (action == 'd') {
        sprintf(st->guiSt.statusMessage, "File decrypted... %0.2fs elapsed,%0.2f MB/s", st->guiSt.totalTime, st->guiSt.averageRate);
        *(st->guiSt.overallProgressFraction) = 1;
    }
    #endif
    
    if(st->optSt.benchmark) {
		writeBenchmark(st->timeSt.totalTime,st->timeSt.averageRate,st);
	}

    /*Use SIGCONT so that calling process isn't terminated*/
    if (st->optSt.quitWhenDone) {
        kill(p, SIGCONT);
    }

    exit(EXIT_SUCCESS);

    return 0;
}
