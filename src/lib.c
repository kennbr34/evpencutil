#include "lib.h"
#include <getopt.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdint.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <sys/sysinfo.h>

extern struct cryptoStruct *cryptStGlobal;

#ifndef gui
/*Lists available encryption algorithms in OpenSSL's EVP library*/
void encListCallback(const OBJ_NAME *obj, void *arg)
{
    struct dataStruct *st = (struct dataStruct *)arg;

    if(st->optSt.listSupportedCiphers) {
        if (isSupportedCipher((unsigned char *)obj->name)) {
            printf("%s\n", obj->name);
        }
    } else if(st->optSt.listAllCiphers) {
        printf("%s\n", obj->name);
    }
}

/*Lists available encryption algorithms in OpenSSL's EVP library*/
void mdListCallback(const OBJ_NAME *obj, void *arg)
{
    struct dataStruct *st = (struct dataStruct *)arg;
    
    if(st->optSt.listSupportedDigests) {
        if (isSupportedDigest((unsigned char *)obj->name)) {
            printf("%s\n", obj->name);
        }
    } else if(st->optSt.listAllDigests) {
        printf("%s\n", obj->name);
    }
}
#endif

size_t getNumCores(void)
{
    FILE *cpuInfoFile = fopen("/proc/cpuinfo", "r");
    if(cpuInfoFile == NULL) {
        perror("/proc/cpuinfo");
        fclose(cpuInfoFile);
        return 0;
    }

    char cpuInfoLine[256];
    while(fgets(cpuInfoLine, sizeof(cpuInfoLine), cpuInfoFile))
    {
        size_t numCores = 0;
        if(sscanf(cpuInfoLine, "cpu cores : %zu", &numCores) == 1)
        {
            fclose(cpuInfoFile);
            return numCores;
        }
    }

    fclose(cpuInfoFile);
    
    return 0;
}

char * getCpuName(void)
{
    FILE *cpuInfoFile = fopen("/proc/cpuinfo", "r");
    if(cpuInfoFile == NULL) {
        perror("/proc/cpuinfo");
        fclose(cpuInfoFile);
        return 0;
    }

    char cpuInfoLine[256];
    while(fgets(cpuInfoLine, sizeof(cpuInfoLine), cpuInfoFile))
    {
        if (strncmp(cpuInfoLine, "model name", 10) == 0) {
            char *colon = strchr(cpuInfoLine, ':');
            if (colon != NULL) {
                colon[strlen(colon) - 1] = '\0';
                return strdup(colon + 2);
            }
        }
    }

    fclose(cpuInfoFile);
    
    return NULL;
}

uint8_t isSupportedCipher(uint8_t *cipher)
{
    if (strstr(cipher, "aes-128-cbc-hmac-sha1") ||
        strstr(cipher, "aes-128-cbc-hmac-sha256") ||
        strstr(cipher, "aes-128-ccm") ||
        strstr(cipher, "aes-128-gcm") ||
        strstr(cipher, "aes-128-ocb") ||
        strstr(cipher, "aes128-wrap") ||
        strstr(cipher, "aes-128-xts") ||
        strstr(cipher, "aes-192-ccm") ||
        strstr(cipher, "aes-192-gcm") ||
        strstr(cipher, "aes-192-ocb") ||
        strstr(cipher, "aes192-wrap") ||
        strstr(cipher, "aes-256-cbc-hmac-sha1") ||
        strstr(cipher, "aes-256-cbc-hmac-sha256") ||
        strstr(cipher, "aes-256-ccm") ||
        strstr(cipher, "aes-256-gcm") ||
        strstr(cipher, "aes-256-ocb") ||
        strstr(cipher, "aes256-wrap") ||
        strstr(cipher, "aes-256-xts") ||
        strstr(cipher, "aria-128-ccm") ||
        strstr(cipher, "aria-128-gcm") ||
        strstr(cipher, "aria-192-ccm") ||
        strstr(cipher, "aria-192-gcm") ||
        strstr(cipher, "aria-256-ccm") ||
        strstr(cipher, "aria-256-gcm") ||
        strstr(cipher, "des3-wrap") ||
        strstr(cipher, "id-aes128-CCM") ||
        strstr(cipher, "id-aes128-GCM") ||
        strstr(cipher, "id-aes128-wrap") ||
        strstr(cipher, "id-aes128-wrap-pad") ||
        strstr(cipher, "id-aes192-CCM") ||
        strstr(cipher, "id-aes192-GCM") ||
        strstr(cipher, "id-aes192-wrap") ||
        strstr(cipher, "id-aes192-wrap-pad") ||
        strstr(cipher, "id-aes256-CCM") ||
        strstr(cipher, "id-aes256-GCM") ||
        strstr(cipher, "id-aes256-wrap") ||
        strstr(cipher, "id-aes256-wrap-pad") ||
        strstr(cipher, "idea") ||
        strstr(cipher, "idea-cbc") ||
        strstr(cipher, "idea-cfb") ||
        strstr(cipher, "idea-ecb") ||
        strstr(cipher, "idea-ofb") ||
        strstr(cipher, "id-smime-alg-CMS3DESwrap")) {
        return 0;
    } else {
        return 1;
    }
}

uint8_t isSupportedDigest(uint8_t *digest)
{
    if (strstr(digest, "shake128") ||
        strstr(digest, "shake256")) {
        return 0;
    } else {
        return 1;
    }
}

uint64_t freadWErrCheck(void *ptr, size_t size, size_t nmemb, FILE *stream, struct dataStruct *st)
{
    int expectedRetVal = 0;
    if (size == 1) {
        expectedRetVal = size;
    } else {
        expectedRetVal = nmemb;
    }

    uint64_t retVal = fread(ptr, size, nmemb, stream);

    if (retVal != expectedRetVal) {
        if (ferror(stream) || (retVal == 0 && !feof(stream))) {
            st->miscSt.returnVal = errno;
            return errno;
        }
    }

    st->miscSt.freadAmt = retVal;

    return 0;
}

uint64_t fwriteWErrCheck(void *ptr, size_t size, size_t nmemb, FILE *stream, struct dataStruct *st)
{
    int expectedRetVal = 0;
    if (size == 1) {
        expectedRetVal = size;
    } else {
        expectedRetVal = nmemb;
    }

    int retVal = fwrite(ptr, size, nmemb, stream);

    if (retVal != expectedRetVal) {
        if (ferror(stream)) {
            st->miscSt.returnVal = errno;
            return errno;
        }
    }

    return 0;
}

uint64_t getFileSize(const char *filename)
{
    struct stat st;
    if(stat(filename, &st) == -1) {
		return 0;
	}

    /*If file is a FIFO, return the max value possible for type*/

    if (S_ISFIFO(st.st_mode) || S_ISCHR(st.st_mode) || S_ISSOCK(st.st_mode)) {
        return (uint64_t)~0;
    } else {
        return st.st_size;
    }
}

size_t getBufSizeMultiple(char *value)
{

#define MAX_DIGITS 13
    char valString[MAX_DIGITS] = {0};
    /* Compiling without optimization results in extremely slow speeds, but this will be optimized
     * out if not set to volatile.
     */
    volatile int valueLength = 0;
    volatile int multiple = 1;

    /* value from getsubopt is not null-terminated so must copy and get the length manually without
     * string functions
     */
    for (valueLength = 0; valueLength < MAX_DIGITS; valueLength++) {
        if (isdigit(value[valueLength])) {
            valString[valueLength] = value[valueLength];
            continue;
        } else if (isalpha(value[valueLength])) {
            valString[valueLength] = value[valueLength];
            valueLength++;
            break;
        }
    }

    if (valString[valueLength - 1] == 'b' || valString[valueLength - 1] == 'B')
        multiple = 1;
    if (valString[valueLength - 1] == 'k' || valString[valueLength - 1] == 'K')
        multiple = 1024;
    if (valString[valueLength - 1] == 'm' || valString[valueLength - 1] == 'M')
        multiple = 1024 * 1024;
    if (valString[valueLength - 1] == 'g' || valString[valueLength - 1] == 'G')
        multiple = 1024 * 1024 * 1024;

    return multiple;
}

void makeMultipleOf(size_t *numberToChange, size_t multiple)
{
    if (*numberToChange > multiple && *numberToChange % multiple != 0) {
        *numberToChange = *numberToChange - (*numberToChange % multiple);
    } else if (*numberToChange > multiple && *numberToChange % multiple == 0) {
        *numberToChange = *numberToChange;
    }
}

void signalHandler(int signum)
{
    exit(EXIT_SUCCESS);
}

void bytesPrefixed(char *prefixedString, unsigned long long bytes)
{
    if (bytes <= 1023) {
        sprintf(prefixedString, "%llu bytes", bytes);
    } else if (bytes >= 1024 && bytes < 1048576) {
        sprintf(prefixedString, "%llu Kb", bytes / 1024);
    } else if (bytes >= 1048576 && bytes < 1073741824) {
        sprintf(prefixedString, "%llu Mb", bytes / 1048576);
    } else if (bytes >= 1073741824) {
        sprintf(prefixedString, "%llu Gb", bytes / 1073741824);
    }
}

void allocateBuffers(struct dataStruct *st)
{
    st->cryptSt.evpKey = calloc(EVP_MAX_KEY_LENGTH, sizeof(*st->cryptSt.evpKey));
    if (st->cryptSt.evpKey == NULL) {
        PRINT_SYS_ERROR(errno);
        PRINT_ERROR("Could not allocate evpKey buffer");
        exit(EXIT_FAILURE);
    }
    st->cryptSt.evpSalt = calloc(EVP_SALT_SIZE, sizeof(*st->cryptSt.evpSalt));
    if (st->cryptSt.evpSalt == NULL) {
        PRINT_SYS_ERROR(errno);
        PRINT_ERROR("Could not allocate evpSalt buffer");
        exit(EXIT_FAILURE);
    }

    st->cryptSt.hmacKey = calloc(HMAC_KEY_SIZE, sizeof(*st->cryptSt.hmacKey));
    if (st->cryptSt.hmacKey == NULL) {
        PRINT_SYS_ERROR(errno);
        PRINT_ERROR("Could not allocate hmacKey buffer");
        exit(EXIT_FAILURE);
    }
}

void cleanUpBuffers(void)
{
    OPENSSL_cleanse(cryptStGlobal->evpKey, EVP_MAX_KEY_LENGTH);
    OPENSSL_cleanse(cryptStGlobal->hmacKey, HMAC_KEY_SIZE);

    OPENSSL_cleanse(cryptStGlobal->userPass, strlen(cryptStGlobal->userPass));
    OPENSSL_cleanse(cryptStGlobal->userPassToVerify, strlen(cryptStGlobal->userPassToVerify));

    OPENSSL_cleanse(cryptStGlobal->keyFileHash, sizeof(cryptStGlobal->keyFileHash));

    DDFREE(free,cryptStGlobal);
}

FILE *parseCryptoHeader(FILE *inFile, struct dataStruct *st)
{
    /*Read cryptoHeader from head of cipher-text or fail if malformed*/
    if (freadWErrCheck(&st->cryptoHeader, sizeof(st->cryptoHeader), 1, inFile, st) != 0) {
        PRINT_SYS_ERROR(st->miscSt.returnVal);
        PRINT_ERROR("Could not read salt");
        remove(st->fileNameSt.outputFileName);
        exit(EXIT_FAILURE);
    }
    if (strcmp(st->cryptoHeader.evpEncUtilString, "evpencutil") != 0) {
        PRINT_ERROR("Not a file produced with evpencutil, exiting");
        remove(st->fileNameSt.outputFileName);
        exit(EXIT_FAILURE);
    }

    /*Populate cryptSt members from cryptoHeader*/
    memcpy(st->cryptSt.evpSalt, st->cryptoHeader.evpSalt, sizeof(*st->cryptSt.evpSalt) * EVP_SALT_SIZE);

    /*Parse algorithmString*/

    char *token_save_ptr;
    char *token = strtok_r(st->cryptoHeader.algorithmString, ":", &token_save_ptr);
    if (token == NULL) {
        printf("Could not parse header.\nIs %s a evpencutil file?\n", st->fileNameSt.inputFileName);
        remove(st->fileNameSt.outputFileName);
        exit(EXIT_FAILURE);
    }
    
    st->cryptSt.evpCipher = EVP_get_cipherbyname(token);
    if(strcmp(token,"null") == 0) {
		st->cryptSt.evpCipher = EVP_enc_null();
	} else {
	    if (!st->cryptSt.evpCipher) {
	        fprintf(stderr, "Could not load cipher: %s\n", token);
	        remove(st->fileNameSt.outputFileName);
	        exit(EXIT_FAILURE);
	    }
	}
    DDFREE(free,st->cryptSt.encAlgorithm);
    st->cryptSt.encAlgorithm = strdup(token);
#ifdef gui
    gtk_combo_box_text_prepend(GTK_COMBO_BOX_TEXT(st->guiSt.encAlgorithmComboBox), 0, st->cryptSt.encAlgorithm);
    gtk_combo_box_set_active(GTK_COMBO_BOX(st->guiSt.encAlgorithmComboBox), 0);
#endif

    token = strtok_r(NULL, ":", &token_save_ptr);
    if (token == NULL) {
        printf("Could not parse header.\nIs %s a evpencutil file?\n", st->fileNameSt.inputFileName);
        remove(st->fileNameSt.outputFileName);
        exit(EXIT_FAILURE);
    }
    st->cryptSt.evpDigest = EVP_get_digestbyname(token);
    if (!st->cryptSt.evpDigest) {
        fprintf(stderr, "Could not load digest: %s\n", token);
        remove(st->fileNameSt.outputFileName);
        exit(EXIT_FAILURE);
    }
    if (st->cryptSt.mdAlgorithm != NULL) {
        DDFREE(free,st->cryptSt.mdAlgorithm);
    }
    st->cryptSt.mdAlgorithm = strdup(token);

    /* Do not forget to make st->cryptoHeader.algorithmString the same format it was when
     * computed for the MAC */
    snprintf(st->cryptoHeader.algorithmString, ALGORITHM_STRING_SIZE, "%s:%s", st->cryptSt.encAlgorithm, st->cryptSt.mdAlgorithm);

#ifdef gui
    gtk_combo_box_text_prepend(GTK_COMBO_BOX_TEXT(st->guiSt.mdAlgorithmComboBox), 0, st->cryptSt.mdAlgorithm);
    gtk_combo_box_set_active(GTK_COMBO_BOX(st->guiSt.mdAlgorithmComboBox), 0);
#endif

    st->cryptSt.nFactor = st->cryptoHeader.scryptWorkFactors[0];
    st->cryptSt.rFactor = st->cryptoHeader.scryptWorkFactors[1];
    st->cryptSt.pFactor = st->cryptoHeader.scryptWorkFactors[2];

#ifdef gui
    gtk_adjustment_set_value(GTK_ADJUSTMENT(st->guiSt.nFactorSpinButtonAdj), (gdouble)st->cryptSt.nFactor);
    gtk_adjustment_set_value(GTK_ADJUSTMENT(st->guiSt.rFactorSpinButtonAdj), (gdouble)st->cryptSt.rFactor);
    gtk_adjustment_set_value(GTK_ADJUSTMENT(st->guiSt.pFactorSpinButtonAdj), (gdouble)st->cryptSt.pFactor);
#endif

    return st->miscSt.inFile;
}

uint8_t printSyntax(char *arg)
{
    printf("\
\nUse: \
\n\n%s [-e|-d|-c|-m] -i infile -o outfile [-p pass] [-k keyfile] [-s sizes]\
\n-e,--encrypt - encrypt infile to outfile\
\n-c, --cipher - encryption algorithm to use\
\n-m, --message-digest - message digest algorithm to use\
\n-d,--decrypt - decrypt infile to outfile\
\n-i,--input-file - input file. Use '-' for standard input\
\n-o,--output-file - output file. Use '-' for standard output\
\n-p,--password - password to use\
\n-P,--prompt-for-pass - get password from prompt instead of as argument\
\n-V,--verify-pass - Will cause the program to ask you to verify the password you just entered via prompt\
\n-D,--display-pass - Will turn on echoing so you can see the password as you type it into the prompt\
\n-w,--work-factors - [N=],[r=],[p=]\
\n\t N=num\
\n\t\t N factor for scrypt to use. Must be a power of 2. Default 1048576\
\n\t r=num\
\n\t\t r factor for scrypt to use. Default 8\
\n\t p=num\
\n\t\t p factor for scrypt to use. Default 1\
\n-k,--key-file - keyfile to use\
\n-b,--buffer-sizes - [auth_buffer=],[file_buffer=]\
\n\t auth_buffer=num[b|k|m]\
\n\t\t Size of input buffer to use for generating MAC, in bytes, kilobytes, or megabytes\
\n\t file_buffer=num[b|k|m]\
\n\t\t Size of encryption/decryption input/output buffers to use in bytes, kilobytes or megabytes\
\n",
           arg);
    printf("\nCopyright (c) 1998-2019 The OpenSSL Project.  All rights reserved.\
This product includes software developed by the OpenSSL Project\
for use in the OpenSSL Toolkit (http://www.openssl.org/)\
\n\n\
This product includes cryptographic software written by Eric Young\
(eay@cryptsoft.com).  This product includes software written by Tim\
Hudson (tjh@cryptsoft.com).\n");
    return EXIT_FAILURE;
}

char *getPass(const char *prompt, char *paddedPass, struct dataStruct *st)
{
    struct termios termiosOld, termiosNew;
    size_t len = 0;
    int i = 0;
    int passLength = 0;
    char *pass = NULL;
    unsigned char *paddedPassTmp = calloc(sizeof(*paddedPassTmp), MAX_PASS_SIZE);
    if (paddedPassTmp == NULL) {
        PRINT_SYS_ERROR(errno);
        remove(st->fileNameSt.outputFileName);
        exit(EXIT_FAILURE);
    }

    if (!RAND_bytes(paddedPassTmp, MAX_PASS_SIZE)) {
        fprintf(stderr, "Failure: CSPRNG bytes could not be made unpredictable\n");
        if (!st->optSt.displayPass) {
            /* Restore terminal. */
            (void)tcsetattr(fileno(stdin), TCSAFLUSH, &termiosOld);
        }
        fprintf(stderr, "\nPassword was too large\n");
        remove(st->fileNameSt.outputFileName);
        exit(EXIT_FAILURE);
    }
    memcpy(paddedPass, paddedPassTmp, sizeof(*paddedPass) * MAX_PASS_SIZE);
    OPENSSL_cleanse(paddedPassTmp, sizeof(*paddedPassTmp) * MAX_PASS_SIZE);
    DDFREE(free,paddedPassTmp);
    paddedPassTmp = NULL;

    int nread = 0;

    if (!st->optSt.displayPass) {
        /* Turn echoing off and fail if we can’t. */
        if (tcgetattr(fileno(stdin), &termiosOld) != 0) {
            remove(st->fileNameSt.outputFileName);
            exit(EXIT_FAILURE);
        }
        termiosNew = termiosOld;
        termiosNew.c_lflag &= ~ECHO;
        if (tcsetattr(fileno(stdin), TCSAFLUSH, &termiosNew) != 0) {
            remove(st->fileNameSt.outputFileName);
            exit(EXIT_FAILURE);
        }
    }

    /* Read the password. */
    fprintf(stderr, "%s", prompt);
    nread = getline(&pass, &len, stdin);
    if (nread == -1) {
        remove(st->fileNameSt.outputFileName);
        exit(EXIT_FAILURE);
    } else if (nread > (MAX_PASS_SIZE - 1)) {
        if (!st->optSt.displayPass) {
            /* Restore terminal. */
            (void)tcsetattr(fileno(stdin), TCSAFLUSH, &termiosOld);
        }
        OPENSSL_cleanse(pass, sizeof(*pass) * nread);
        DDFREE(free,pass);
        pass = NULL;
        fprintf(stderr, "\nPassword was too large\n");
        remove(st->fileNameSt.outputFileName);
        exit(EXIT_FAILURE);
    } else {
        /*Replace newline with null terminator*/
        pass[nread - 1] = '\0';
    }

    if (!st->optSt.displayPass) {
        /* Restore terminal. */
        (void)tcsetattr(fileno(stdin), TCSAFLUSH, &termiosOld);
    }

    fprintf(stderr, "\n");

    /*Copy pass into paddedPass then remove sensitive information*/
    passLength = strlen(pass);
    for (i = 0; i < passLength + 1; i++)
        paddedPass[i] = pass[i];

    OPENSSL_cleanse(pass, sizeof(*pass) * nread);
    DDFREE(free,pass);
    pass = NULL;

    return paddedPass;
}

#ifdef gui
int writeBenchmark(double time, double rate, struct dataStruct *st)
{
	FILE *benchmarkFile = NULL;
	char benchmarkFileName[] = "benchmark.csv";
	
	
	if(!getFileSize(benchmarkFileName)) {
		benchmarkFile = fopen(benchmarkFileName, "w");
		if (benchmarkFile == NULL) {
			PRINT_FILE_ERROR(benchmarkFileName, errno);
			return 1;
		}
		
		fprintf(benchmarkFile,"Mode,Cipher,Digest,File Buffer,Auth Buffer,Elapsed\(s),Throughput(MB/s),Threads,Cores,CPU,\n");
	} else {
		benchmarkFile = fopen(benchmarkFileName, "a");
		if (benchmarkFile == NULL) {
			PRINT_FILE_ERROR(benchmarkFileName, errno);
			return 1;
		}
	}
		
    fprintf(benchmarkFile, "%s,", st->guiSt.encryptOrDecrypt);
    fprintf(benchmarkFile, "%s,", st->cryptSt.encAlgorithm);
    fprintf(benchmarkFile, "%s,", st->cryptSt.mdAlgorithm);
    fprintf(benchmarkFile, "%s,", st->guiSt.fileBufSizeComboBoxText);
    fprintf(benchmarkFile, "%s,", st->guiSt.authBufSizeComboBoxText);
    fprintf(benchmarkFile, "%0.2f,", time);
    fprintf(benchmarkFile, rate < 1 ? "%0.2f," : "%f,", rate);
    fprintf(benchmarkFile, "%zu,", st->cryptSt.threadNumber);
    fprintf(benchmarkFile, "%zu,", getNumCores());
    fprintf(benchmarkFile, "%s,", getCpuName());
    fprintf(benchmarkFile, "\n");

    fclose(benchmarkFile);

    return 0;
}
#endif

void parseOptions(
    int argc,
    char *argv[],
    struct dataStruct *st)
{
    int c;
    int errflg = 0;
    char binName[MAX_FILE_NAME_SIZE];
    snprintf(binName, MAX_FILE_NAME_SIZE, "%s", argv[0]);

    while (1) {
        int option_index = 0;
        static struct option long_options[] = {
            {"help", no_argument, 0, 'h'},
            {"encrypt", no_argument, 0, 'e'},
            {"decrypt", no_argument, 0, 'd'},
            {"benchmark", no_argument, 0, 'B'},
            {"benchmark-amount", no_argument, 0, 'a'},
            {"prompt-for-pass", no_argument, 0, 'P'},
            {"verify-pass", no_argument, 0, 'V'},
            {"display-pass", no_argument, 0, 'D'},
            {"input-file", required_argument, 0, 'i'},
            {"threads", required_argument, 0, 't'},
            {"output-file", required_argument, 0, 'o'},
            {"key-file", required_argument, 0, 'k'},
            {"password", required_argument, 0, 'p'},
            {"work-factors", required_argument, 0, 'w'},
            {"buffer-sizes", required_argument, 0, 'b'},
            {"cipher", required_argument, 0, 'c'},
            {"message-digest", required_argument, 0, 'm'},
            {0, 0, 0, 0}};

        char *subopts;
        char *value;

        c = getopt_long(argc, argv, "hqedPVDBa:i:t:o:k:p:w:b:c:m:",
                        long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {

        case 'h':
            printSyntax(binName);
            exit(EXIT_FAILURE);
            break;
        case 'q':
            st->optSt.quitWhenDone = true;
            break;
        case 'e':
            st->optSt.encrypt = true;
            break;
        case 'd':
            st->optSt.decrypt = true;
            break;
        case 'B':
            st->optSt.benchmark = true;
            break;
        case 'a':
            st->optSt.benchmarkTime = true;
            st->miscSt.benchmarkTime = atol(optarg);
            break;
        case 'V':
            st->optSt.verifyPass = true;
            break;
        case 'D':
            st->optSt.displayPass = true;
            break;
        case 'P':
            st->optSt.getPassFromPrompt = true;
            st->optSt.passWordGiven = true;
            break;
        case 't':
            if (optarg[0] == '-' && strlen(optarg) == 2) {
                fprintf(stderr, "Option -t requires an argument\n");
                errflg++;
                break;
            } else {
				st->optSt.useThreads = true;
				st->cryptSt.threadNumber = atol(optarg);
				if(st->cryptSt.threadNumber == 0) {
					st->cryptSt.threadNumber = get_nprocs_conf();
				}
			}
            break;
        case 'i':
            if (optarg[0] == '-' && strlen(optarg) == 2) {
                fprintf(stderr, "Option -i requires an argument\n");
                errflg++;
                break;
            } else if (optarg[0] == '-') {
                st->optSt.inputFileGiven = true;
                st->fileNameSt.inputFileName = strdup("stdin");

                st->optSt.readFromStdin = true;
            } else {
                st->optSt.inputFileGiven = true;
                st->fileNameSt.inputFileName = strdup(optarg);
            }
            break;
        case 'o':
            if (optarg[0] == '-' && strlen(optarg) == 2) {
                fprintf(stderr, "Option -o requires an argument\n");
                errflg++;
                break;
            } else if (optarg[0] == '-') {
                st->optSt.outputFileGiven = true;
                st->fileNameSt.outputFileName = strdup("stdout");

                st->optSt.writeToStdout = true;
            } else {
                st->optSt.outputFileGiven = true;
                st->fileNameSt.outputFileName = strdup(optarg);
            }
            break;
        case 'k':
            if (optarg[0] == '-' && strlen(optarg) == 2) {
                fprintf(stderr, "Option -k requires an argument\n");
                errflg++;
                break;
            } else if (optarg[0] == '-') {
                st->optSt.keyFileGiven = true;
                st->fileNameSt.keyFileName = strdup("stdin");

                st->optSt.keyFromStdin = true;
            } else {
                st->optSt.keyFileGiven = true;
                st->fileNameSt.keyFileName = strdup(optarg);
            }
            break;
        case 'p':
            if (optarg[0] == '-' && strlen(optarg) == 2) {
                fprintf(stderr, "Option -p requires an argument\n");
                errflg++;
                break;
            } else {
                st->optSt.getPassFromArg = true;
                snprintf(st->cryptSt.userPass, MAX_PASS_SIZE, "%s", optarg);
                st->optSt.passWordGiven = true;
            }
            break;
        case 'w':
            if (optarg[0] == '-') {
                fprintf(stderr, "Option -%c requires an argument\n", c);
                errflg++;
                break;
            }

            enum {
                N_FACTOR = 0,
                R_FACTOR,
                P_FACTOR
            };

            char *const token[] = {
                [N_FACTOR] = "N",
                [R_FACTOR] = "r",
                [P_FACTOR] = "p",
                NULL};

            subopts = optarg;

            while (*subopts != '\0' && !errflg) {
                switch (getsubopt(&subopts, token, &value)) {
                case N_FACTOR:
                    st->cryptSt.nFactor = atol(value);

                    int testNum = st->cryptSt.nFactor;
                    while (testNum > 1) {
                        if (testNum % 2 != 0) {
                            fprintf(stderr, "scrypt's N factor must be a power of 2.");
                            st->cryptSt.nFactor--;
                            st->cryptSt.nFactor |= st->cryptSt.nFactor >> 1;
                            st->cryptSt.nFactor |= st->cryptSt.nFactor >> 2;
                            st->cryptSt.nFactor |= st->cryptSt.nFactor >> 4;
                            st->cryptSt.nFactor |= st->cryptSt.nFactor >> 8;
                            st->cryptSt.nFactor |= st->cryptSt.nFactor >> 16;
                            st->cryptSt.nFactor++;
                            fprintf(stderr, " Rounding it up to %zu\n", st->cryptSt.nFactor);
                            break;
                        }
                        testNum /= 2;
                    }
                    st->optSt.nFactorGiven = true;
                    break;
                case R_FACTOR:
                    st->cryptSt.rFactor = atol(value);
                    st->optSt.rFactorGiven = true;
                    break;
                case P_FACTOR:
                    st->cryptSt.pFactor = atol(value);
                    st->optSt.pFactorGiven = true;
                    break;
                default:
                    fprintf(stderr, "No match found for token: %s\n", value);
                    errflg = 1;
                    break;
                }
            }
            break;
        case 'b':
            if (optarg[0] == '-' && strlen(optarg) == 2) {
                fprintf(stderr, "Option -b requires an argument\n");
                errflg++;
                break;
            } else {
                enum {
                    AUTH_BUFFER = 0,
                    FILE_BUFFER
                };

                char *const token[] = {
                    [AUTH_BUFFER] = "auth_buffer",
                    [FILE_BUFFER] = "file_buffer",
                    NULL};

                subopts = optarg;
                while (*subopts != '\0' && !errflg) {
                    switch (getsubopt(&subopts, token, &value)) {
                    case AUTH_BUFFER:
                        if (value == NULL) {
                            fprintf(stderr, "Missing value for suboption '%s'\n", token[AUTH_BUFFER]);
                            errflg = 1;
                            continue;
                        }

                        st->optSt.authBufSizeGiven = true;
                        st->cryptSt.genAuthBufSize = atol(value) * sizeof(uint8_t) * getBufSizeMultiple(value);
                        break;
                    case FILE_BUFFER:
                        if (value == NULL) {
                            fprintf(stderr, "Missing value for "
                                            "suboption '%s'\n",
                                    token[FILE_BUFFER]);
                            errflg = 1;
                            continue;
                        }

                        st->optSt.fileBufSizeGiven = true;

                        st->cryptSt.fileBufSize = (atol(value) * getBufSizeMultiple(value));
                        break;
                    default:
                        fprintf(stderr, "No match found for token: /%s/\n", value);
                        errflg = 1;
                        break;
                    }
                }
            }
            break;
        case 'c':
            if (optarg[0] == '-' && strlen(optarg) == 2) {
                fprintf(stderr, "Option -c requires an argument\n");
                errflg++;
                break;
            } else {
                DDFREE(free,st->cryptSt.encAlgorithm);
                st->cryptSt.encAlgorithm = strdup(optarg);
                if (st->cryptSt.encAlgorithm == NULL) {
                    PRINT_SYS_ERROR(errno);
                    exit(EXIT_FAILURE);
                }

                if(strcmp(st->cryptSt.encAlgorithm,"null") == 0) {
                    st->cryptSt.evpCipher = EVP_enc_null();
                } else if (strcmp(st->cryptSt.encAlgorithm,"list-supported") == 0) {
                    st->optSt.listSupportedCiphers = true;
                    OBJ_NAME_do_all(OBJ_NAME_TYPE_CIPHER_METH, encListCallback, st);
                    exit(EXIT_SUCCESS);
                } else if (strcmp(st->cryptSt.encAlgorithm,"list-all") == 0) {
                    st->optSt.listAllCiphers = true;
                    OBJ_NAME_do_all(OBJ_NAME_TYPE_CIPHER_METH, encListCallback, st);
                    exit(EXIT_SUCCESS);
                } else {
                    st->cryptSt.evpCipher = EVP_get_cipherbyname(st->cryptSt.encAlgorithm);
                    if (!st->cryptSt.evpCipher) {
                        fprintf(stderr, "Could not load cipher: %s\n", st->cryptSt.encAlgorithm);
                        exit(EXIT_FAILURE);
                    } else if (!isSupportedCipher(st->cryptSt.encAlgorithm)) {
                        fprintf(stderr, "Cipher not supported: %s\n", st->cryptSt.encAlgorithm);
                        exit(EXIT_FAILURE);
                    }
                }

                st->optSt.encAlgorithmGiven = true;
            }
            break;
        case 'm':
            if (optarg[0] == '-' && strlen(optarg) == 2) {
                fprintf(stderr, "Option -m requires an argument\n");
                errflg++;
                break;
            } else {
                st->cryptSt.mdAlgorithm = strdup(optarg);
                if (st->cryptSt.mdAlgorithm == NULL) {
                    PRINT_SYS_ERROR(errno);
                    exit(EXIT_FAILURE);
                }

                if(strcmp(st->cryptSt.mdAlgorithm,"null") == 0) {
                    st->cryptSt.evpDigest = EVP_md_null();
                } else if(strcmp(st->cryptSt.mdAlgorithm,"list-supported") == 0) {
                    st->optSt.listSupportedDigests = true;
                    OBJ_NAME_do_all(OBJ_NAME_TYPE_MD_METH, mdListCallback, st);
                    exit(EXIT_SUCCESS);
                } else if(strcmp(st->cryptSt.mdAlgorithm,"list-all") == 0) {
                    st->optSt.listAllDigests = true;
                    OBJ_NAME_do_all(OBJ_NAME_TYPE_MD_METH, mdListCallback, st);
                    exit(EXIT_SUCCESS);
                } else {
                    st->cryptSt.evpDigest = EVP_get_digestbyname(st->cryptSt.mdAlgorithm);
                    if (!st->cryptSt.evpDigest) {
                        fprintf(stderr, "Could not load digest: %s\n", st->cryptSt.mdAlgorithm);
                        exit(EXIT_FAILURE);
                    }
                }

                st->optSt.mdAlgorithmGiven = true;
            }
            break;
        case ':':
            fprintf(stderr, "Option -%c requires an argument\n", optopt);
            errflg++;
            break;
        case '?':
            errflg++;
            break;
        }
    }

    if (st->optSt.encrypt && st->optSt.decrypt) {
        fprintf(stderr, "-d and -e are mutually exlusive. Can only encrypt or decrypt, not both.\n");
        errflg++;
    }
    if (!st->optSt.encrypt && !st->optSt.decrypt) {
        fprintf(stderr, "Must specify to either encrypt or decrypt (-e or -d)\n");
        errflg++;
    }
    if (!st->optSt.inputFileGiven || !st->optSt.outputFileGiven) {
        fprintf(stderr, "Must specify an input and output file\n");
        errflg++;
    }

    if (!strcmp(st->fileNameSt.inputFileName, st->fileNameSt.outputFileName)) {
        fprintf(stderr, "Input file and output file are the same\n");
        errflg++;
    }

    if (st->optSt.getPassFromPrompt && st->optSt.getPassFromArg) {
        fprintf(stderr, "Supply the password either via prompt or via arg, not both\n");
        errflg++;
    }

    if (st->optSt.readFromStdin && st->optSt.keyFromStdin) {
        fprintf(stderr, "Cannot read both input file and keyfile from standard input. Must choose only one, or use a FIFO.\n");
        errflg++;
    }
    
    if(st->optSt.fileBufSizeGiven && st->optSt.encAlgorithmGiven) {
		uint8_t cipherBlockSize = EVP_CIPHER_get_block_size(EVP_get_cipherbyname(st->cryptSt.encAlgorithm));
		
		if(st->cryptSt.fileBufSize % cipherBlockSize) {
			fprintf(stderr,"File buffer size (%zu) needs to be a multiple of the cipher block size (%d) if using %s\nReducing to %zu\n", st->cryptSt.fileBufSize, cipherBlockSize, st->cryptSt.encAlgorithm, st->cryptSt.fileBufSize - (st->cryptSt.fileBufSize % cipherBlockSize));
			makeMultipleOf(&st->cryptSt.fileBufSize, cipherBlockSize);
		}
	}

    for (int i = 1; i < argc; i++) {
        OPENSSL_cleanse(argv[i], strlen(argv[i]));
    }

    if (errflg) {
        printSyntax(binName);
        exit(EXIT_FAILURE);
    }
}
