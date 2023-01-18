#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include "lib.h"

uint64_t freadWErrCheck(void *ptr, size_t size, size_t nmemb, FILE *stream, struct dataStruct *st)
{
    if (fread(ptr, size, nmemb, stream) != nmemb / size) {
        if (feof(stream)) {
            st->miscSt.returnVal = EBADMSG;
            return EBADMSG;
        } else if (ferror(stream)) {
            st->miscSt.returnVal = errno;
            return errno;
        }
    }

    return 0;
}

uint64_t fwriteWErrCheck(void *ptr, size_t size, size_t nmemb, FILE *stream, struct dataStruct *st)
{
    if (fwrite(ptr, size, nmemb, stream) != nmemb / size) {
        if (feof(stream)) {
            st->miscSt.returnVal = EBADMSG;
            return EBADMSG;
        } else if (ferror(stream)) {
            st->miscSt.returnVal = errno;
            return errno;
        }
    }

    return 0;
}

uint64_t getFileSize(const char *filename)
{
    struct stat st;
    stat(filename, &st);
    return st.st_size;
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

uint8_t printSyntax(char *arg)
{
    printf("\
\nUse: \
\n\n%s [-e|-d] -i infile -o outfile [-p pass] [-k keyfile] [-s sizes]\
\n-e,--encrypt - encrypt infile to outfile\
\n-d,--decrypt - decrypt infile to outfile\
\n-i,--input-file - input file\
\n-o,--output-file - output file\
\n-p,--password - password to use\
\n-w,--work-factors - [N=],[r=],[p=]\
\n\t N=num\
\n\t\t N factor for scrypt to use. Must be a power of 2. Default 1048576\
\n\t r=num\
\n\t\t r factor for scrypt to use. Default 8\
\n\t p=num\
\n\t\t p factor for scrypt to use. Default 1\
\n-k,--key-file - keyfile to use\
\n-s,--sizes - [mac_buffer=],[message_buffer=]\
\n\t mac_buffer=num[b|k|m]\
\n\t\t Size of input buffer to use for generating MAC, in bytes, kilobytes, or megabytes\
\n\t message_buffer=num[b|k|m]\
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
            {"input-file", required_argument, 0, 'i'},
            {"output-file", required_argument, 0, 'o'},
            {"key-file", required_argument, 0, 'k'},
            {"password", required_argument, 0, 'p'},
            {"work-factors", required_argument, 0, 'w'},
            {"sizes", required_argument, 0, 's'},
            {0, 0, 0, 0}};

        char *subopts;
        char *value;

        c = getopt_long(argc, argv, "hqedi:o:k:p:w:s:c:m:",
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
        case 'i':
            if (optarg[0] == '-' && strlen(optarg) == 2) {
                fprintf(stderr, "Option -i requires an argument\n");
                errflg++;
                break;
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
                st->optSt.passWordGiven = true;
                snprintf(st->cryptSt.userPass, MAX_PASS_SIZE, "%s", optarg);
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
        case 's':
            if (optarg[0] == '-' && strlen(optarg) == 2) {
                fprintf(stderr, "Option -s requires an argument\n");
                errflg++;
                break;
            } else {
                enum {
                    MAC_BUFFER = 0,
                    MSG_BUFFER
                };

                char *const token[] = {
                    [MAC_BUFFER] = "mac_buffer",
                    [MSG_BUFFER] = "message_buffer",
                    NULL};

                subopts = optarg;
                while (*subopts != '\0' && !errflg) {
                    switch (getsubopt(&subopts, token, &value)) {
                    case MAC_BUFFER:
                        if (value == NULL) {
                            fprintf(stderr, "Missing value for suboption '%s'\n", token[MAC_BUFFER]);
                            errflg = 1;
                            continue;
                        }

                        st->optSt.macBufSizeGiven = true;
                        st->cryptSt.genHmacBufSize = atol(value) * sizeof(uint8_t) * getBufSizeMultiple(value);
                        makeMultipleOf(&st->cryptSt.genHmacBufSize, sizeof(uint64_t));
                        break;
                    case MSG_BUFFER:
                        if (value == NULL) {
                            fprintf(stderr, "Missing value for "
                                            "suboption '%s'\n",
                                    token[MSG_BUFFER]);
                            errflg = 1;
                            continue;
                        }

                        st->optSt.msgBufSizeGiven = true;

                        /*Divide the amount specified by the size of uint64_t since it will
                         * be multipled later*/
                        st->cryptSt.msgBufSize = (atol(value) * getBufSizeMultiple(value));
                        makeMultipleOf(&st->cryptSt.msgBufSize, sizeof(uint64_t));
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
                st->cryptSt.encAlgorithm = strdup(optarg);
                if (st->cryptSt.encAlgorithm == NULL) {
                    printSysError(errno);
                    exit(EXIT_FAILURE);
                }

                st->cryptSt.evpCipher = EVP_get_cipherbyname(st->cryptSt.encAlgorithm);
                if (!st->cryptSt.evpCipher) {
                    fprintf(stderr, "Could not load cipher: %s\n", st->cryptSt.encAlgorithm);
                    exit(EXIT_FAILURE);
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
                    printSysError(errno);
                    exit(EXIT_FAILURE);
                }

                st->cryptSt.evpDigest = EVP_get_digestbyname(st->cryptSt.mdAlgorithm);
                if (!st->cryptSt.evpDigest) {
                    fprintf(stderr, "Could not load digest: %s\n", st->cryptSt.mdAlgorithm);
                    exit(EXIT_FAILURE);
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

    if (errflg) {
        printSyntax(binName);
        exit(EXIT_FAILURE);
    }
}