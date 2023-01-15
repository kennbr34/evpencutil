#include "headers.h"

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
\n", arg);
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
struct dataStruct *st
) {
    int c;
    int errflg = 0;
    char binName[MAX_FILE_NAME_SIZE];
    snprintf(binName,MAX_FILE_NAME_SIZE,"%s",argv[0]);

    /*Process through arguments*/
    while (1) {
        int option_index = 0;
        static struct option long_options[] = {
            {"help",           no_argument,       0,'h' },
            {"encrypt",        no_argument,       0,'e' },
            {"decrypt",        no_argument,       0,'d' },
            {"input-file",     required_argument, 0,'i' },
            {"output-file",    required_argument, 0,'o' },
            {"key-file",       required_argument, 0,'k' },
            {"password",       required_argument, 0,'p' },
            {"work-factors",   required_argument, 0,'w' },
            {"sizes",          required_argument, 0,'s' },
            {0,                0,                 0, 0  }
        };
        
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
                    [MAC_BUFFER]   = "mac_buffer",
                    [MSG_BUFFER]   = "message_buffer",
                    NULL
                };
                
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
                        makeMultipleOf(&st->cryptSt.genHmacBufSize,sizeof(uint64_t));
                    break;
                    case MSG_BUFFER:
                        if (value == NULL) {
                            fprintf(stderr, "Missing value for "
                            "suboption '%s'\n", token[MSG_BUFFER]);
                            errflg = 1;
                            continue;
                        }
                        
                        st->optSt.msgBufSizeGiven = true;
                        
                        /*Divide the amount specified by the size of uint64_t since it will 
                         * be multipled later*/
                        st->cryptSt.msgBufSize = (atol(value) * getBufSizeMultiple(value));
                        makeMultipleOf(&st->cryptSt.msgBufSize,sizeof(uint64_t));
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
                if(st->cryptSt.encAlgorithm == NULL) {
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
                if(st->cryptSt.mdAlgorithm == NULL) {
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

    if(st->optSt.encrypt && st->optSt.decrypt) {
        fprintf(stderr, "-d and -e are mutually exlusive. Can only encrypt or decrypt, not both.\n");
        errflg++;
    }
    if(!st->optSt.encrypt && !st->optSt.decrypt) {
        fprintf(stderr, "Must specify to either encrypt or decrypt (-e or -d)\n");
        errflg++;
    }
    if(!st->optSt.inputFileGiven || !st->optSt.outputFileGiven) {
        fprintf(stderr, "Must specify an input and output file\n");
        errflg++;
    }
    
    if(!strcmp(st->fileNameSt.inputFileName,st->fileNameSt.outputFileName)) {
        fprintf(stderr, "Input file and output file are the same\n");
        errflg++;
    }
    
    if (errflg) {
        printSyntax(binName);
        exit(EXIT_FAILURE);
    }
}
