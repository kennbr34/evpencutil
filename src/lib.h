#include <ctype.h>
#include <errno.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#ifdef gui
#include <gtk/gtk.h>
#endif

#define _FILE_OFFSET_BITS 64
#define MAX_PASS_SIZE 512
#define DEFAULT_ENC "aes-256-ctr"
#define DEFAULT_MD "sha512"
#define DEFAULT_SCRYPT_N 1048576
#define DEFAULT_SCRYPT_R 8
#define DEFAULT_SCRYPT_P 1
#define PASS_KEYED_HASH_SIZE SHA512_DIGEST_LENGTH
#define HMAC_KEY_SIZE SHA512_DIGEST_LENGTH
#define MAC_SIZE SHA512_DIGEST_LENGTH
#define EVP_SALT_SIZE SHA512_DIGEST_LENGTH
#define EVPENCUTIL_STRING_SIZE 11
#define ALGORITHM_STRING_SIZE SHA512_DIGEST_LENGTH
#define MAX_FILE_NAME_SIZE PATH_MAX + NAME_MAX + 1

struct cryptoStruct {
    uint8_t *evpKey;
    uint8_t *evpSalt;
    uint8_t *keyFileBuffer;

    char userPass[MAX_PASS_SIZE];
    char userPassToVerify[MAX_PASS_SIZE];
    uint8_t passKeyedHash[PASS_KEYED_HASH_SIZE], passKeyedHashFromFile[PASS_KEYED_HASH_SIZE];

    size_t nFactor;
    size_t pFactor;
    size_t rFactor;

    uint8_t generatedMAC[EVP_MAX_MD_SIZE];
    uint8_t fileMAC[EVP_MAX_MD_SIZE];
    uint8_t *hmacKey;
    uint32_t *HMACLengthPtr;

    uint8_t keyFileHash[EVP_MAX_MD_SIZE];

    size_t genAuthBufSize;
    size_t fileBufSize;

    const EVP_CIPHER *evpCipher;
    const EVP_MD *evpDigest;

    char *encAlgorithm;
    char *mdAlgorithm;
    
    uint64_t threadNumber;
};

struct fileNames {
    char *inputFileName;
    char *outputFileName;
    char *keyFileName;
    char *otpInFileName;
    char *otpOutFileName;
};

struct optionsStruct {
    bool encrypt;
    bool decrypt;
    bool benchmark;
    bool benchmarkTime;
    bool inputFileGiven;
    bool readFromStdin;
    bool writeToStdout;
    bool outputFileGiven;
    bool keyFileGiven;
    bool keyFromStdin;
    bool passWordGiven;
    bool getPassFromPrompt;
    bool getPassFromArg;
    bool verifyPass;
    bool displayPass;
    bool keyBufSizeGiven;
    bool authBufSizeGiven;
    bool fileBufSizeGiven;
    bool nFactorGiven;
    bool rFactorGiven;
    bool pFactorGiven;
    bool quitWhenDone;
    bool encAlgorithmGiven;
    bool mdAlgorithmGiven;
    bool useThreads;
    bool listAllCiphers;
    bool listSupportedCiphers;
    bool listSupportedDigests;
    bool listAllDigests;
};

struct miscStruct {
    uint64_t returnVal;
    uint64_t freadAmt;
    FILE *inFile;
    size_t benchmarkTime;
};

#ifdef gui
struct guiStruct {
    char encryptOrDecrypt[8];

    GtkWidget *win;

    GtkWidget *inputFileNameBox;
    GtkWidget *outputFileNameBox;
    GtkWidget *keyFileNameBox;
    GtkWidget *passwordBox;
    GtkWidget *passwordVerificationBox;

    GtkWidget *nFactorTextBox;
    GtkWidget *rFactorTextBox;
    GtkWidget *pFactorTextBox;

    GtkAdjustment *nFactorSpinButtonAdj;
    GtkAdjustment *rFactorSpinButtonAdj;
    GtkAdjustment *pFactorSpinButtonAdj;

    GtkWidget *keyFileButton;

    GtkWidget *keySizeComboBox;
    GtkWidget *authBufSizeComboBox;
    GtkWidget *fileBufSizeComboBox;
    GtkWidget *encAlgorithmComboBox;
    GtkWidget *mdAlgorithmComboBox;

    const char *inputFilePath;
    const char *outputFilePath;
    const char *keyFilePath;
    const char *passWord;
    const char *verificationPass;
    const char *keySizeComboBoxText;
    const char *authBufSizeComboBoxText;
    const char *fileBufSizeComboBoxText;

    double *progressFraction;
    char *statusMessage;

    GtkWidget *statusBar;
    guint statusContextID;

    GtkWidget *overallProgressBar;
    double *overallProgressFraction;

    GtkWidget *progressBar;
    
    clock_t startTime, endTime;
    double totalTime;
    uint64_t startBytes, endBytes, totalBytes;

    clock_t startLoop, endLoop;
    double loopTime;

    double loopRate, averageRate;
};
#endif

struct headerStruct {
    const char evpEncUtilString[EVPENCUTIL_STRING_SIZE];
    char algorithmString[ALGORITHM_STRING_SIZE];
    uint8_t evpSalt[EVP_SALT_SIZE];
    uint32_t scryptWorkFactors[3];
    size_t fileBufSize;
};

struct timerStruct {
	clock_t startTime, endTime;
    double totalTime;
    uint64_t startBytes, endBytes, totalBytes;

    clock_t startLoop, endLoop;
    double loopTime;

    double loopRate, averageRate;
    
    size_t benchmarkTime;
};

struct dataStruct {
    struct cryptoStruct cryptSt;
    struct fileNames fileNameSt;
    struct optionsStruct optSt;
    struct miscStruct miscSt;
#ifdef gui
    struct guiStruct guiSt;
#endif
    struct headerStruct cryptoHeader;
    struct timerStruct timeSt;
};

#define PRINT_SYS_ERROR(errCode) \
    { \
        fprintf(stderr, "%s:%s:%d: %s\n", __FILE__, __func__, __LINE__, strerror(errCode)); \
    }

#define PRINT_FILE_ERROR(fileName, errCode) \
    { \
        fprintf(stderr, "%s: %s (Line: %i)\n", fileName, strerror(errCode), __LINE__); \
    }

#define PRINT_ERROR(errMsg) \
    { \
        fprintf(stderr, "%s:%s:%d: %s\n", __FILE__, __func__, __LINE__, errMsg); \
    }
    
//Double-Free/Dangling-Pointer-free cleanup function wrapper for free(), EVP_CIPHER_CTX_free(), etc.
#define DDFREE(freeFunc, ptr) do { \
    if ((ptr) != NULL) { \
        freeFunc(ptr); \
        (ptr) = NULL; \
    } \
} while (0)

#define PRINT_BUFFER(buffer, size, message) do { \
    printf("%s:%d %s\n", __func__, __LINE__, message); \
    for(int i = 0; i < size; i++) { \
        printf("%02x", buffer[i] & 0xff); \
    };printf("\n"); \
} while (0)

#ifndef gui
void encListCallback(const OBJ_NAME *obj, void *arg);
void mdListCallback(const OBJ_NAME *obj, void *arg);
#endif
char * getCpuName(void);
size_t getNumCores(void);
uint8_t isSupportedCipher(uint8_t *cipher);
uint8_t isSupportedDigest(uint8_t *digest);
void allocateBuffers(struct dataStruct *st);
void cleanUpBuffers(void);
void doEncrypt(FILE *inFile, FILE *outFile, uint64_t fileSize, struct dataStruct *st);
void doDecrypt(FILE *inFile, FILE *outFile, uint64_t fileSize, struct dataStruct *st);
uint64_t freadWErrCheck(void *ptr, size_t size, size_t nmemb, FILE *stream, struct dataStruct *st);
uint64_t fwriteWErrCheck(void *ptr, size_t size, size_t nmemb, FILE *stream, struct dataStruct *st);
void genChunkKey(struct dataStruct *st);
void genHMAC(FILE *dataFile, uint64_t fileSize, struct dataStruct *st);
void genHMACKey(struct dataStruct *st, uint8_t *lastChunk, uint32_t chunkSize);
void genPassTag(struct dataStruct *st);
void genEvpSalt(struct dataStruct *st);
void genEvpKey(struct dataStruct *st);
void HKDFKeyFile(struct dataStruct *st);
void genKeyFileHash(FILE *dataFile, uint64_t fileSize, struct dataStruct *st);
uint64_t getFileSize(const char *filename);
uint8_t printSyntax(char *arg);
void signalHandler(int signum);
void makeMultipleOf(size_t *numberToChange, size_t multiple);
int workThread(char action, struct dataStruct *st);
char *getPass(const char *prompt, char *paddedPass, struct dataStruct *st);
void parseOptions(int argc, char *argv[], struct dataStruct *st);
void bytesPrefixed(char *prefixedString, unsigned long long bytes);
size_t getBufSizeMultiple(char *value);
void encListCallback(const OBJ_NAME *obj, void *arg);
void mdListCallback(const OBJ_NAME *obj, void *arg);
int writeBenchmark(double time, double rate, struct dataStruct *st);
FILE *parseCryptoHeader(FILE *inFile, struct dataStruct *st);
