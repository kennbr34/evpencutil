#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <termios.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "lib.h"

struct termios termiosOld, termiosNew;


char *getPass(const char *prompt, char *paddedPass)
{
    size_t len = 0;
    int i = 0;
    int passLength = 0;
    char *pass = NULL;
    unsigned char *paddedPassTmp = calloc(sizeof(*paddedPassTmp), MAX_PASS_SIZE);
    if (paddedPassTmp == NULL) {
        printSysError(errno);
        exit(EXIT_FAILURE);
    }

    if (!RAND_bytes(paddedPassTmp, MAX_PASS_SIZE)) {
        fprintf(stderr, "Failure: CSPRNG bytes could not be made unpredictable\n");
        /* Restore terminal. */
        (void)tcsetattr(fileno(stdin), TCSAFLUSH, &termiosOld);
        fprintf(stderr, "\nPassword was too large\n");
        exit(EXIT_FAILURE);
    }
    memcpy(paddedPass, paddedPassTmp, sizeof(*paddedPass) * MAX_PASS_SIZE);
    OPENSSL_cleanse(paddedPassTmp, sizeof(*paddedPassTmp) * MAX_PASS_SIZE);
    free(paddedPassTmp);
    paddedPassTmp = NULL;

    int nread = 0;

    /* Turn echoing off and fail if we can’t. */
    if (tcgetattr(fileno(stdin), &termiosOld) != 0)
        exit(EXIT_FAILURE);
    termiosNew = termiosOld;
    termiosNew.c_lflag &= ~ECHO;
    if (tcsetattr(fileno(stdin), TCSAFLUSH, &termiosNew) != 0)
        exit(EXIT_FAILURE);

    /* Read the password. */
    fprintf(stderr, "\n%s", prompt);
    nread = getline(&pass, &len, stdin);
    if (nread == -1)
        exit(EXIT_FAILURE);
    else if (nread > (MAX_PASS_SIZE - 1)) {
        /* Restore terminal. */
        (void)tcsetattr(fileno(stdin), TCSAFLUSH, &termiosOld);
        OPENSSL_cleanse(pass, sizeof(*pass) * nread);
        free(pass);
        pass = NULL;
        fprintf(stderr, "\nPassword was too large\n");
        exit(EXIT_FAILURE);
    } else {
        /*Replace newline with null terminator*/
        pass[nread - 1] = '\0';
    }

    /* Restore terminal. */
    (void)tcsetattr(fileno(stdin), TCSAFLUSH, &termiosOld);

    fprintf(stderr, "\n");

    /*Copy pass into paddedPass then remove sensitive information*/
    passLength = strlen(pass);
    for (i = 0; i < passLength + 1; i++)
        paddedPass[i] = pass[i];

    OPENSSL_cleanse(pass, sizeof(*pass) * nread);
    free(pass);
    pass = NULL;

    return paddedPass;
}

int main(int argc, char *argv[])
{
    if (argc == 1) {
        printSyntax(argv[0]);
        exit(EXIT_FAILURE);
    }

    struct dataStruct st = {0};

    #if OPENSSL_VERSION_MAJOR >= 3
    OSSL_PROVIDER_load(NULL, "legacy");
    OSSL_PROVIDER_load(NULL, "default");
    #endif

    OpenSSL_add_all_algorithms();

    st.cryptSt.encAlgorithm = strdup(DEFAULT_ENC);
    st.cryptSt.evpCipher = EVP_get_cipherbyname(st.cryptSt.encAlgorithm);
    st.cryptSt.mdAlgorithm = strdup(DEFAULT_MD);
    st.cryptSt.evpDigest = EVP_get_digestbyname(st.cryptSt.mdAlgorithm);

    st.cryptSt.nFactor = DEFAULT_SCRYPT_N;
    st.cryptSt.pFactor = DEFAULT_SCRYPT_P;
    st.cryptSt.rFactor = DEFAULT_SCRYPT_R;

    st.cryptSt.genHmacBufSize = 1024 * 1024;
    st.cryptSt.msgBufSize = 1024 * 1024;

    parseOptions(argc, argv, &st);

    allocateBuffers(&st);

    if (st.optSt.encrypt) {
        workThread('e', &st);
    } else if (st.optSt.decrypt) {
        workThread('d', &st);
    }

    wait(NULL);

    cleanUpBuffers(&st);

    return EXIT_SUCCESS;
}
