#include <openssl/crypto.h>
#if OPENSSL_VERSION_MAJOR >= 3
#include <openssl/provider.h>
#endif
#include "lib.h"
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
    if (argc == 1) {
        printSyntax(argv[0]);
        exit(EXIT_FAILURE);
    }

    struct dataStruct st = {0};
    dataStGlobal = &st;

#if OPENSSL_VERSION_MAJOR >= 3
    typedef struct ossl_provider_st OSSL_PROVIDER;
    OSSL_PROVIDER *legacy = OSSL_PROVIDER_load(NULL, "legacy");
    OSSL_PROVIDER *dfault = OSSL_PROVIDER_load(NULL, "default");
#endif

    OpenSSL_add_all_algorithms();

    st.cryptSt.encAlgorithm = strdup(DEFAULT_ENC);
    st.cryptSt.evpCipher = EVP_get_cipherbyname(st.cryptSt.encAlgorithm);
    st.cryptSt.mdAlgorithm = strdup(DEFAULT_MD);
    st.cryptSt.evpDigest = EVP_get_digestbyname(st.cryptSt.mdAlgorithm);

    st.cryptSt.nFactor = DEFAULT_SCRYPT_N;
    st.cryptSt.pFactor = DEFAULT_SCRYPT_P;
    st.cryptSt.rFactor = DEFAULT_SCRYPT_R;

    st.cryptSt.fileBufSize = 1024 * 1024;

    parseOptions(argc, argv, &st);

    if (st.optSt.getPassFromPrompt) {
        getPass("Enter password: ", st.cryptSt.userPass, &st);
        if (st.optSt.verifyPass) {
            getPass("Verify password: ", st.cryptSt.userPassToVerify, &st);
            if (strcmp(st.cryptSt.userPass, st.cryptSt.userPassToVerify) != 0) {
                printf("Passwords didn't match\n");
                exit(EXIT_FAILURE);
            }
        }
    }

    allocateBuffers(&st);

    if (st.optSt.encrypt) {
        workThread('e', &st);
    } else if (st.optSt.decrypt) {
        workThread('d', &st);
    }

    int waitStatus = 0;

    wait(&waitStatus);

    DDFREE(free, st.cryptSt.encAlgorithm);

    DDFREE(free, st.cryptSt.mdAlgorithm);

    DDFREE(free, st.fileNameSt.outputFileName);

    DDFREE(free, st.fileNameSt.inputFileName);

    DDFREE(free, st.cryptSt.evpKey);

    DDFREE(free, st.cryptSt.evpSalt);

    DDFREE(free, st.cryptSt.hmacKey);

#if OPENSSL_VERSION_MAJOR >= 3
    DDFREE(OSSL_PROVIDER_unload, legacy);
    DDFREE(OSSL_PROVIDER_unload, dfault);
#endif

    OPENSSL_cleanup();

    if (WIFEXITED(waitStatus)) {
        return WEXITSTATUS(waitStatus);
    } else {
        return EXIT_FAILURE;
    }
}
