#include <openssl/crypto.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "lib.h"

struct cryptoStruct *cryptStGlobal = NULL;

int main(int argc, char *argv[])
{
    if (argc == 1) {
        printSyntax(argv[0]);
        exit(EXIT_FAILURE);
    }

    struct dataStruct st = {0};
    cryptStGlobal = &st.cryptSt;

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

    st.cryptSt.genAuthBufSize = 1024 * 1024;
    st.cryptSt.fileBufSize = 1024 * 1024;

    parseOptions(argc, argv, &st);

    allocateBuffers(&st);

    if (st.optSt.encrypt) {
        workThread('e', &st);
    } else if (st.optSt.decrypt) {
        parseCryptoHeader(&st);
        workThread('d', &st);
    }
    
    int waitStatus = 0;

    wait(&waitStatus);
    
    if(WIFEXITED(waitStatus)) {
        return WEXITSTATUS(waitStatus);
    } else {
        return EXIT_FAILURE;
    }
}
