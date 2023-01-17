#include <errno.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#if OPENSSL_VERSION_MAJOR >= 3
#include <openssl/provider.h>
#endif
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <termios.h>
#include <stdbool.h>
#ifdef gui
#include <gtk/gtk.h>
#endif
#include <sys/mman.h>
#include <getopt.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <time.h>

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

#define MAX_FILE_NAME_SIZE PATH_MAX + NAME_MAX + 1

/*Do NOT change the order of these*/

#include "macros.h"

#include "globals.h"

#include "structs.h"

#include "prototypes.h"
