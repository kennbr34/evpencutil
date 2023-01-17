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
    
    uint8_t generatedMAC[MAC_SIZE];
    uint8_t fileMAC[MAC_SIZE];
    uint8_t *hmacKey;
    uint32_t *HMACLengthPtr;
    
    uint8_t keyFileHash[EVP_MAX_MD_SIZE];
    
    size_t genHmacBufSize;
    size_t msgBufSize;
    
    const EVP_CIPHER *evpCipher;
    const EVP_MD *evpDigest;
    
    const char *encAlgorithm;
    const char *mdAlgorithm;
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
    bool inputFileGiven;
    bool outputFileGiven;
    bool keyFileGiven;
    bool passWordGiven;
    bool keyBufSizeGiven;
    bool macBufSizeGiven;
    bool msgBufSizeGiven;
    bool gotPassFromCmdLine;
    bool nFactorGiven;
    bool rFactorGiven;
    bool pFactorGiven;
    bool quitWhenDone;
    bool encAlgorithmGiven;
    bool mdAlgorithmGiven;
};

struct miscStruct {
    uint64_t returnVal;
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
    
    GtkWidget *keyFileButton;
    
    GtkWidget *keySizeComboBox;
    GtkWidget *macBufSizeComboBox;
    GtkWidget *msgBufSizeComboBox;
    GtkWidget *encAlgorithmComboBox;
    GtkWidget *mdAlgorithmComboBox;
    
    const char *inputFilePath;
    const char *outputFilePath;
    const char *keyFilePath;
    const char *passWord;
    const char *verificationPass;
    const char *keySizeComboBoxText;
    const char *macBufSizeComboBoxText;
    const char *msgBufSizeComboBoxText;

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

struct dataStruct {
    struct cryptoStruct cryptSt;
    struct fileNames fileNameSt;
    struct optionsStruct optSt;
    struct miscStruct miscSt;
    #ifdef gui
    struct guiStruct guiSt;
    #endif
};
