#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#if OPENSSL_VERSION_MAJOR >= 3
#include <openssl/provider.h>
#endif
#include <signal.h>
#include <string.h>
#include <gtk/gtk.h>
#include <sys/mman.h>
#include "lib.h"

struct cryptoStruct *cryptStGlobal = NULL;

#ifdef gui
/*Lists available encryption algorithms in OpenSSL's EVP library*/
void encListCallback(const OBJ_NAME *obj, void *arg)
{
    struct dataStruct *st = (struct dataStruct *)arg;

    /*Do not list authenticated or wrap modes since they will not work*/
    if (isSupportedCipher((unsigned char *)obj->name)) {
        gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(st->guiSt.encAlgorithmComboBox), obj->name);
    }
}

/*Lists available encryption algorithms in OpenSSL's EVP library*/
void mdListCallback(const OBJ_NAME *obj, void *arg)
{
    struct dataStruct *st = (struct dataStruct *)arg;

    /*Do not list shake128 since it will not work*/
    if (!strstr(obj->name, "shake128")) {
        gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(st->guiSt.mdAlgorithmComboBox), obj->name);
    }
}
#endif

static gboolean updateStatus(gpointer user_data)
{
    struct dataStruct *st = (struct dataStruct *)user_data;
    st->guiSt.statusContextID = gtk_statusbar_get_context_id(GTK_STATUSBAR(st->guiSt.statusBar), "Statusbar");
    gtk_statusbar_push(GTK_STATUSBAR(st->guiSt.statusBar), GPOINTER_TO_INT(st->guiSt.statusContextID), st->guiSt.statusMessage);

    return TRUE;
}

static gboolean updateProgress(gpointer user_data)
{
    struct dataStruct *st = (struct dataStruct *)user_data;
    gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(st->guiSt.progressBar), *(st->guiSt.progressFraction));
    if (*(st->guiSt.progressFraction) > 1)
        *(st->guiSt.progressFraction) = 0.0;

    return TRUE;
}

static gboolean updateOverallProgress(gpointer user_data)
{
    struct dataStruct *st = (struct dataStruct *)user_data;
    gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(st->guiSt.overallProgressBar), *(st->guiSt.overallProgressFraction));
    if (*(st->guiSt.overallProgressFraction) > 1)
        *(st->guiSt.overallProgressFraction) = 0.0;

    return TRUE;
}

void choseEncrypt(GtkWidget *wid, gpointer ptr)
{
    struct dataStruct *st = (struct dataStruct *)ptr;
    strcpy(st->guiSt.encryptOrDecrypt, "encrypt");
    st->optSt.encrypt = true;
}

void choseDecrypt(GtkWidget *wid, gpointer ptr)
{
    struct dataStruct *st = (struct dataStruct *)ptr;
    strcpy(st->guiSt.encryptOrDecrypt, "decrypt");
    st->optSt.decrypt = true;
}

void on_cryptButton_clicked(GtkWidget *wid, gpointer ptr)
{
    struct dataStruct *st = ptr;

    gboolean passwordsMatch = FALSE;
    gboolean error = FALSE;

    st->guiSt.inputFilePath = gtk_entry_get_text(GTK_ENTRY(st->guiSt.inputFileNameBox));
    st->guiSt.outputFilePath = gtk_entry_get_text(GTK_ENTRY(st->guiSt.outputFileNameBox));
    st->guiSt.passWord = gtk_entry_get_text(GTK_ENTRY(st->guiSt.passwordBox));
    st->guiSt.verificationPass = gtk_entry_get_text(GTK_ENTRY(st->guiSt.passwordVerificationBox));
    st->guiSt.keyFilePath = gtk_entry_get_text(GTK_ENTRY(st->guiSt.keyFileNameBox));
    st->guiSt.authBufSizeComboBoxText = gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(st->guiSt.authBufSizeComboBox));
    st->guiSt.fileBufSizeComboBoxText = gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(st->guiSt.fileBufSizeComboBox));

    st->cryptSt.encAlgorithm = gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(st->guiSt.encAlgorithmComboBox));
    st->cryptSt.mdAlgorithm = gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(st->guiSt.mdAlgorithmComboBox));

    st->cryptSt.evpCipher = EVP_get_cipherbyname(st->cryptSt.encAlgorithm);
    if(strcmp(st->cryptSt.encAlgorithm,"null") == 0) {
        st->cryptSt.evpCipher = EVP_enc_null();
    } else {
        if (!st->cryptSt.evpCipher) {
            sprintf(st->guiSt.statusMessage, "Could not load cipher: %s\n", st->cryptSt.encAlgorithm);
            error = TRUE;
        }
    }

    st->cryptSt.evpDigest = EVP_get_digestbyname(st->cryptSt.mdAlgorithm);
    if (!st->cryptSt.evpDigest) {
        sprintf(st->guiSt.statusMessage, "Could not load digest: %s\n", st->cryptSt.mdAlgorithm);
        error = TRUE;
    }

    if (strlen(st->guiSt.inputFilePath)) {
        st->optSt.inputFileGiven = true;
        st->fileNameSt.inputFileName = strdup(st->guiSt.inputFilePath);
    } else {
        strcpy(st->guiSt.statusMessage, "Need input file...");
        error = TRUE;
    }

    if (strlen(st->guiSt.outputFilePath)) {
        st->optSt.outputFileGiven = true;
        st->fileNameSt.outputFileName = strdup(st->guiSt.outputFilePath);
    } else {
        strcpy(st->guiSt.statusMessage, "Need output file...");
        error = TRUE;
    }

    if (!strcmp(st->guiSt.inputFilePath, st->guiSt.outputFilePath)) {
        strcpy(st->guiSt.statusMessage, "Input and output file are the same...");
        error = TRUE;
    }

    st->cryptSt.nFactor = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(st->guiSt.nFactorTextBox));
    st->cryptSt.rFactor = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(st->guiSt.rFactorTextBox));
    st->cryptSt.pFactor = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(st->guiSt.pFactorTextBox));

    st->cryptSt.genAuthBufSize = atol(st->guiSt.authBufSizeComboBoxText) * sizeof(uint8_t) * getBufSizeMultiple((char *)st->guiSt.authBufSizeComboBoxText);
    makeMultipleOf(&st->cryptSt.genAuthBufSize, sizeof(uint64_t));

    st->cryptSt.fileBufSize = atol(st->guiSt.fileBufSizeComboBoxText) * sizeof(uint8_t) * getBufSizeMultiple((char *)st->guiSt.fileBufSizeComboBoxText);
    makeMultipleOf(&st->cryptSt.fileBufSize, sizeof(uint64_t));

    if (strlen(st->guiSt.passWord)) {
        st->optSt.passWordGiven = true;
    } else {
        st->optSt.passWordGiven = false;
    }

    if (strlen(st->guiSt.keyFilePath)) {
        st->optSt.keyFileGiven = true;
        st->fileNameSt.keyFileName = strdup(st->guiSt.keyFilePath);
    } else {
        st->optSt.keyFileGiven = false;
    }

    if (!st->optSt.passWordGiven && !st->optSt.keyFileGiven) {
        strcpy(st->guiSt.statusMessage, "Need at least password or keyfile");
        error = TRUE;
    }

    if (strcmp(st->guiSt.encryptOrDecrypt, "encrypt") == 0) {
        if (st->optSt.passWordGiven) {
            st->guiSt.verificationPass = gtk_entry_get_text(GTK_ENTRY(st->guiSt.passwordVerificationBox));
            if (strcmp(st->guiSt.passWord, st->guiSt.verificationPass) == 0)
                passwordsMatch = TRUE;

            if (passwordsMatch == FALSE) {
                strcpy(st->guiSt.statusMessage, "Passwords didn't match");
                error = TRUE;
            } else if (passwordsMatch == TRUE) {
                snprintf(st->cryptSt.userPass, MAX_PASS_SIZE, "%s", st->guiSt.passWord);

                gtk_entry_set_text(GTK_ENTRY(st->guiSt.passwordBox), "");
                OPENSSL_cleanse((void *)st->guiSt.passWord, strlen(st->guiSt.passWord));
                gtk_entry_set_text(GTK_ENTRY(st->guiSt.passwordBox), st->guiSt.passWord);

                gtk_entry_set_text(GTK_ENTRY(st->guiSt.passwordVerificationBox), "");
                OPENSSL_cleanse((void *)st->guiSt.verificationPass, strlen(st->guiSt.verificationPass));
                gtk_entry_set_text(GTK_ENTRY(st->guiSt.passwordVerificationBox), st->guiSt.verificationPass);
            }
        }
    } else if (strcmp(st->guiSt.encryptOrDecrypt, "decrypt") == 0) {
        snprintf(st->cryptSt.userPass, MAX_PASS_SIZE, "%s", st->guiSt.passWord);

        gtk_entry_set_text(GTK_ENTRY(st->guiSt.passwordBox), "");
        OPENSSL_cleanse((void *)st->guiSt.passWord, strlen(st->guiSt.passWord));
        gtk_entry_set_text(GTK_ENTRY(st->guiSt.passwordBox), st->guiSt.passWord);

        if (strlen(st->guiSt.verificationPass)) {
            gtk_entry_set_text(GTK_ENTRY(st->guiSt.passwordVerificationBox), "");
            OPENSSL_cleanse((void *)st->guiSt.verificationPass, strlen(st->guiSt.verificationPass));
            gtk_entry_set_text(GTK_ENTRY(st->guiSt.passwordVerificationBox), st->guiSt.verificationPass);
        }
    }

    if (error != TRUE) {
        if (strcmp(st->guiSt.encryptOrDecrypt, "encrypt") == 0) {
            strcpy(st->guiSt.statusMessage, "Starting encryption...");
            workThread('e', st);
        } else if (strcmp(st->guiSt.encryptOrDecrypt, "decrypt") == 0) {
            strcpy(st->guiSt.statusMessage, "Starting decryption...");
            //parseCryptoHeader(st);
            workThread('d', st);
        }
    }

    OPENSSL_cleanse((void *)st->cryptSt.userPass, strlen(st->cryptSt.userPass));
}

static void inputFileSelect(GtkWidget *wid, gpointer ptr)
{
    struct dataStruct *st = (struct dataStruct *)ptr;
    GtkWidget *dialog;
    GtkFileChooserAction action = GTK_FILE_CHOOSER_ACTION_OPEN;
    gint res;
    char *fileName;

    dialog = gtk_file_chooser_dialog_new("Open File",
                                         GTK_WINDOW(st->guiSt.win),
                                         action,
                                         "Cancel",
                                         GTK_RESPONSE_CANCEL,
                                         "Open",
                                         GTK_RESPONSE_ACCEPT,
                                         NULL);

    res = gtk_dialog_run(GTK_DIALOG(dialog));
    if (res == GTK_RESPONSE_ACCEPT) {
        GtkFileChooser *chooser = GTK_FILE_CHOOSER(dialog);
        fileName = gtk_file_chooser_get_filename(chooser);
        gtk_entry_set_text(GTK_ENTRY(st->guiSt.inputFileNameBox), fileName);
    }

    gtk_widget_destroy(dialog);
}

static void outputFileSelect(GtkWidget *wid, gpointer ptr)
{
    struct dataStruct *st = (struct dataStruct *)ptr;
    GtkWidget *dialog;
    GtkFileChooserAction action = GTK_FILE_CHOOSER_ACTION_SAVE;
    gint res;
    char *fileName;

    dialog = gtk_file_chooser_dialog_new("Save File",
                                         GTK_WINDOW(st->guiSt.win),
                                         action,
                                         "Cancel",
                                         GTK_RESPONSE_CANCEL,
                                         "Save As",
                                         GTK_RESPONSE_ACCEPT,
                                         NULL);

    res = gtk_dialog_run(GTK_DIALOG(dialog));
    if (res == GTK_RESPONSE_ACCEPT) {
        GtkFileChooser *chooser = GTK_FILE_CHOOSER(dialog);
        fileName = gtk_file_chooser_get_filename(chooser);
        gtk_entry_set_text(GTK_ENTRY(st->guiSt.outputFileNameBox), fileName);
    }

    gtk_widget_destroy(dialog);
}

static void keyFileSelect(GtkWidget *wid, gpointer ptr)
{
    struct dataStruct *st = (struct dataStruct *)ptr;
    GtkWidget *dialog;
    GtkFileChooserAction action = GTK_FILE_CHOOSER_ACTION_OPEN;
    gint res;
    char *fileName;

    dialog = gtk_file_chooser_dialog_new("Open File",
                                         GTK_WINDOW(st->guiSt.win),
                                         action,
                                         "Cancel",
                                         GTK_RESPONSE_CANCEL,
                                         "Open",
                                         GTK_RESPONSE_ACCEPT,
                                         NULL);

    res = gtk_dialog_run(GTK_DIALOG(dialog));
    if (res == GTK_RESPONSE_ACCEPT) {
        GtkFileChooser *chooser = GTK_FILE_CHOOSER(dialog);
        fileName = gtk_file_chooser_get_filename(chooser);
        gtk_entry_set_text(GTK_ENTRY(st->guiSt.keyFileNameBox), fileName);
    }

    gtk_widget_destroy(dialog);
}

void passVisibilityToggle(GtkWidget *wid, gpointer ptr)
{
    struct dataStruct *st = (struct dataStruct *)ptr;
    gtk_entry_set_visibility(GTK_ENTRY(st->guiSt.passwordBox), gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(wid)));
    gtk_entry_set_visibility(GTK_ENTRY(st->guiSt.passwordVerificationBox), gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(wid)));
}

int main(int argc, char *argv[])
{

    unsigned long long int number = 1;

    /*Catch SIGCONT to kill GUI if -q was used for testing*/
    signal(SIGCONT, signalHandler);

    static struct dataStruct st = {0};
    cryptStGlobal = &st.cryptSt;

    st.cryptSt.nFactor = DEFAULT_SCRYPT_N;
    st.cryptSt.pFactor = DEFAULT_SCRYPT_P;
    st.cryptSt.rFactor = DEFAULT_SCRYPT_R;

    st.cryptSt.genAuthBufSize = 1024 * 1024;
    st.cryptSt.fileBufSize = 1024 * 1024;
    
    st.cryptSt.threadNumber = 1;

    /*These must be mapped as shared memory for the worker thread to manipulate their values in the main thread*/
    st.guiSt.statusMessage = mmap(NULL, 256, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    st.guiSt.progressFraction = mmap(NULL, sizeof(double), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    st.guiSt.overallProgressFraction = mmap(NULL, sizeof(double), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);

    if (argc > 1) {
        parseOptions(argc, argv, &st);
    }

    allocateBuffers(&st);

    #if OPENSSL_VERSION_MAJOR >= 3
    OSSL_PROVIDER_load(NULL, "legacy");
    OSSL_PROVIDER_load(NULL, "default");
    #endif

    OpenSSL_add_all_algorithms();

    gtk_init(&argc, &argv);

    st.guiSt.win = gtk_window_new(GTK_WINDOW_TOPLEVEL);

    gtk_window_set_title(GTK_WINDOW(st.guiSt.win), "EVP Enc Utility");

    GtkWidget *inputFileLabel = gtk_label_new("Input File Path");
    st.guiSt.inputFileNameBox = gtk_entry_new();
    gtk_widget_set_tooltip_text(st.guiSt.inputFileNameBox, "Enter the full path to the file you want to encrypt/decrypt here");
    GtkWidget *inputFileButton = gtk_button_new_with_label("Select File");
    gtk_widget_set_tooltip_text(inputFileButton, "Select the file you want to encrypt/decrypt to fill in this path");
    g_signal_connect(inputFileButton, "clicked", G_CALLBACK(inputFileSelect), (gpointer)&st);

    GtkWidget *outputFileLabel = gtk_label_new("Output File Path");
    st.guiSt.outputFileNameBox = gtk_entry_new();
    gtk_widget_set_tooltip_text(st.guiSt.outputFileNameBox, "Enter the full path to where you want to save the result of encryption/decryption");
    GtkWidget *outputFileButton = gtk_button_new_with_label("Select File");
    gtk_widget_set_tooltip_text(outputFileButton, "Select where you want to save the result of encryption/decryption to fill in this path");
    g_signal_connect(outputFileButton, "clicked", G_CALLBACK(outputFileSelect), (gpointer)&st);

    GtkWidget *passwordLabel = gtk_label_new("Password");
    st.guiSt.passwordBox = gtk_entry_new();
    gtk_widget_set_tooltip_text(st.guiSt.passwordBox, "Password to derive key from");
    gtk_entry_set_invisible_char(GTK_ENTRY(st.guiSt.passwordBox), '*');
    gtk_entry_set_visibility(GTK_ENTRY(st.guiSt.passwordBox), FALSE);

    GtkWidget *verificationLabel = gtk_label_new("Verify Password");
    st.guiSt.passwordVerificationBox = gtk_entry_new();
    gtk_widget_set_tooltip_text(st.guiSt.passwordVerificationBox, "Note: Not needed for decryption");
    gtk_entry_set_invisible_char(GTK_ENTRY(st.guiSt.passwordVerificationBox), '*');
    gtk_entry_set_visibility(GTK_ENTRY(st.guiSt.passwordVerificationBox), FALSE);

    GtkWidget *encAlgorithmLabel = gtk_label_new("Encryption Algorithm");
    st.guiSt.encAlgorithmComboBox = gtk_combo_box_text_new();
    OBJ_NAME_do_all(OBJ_NAME_TYPE_CIPHER_METH, encListCallback, &st);
    
    char encAlgorithmToolTipText[] = "\
    Choose which encryption algorithm to use\n\
    Best options: aes-256-ctr or chacha20\n\
    AES will generally be faster since most architectures have AES instruction sets built into the\
    CPU\
    \n\
    If you're unsure what to use, it is best to stick to defaults. Many of these options are sipmly\
    added automatically by listing what is available in the OpenSSL library, and may not be\
    appropriate for all use cases. As well, some are fairly out-of-date and not reccomended\
    such as RC4 or blowfish, and some may not actually be configured to work correctly with this program\
    such as chacha20-poly1305\
    \n";
    gtk_widget_set_tooltip_text(st.guiSt.encAlgorithmComboBox, encAlgorithmToolTipText);

    GtkWidget *mdAlgorithmLabel = gtk_label_new("Message Digest Algorithm");
    st.guiSt.mdAlgorithmComboBox = gtk_combo_box_text_new();
    OBJ_NAME_do_all(OBJ_NAME_TYPE_MD_METH, mdListCallback, &st);
    
    char mdAlgorithmToolTipText[] = "\
    Choose which message digest algorithm to use. This is what will be used by HMAC as the hash\
    for your authentication code, as well as what HKDF will use as a hash for key derivation\n\
    Best options: sha512, sha3-512 or blake2b512\n\
    Whichever is fastest, which you can benchmark with 'openssl speed -evp *algoname*\
    \n\
    If you're unsure what to use, it is best to stick to defaults. Many of these options are sipmly\
    added automatically by listing what is available in the OpenSSL library, and may not be\
    appropriate for all use cases. As well, some are fairly out-of-date and not reccomended\
    such as md5 or sha1, and some may not actually be configured to work correctly with this program\
    \n";
    gtk_widget_set_tooltip_text(st.guiSt.mdAlgorithmComboBox, mdAlgorithmToolTipText);

    GtkWidget *scryptWorkFactorsLabel = gtk_label_new("scrypt work factors:");

    GtkWidget *nFactorLabel = gtk_label_new("N Factor");
    st.guiSt.nFactorSpinButtonAdj = gtk_adjustment_new(DEFAULT_SCRYPT_N, 0, DEFAULT_SCRYPT_N * 8, 1048576, 0, 0);
    st.guiSt.nFactorTextBox = gtk_spin_button_new(GTK_ADJUSTMENT(st.guiSt.nFactorSpinButtonAdj), 0, 0);
    gtk_widget_set_tooltip_text(st.guiSt.nFactorTextBox, "This is the N factor that will be used by scrypt");

    GtkWidget *rFactorLabel = gtk_label_new("r Factor");
    st.guiSt.rFactorSpinButtonAdj = gtk_adjustment_new(DEFAULT_SCRYPT_R, 0, 10, 1, 0, 0);
    st.guiSt.rFactorTextBox = gtk_spin_button_new(GTK_ADJUSTMENT(st.guiSt.rFactorSpinButtonAdj), 0, 0);
    gtk_widget_set_tooltip_text(st.guiSt.rFactorTextBox, "This is the r factor that will be used by scrypt");

    GtkWidget *pFactorLabel = gtk_label_new("p Factor");
    st.guiSt.pFactorSpinButtonAdj = gtk_adjustment_new(DEFAULT_SCRYPT_P, 0, 10, 1, 0, 0);
    st.guiSt.pFactorTextBox = gtk_spin_button_new(GTK_ADJUSTMENT(st.guiSt.pFactorSpinButtonAdj), 0, 0);
    gtk_widget_set_tooltip_text(st.guiSt.pFactorTextBox, "This is the p factor that will be used by scrypt");

    char scryptToolTipText[] = "\
    scrypt is a Key Derivation Function which derives a key from a password \
    that is very computationally and memory-expensive to attempt to brute-force\
    \n\
    \nN is the \"CostFactor\" and will increase CPU and memory usage. It must be a power of 2 and \
    it will increase memory usage exponentially, so you may run out of RAM if you set too high\n\
    \nr is the \"BlockSizeFactor\" which controls memory read size and performance\n\
    \np is the \"ParallelizationFactor\" factor which controls how many CPUs or cores to use\n\
    \nThe N factor is typically the only value which the user should modify and the default\
    is the current reccomendation, but one should Google for more guidance on this. Or, \
    as a rule of thumb, tune this to a factor which takes as long for your CPU to generate\
    a key as is satisfactory to you and/or that your computer has memory resources for.";

    gtk_widget_set_tooltip_text(scryptWorkFactorsLabel, (const gchar *)scryptToolTipText);
    gtk_widget_set_tooltip_text(nFactorLabel, (const gchar *)scryptToolTipText);
    gtk_widget_set_tooltip_text(rFactorLabel, (const gchar *)scryptToolTipText);
    gtk_widget_set_tooltip_text(pFactorLabel, (const gchar *)scryptToolTipText);

    GtkWidget *visibilityButton = gtk_check_button_new_with_label("Show Password");
    gtk_widget_set_tooltip_text(visibilityButton, "Hint: Use this to avoid typos");
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(visibilityButton), FALSE);
    g_signal_connect(visibilityButton, "toggled", G_CALLBACK(passVisibilityToggle), (gpointer)&st);

    GtkWidget *keyFileLabel = gtk_label_new("Key File Path");
    st.guiSt.keyFileNameBox = gtk_entry_new();
    gtk_widget_set_tooltip_text(st.guiSt.keyFileNameBox, "Enter the full path to the key you want to use here");
    st.guiSt.keyFileButton = gtk_button_new_with_label("Select File");
    gtk_widget_set_tooltip_text(st.guiSt.keyFileButton, "Select the key file you want to use here");
    g_signal_connect(st.guiSt.keyFileButton, "clicked", G_CALLBACK(keyFileSelect), (gpointer)&st);

    GtkWidget *authBufSizeLabel = gtk_label_new("Authentication Buffer Size");
    st.guiSt.authBufSizeComboBox = gtk_combo_box_text_new();
    gtk_widget_set_tooltip_text(st.guiSt.authBufSizeComboBox, "This controls the size of the buffer used for authenticating data");
    char authBufSizeComboBoxTextString[15] = {0};
    number = 1;
    for (int i = 0; i < 34; i++) {
        bytesPrefixed(authBufSizeComboBoxTextString, number);
        gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(st.guiSt.authBufSizeComboBox), authBufSizeComboBoxTextString);
        number = number << 1;
    }
    gtk_combo_box_set_active(GTK_COMBO_BOX(st.guiSt.authBufSizeComboBox), 20);

    GtkWidget *fileBufSizeLabel = gtk_label_new("File Buffer Size");
    st.guiSt.fileBufSizeComboBox = gtk_combo_box_text_new();
    gtk_widget_set_tooltip_text(st.guiSt.fileBufSizeComboBox, "This controls the size of the buffer used for encryption/decryption data");
    char fileBufSizeComboBoxTextString[15] = {0};
    number = 1;
    for (int i = 0; i < 34; i++) {
        bytesPrefixed(fileBufSizeComboBoxTextString, number);
        gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(st.guiSt.fileBufSizeComboBox), fileBufSizeComboBoxTextString);
        number = number << 1;
    }
    gtk_combo_box_set_active(GTK_COMBO_BOX(st.guiSt.fileBufSizeComboBox), 20);

    GtkWidget *encryptButton = gtk_button_new_with_label("Encrypt");
    g_signal_connect(encryptButton, "clicked", G_CALLBACK(choseEncrypt), (gpointer)&st);
    g_signal_connect(encryptButton, "clicked", G_CALLBACK(on_cryptButton_clicked), (gpointer)&st);

    GtkWidget *decryptButton = gtk_button_new_with_label("Decrypt");
    g_signal_connect(decryptButton, "clicked", G_CALLBACK(choseDecrypt), (gpointer)&st);
    g_signal_connect(decryptButton, "clicked", G_CALLBACK(on_cryptButton_clicked), (gpointer)&st);

    st.guiSt.progressBar = gtk_progress_bar_new();
    gtk_progress_bar_set_text(GTK_PROGRESS_BAR(st.guiSt.progressBar), "Step Progress");
    gtk_progress_bar_set_show_text(GTK_PROGRESS_BAR(st.guiSt.progressBar), TRUE);
    *(st.guiSt.progressFraction) = 0.0;
    g_timeout_add(50, updateProgress, (gpointer)&st);

    st.guiSt.overallProgressBar = gtk_progress_bar_new();
    gtk_progress_bar_set_text(GTK_PROGRESS_BAR(st.guiSt.overallProgressBar), "Overall Progress");
    gtk_progress_bar_set_show_text(GTK_PROGRESS_BAR(st.guiSt.overallProgressBar), TRUE);
    *(st.guiSt.overallProgressFraction) = 0.0;
    g_timeout_add(50, updateOverallProgress, (gpointer)&st);

    st.guiSt.statusBar = gtk_statusbar_new();
    gtk_widget_set_tooltip_text(st.guiSt.statusBar, "Program will show status updates here");
    strcpy(st.guiSt.statusMessage, "Ready");
    g_timeout_add(50, updateStatus, (gpointer)&st);

    if (st.optSt.inputFileGiven) {
        gtk_entry_set_text(GTK_ENTRY(st.guiSt.inputFileNameBox), (const gchar *)st.fileNameSt.inputFileName);
    }

    if (st.optSt.outputFileGiven) {
        gtk_entry_set_text(GTK_ENTRY(st.guiSt.outputFileNameBox), (const gchar *)st.fileNameSt.outputFileName);
    }

    if (st.optSt.keyFileGiven) {
        gtk_entry_set_text(GTK_ENTRY(st.guiSt.keyFileNameBox), (const gchar *)st.fileNameSt.keyFileName);
    }

    if (st.optSt.passWordGiven) {
        gtk_entry_set_text(GTK_ENTRY(st.guiSt.passwordBox), (const gchar *)st.cryptSt.userPass);
        if (st.optSt.encrypt) {
            gtk_entry_set_text(GTK_ENTRY(st.guiSt.passwordVerificationBox), (const gchar *)st.cryptSt.userPass);
        }
    }

    if (st.optSt.nFactorGiven) {
        gtk_adjustment_set_value(GTK_ADJUSTMENT(st.guiSt.nFactorSpinButtonAdj), (gdouble)st.cryptSt.nFactor);
    }

    if (st.optSt.rFactorGiven) {
        gtk_adjustment_set_value(GTK_ADJUSTMENT(st.guiSt.rFactorSpinButtonAdj), (gdouble)st.cryptSt.rFactor);
    }

    if (st.optSt.pFactorGiven) {
        gtk_adjustment_set_value(GTK_ADJUSTMENT(st.guiSt.pFactorSpinButtonAdj), (gdouble)st.cryptSt.pFactor);
    }

    if (st.optSt.authBufSizeGiven) {
        char size_string[15];
        bytesPrefixed(size_string, st.cryptSt.genAuthBufSize);
        gtk_combo_box_text_prepend(GTK_COMBO_BOX_TEXT(st.guiSt.authBufSizeComboBox), 0, (const gchar *)size_string);
        gtk_combo_box_set_active(GTK_COMBO_BOX(st.guiSt.authBufSizeComboBox), 0);
    }

    if (st.optSt.fileBufSizeGiven) {
        char size_string[15];
        bytesPrefixed(size_string, st.cryptSt.fileBufSize);
        gtk_combo_box_text_prepend(GTK_COMBO_BOX_TEXT(st.guiSt.fileBufSizeComboBox), 0, (const gchar *)size_string);
        gtk_combo_box_set_active(GTK_COMBO_BOX(st.guiSt.fileBufSizeComboBox), 0);
    }

    if (st.optSt.encAlgorithmGiven) {
        gtk_combo_box_text_prepend(GTK_COMBO_BOX_TEXT(st.guiSt.encAlgorithmComboBox), 0, st.cryptSt.encAlgorithm);
        gtk_combo_box_set_active(GTK_COMBO_BOX(st.guiSt.encAlgorithmComboBox), 0);
    } else {
        gtk_combo_box_text_prepend(GTK_COMBO_BOX_TEXT(st.guiSt.encAlgorithmComboBox), 0, DEFAULT_ENC);
        gtk_combo_box_set_active(GTK_COMBO_BOX(st.guiSt.encAlgorithmComboBox), 0);
    }

    if (st.optSt.mdAlgorithmGiven) {
        gtk_combo_box_text_prepend(GTK_COMBO_BOX_TEXT(st.guiSt.mdAlgorithmComboBox), 0, st.cryptSt.mdAlgorithm);
        gtk_combo_box_set_active(GTK_COMBO_BOX(st.guiSt.mdAlgorithmComboBox), 0);
    } else {
        gtk_combo_box_text_prepend(GTK_COMBO_BOX_TEXT(st.guiSt.mdAlgorithmComboBox), 0, DEFAULT_MD);
        gtk_combo_box_set_active(GTK_COMBO_BOX(st.guiSt.mdAlgorithmComboBox), 0);
    }

    GtkWidget *grid = gtk_grid_new();
    gtk_widget_set_hexpand(inputFileLabel, TRUE);
    gtk_grid_attach(GTK_GRID(grid), inputFileLabel, 0, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), st.guiSt.inputFileNameBox, 0, 2, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), inputFileButton, 1, 2, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), outputFileLabel, 0, 4, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), st.guiSt.outputFileNameBox, 0, 5, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), outputFileButton, 1, 5, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), passwordLabel, 0, 7, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), st.guiSt.passwordBox, 0, 8, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), visibilityButton, 1, 8, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), verificationLabel, 0, 9, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), st.guiSt.passwordVerificationBox, 0, 10, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), scryptWorkFactorsLabel, 0, 12, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), nFactorLabel, 0, 13, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), st.guiSt.nFactorTextBox, 1, 13, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), rFactorLabel, 0, 15, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), st.guiSt.rFactorTextBox, 1, 15, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), pFactorLabel, 0, 17, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), st.guiSt.pFactorTextBox, 1, 17, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), keyFileLabel, 0, 18, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), st.guiSt.keyFileNameBox, 0, 19, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), st.guiSt.keyFileButton, 1, 19, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), authBufSizeLabel, 0, 24, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), st.guiSt.authBufSizeComboBox, 0, 25, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), fileBufSizeLabel, 1, 24, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), st.guiSt.fileBufSizeComboBox, 1, 25, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), encAlgorithmLabel, 0, 26, 2, 1);
    gtk_grid_attach(GTK_GRID(grid), st.guiSt.encAlgorithmComboBox, 0, 27, 2, 1);
    gtk_grid_attach(GTK_GRID(grid), mdAlgorithmLabel, 0, 28, 2, 1);
    gtk_grid_attach(GTK_GRID(grid), st.guiSt.mdAlgorithmComboBox, 0, 29, 2, 1);
    gtk_grid_attach(GTK_GRID(grid), encryptButton, 0, 30, 2, 1);
    gtk_grid_attach(GTK_GRID(grid), decryptButton, 0, 31, 2, 1);
    gtk_grid_attach(GTK_GRID(grid), st.guiSt.progressBar, 0, 32, 2, 1);
    gtk_grid_attach(GTK_GRID(grid), st.guiSt.overallProgressBar, 0, 33, 2, 1);
    gtk_grid_attach(GTK_GRID(grid), st.guiSt.statusBar, 0, 34, 2, 1);

    gtk_container_add(GTK_CONTAINER(st.guiSt.win), grid);

    g_signal_connect(st.guiSt.win, "delete_event", G_CALLBACK(gtk_main_quit), NULL);

    gtk_widget_show_all(st.guiSt.win);

    if (argc > 1) {
        if (st.optSt.encrypt) {
            strcpy(st.guiSt.encryptOrDecrypt, "encrypt");
            on_cryptButton_clicked(NULL, &st);
        } else if (st.optSt.decrypt) {
            strcpy(st.guiSt.encryptOrDecrypt, "decrypt");
            on_cryptButton_clicked(NULL, &st);
        }
    }

    gtk_main();

    exit(EXIT_SUCCESS);
}
