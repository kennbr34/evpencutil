#include "headers.h"

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

size_t getBufSizeMultiple(char *value) { 
    
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
    for(valueLength = 0;valueLength < MAX_DIGITS;valueLength++) {
        if(isdigit(value[valueLength])) {
            valString[valueLength] = value[valueLength];
            continue;
        }
        else if(isalpha(value[valueLength])) {
            valString[valueLength] = value[valueLength];
            valueLength++;
            break;
        }
    }
    
    if(valString[valueLength-1] == 'b' || valString[valueLength-1] == 'B')
        multiple = 1;
    if(valString[valueLength-1] == 'k' || valString[valueLength-1] == 'K')
        multiple = 1024;
    if(valString[valueLength-1] == 'm' || valString[valueLength-1] == 'M')
        multiple = 1024*1024;
    if(valString[valueLength-1] == 'g' || valString[valueLength-1] == 'G')
        multiple = 1024*1024*1024;
        
    return multiple;
}

void makeMultipleOf(size_t *numberToChange, size_t multiple) {
	 if(*numberToChange > multiple && *numberToChange % multiple != 0) {
                *numberToChange = *numberToChange - (*numberToChange % multiple);
        } else if (*numberToChange > multiple && *numberToChange % multiple == 0) {
                *numberToChange = *numberToChange;
        }
}

void signalHandler(int signum) {
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

#ifdef gui
/*Lists available encryption algorithms in OpenSSL's EVP library*/
void encListCallback(const OBJ_NAME *obj, void *arg)
{
    struct dataStruct *st = (struct dataStruct *)arg;
    
    /*Do not list authenticated or wrap modes since they will not work*/
    if(!strstr(obj->name,"gcm") &&
       !strstr(obj->name,"GCM") && 
       !strstr(obj->name,"ccm") &&
       !strstr(obj->name,"CCM") && 
       !strstr(obj->name,"ocb") &&
       !strstr(obj->name,"wrap")) {
        gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st->guiSt.encAlgorithmComboBox), obj->name);
    }
}

/*Lists available encryption algorithms in OpenSSL's EVP library*/
void mdListCallback(const OBJ_NAME *obj, void *arg)
{
    struct dataStruct *st = (struct dataStruct *)arg;
    
    /*Do not list shake128 since it will not work*/
    if(!strstr(obj->name,"shake128")) {
        gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st->guiSt.mdAlgorithmComboBox), obj->name);
    }
}
#endif
