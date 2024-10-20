/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * Authors:
 *      José Ignacio Bravo Vicente <nacho.bravo@gmail.com>
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <windows.h>
#include "debug_priv.h"
#include "_seap.h"
#include "probe-api.h"
#include "probe/entcmp.h"
#include "probe/probe.h"
#include "file_probe.h"
#include "oscap_helpers.h"
#include <sys/stat.h>
#include <accctrl.h>
#include <aclapi.h>
#include <stdlib.h>
#include <ImageHlp.h>

// algunos tamanios de buffer
#define SZ_MIN 256
#define SZ_MED 1024
#define SZ_MAX 4096
#define SZ_VER 25

// inicializa string a cadena vacia
#define SEMPTY(x) strcpy(x, "");

// sacado de unix file.c 
#define STRLEN_PAIR(str) (str),strlen(str)

// strings para windows type 
#define S_FILE_TYPE_DISK "FILE_TYPE_DISK"
#define S_FILE_TYPE_CHAR "FILE_TYPE_CHAR"
#define S_FILE_TYPE_PIPE "FILE_TYPE_PIPE"
#define S_FILE_TYPE_UNKNOWN "FILE_TYPE_UNKNOWN"

// strings para windows view 
#define S_WINDOWS_VIEW_64_BIT "64_bit"
#define S_WINDOWS_VIEW_32_BIT "32_bit"

// separador en windows filesystem
#define FILE_SEPARATOR '\\'
#define DEFAULT_ROOT "C:\\"

//  posibles vistas del sistema de ficheros
enum windows_view {
    WINDOWS_VIEW_64_BIT,
    WINDOWS_VIEW_32_BIT
};


static char* get_windows_view()
{
    // TODO de momento, por defecto
    int wv = WINDOWS_VIEW_64_BIT;
    
    switch (wv) {
        case WINDOWS_VIEW_64_BIT:
            return S_WINDOWS_VIEW_64_BIT;
        case WINDOWS_VIEW_32_BIT:
            return S_WINDOWS_VIEW_32_BIT;
    }

    return NULL;
}


static int get_file_checksum(const char* filePath, 
        char* s_checksum, size_t sz_checksum)
{
    DWORD headerSum = 0, checksum = 0;

    if (MapFileAndCheckSum(filePath, &headerSum, &checksum) != 0) {
        dE("get_file_checksum: error calling 'MapFileAndCheckSum'.");
        return -1;
    }

    // tamanio maximo string 10+1 caracteres
    snprintf(s_checksum, sz_checksum, "%u", checksum);

    return 0;
}


// TODO pendiente mejorar seguridad
static int check_valid_path(const char* filePath) 
{
    LPCSTR p = filePath;
    size_t len = 0;

    // caracteres no admitidos
    while (*p != '\0' && len++ < MAX_PATH) {
        switch (*p) {
            case '<':
            case '>':
            case '"':
            case '/':
            case '|':
            case '?':
            case '*':
                return -1; 
            default:
                p++;
        }
    }

    // longitud maxima
    if (len == MAX_PATH) {
        return -1; 
    }

    // nombres especiales excluidos
    static const char* specialNames[] = {
        "CON", "PRN", "AUX", "NUL",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
    };

    for (int i = 0; i < sizeof(specialNames) / sizeof(char*); i++) {
        if (!_stricmp(filePath, specialNames[i])) {
            return -1;
        }
    }
    
    return 0;
}


static int concat_path(char* s_filepath, size_t sz_filepath,
    const char* s_path, const char* s_filename)
{
    size_t len = strlen(s_path);

    // avoid 2 slashes
    if (len > 0 && s_path[len - 1] == FILE_SEPARATOR) {
        snprintf(s_filepath, sz_filepath, "%s%s",
            s_path, s_filename);
    }
    else {
        snprintf(s_filepath, sz_filepath, "%s%c%s",
            s_path, FILE_SEPARATOR, s_filename);
    }

    if (check_valid_path(s_filepath) != 0) {
        return -1;
    }

    return 0;
}


static int get_path_filename(const char* filePath, 
        char* path, size_t sz_path,
        char* filename, size_t sz_filename)
{
    char drive[_MAX_DRIVE];
    char dir[_MAX_DIR];
    char fname[_MAX_FNAME];
    char ext[_MAX_EXT];

    if (_splitpath_s(filePath, drive, sizeof drive, 
            dir, sizeof dir, 
            fname, sizeof fname, 
            ext, sizeof ext) != 0) {

        dE("get_path_filename: error calling '_splitpath_s'.");
        return -1;
    }

    if (concat_path(path, sz_path, drive, dir) != 0) {
        dE("get_path_filename: error invalid path.");
        return -1;
    }

    if (concat_path(filename, sz_filename, fname, ext) != 0) {
        dE("get_path_filename: error invalid filename.");
        return -1;
    }
    
    return 0;
}


// auxiliar para pruebas y debug
const char* get_msg_error()
{
    static char msg[SZ_MAX];
    LPSTR sbuf = NULL;
    DWORD err = GetLastError();

    if (err) {
        size_t sz = FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | \
            FORMAT_MESSAGE_FROM_SYSTEM | \
            FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL,
            err,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPSTR)&sbuf,
            0,
            NULL);

        snprintf(msg, sizeof msg, "error %d: %s", err, sz ? sbuf : "");
        LocalFree(sbuf);

        return msg;
    }

    return "";
}


static int get_file_owner(const char* filePath, 
        char* s_owner, size_t sz_owner) 
{
    PSECURITY_DESCRIPTOR sd;

    if (GetNamedSecurityInfo(filePath, SE_FILE_OBJECT, 
            OWNER_SECURITY_INFORMATION, NULL, NULL, NULL, NULL, &sd) != 0) {

        dE("get_file_owner: error calling 'GetNamedSecurtyInfo'.");
        return -1;
    }

    PSID ownerSid;
    BOOL ownerDefaulted;

    if (!GetSecurityDescriptorOwner(sd, &ownerSid, &ownerDefaulted)) {
        dE("get_file_owner: error calling 'GetSecurityDescriptorOwner'.");
        LocalFree(sd);
        return -1;
    }

    LocalFree(sd);

    char ownerName[SZ_MIN] = "";
    DWORD ownerNameSize = sizeof ownerName;
    char domainName[SZ_MIN] = "";
    DWORD domainNameSize = sizeof domainName;
    SID_NAME_USE sidUse = 0;
    
    if (!LookupAccountSid(NULL, ownerSid, ownerName, &ownerNameSize, 
            domainName, &domainNameSize, &sidUse)) {
        dE("get_file_owner: error calling 'LookupAccountSid'.");
        return -1;
    }

    // TODO pendiente revision, formato correcto?
    snprintf(s_owner, sz_owner, "%s\\%s", domainName, ownerName);

    return 0;
}


static int get_file_time(const char* filePath, 
        time_t* c_time, time_t* a_time, time_t* m_time) 
{
    HANDLE hFile = CreateFile(filePath, 
        GENERIC_READ, 
        FILE_SHARE_READ, 
        NULL, 
        OPEN_EXISTING, 
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        dE("get_file_time: error calling 'CreateFile'.");
        return -1;
    }

    // TODO revisar como afecta conversion FILETIME a time_t
    if (!GetFileTime(hFile, (FILETIME*)c_time, 
            (FILETIME*)a_time, (FILETIME*)m_time)) {

        dE("get_file_time: error calling 'GetFileTime'.");
        CloseHandle(hFile);
        return -1;
    }

    CloseHandle(hFile);

    return 0;
}


static int get_file_size(const char* filePath, size_t* size)
{
    struct _stat fileStat;
 
    if (_stat(filePath, &fileStat) != 0) {
        dE("get_file_size: error calling '_stat'");
        return -1;
    }

    *size = fileStat.st_size;

    return 0;
}


static int get_file_version_info(const char* filePath, 
        char *s_version, const size_t sz_version, 
        char *s_product_version, const size_t sz_product_version, 
        char *s_product_name, const size_t sz_product_name,
        char *s_file_version, const size_t sz_file_version,
        char *s_original_filename, const size_t sz_original_filename,
        char *s_internal_name, const size_t sz_internal_name,
        char *s_company_name, const size_t sz_company_name,
        char *s_language, const size_t sz_language)
{
    UINT uLen = 0;
    LPSTR lpBuf = NULL;
    DWORD dwDummyHandle = 0;

    DWORD dwSize = GetFileVersionInfoSize(filePath, &dwDummyHandle);

    if (dwSize == 0) {
        dE("get_file_version_info: error calling 'GetFileVersionInfoSize'.");
        return -1;
    }

    LPVOID lpData = malloc(dwSize);

    if (lpData == NULL) {
        dE("get_file_version_info: error calling 'malloc'.");
        return -1;
    }

    if (!GetFileVersionInfo(filePath, 0, dwSize, lpData)) {
        dE("get_file_version_info: error calling 'GetFileVersionInfo'.");
        free(lpData);
        return -1;
    }

    VS_FIXEDFILEINFO* pFileInfo;

    if (!VerQueryValue(lpData, "\\", (LPVOID*)&pFileInfo, &uLen)) {
        dE("get_file_version_info: error calling 'VerQueryValue'.");
        free(lpData);
        return -1;
    }

    // https://stackoverflow.com/questions/38068477/why-does-getfileversioninfo-on-kernel32-dll-in-windows-10-return-version-6-2 
    /*
    snprintf(s_version, sz_version, "%lu.%lu.%lu.%lu",
        HIWORD(pFileInfo->dwFileVersionMS), LOWORD(pFileInfo->dwFileVersionMS),
        HIWORD(pFileInfo->dwFileVersionLS), LOWORD(pFileInfo->dwFileVersionLS));
    */
    
    // TODO hacemos coincidir s_version y s_product_version, revisar
    snprintf(s_version, sz_version, "%lu.%lu.%lu.%lu",
        HIWORD(pFileInfo->dwProductVersionMS), LOWORD(pFileInfo->dwProductVersionMS),
        HIWORD(pFileInfo->dwProductVersionLS), LOWORD(pFileInfo->dwProductVersionLS));
    
    snprintf(s_product_version, sz_product_version, "%lu.%lu.%lu.%lu",
        HIWORD(pFileInfo->dwProductVersionMS), LOWORD(pFileInfo->dwProductVersionMS),
        HIWORD(pFileInfo->dwProductVersionLS), LOWORD(pFileInfo->dwProductVersionLS));

#define VER_QUERY_VALUE(s) { \
    uLen = 0; lpBuf = NULL; \
    if (!VerQueryValue(lpData, s, (LPVOID*)&lpBuf, &uLen)) { \
        dE("get_file_version_info: '%s' was not found in the version information.", s); \
        free(lpData); \
        return -1; \
    } \
}

    VER_QUERY_VALUE("\\VarFileInfo\\Translation");

    typedef struct LANGANDCODEPAGE {
        WORD wLanguage;
        WORD wCodePage;
    } Translate;

    WORD lang = ((Translate*)lpBuf)[0].wLanguage;
    WORD cpid = ((Translate*)lpBuf)[0].wCodePage;
   
    // tecnicamente, deberiamos primero interrogar la longitud del buffer
    if (!GetLocaleInfo(lang, LOCALE_SLANGUAGE, s_language, (int)sz_language)) {
        dE("get_file_version_info: error calling 'GetLocateInfo'.");
        free(lpData);
        return -1;
    }

    char s_path[SZ_MIN] = "";

#define GET_STRING_FILE_INFO(s, dst, sz) { \
    snprintf(s_path, sizeof s_path, "\\StringFileInfo\\%04x%04x\\" s, lang, cpid); \
    VER_QUERY_VALUE(s_path); \
    strncpy(dst, lpBuf, sz); \
    dst[sz - 1] = '\0'; \
}

    GET_STRING_FILE_INFO("ProductName", s_product_name, sz_product_name);
    GET_STRING_FILE_INFO("FileVersion", s_file_version, sz_file_version);
    GET_STRING_FILE_INFO("OriginalFilename", s_original_filename, sz_original_filename);
    GET_STRING_FILE_INFO("InternalName", s_internal_name, sz_internal_name);
    GET_STRING_FILE_INFO("CompanyName", s_company_name, sz_company_name);

    // al liberar lpData, se libera lpBuf
    free(lpData);

    return 0;
}


static int file_exist(const char* filePath) 
{
    DWORD fileAttr = GetFileAttributes(filePath);
    return fileAttr != INVALID_FILE_ATTRIBUTES; 
}


static char* get_file_type(const char* filePath)
{
    HANDLE hFile = CreateFile(
        filePath,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        dE("get_file_type: error calling 'CreateFile'.");
        return NULL;
    }

    DWORD fileType = GetFileType(hFile);
    CloseHandle(hFile);

    switch (fileType) {
        case FILE_TYPE_DISK:
            return S_FILE_TYPE_DISK;
        case FILE_TYPE_CHAR:
            return S_FILE_TYPE_CHAR;
        case FILE_TYPE_PIPE:
            return S_FILE_TYPE_PIPE;
        case FILE_TYPE_UNKNOWN:
            return S_FILE_TYPE_UNKNOWN;
    }

    return NULL;
}


static int file_cb(const char* s_path, char* s_filename, probe_ctx* ctx)
{
    char s_filepath[MAX_PATH] = "";

    dI("file_cb: path = '%s'.", s_path);
    dI("file_cb: filename = '%s'.", s_filename);

    if (concat_path(s_filepath, sizeof s_filepath, s_path, s_filename) != 0) {
        dE("file_cb: invalid filepath name.");
        return PROBE_EINVAL;
    }
    
    dI("file_cb: filepath = '%s'.", s_filepath);
        
    if (!file_exist(s_filepath)) {
        dE("file_cb: filepath doesn't exist.");
        return PROBE_ENOENT;
    }

    char s_version[SZ_VER] = "", s_product_version[SZ_VER] = "",
            s_product_name[SZ_MIN] = "", s_file_version[SZ_MIN] = "",
            s_original_filename[SZ_MIN] = "", s_internal_name[SZ_MIN] = "",
            s_company_name[SZ_MIN] = "", s_language[SZ_MIN] = "";

    if (get_file_version_info(s_filepath, 
            s_version, sizeof s_version, 
            s_product_version, sizeof s_product_version, 
            s_product_name, sizeof s_product_name,
            s_file_version, sizeof s_file_version,
            s_original_filename, sizeof s_original_filename,
            s_internal_name, sizeof s_internal_name,
            s_company_name, sizeof s_company_name,
            s_language, sizeof s_language) != 0) {

        // hay ficheros sin info, no queremos parar
        /*
        dE("file_cb: error getting file version info.");
        return PROBE_ESYSTEM; 
        */
    }

    dI("file_cb: version = '%s'.", s_version);
    dI("file_cb: product version = '%s'.", s_product_version);
    dI("file_cb: product name = '%s'.", s_product_name);
    dI("file_cb: file version = '%s'.", s_file_version);
    dI("file_cb: original filename = '%s'.", s_original_filename);
    dI("file_cb: internal name = '%s'.", s_internal_name);
    dI("file_cb: company name = '%s'.", s_company_name);
    dI("file_cb: language = '%s'.", s_language);

    size_t f_size = 0;

    if (get_file_size(s_filepath, &f_size) != 0) {
        dE("file_cb: error getting file size.");
        return PROBE_ESYSTEM;
    }

    dI("file_cb: size = '%lu'.", f_size);

    time_t a_time = 0, m_time = 0, c_time = 0;

    if (get_file_time(s_filepath, &c_time, &a_time, &m_time) != 0) {
        dE("file_cb: error getting file times.");
        return PROBE_ESYSTEM;
    }

    dI("file_cb: creation time = '%llu'.", c_time);
    dI("file_cb: access time = '%llu'.", a_time);
    dI("file_cb: modification time = '%llu'.", m_time);

    char s_checksum[11] = "";

    if (get_file_checksum(s_filepath, s_checksum, sizeof s_checksum) != 0) {
        dE("file_cb: error getting file checksum.");
        return PROBE_ESYSTEM;
    }

    dI("file_cb: checksum = '%s'.", s_checksum); 

    char s_owner[SZ_MIN] = "";
    int tries; 

    // por timeout, a veces falla... reintentamos
    for (tries = 0; tries < 3; tries++) {
        if (get_file_owner(s_filepath, s_owner, sizeof s_owner) == 0)
            break;

        Sleep(100);
        dW("file_cb: retry...");
    }

    if (tries == 3) {
        dE("file_cb: error getting file owner.");
        return PROBE_ESYSTEM;
    }

    dI("file_cb: owner = '%s'.", s_owner);
    
    char* p_type = get_file_type(s_filepath);

    if (p_type == NULL) {
        dE("file_cb: error getting type.");
        return PROBE_ESYSTEM;
    }

    dI("file_cb: type = '%s'.", p_type);

    char* p_windows_view = get_windows_view();

    if (p_windows_view == NULL) {
        dE("file_cb: error getting windows view.");
        return PROBE_ESYSTEM;
    }

    dI("file_cb: windows view = '%s'.", p_windows_view);

    dI("-");

    SEXP_t *item = probe_item_create(OVAL_WINDOWS_FILE, NULL,
        "filepath", OVAL_DATATYPE_STRING, s_filepath,
        "path", OVAL_DATATYPE_STRING, s_path,
        "filename", OVAL_DATATYPE_STRING, s_filename,
        "owner", OVAL_DATATYPE_STRING, s_owner,
        "size", OVAL_DATATYPE_INTEGER, f_size,
        "a_time", OVAL_DATATYPE_INTEGER, a_time,
        "c_time", OVAL_DATATYPE_INTEGER, c_time,
        "m_time", OVAL_DATATYPE_INTEGER, m_time,
        "ms_checksum", OVAL_DATATYPE_STRING, s_checksum,
        "version", OVAL_DATATYPE_VERSION, s_version, 
        "type", OVAL_DATATYPE_STRING, p_type,
        "development_class", OVAL_DATATYPE_STRING, "", // TODO
        "company", OVAL_DATATYPE_STRING, s_company_name,
        "internal_name", OVAL_DATATYPE_STRING, s_internal_name,
        "language", OVAL_DATATYPE_STRING, s_language,
        "original_filename", OVAL_DATATYPE_STRING, s_original_filename,
        "product_name", OVAL_DATATYPE_STRING, s_product_name,
        "product_version", OVAL_DATATYPE_VERSION, s_product_version,
        "windows_view", OVAL_DATATYPE_STRING, p_windows_view, // TODO
        NULL);

    // Stop collecting if memory usage limit (return 2)
    return probe_item_collect(ctx, item) == 2 ? 1 : 0;
}


// --------------------
// oval_winfts 
// --------------------

#define OVAL_RECURSE_DIRECTION_NONE 0 /* default */
#define OVAL_RECURSE_DIRECTION_DOWN 1
#define OVAL_RECURSE_DIRECTION_UP   2

#define OVAL_RECURSE_FILES    0x01
#define OVAL_RECURSE_DIRS     0x02
#define OVAL_RECURSE_SYMLINKS 0x04

#define OVAL_RECURSE_SYMLINKS_AND_DIRS (OVAL_RECURSE_SYMLINKS|OVAL_RECURSE_DIRS) /* default */
#define OVAL_RECURSE_FILES_AND_DIRS    (OVAL_RECURSE_FILES|OVAL_RECURSE_SYMLINKS)

#define OVAL_RECURSE_FS_LOCAL   0
#define OVAL_RECURSE_FS_DEFINED 1
#define OVAL_RECURSE_FS_ALL     2 /* default */

#define MAX_OVAL_WINFTS_ENTS 100


typedef struct {
    char* file;
    char* path;

} OVAL_WINFTS_ENT;


typedef struct {
    SEXP_t* path;
    SEXP_t* filename;
    SEXP_t* filepath;
    SEXP_t* behaviors;
    SEXP_t* result;

    // behaviors
    int max_depth;
    int direction;
    int recurse;
    int filesystem;

    char* s_path;
    char* s_file;

    OVAL_WINFTS_ENT** owfts_ent;
    size_t cnt; 
    pcre* path_regex;
    uint32_t path_op;

} OVAL_WINFTS;


// api oval_winfts 
OVAL_WINFTS* oval_winfts_open(SEXP_t* path, SEXP_t* filename, SEXP_t* filepath, SEXP_t* behaviors, SEXP_t* result);
OVAL_WINFTS_ENT* oval_winfts_read(OVAL_WINFTS* owfts);
int oval_winfts_close(OVAL_WINFTS* owfts);
void oval_winftsent_free(OVAL_WINFTS_ENT* owfts_ent);


static OVAL_WINFTS_ENT* OVAL_WINFTS_ENT_new(const char* path, const char* file) 
{
    OVAL_WINFTS_ENT* owfts_ent = calloc(1, sizeof(OVAL_WINFTS_ENT));

    if (owfts_ent != NULL) {
        owfts_ent->path = strdup(path);
        owfts_ent->file = strdup(file);
    }

    return owfts_ent;
}


static void OVAL_WINFTS_ENT_free(OVAL_WINFTS_ENT* owfts_ent) 
{
    if (owfts_ent != NULL) {
        free(owfts_ent->path);
        free(owfts_ent->file);
        free(owfts_ent);
    }
}


static OVAL_WINFTS* OVAL_WINFTS_new()
{
    OVAL_WINFTS* owfts = calloc(1, sizeof(OVAL_WINFTS));

    if (owfts) {
        owfts->path = NULL;
        owfts->filename = NULL;
        owfts->filepath = NULL;
        owfts->behaviors = NULL;
        owfts->result = NULL;

        owfts->s_path = NULL;
        owfts->s_file = NULL;
        owfts->path_regex = NULL;

        // inicialmente, creamos array de entradas
        owfts->owfts_ent = calloc(MAX_OVAL_WINFTS_ENTS, sizeof(OVAL_WINFTS_ENT*));
        owfts->cnt = 0;

        // valores por defecto
        owfts->path_op = OVAL_OPERATION_EQUALS;
        owfts->max_depth = -1;
        owfts->recurse = OVAL_RECURSE_SYMLINKS_AND_DIRS;
        owfts->direction = OVAL_RECURSE_DIRECTION_NONE;
        owfts->filesystem = OVAL_RECURSE_FS_ALL;
    }

    return owfts;
}


static void OVAL_WINFTS_free(OVAL_WINFTS* owfts)
{
    if (owfts) {
        free(owfts->s_path);
        free(owfts->s_file);

        pcre_free(owfts->path_regex);

        if (owfts->owfts_ent != NULL) {
            for (int i = 0; i < owfts->cnt; i++) {
                free(owfts->owfts_ent[i]);
            }
            free(owfts->owfts_ent);
        }

        free(owfts);
    }

    return;
}


void oval_winftsent_free(OVAL_WINFTS_ENT* owfts_ent) 
{
    // por coherencia en sintaxis api linux
    OVAL_WINFTS_ENT_free(owfts_ent);
}


// trunca en primer caracter regex y devuelve posicion
static char* __regex_locate(char* s)
{
    bool esc = false;

    while (*s) {
        if (*s == '\\') esc = !esc;
        else {
            /*<< regex start chars */
            if (!esc && strchr("^*?$.([", *s))
                return s;

            esc = false;
        }
        ++s;
    }

    return s;
}


// no hay strndup en windows
static char* strndup(const char* str, size_t sz)
{
    size_t len = strnlen(str, sz);
    char* dup = malloc(len + 1);

    if (dup == NULL) {
        return NULL;
    }

    strncpy(dup, str, len);
    dup[len] = '\0';

    return dup;
}


// devuelve copia de cadena sin caracter de escape
static char* __string_unescape(char* str, size_t len)
{
    char* ret;
    size_t i, j;

    if (str == NULL || len == 0)
        return NULL;

    if ((ret = strndup(str, len)) == NULL)
        return NULL;

    for (i = j = 0; i < len && j <= i; i++, j++) {
        if (str[i] != '\\') ret[j] = str[i]; 
        else {
            // invalid escape ?
            if (str[i + 1] == '\0') {
                free(ret);
                return NULL;
            }

            ret[j] = str[++i];
        }
    }

    ret[j] = '\0';

    return ret;
}


// intenta extraer path de regex
static char* extract_fixed_path_prefix(char* path)
{
    char* s;

    if (path[0] == '^') path++;
    s = __regex_locate(path);

    // retrocedemos hasta separador
    if (*s) for (s--; s > (path + 1) && *s != '\\'; s--);

    if (s > (path + 1)) {
        s = __string_unescape(path, (size_t)(s - path));
        if (s != NULL) {
            if (s[0])
                return s;

            free(s);
        }
    }

    // por defecto
    return strdup(DEFAULT_ROOT);
}


static int process_pattern_match(const char* path, pcre** regex)
{
    int errofs = 0;
    const char* errptr = NULL;

    // Windows no es case sensitive
    *regex = pcre_compile(path, PCRE_CASELESS, &errptr, &errofs, NULL);

    if (*regex == NULL) {
        dE("process_pattern_match: error calling 'pcre_compile'");
        return -1;
    }

    return 0;
}


void list_dir(OVAL_WINFTS* owfts, const char* from, int depth)
{
    WIN32_FIND_DATA fd;
    HANDLE h = NULL;
    char sPath[MAX_PATH];
    bool partial_path = false;

    // superado nivel de profundidad maximo definido ? 
    if (owfts->max_depth > 0 && depth > owfts->max_depth) {
        dE("list_dir: max_depth reached!");
        return;
    }

    // TODO pendiente verificar si solo path admite regex
    if (owfts->path_op == OVAL_OPERATION_PATTERN_MATCH) {

        // primero... comparamos ruta con regex? puede ser parcial
        int ret = pcre_exec(owfts->path_regex, NULL,
                    from, (int)strlen(from), 0, PCRE_PARTIAL, NULL, 0);

        if (ret < 0) {
            switch (ret) {
                case PCRE_ERROR_PARTIAL:
                    // no es esta ruta, pero estamos cerca, continuamos...
                    partial_path = true;
                    break;
                case PCRE_ERROR_NOMATCH:
                    // la ruta no comienza igual, salimos
                    return;
                default:
                    dE("list_dir: regex error!");
                    return;
            }
        }
    }

    // from = filepath 
    if (owfts->filepath) {
        strncpy(sPath, from, sizeof sPath);
        sPath[sizeof sPath - 1] = 0;
    }

    else {
        // TODO tiene sentido la busqueda iterativa si no hay recursion?
        concat_path(sPath, sizeof sPath, from,
            owfts->direction == OVAL_RECURSE_DIRECTION_NONE &&
            owfts->filename ? owfts->s_file : "*.*");
    }

    if ((h = FindFirstFile(sPath, &fd)) == INVALID_HANDLE_VALUE) {
        dD("list_dir: path not found '%s'", from);
        return;
    }

    do {
        // ignorar directorios "." y ".."
        if (strcmp(fd.cFileName, ".") != 0 && strcmp(fd.cFileName, "..") != 0) {

            // Construir la ruta completa para el archivo o directorio si no lo hemos hecho
            if (owfts->filepath == NULL || owfts->direction != OVAL_RECURSE_DIRECTION_NONE) {
                concat_path(sPath, sizeof sPath, from, fd.cFileName);
            }

            if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) 
                    && (owfts->recurse & OVAL_RECURSE_DIRS)) {

                // aceptamos links ? 
                if ((fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
                        && !(owfts->recurse & OVAL_RECURSE_SYMLINKS)) {
                    continue;
                }

                switch (owfts->direction) {
                    case OVAL_RECURSE_DIRECTION_NONE:
                        continue;
                    case OVAL_RECURSE_DIRECTION_UP:
                        dE("list_dir: OVAL_RECURSE_DIRECTION_UP not implemented!");
                        return;
                    case OVAL_RECURSE_DIRECTION_DOWN:
                        dD("list_dir: entering directory '%s'", sPath);
                        list_dir(owfts, sPath, ++depth);
                        continue;
                    default:
                        dE("list_dir: invalid recurse direction option!");
                        return;
                }
            }

            else {

                // no miramos ficheros, pero si entrar en subdirs
                if (partial_path) continue; 

                dD("list_dir: checking file '%s'", sPath);

                // TODO no tengo claro si obligatorio filename 
                if (owfts->filename && _stricmp(fd.cFileName, owfts->s_file) != 0) {
                    continue;
                }

                dI("list_dir: saving file '%s'", sPath);

                // TODO ampliar dinamicamente por tramos
                if (owfts->cnt == MAX_OVAL_WINFTS_ENTS) {
                    dE("list_dir: MAX_OVAL_WINFTS_ENTS reached!");
                    return;
                }
                
                owfts->owfts_ent[owfts->cnt] = OVAL_WINFTS_ENT_new(from, fd.cFileName);
                owfts->cnt++; 
            }
        }

        // Buscar el siguiente archivo
    } while (FindNextFile(h, &fd));

    // Cerrar el handle de búsqueda
    FindClose(h);
}


OVAL_WINFTS* oval_winfts_open(SEXP_t* path, SEXP_t* filename, 
        SEXP_t* filepath, SEXP_t* behaviors, SEXP_t* result) 
{
    SEXP_t* r0;
    char sbuf[SZ_MIN];
    char* from = NULL;
    
    if ((path != NULL || filename != NULL || filepath == NULL)
            && (path == NULL || filepath != NULL)) {
        return NULL;
    }
    if (behaviors == NULL) {
        return NULL;
    }

    OVAL_WINFTS* owfts = OVAL_WINFTS_new();

    if (owfts == NULL) {
        dE("oval_winfts_open: error creating 'owfts'.");
        return NULL;
    }

    // TODO ver uso 
    owfts->behaviors = behaviors;
    owfts->result = result;


    // path + filename o filepath
    // ---

    char s_path[MAX_PATH] = "";
    char s_file[MAX_PATH] = "";

    if (path) /* filepath == NULL */ {
        PROBE_ENT_STRVAL(path, s_path, sizeof s_path, goto e;, goto e;);
        owfts->path = path;

        // TODO xsi:nil
        if (probe_ent_getvals(filename, NULL) != 0) {
            PROBE_ENT_STRVAL(filename, s_file, sizeof s_file, goto e;, /**/;);
            owfts->filename = filename;
        }
    }
    else /* filepath != NULL */ {
        PROBE_ENT_STRVAL(filepath, s_path, sizeof s_path, goto e;, goto e;);
        owfts->filepath = filepath;
    }

    dI("oval_winfts_open: path = '%s', filename = '%s'.", s_path, s_file);

    owfts->s_path = strdup(s_path);
    owfts->s_file = strdup(s_file);


    // max_depth
    // ---

    PROBE_ENT_AREF(behaviors, r0, "max_depth", goto e;);
    SEXP_string_cstr_r(r0, sbuf, sizeof sbuf - 1);
    SEXP_free(r0);

    owfts->max_depth = strtol(sbuf, NULL, 10);

    if (errno == EINVAL || errno == ERANGE) {
        dE("oval_winfts_open: invalid value for 'max_depth'.");
        goto e;
    }

    dI("oval_winfts_open: max_depth = %d.", owfts->max_depth);


    // recurse_direction
    // ---

    PROBE_ENT_AREF(behaviors, r0, "recurse_direction", goto e;);
    SEXP_string_cstr_r(r0, sbuf, sizeof sbuf - 1);
    SEXP_free(r0);

    if (strcmp(sbuf, "none") == 0)
        owfts->direction = OVAL_RECURSE_DIRECTION_NONE;
    else if (strcmp(sbuf, "down") == 0)
        owfts->direction = OVAL_RECURSE_DIRECTION_DOWN;
    else if (strcmp(sbuf, "up") == 0)
        owfts->direction = OVAL_RECURSE_DIRECTION_UP;
    else {
        dE("oval_winfts_open: invalid direction: %s", sbuf);
        goto e;
    }

    dI("oval_winfts_open: direction = '%s' (%d).", sbuf, owfts->direction);


    // recurse
    // ---

    PROBE_ENT_AREF(behaviors, r0, "recurse", /**/);

    if (r0 != NULL) {
        SEXP_string_cstr_r(r0, sbuf, sizeof sbuf - 1);
        SEXP_free(r0);

        if (strcmp(sbuf, "symlinks and directories") == 0)
            owfts->recurse = OVAL_RECURSE_SYMLINKS_AND_DIRS;
        else if (strcmp(sbuf, "files and directories") == 0)
            owfts->recurse = OVAL_RECURSE_FILES_AND_DIRS;
        else if (strcmp(sbuf, "symlinks") == 0)
            owfts->recurse = OVAL_RECURSE_SYMLINKS;
        else if (strcmp(sbuf, "directories") == 0)
            owfts->recurse = OVAL_RECURSE_DIRS;
        else {
            dE("oval_winfts_open: invalid recurse.");
            goto e;
        }
    }

    dI("oval_winfts_open: recurse = '%s' (%d)", sbuf, owfts->recurse);


    // recurse_file_system
    // ---

    PROBE_ENT_AREF(behaviors, r0, "recurse_file_system", /**/);

    if (r0 != NULL) {
        SEXP_string_cstr_r(r0, sbuf, sizeof sbuf - 1);
        SEXP_free(r0);

        if (strcmp(sbuf, "local") == 0)
            owfts->filesystem = OVAL_RECURSE_FS_LOCAL;
        else if (strcmp(sbuf, "all") == 0)
            owfts->filesystem = OVAL_RECURSE_FS_ALL;
        else if (strcmp(sbuf, "defined") == 0)
            owfts->filesystem = OVAL_RECURSE_FS_DEFINED;
        else {
            dE("oval_winfts_open: invalid recurse filesystem.");
            goto e;
        }
    }

    dI("oval_winfts_open: filesystem = '%s' (%d).", sbuf, owfts->filesystem);


    // path de inicio 
    // ---

    if (path) PROBE_ENT_AREF(path, r0, "operation", /**/);
        else PROBE_ENT_AREF(filepath, r0, "operation", /**/);

    if (r0 != NULL) {
        owfts->path_op = SEXP_number_getu(r0);
        SEXP_free(r0);
    }

    dI("oval_winfts_open: path_op = '%s' (%u).", oval_operation_get_text(owfts->path_op), owfts->path_op);

    if (owfts->path_op == OVAL_OPERATION_EQUALS) {
        from = strdup(s_path);
    }

    else if (owfts->path_op == OVAL_OPERATION_PATTERN_MATCH) {
        if (process_pattern_match(s_path, &owfts->path_regex) != 0) {
            goto e;
        }
        from = extract_fixed_path_prefix(s_path);

        // TODO para que funcione regex, necesitamos recursion
        owfts->direction = OVAL_RECURSE_DIRECTION_DOWN;
    }

    else {
        // by default, TODO revisar
        from = strdup(DEFAULT_ROOT);
    }

    dI("oval_winfts_open: from = '%s'.", from);

    if (!file_exist(from)) {
        dE("oval_winfts_open: path doesn't exist.");
        goto e;
    }

    list_dir(owfts, from, 1);
    free(from);

    return owfts;

e:
    OVAL_WINFTS_free(owfts);
    free(from);

    return NULL;
}


OVAL_WINFTS_ENT* oval_winfts_read(OVAL_WINFTS* owfts) 
{
    OVAL_WINFTS_ENT* e = NULL; 

    // pop owfts_ent 
    if (owfts->cnt) {
        e = owfts->owfts_ent[--owfts->cnt];
        owfts->owfts_ent[owfts->cnt] = NULL;
    }

    return e;
}


int oval_winfts_close(OVAL_WINFTS* owfts) 
{
    OVAL_WINFTS_free(owfts);
    return 0;
}



// ---
// pseudo main
// ---
int file_probe_main(probe_ctx* ctx, void* mutex)
{
    int err = 0;

    SEXP_t* probe_in = probe_ctx_getobject(ctx);

    SEXP_t* filepath = probe_obj_getent(probe_in, "filepath", 1);
    SEXP_t* path = probe_obj_getent(probe_in, "path", 1);
    SEXP_t* filename = probe_obj_getent(probe_in, "filename", 1);
    SEXP_t* behaviors = probe_obj_getent(probe_in, "behaviors", 1);

    if (filepath == NULL && (path == NULL || filename == NULL)) {
        dE("file_probe_main: filepath or path + filename missing.");
        err = PROBE_ENOELM;
        goto e;
    }

    // si no configurada, por defecto
    probe_filebehaviors_canonicalize(&behaviors);

    // TODO implementar behavior: ej oval:org.cisecurity:obj:3310 
    if (behaviors == NULL) {
        dE("file_probe_main: behaviors missing.");
        err = PROBE_ENOELM;
        goto e;
    }

    OVAL_WINFTS* owfts = NULL;
    OVAL_WINFTS_ENT* owfts_ent = NULL;

    if ((owfts = oval_winfts_open(path, filename, filepath, behaviors, probe_ctx_getresult(ctx))) != NULL) {
        while ((owfts_ent = oval_winfts_read(owfts)) != NULL) {
            if ((err = file_cb(owfts_ent->path, owfts_ent->file, ctx)) != 0) {
                oval_winftsent_free(owfts_ent);
                break;
            }
            oval_winftsent_free(owfts_ent);
        }
        oval_winfts_close(owfts);
    }

e:
    SEXP_free(filepath);
    SEXP_free(path);
    SEXP_free(filename);
    SEXP_free(behaviors);

    return err;
}
