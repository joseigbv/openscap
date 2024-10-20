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

// descripcion filetypes en Windows 
#define S_FILE_TYPE_DISK "FILE_TYPE_DISK"
#define S_FILE_TYPE_CHAR "FILE_TYPE_CHAR"
#define S_FILE_TYPE_PIPE "FILE_TYPE_PIPE"
#define S_FILE_TYPE_UNKNOWN "FILE_TYPE_UNKNOWN"

#define S_WINDOWS_VIEW_64_BIT "64_bit"
#define S_WINDOWS_VIEW_32_BIT "32_bit"


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
        dE("Error calling 'MapFileAndCheckSum'.");
        return -1;
    }

    // TODO: comprobar tamanio maximo de checksum 
    snprintf(s_checksum, sz_checksum, "%ul", checksum);

    return 0;
}


static int check_valid_path(const char* filePath) 
{
    LPCSTR p = filePath;
    int len = 0;

    // caracteres no admitidos
    while (*p != '\0' && len++ < MAX_PATH) {
        switch (*p) {
            case '<':
            case '>':
            case ':':
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

    // TODO pendiente mejorar
    for (int i = 0; i < sizeof(specialNames) / sizeof(char*); i++) {
        if (_stricmp(filePath, specialNames[i]) == 0) {
            return -1;
        }
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

        dE("Error calling '_splitpath_s'.");
        return -1;
    }

    if (check_valid_path(dir) != 0) {
        dE("Error invalid dir.");
        return -1;
    }

    // TODO: pendiente de mejorar seguridad
    snprintf(path, sz_path, "%s%s", drive, dir);
    snprintf(filename, sz_filename, "%s%s", fname, ext);

    if (check_valid_path(fname) != 0) {
        dE("Error invalid filename.");
        return -1;
    }

    return 0;
}


static int get_file_owner(const char* filePath, 
        char* s_owner, size_t sz_owner) 
{
    PSECURITY_DESCRIPTOR sd;

    if (GetNamedSecurityInfo(filePath, SE_FILE_OBJECT, 
            OWNER_SECURITY_INFORMATION, NULL, NULL, NULL, NULL, &sd) != 0) {

        dE("Error calling 'GetNamedSecurtyInfo'.");
        return -1;
    }

    PSID ownerSid;
    BOOL ownerDefaulted;

    if (GetSecurityDescriptorOwner(sd, &ownerSid, &ownerDefaulted) == 0) {
        dE("Error calling 'GetSecurityDescriptorOwner'.");
        LocalFree(sd);
        return -1;
    }

    LocalFree(sd);

    char ownerName[SZ_MIN] = "";
    DWORD ownerNameSize = sizeof ownerName;
    char domainName[SZ_MIN] = "";
    DWORD domainNameSize = sizeof domainName;
    SID_NAME_USE sidUse = 0;

    if (LookupAccountSid(NULL, ownerSid, ownerName, &ownerNameSize, 
            domainName, &domainNameSize, &sidUse) == 0) {

        dE("Error calling 'LookupAccountSid'.");
        return -1;
    }

    // TODO pendiente revision
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
        dE("Error calling 'CreateFile'.");
        return -1;
    }

    // TODO revisar como afecta conversion FILETIME a time_t
    if (GetFileTime(hFile, (FILETIME*)c_time, 
            (FILETIME*)a_time, (FILETIME*)m_time) == 0) {

        dE("Error calling 'GetFileTime'.");
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
        dE("Error calling '_stat'");
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
        dE("Error calling 'GetFileVersionInfoSize'.");
        return -1;
    }

    LPVOID lpData = malloc(dwSize);

    if (lpData == NULL) {
        dE("Error calling 'malloc'.");
        return -1;
    }

    if (GetFileVersionInfo(filePath, 0, dwSize, lpData) == 0) {
        dE("Error calling 'GetFileVersionInfo'.");
        free(lpData);
        return -1;
    }

    VS_FIXEDFILEINFO* pFileInfo;

    if (VerQueryValue(lpData, "\\", (LPVOID*)&pFileInfo, &uLen) == 0) {
        dE("Error calling 'VerQueryValue'.");
        free(lpData);
        return -1;
    }

    // pruebas: porque version es diferente de product version
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
    if (VerQueryValue(lpData, s, (LPVOID*)&lpBuf, &uLen) == 0) { \
        dE("%s was not found in the version information.", s); \
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
    if (GetLocaleInfo(lang, LOCALE_SLANGUAGE, s_language, (int)sz_language) == 0) {
        dE("Error calling 'GetLocateInfo'.");
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
    return (fileAttr != INVALID_FILE_ATTRIBUTES); 
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
        dE("Error calling 'CreateFile'.");
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



// file_cb(prefix, ofts_ent->path, ofts_ent->file, &cbargs, over, cache, grs, &gr_lastpath)
static int file_cb(const char* filepath, const char* path, const char* filename, probe_ctx* ctx)
//        void* ptr, oval_schema_version_t over, struct ID_cache* cache, 
//        struct gr_sexps* grs, SEXP_t* gr_lastpath)
{
    char s_path[MAX_PATH] = "",
        s_filename[MAX_PATH] = "", 
        s_filepath[MAX_PATH] = "";

    // no filepath? usamos path+filename
    // TODO de momento, no soportados comodines (behaviors)
    if (filepath) {
        PROBE_ENT_STRVAL(filepath, s_filepath, sizeof s_filepath, /* void */, 
            SEMPTY(s_filepath));
    }
    else {
        PROBE_ENT_STRVAL(path, s_path, sizeof s_path, /* void */, 
            SEMPTY(s_path));
        PROBE_ENT_STRVAL(filename, s_filename, sizeof s_filename, /* void */, 
            SEMPTY(s_filename));

        // TODO mejorar seguridad
        snprintf(s_filepath, sizeof s_filepath, "%s\\%s", s_path, s_filename);
    }

    // reconstruimos path y filename, util para verificar paths
    if (get_path_filename(s_filepath, s_path, sizeof s_path,
            s_filename, sizeof s_filename) != 0) {

        dE("Error getting filename and path.");
        return PROBE_EINVAL;
    }

    dI("Filepath: %s", s_filepath);
    dI("Path: %s", s_path);
    dI("Filename: %s", s_filename);

    if (!file_exist(s_filepath)) {
        dI("No existe");
        return 0;
    }

    char s_version[SZ_VER], s_product_version[SZ_VER], s_product_name[SZ_MIN],
            s_file_version[SZ_MIN], s_original_filename[SZ_MIN], s_internal_name[SZ_MIN],
            s_company_name[SZ_MIN], s_language[SZ_MIN];

    if (get_file_version_info(s_filepath, 
            s_version, sizeof s_version, 
            s_product_version, sizeof s_product_version, 
            s_product_name, sizeof s_product_name,
            s_file_version, sizeof s_file_version,
            s_original_filename, sizeof s_original_filename,
            s_internal_name, sizeof s_internal_name,
            s_company_name, sizeof s_company_name,
            s_language, sizeof s_language) != 0) {

        dE("Error getting file version info.");
        return PROBE_ESYSTEM;
    }

    dI("Version: %s", s_version);
    dI("Product version: %s", s_product_version);
    dI("Product name: %s", s_product_name);
    dI("File version: %s", s_file_version);
    dI("Original filename: %s", s_original_filename);
    dI("Internal name: %s", s_internal_name);
    dI("Company name: %s", s_company_name);
    dI("Language: %s", s_language);

    size_t f_size = 0;

    if (get_file_size(s_filepath, &f_size) != 0) {
        dE("Error getting file size.");
        return PROBE_ESYSTEM;
    }

    dI("Size: %lu", f_size);

    time_t a_time = 0, m_time = 0, c_time = 0;

    if (get_file_time(s_filepath, &c_time, &a_time, &m_time) != 0) {
        dE("Error getting file times.");
        return PROBE_ESYSTEM;
    }

    dI("Creation time: %llu", c_time);
    dI("Access time: %llu", a_time);
    dI("Modification time: %llu", m_time);

    char s_checksum[10];

    if (get_file_checksum(s_filepath, s_checksum, 10) != 0) {
        dE("error getting file checksum.");
        return PROBE_ESYSTEM;
    }

    dI("Checksum: %s", s_checksum); 

    char s_owner[SZ_MIN] = "";

    if (get_file_owner(s_filepath, s_owner, sizeof s_owner) != 0) {
        dE("Error getting file owner.");
        return PROBE_ESYSTEM;
    }

    dI("Owner: %s", s_owner);
    
    char* p_type = get_file_type(s_filepath);

    if (get_file_type(s_filepath) == NULL) {
        dE("Error getting type.");
        return PROBE_ESYSTEM;
    }

    dI("Type: %s", p_type);

    char* p_windows_view = get_windows_view();

    if (p_windows_view == NULL) {
        dE("Error getting windows view.");
        return PROBE_ESYSTEM;
    }

    dI("Windows View: %s", p_windows_view);

    dI("-");

    /*
    SEXP_t* se_version = SEXP_string_new(STRLEN_PAIR(s_version));
    SEXP_t* se_product_version = SEXP_string_new(STRLEN_PAIR(s_product_version));
    SEXP_t* se_product_name = SEXP_string_new(STRLEN_PAIR(s_product_name));
    SEXP_t* se_original_filename = SEXP_string_new(STRLEN_PAIR(s_original_filename));
    SEXP_t* se_internal_name = SEXP_string_new(STRLEN_PAIR(s_internal_name));
    SEXP_t* se_company_name = SEXP_string_new(STRLEN_PAIR(s_company_name));
    SEXP_t* se_language = SEXP_string_new(STRLEN_PAIR(s_language));
    SEXP_t* se_size = SEXP_number_newu_64(f_size);
    SEXP_t* se_a_time = SEXP_number_newu_64(a_time);
    SEXP_t* se_c_time = SEXP_number_newu_64(c_time);
    SEXP_t* se_m_time = SEXP_number_newu_64(m_time);
    SEXP_t* se_ms_checksum = SEXP_number_newu(ms_checksum);
    SEXP_t* se_owner = SEXP_string_new(STRLEN_PAIR(s_owner));
    SEXP_t* se_windows_view = SEXP_string_new(STRLEN_PAIR(s_windows_view));

    // no tengo claro si esto es necesario o vale con los originales
    SEXP_t* se_filepath = SEXP_string_new(STRLEN_PAIR(s_filepath));
    SEXP_t* se_path = SEXP_string_new(STRLEN_PAIR(s_path));
    SEXP_t* se_filename = SEXP_string_new(STRLEN_PAIR(s_filename));
    */

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
        "development_class", OVAL_DATATYPE_STRING, "N/A", // TODO
        "company", OVAL_DATATYPE_STRING, s_company_name,
        "internal_name", OVAL_DATATYPE_STRING, s_internal_name,
        "language", OVAL_DATATYPE_STRING, s_language,
        "original_filename", OVAL_DATATYPE_STRING, s_original_filename,
        "product_name", OVAL_DATATYPE_STRING, s_product_name,
        "product_version", OVAL_DATATYPE_VERSION, s_product_version,
        "windows_view", OVAL_DATATYPE_STRING, p_windows_view, // TODO
        NULL);

    /*
    SEXP_free(se_version);
    SEXP_free(se_product_version);
    SEXP_free(se_product_name);
    SEXP_free(se_original_filename);
    SEXP_free(se_internal_name);
    SEXP_free(se_company_name);
    SEXP_free(se_language);
    SEXP_free(se_size);
    SEXP_free(se_a_time);
    SEXP_free(se_c_time);
    SEXP_free(se_m_time);
    SEXP_free(se_ms_checksum);
    SEXP_free(se_owner);
    SEXP_free(se_windows_view);

    SEXP_free(se_filepath);
    SEXP_free(se_path);
    SEXP_free(se_filename);
    */

    // Stop collecting if we hit the memory usage limit (return code == 2)
    return probe_item_collect(ctx, item) == 2 ? 1 : 0;
}


int file_probe_main(probe_ctx* ctx, void* mutex)
{
    // TODO no implementado
    /*
    if (mutex == NULL) {
        return PROBE_EINIT;
    }
    */

    SEXP_t* probe_in = probe_ctx_getobject(ctx);

    SEXP_t* behaviors = probe_obj_getent(probe_in, "behaviors", 1);
    SEXP_t* path = probe_obj_getent(probe_in, "path", 1);
    SEXP_t* filename = probe_obj_getent(probe_in, "filename", 1);
    SEXP_t* filepath = probe_obj_getent(probe_in, "filepath", 1);

    // TODO de momento, solo soportadas estas opciones, para fichero unico
    if (filepath == NULL && (path == NULL || filename == NULL)) {
        SEXP_free(behaviors);
        SEXP_free(path);
        SEXP_free(filename);
        SEXP_free(filepath);

        dE("filepath or path + filename missing.");
        return PROBE_ENOELM;
    }

    probe_filebehaviors_canonicalize(&behaviors);

    // TODO implementar behavior: ej oval:org.cisecurity:obj:3310 
    /*
    if (behaviors != NULL) {
        SEXP_free(behaviors);
        SEXP_free(path);
        SEXP_free(filename);
        SEXP_free(filepath);

        dE("Behaviors not implemented.");
        return PROBE_EOPNOTSUPP;
    }
    */
    
    // TODO en pruebas
    file_cb(filepath, path, filename, ctx);

    SEXP_free(path);
    SEXP_free(filename);
    SEXP_free(filepath);
    SEXP_free(behaviors);

    // TODO de momento asumimos OK
    return 0;
}


void* file_probe_init(void) {
    dW("probe init !!!");
    return NULL;
}


void file_probe_fini(void* mutex) {
    dW("probe fini");
}
