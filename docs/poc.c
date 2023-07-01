#include <stdio.h>
#include <unistd.h>
#include <dlfcn.h>
#include <string.h>

// Compile:
// gcc poc.c -o poc.so -fPIC -shared -ldl -D_GNU_SOURCE

// hook __vasprintf_chk() function for pre password reading detection
int __vasprintf_chk (char **__restrict __ptr, int __flag, const char *__restrict __fmt, __gnuc_va_list __arg) {
    if (strcmp(__fmt, "%s@%s's password: ") == 0)
        printf("[HOOK __vasprintf_chk] %s\n", __fmt);
    int (*__vasprintf_chk_real)(char **__restrict __ptr, int __flag, const char *__restrict __fmt, __gnuc_va_list __arg);
    __vasprintf_chk_real = dlsym(RTLD_NEXT, "__vasprintf_chk");
    return __vasprintf_chk_real(__ptr, __flag, __fmt, __arg);
}

// hook write() libc wrapper for pre password reading detection
ssize_t write (int __fd, const void *__buf, size_t __n) {
    if (strstr(__buf, "'s password: ") != NULL)
        printf("[HOOK write] %s\n", __buf);
    ssize_t (*libc_write)(int __fd, const void *__buf, size_t __n);
    ssize_t result;
    libc_write = dlsym(RTLD_NEXT, "write");
    return libc_write(__fd, __buf, __n);
}