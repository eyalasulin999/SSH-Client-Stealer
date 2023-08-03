#include <stdio.h>
#include <dlfcn.h>
#include <string.h>

#define PASSWORD_READ_DETECTED 1
#define PASSWORD_READ_FMT "%s@%s's password: "

int password_read_detected = 0;

// password reading detection
int __vasprintf_chk (char **__restrict __ptr, int __flag, const char *__restrict __fmt, __gnuc_va_list __arg) {
    if (0 == strcmp(__fmt, PASSWORD_READ_FMT)) {
        password_read_detected = PASSWORD_READ_DETECTED;
    }
    int (*__vasprintf_chk_orig)(char **__restrict __ptr, int __flag, const char *__restrict __fmt, __gnuc_va_list __arg);
    __vasprintf_chk_orig = dlsym(RTLD_NEXT, "__vasprintf_chk");
    return __vasprintf_chk_orig(__ptr, __flag, __fmt, __arg);
}