# SSH Client Research

***Commit 8a6cd08 - https://github.com/openssh/openssh-portable***

I want my ssh client credentials stealer to extract user@host and password or priavte key

## Password Extraction

It seems that the password is read in function `userauth_passwd()`

```c
// sshconnect2.c
// Line 1056
xasprintf(&prompt, "%s@%s's password: ", authctxt->server_user, host);
password = read_passphrase(prompt, 0);
```

We want to hook printing of `"%s@%s's password: "` to 'invoke' the next hook of reading the password

Let's check call stack for library function that we can hook

```
[#0] 0x7ffff7736380 → __vasprintf_chk(result_ptr=0x7fffffffc1e0, flag=0x1, format=0x5555556106ae "%s@%s's password: ", ap=0x7fffffffc100)
[#1] 0x5555555c79aa → vasprintf(__ap=0x7fffffffc100, __fmt=0x5555556106ae "%s@%s's password: ", __ptr=0x7fffffffc1e0)
[#2] 0x5555555c79aa → xvasprintf(ap=0x7fffffffc100, fmt=0x5555556106ae "%s@%s's password: ", ret=0x7fffffffc1e0)
[#3] 0x5555555c79aa → xasprintf(ret=0x7fffffffc1e0, fmt=0x5555556106ae "%s@%s's password: ")
```

`vasprintf()` is inline function, but `__vasprintf_chk()` is great

```c
int __vasprintf_chk (char **__restrict __ptr, int __flag, const char *__restrict __fmt, __gnuc_va_list __arg);
```

another possible option is to hook `write()` libc wrapper function

```c
// readpassphrase.c
// Line 128
if (!(flags & RPP_STDIN))
	(void)write(output, prompt, strlen(prompt));
```

```c
ssize_t write (int __fd, const void *__buf, size_t __n);
```

There we set a global variable so we can 'invoke' the next hook by reading the variable value

Let's move to password reading

```c
// readpassphrase.c
// Line 132
while ((nr = read(input, &ch, 1)) == 1 && ch != '\n' && ch != '\r') {
```

we can hook `read()` libc wrapper function, until reading `'\n'`

```c
ssize_t read (int __fd, void *__buf, size_t __nbytes);
```

another possible option is to hook `memcpy()`

```c
// readpass.c
// Line 193
ret = xstrdup(buf);
explicit_bzero(buf, sizeof(buf));
return ret
```

```c
void * memcpy (void *__restrict __dest, const void *__restrict __src, size_t __len);
```

1024 is max length of password:

```c
// readpass.c
// Line 125
char cr = '\r', *askpass = NULL, *ret, buf[1024];

// Line 187
if (readpassphrase(prompt, buf, sizeof buf, rppflags) == NULL) {
```