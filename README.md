# SSH-Client-Stealer
OpenSSH client credentials stealer by functions hooking

### This is POC

- you should hijacking a SharedObject used by ssh (`ldd /bin/ssh`)
- output written to STDOUT

### Usage

```bash
make  # Compile SharedObject File

LD_PRELOAD=$PWD/stealer.so ssh user@localhost
```

![image](https://github.com/eyalasulin999/SSH-Client-Stealer/assets/41264556/c63d9d4c-d70a-4cca-9ef7-21e65366dcef)

you can set log level by `LOG_LEVEL` value

```c
// src/stealer.c - line 16
#define LOG_LEVEL <>
```

Used Levels: LOG_TRACE, LOG_INFO

### TBD

- extracting private keys
