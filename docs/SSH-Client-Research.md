# SSH Client Research

***Commit 8a6cd08 - https://github.com/openssh/openssh-portable***

I want my ssh client credentials stealer to extract user@host and password or priavte key

## Generic Solution

TODO - *I can find generic solution for extracting all information I want*

## Password Extraction

It seems that the password is read in function `userauth_passwd()`

```c
// sshconnect2.c
// Line 1056
xasprintf(&prompt, "%s@%s's password: ", authctxt->server_user, host);
password = read_passphrase(prompt, 0);
```

I have two possible options:

- hook library functions that used by `read_passphrase()`
- hook library functions that used by functions that using `password` variable

### Who is using `password` variable?

The `password` variable is passed to

```c
// sshconnect2.c
(r = sshpkt_put_cstring(ssh, password)) != 0 || // Line 1064
freezero(password, strlen(password)); // Line 1071
```

These functions is too generic and used many times in sequence, so it seems too hard for hooking for me

### How `read_passphrase()` function works?

*I am gonna ignore askpass feature for now*

```c
// readpass.c
// Line 187
if (readpassphrase(prompt, buf, sizeof buf, rppflags) == NULL) {
	if (flags & RP_ALLOW_EOF)
		return NULL;
	return xstrdup("");
}

ret = xstrdup(buf);
explicit_bzero(buf, sizeof(buf));
return ret;
```

TODO - *Continue*