# SSH Client Research

***Commit 8a6cd08 - https://github.com/openssh/openssh-portable***

I want my ssh client credentials stealer to extract user@host and password or priavte key

## Generic Solution

TODO - *We can find generic solution for extracting all information we want*

## Password Extraction

It seems that the password is read in function `userauth_passwd()`

```c
// sshconnect2.c
// Line 1056
xasprintf(&prompt, "%s@%s's password: ", authctxt->server_user, host);
password = read_passphrase(prompt, 0);
```

We have two possible options:

- hook library functions that used by `read_passphrase()`
- hook library functions that used by functions that using `password` variable

### How `read_passphrase()` function works?

```c
// readpass.c
// Line 116
/*
 * Reads a passphrase from /dev/tty with echo turned off/on.  Returns the
 * passphrase (allocated with xmalloc).  Exits if EOF is encountered. If
 * RP_ALLOW_STDIN is set, the passphrase will be read from stdin if no
 * tty is or askpass program is available
 */
```

`read_passphrase()` function has `return` few times:

```c
// readpass.c
// Line 56
if ((flags & RP_USE_ASKPASS) && !allow_askpass)
	return (flags & RP_ALLOW_EOF) ? NULL : xstrdup("");

if (use_askpass && allow_askpass) {
	if (getenv(SSH_ASKPASS_ENV))
		askpass = getenv(SSH_ASKPASS_ENV);
	else
		askpass = _PATH_SSH_ASKPASS_DEFAULT;
	if ((flags & RP_ASK_PERMISSION) != 0)
		askpass_hint = "confirm";
	if ((ret = ssh_askpass(askpass, prompt, askpass_hint)) == NULL)
		if (!(flags & RP_ALLOW_EOF))
			return xstrdup("");
	return ret;
}

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


### Who is using `password` variable?

The `password` variable is passed to

```c
// sshconnect2.c
(r = sshpkt_put_cstring(ssh, password)) != 0 || // Line 1064
freezero(password, strlen(password)); // Line 1071
```

TODO - *Continue*