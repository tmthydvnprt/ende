Ende
====

Personal (En)cryption (De)cryption package with command-line tool


Description
-----------

This program provides string, file & whole folder encrytion / decryption.
It may be used either as a importable package or a command-line tool.

- Encryption uses AES-128 CBC mode
- Authentication is signed with a SHA256 HMAC.
- Individual encryption and authentication keys are generated from the password via PBKDF2.

Modules:

1. `ende.Data` - data and string level functions
2. `ende.File` - folder level functions
3. `ende.Util` - ranodm utility functions

> This was built for fun, to learn about encryption,
> and for a real, non-trival, use case for learning about structuring python classes.
> An attempt was made to make this secure but it was **not** designed by a professional cyrptographer.


Code Examples
-------------

### Module Interface

```python
# import
from ende.Data import Encryption, Decryption, SignedEncryption, SignedDecryption

# Encryption Object
enc = Encryption('this is a message', 'password')

# Decryption as object
dec = Decryption(enc, 'password')

# Decryption as unicode string
dec = Decryption(message=enc.message(), 'password')

# Decryption as base64 string
dec = Decryption(b64_message=enc.b64_message(), 'password')

# Get plaintext
dec.plaintext
```

### Command-Line Interface

Encrypt string with password (you should use password file,`-p`, instead)

```ShellSession
machine:user$ python ende -en -s 'this is a message' -k 'insecure-password'
Encrypting: this is a message    

MjIwMTUtMDItMjJUMTI6NDA6NTEtMDgwMCQkkZcQjy6SiWjPHmoCphqMTL6owrQquX9xw8hxFYkUG0_zNrPu-DJyDMrUCfDg4-NR8kiRMNh4ZvkEc1m90EU=
```

Decrypt string with password

```ShellSession
machine:user$ python ende -de -s 'MjIwMTUtMDItMjJUMTI6NDA6NTEtMDgwMCQkkZcQjy6SiWjPHmoCphqMTL6owrQquX9xw8hxFYkUG0_zNrPu-DJyDMrUCfDg4-NR8kiRMNh4ZvkEc1m90EU=' -k 'insecure-password'
Decrypting: MjIwMTUtMDItMjJUMTI6NDA6NTEtMDgwMCQkkZcQjy6SiWjPHmoCphqMTL6owrQquX9xw8hxFYkUG0_zNrPu-DJyDMrUCfDg4-NR8kiRMNh4ZvkEc1m90EU=

this is a message
```


Installation
------------
At the moment, none.  Run `python ende -h` for CLI usage or `import ende` from your current working directory for python import module-ness


API Reference
-------------

### Module Interface

TBD

### Command-Line Interface

    usage: ende [-h] (-en | -de) (-i FILE | -s STR | -id DIR) (-p FILE | -k STR)
                [-o FILE | -od DIR] [-a] [-u] [-v | -q] [--version]

    Personal (En)cryption (De)cryption package with command-line tool

    This program provides string, file & whole folder encrytion / decryption.
    It may be used either as a importable package or a command-line tool.

    - Encryption uses AES-128 CBC mode
    - Authentication is signed with a SHA256 HMAC.
    - Individual encryption and authentication keys are generated from the password via PBKDF2.

    optional arguments:
      -h, --help                 show this help message and exit
      -en, --encrypt             perform encryption
      -de, --decrypt             perform decryption
      -i FILE, --input FILE      input file, or "-" for stdin
      -s STR, --instr STR        input string
      -id DIR, --indir DIR       input directory
      -p FILE, --pswrdfile FILE  password file, or "-" for stdin
      -k STR, --pswrd STR        password string (do not EVER use this for
                                 security)
      -o FILE, --output FILE     output file, default is stdout
      -od DIR, --outdir DIR      output directory
      -a, --authenticate         sign or authenticate message
      -u, --unicode              input or output is unicode instead of base64
                                 (default is false)
      -v, --verbose              show verbose info
      -q, --quiet                show no info
      --version                  display the program's version

    > This was built for fun, to learn about encryption,
    > and for a real, non-trival, use case for learning about structuring python classes.
    > An attempt was made to make this secure but it was not designed by a professional cyrptographer.


Tests
-----
see `/tests`


TODO
----
- [x] write code
- [ ] improvements?


History
-------
Ende was originally written with [`pycrypto`](https://www.dlitz.net/software/pycrypto/), it now uses [`cryptography`](https://cryptography.io/).


License
-------
[MIT](https://github.com/tmthydvnprt/ende/blob/master/LICENSE)
