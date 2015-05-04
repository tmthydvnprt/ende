Ende
====

Description
-----------
Personal (En)cryption (De)cryption package and command-line tool

This program provides string, file & whole folder encrytion / decryption.
It may be used either as a importable package or a command-line tool.

- Encryption uses AES-128 CBC mode
- Authentication is signed with a SHA256 HMAC.
- Individual encryption and authentication keys are generated from the password via PBKDF2.

Modules:

1. `ende.Data` - data and string level functions
2. `ende.File` - folder level functions
3. `ende.Util` - ranodm utility functions


Code Examples
-------------

###Module Interface
import
>from ende.Data import Encryption, Decryption, SignedEncryption, SignedDecryption
>

Encryption Object
>en = Encryption('this is a message', 'password')
>

Decryption as object
>de = Decryption( en, 'password')

Decryption as unicode string
>de = Decryption( message=en.message(), 'password')

Decryption as base64 string
>de = Decryption( b64_message=en.b64_message(), 'password')

Get plaintext
>de.plaintext
>

###Command-Line Interface
Encrypt string with password (you should use password file,`-p`, instead)
>python ende -en -s 'this is a message' -k 'insecure-password' 

ouput
>Encrypting: this is a message
>
>MjIwMTUtMDItMjJUMTI6NDA6NTEtMDgwMCQkkZcQjy6SiWjPHmoCphqMTL6owrQquX9xw8hxFYkUG0_zNrPu-DJyDMrUCfDg4-NR8kiRMNh4ZvkEc1m90EU=

Decrypt string with password
>python ende -de -s 'MjIwMTUtMDItMjJUMTI6NDA6NTEtMDgwMCQkkZcQjy6SiWjPHmoCphqMTL6owrQquX9xw8hxFYkUG0_zNrPu-DJyDMrUCfDg4-NR8kiRMNh4ZvkEc1m90EU=' -k 'insecure-password' 

output
>Decrypting: MjIwMTUtMDItMjJUMTI6NDA6NTEtMDgwMCQkkZcQjy6SiWjPHmoCphqMTL6owrQquX9xw8hxFYkUG0_zNrPu-DJyDMrUCfDg4-NR8kiRMNh4ZvkEc1m90EU=
>
>this is a message


Installation
------------
At the moment, none.  Run `python ende -h` for CLI usage or `import ende` from your current working directory for python import module-ness


API Reference
-------------
...TBD...


Tests
-----
see `/tests`


TODO
----
- [x] write code
- [ ] improvements?


History
-------
Ende was originally written with `pycrypto`, it now uses `cryptography`


License
-------
[MIT]()
