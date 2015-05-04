"""
Ende

Personal (En)cryption (De)cryption package with command-line tool

This program provides string, file & whole folder encrytion / decryption.
It may be used either as a importable package or a command-line tool.

- Encryption uses AES-128 CBC mode
- Authentication is signed with a SHA256 HMAC.
- Individual encryption and authentication keys are generated from the password via PBKDF2.

Modules:

1. `ende.Data` - data and string level functions
2. `ende.File` - folder level functions
3. `ende.Util` - ranodm utility functions

> This was built for fun, to learn about encryption, and for a real, hopefully non-trival, use case for learning about structuring python classes.  An attempt was made to make this secure but it was not designed by a professional cyrptographer.
"""

__all__ = ['Data', 'File', 'Util']
__version__ = '0.1.0'
