"""
Personal (En)cryption (De)cryption package and command-line tool

This program provides string, file & whole folder encrytion / decryption.
It may be used either as a importable package or a command-line tool.

    * Encryption uses AES-128 CBC mode
    * Authentication is signed with a SHA256 HMAC.
    * Individual encryption and authentication keys are generated from the password via PBKDF2.

Modules:
    ende.Data - data and string level functions
    ende.File - folder level functions
    ende.Util - ranodm utility functions

"""

__all__ = ['Data', 'File', 'Util']
__version__ = '0.1.0'
