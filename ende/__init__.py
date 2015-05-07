"""
Ende
====

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

> This was built for fun, to learn about encryption,
> and for a real, non-trival, use case for learning about structuring python classes.
> An attempt was made to make this secure but it was not designed by a professional cyrptographer.

project    : Ende
version    : 0.1.0
status     : development
modifydate : 2015-05-06 19:28:00 -0700
createdate : 2015-05-04 06:08:00 -0700
website    : https://github.com/tmthydvnprt/ende
author     : tmthydvnprt
email      : tmthydvnprt@users.noreply.github.com
maintainer : tmthydvnprt
license    : MIT
copyright  : Copyright 2015, project
credits    : 

"""

__all__ = ['Data', 'File', 'Util']
__version__ = '0.1.0'
__status__ = 'development'
__date__ = '2015-05-06 19:28:00 -0700'
__website__ = 'https://github.com/tmthydvnprt/ende'
__author__ = 'tmthydvnprt'
__email__ = 'tmthydvnprt@users.noreply.github.com'
__maintainer__ = 'tmthydvnprt'
__license__ = 'MIT'
__copyright__ = 'Copyright 2015, project'
__credits__ = ''
