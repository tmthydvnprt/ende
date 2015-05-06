"""
ende.Util - Random utility functions

project    : Ende
version    : 0.1.0
status     : development
modifydate : 2015-05-06 05:54:39 -0700
createdate : 2015-05-04 06:08:38 -0700
website    : https://github.com/tmthydvnprt/project
author     : tmthydvnprt
email      : tmthydvnprt@users.noreply.github.com
maintainer : tmthydvnprt
license    : MIT
copyright  : Copyright 2015, project
credits    : 

"""

# external dependancies
from math import ceil
import os
import tarfile

class EndeError(Exception):
    """error handler"""

    pass

def str2ord(string):
    """ returns the ord() of each character of a string as a list """

    return [ord(c) for c in string]

def str_sum(string):
    """ return the sum() of an ord() list """

    return sum(str2ord(string))

def pad(message='', block_size=16):
    """ returns a message padded to the appropriate block size """

    pad_size = block_size - (len(message) % block_size)
    padding = chr(pad_size) * pad_size
    return message + padding

def unpad(message=''):
    """ returns a message with padding removed, assumes chr(padSize) * padSize type padding """

    return message[:-ord(message[-1])]

def b64len(num=1):
    """ returns the length of base64 encoding length of n """

    return int(4 * ceil(num / 3))

def ellipsis_truncate(message='', length=16):
    """truncate a string and add ellipsis if longer than constant"""

    return message[:length] + '...' if len(message) > length else message[:length]

def make_tar(output, sources):
    """store test data as tar"""

    with tarfile.open(output, 'w') as tar:
        for source in sources:
            tar.add(source, arcname=os.path.basename(source))

def open_tar(source):
    """open tar file"""

    tar = tarfile.open(source, 'r')
    tar.extractall()
    tar.close()
