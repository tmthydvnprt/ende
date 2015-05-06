"""
Ende
====

Personal (En)cryption (De)cryption package with command-line tool

This program provides string, file & whole folder encrytion / decryption.
It may be used either as a importable package or a command-line tool.

- Encryption uses AES-128 CBC mode
- Authentication is signed with a SHA256 HMAC.
- Individual encryption and authentication keys are generated from the password via PBKDF2.

project    : Ende
version    : 0.1.0
status     : development
modifydate : 2015-05-06 05:54:18 -0700
createdate : 2015-05-04 06:08:38 -0700
website    : https://github.com/tmthydvnprt/project
author     : tmthydvnprt
email      : tmthydvnprt@users.noreply.github.com
maintainer : tmthydvnprt
license    : MIT
copyright  : Copyright 2015, project
credits    : 

"""

import os
import sys
import argparse

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from ende import __version__
from ende.File import encrypt_folders, decrypt_folders
from ende.Data import Encryption, Decryption, SignedEncryption, SignedDecryption

def readable_directory(prospective_directory):
    """check if argument is directory and is readable"""

    if not os.path.isdir(prospective_directory):
        raise Exception('readable_directory:{0} is not a valid path'.format(prospective_directory))
    if os.access(prospective_directory, os.R_OK):
        return prospective_directory
    else:
        raise Exception('readable_directory:{0} is not a readable directory'.format(prospective_directory))

def list_files(startpath=''):
    """list directory tree"""

    for root, _, files in os.walk(startpath):
        level = root.replace(startpath, '').count(os.sep)
        indent = ' ' * 4 * (level)
        print '{}{}/'.format(indent, os.path.basename(root))
        subindent = ' ' * 4 * (level + 1)
        for f in files:
            print '{}{}'.format(subindent, f)

def parse_args(args):
    """command line argument parser"""

    parser = argparse.ArgumentParser(
        formatter_class=lambda prog: argparse.RawDescriptionHelpFormatter(prog, max_help_position=30),
        description=__doc__,
        epilog='''> This was built for fun, to learn about encryption,
> and for a real, non-trival, use case for learning about structuring python classes.
> An attempt was made to make this secure but it was not designed by a professional cyrptographer.'''
    )
    direction_group = parser.add_mutually_exclusive_group(required=True)
    direction_group.add_argument(
        '-en', '--encrypt',
        help='perform encryption',
        action='store_true'
    )
    direction_group.add_argument(
        '-de', '--decrypt',
        help='perform decryption',
        action='store_true'
    )

    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        '-i', '--input',
        metavar='FILE',
        type=argparse.FileType('r'),
        help='input file, or "-" for stdin'
    )
    input_group.add_argument(
        '-s', '--instr',
        metavar='STR',
        type=str,
        help='input string'
    )
    input_group.add_argument(
        '-id', '--indir',
        metavar='DIR',
        type=readable_directory,
        help='input directory'
    )

    password_group = parser.add_mutually_exclusive_group(required=True)
    password_group.add_argument(
        '-p', '--pswrdfile',
        metavar='FILE',
        type=argparse.FileType('r'),
        help='password file, or "-" for stdin'
    )
    password_group.add_argument(
        '-k', '--pswrd',
        metavar='STR',
        type=str,
        default='password',
        help='password string (do not EVER use this for security)'
    )

    output_group = parser.add_mutually_exclusive_group()
    output_group.add_argument(
        '-o', '--output',
        metavar='FILE',
        type=argparse.FileType('w'),
        default='-',
        help='output file, default is stdout'
    )
    output_group.add_argument(
        '-od', '--outdir',
        metavar='DIR',
        type=readable_directory,
        help='output directory'
    )
    parser.add_argument(
        '-a', '--authenticate',
        help='sign or authenticate message',
        action='store_true'
    )

    parser.add_argument(
        '-u', '--unicode',
        help='input or output is unicode instead of base64 (default is false)',
        action='store_true'
    )

    loudness_group = parser.add_mutually_exclusive_group()
    loudness_group.add_argument(
        '-v', '--verbose',
        help='show verbose info',
        action='store_true'
    )
    loudness_group.add_argument(
        '-q', '--quiet',
        help='show no info',
        action='store_true'
    )
    parser.add_argument(
        '--version',
        help='display the program\'s version',
        action='version',
        version='%(prog)s '+__version__
    )

    return parser.parse_args(args)

def directory_ende(args):
    """directory based en/de"""

    password = args.pswrdfile.read() if args.pswrdfile else args.pswrd
    if args.encrypt:
        outdir = args.outdir if args.outdir else args.indir+'_encrypted'
        encrypt_folders(args.indir, password, outdir)
        if args.verbose:
            print 'Encrypting  :', os.path.abspath(args.indir)
            print 'Files:'
            list_files(args.indir)
            print
            print 'Encrypted to:', os.path.abspath(outdir)
        elif not args.quiet:
            print 'Encrypting  :', os.path.abspath(args.indir)
            print 'Encrypted to:', os.path.abspath(outdir)
    elif args.decrypt:
        outdir = args.outdir if args.outdir else args.indir+'_decrypted'
        decrypt_folders(args.indir, password, outdir)
        if args.verbose:
            print 'Decrypting  :', os.path.abspath(args.indir)
            print 'Files:'
            list_files(args.indir)
            print
            print 'Decrypted to:', os.path.abspath(outdir)
        elif not args.quiet:
            print 'Decrypting  :', os.path.abspath(args.indir)
            print 'Decrypted to:', os.path.abspath(outdir)

def file_or_string_ende(args):
    """file or string based en/de"""

    base64 = not args.unicode
    input_name = args.input.name if args.input else args.instr
    input_text = args.input.read() if args.input else args.instr
    password = args.pswrdfile.read() if args.pswrdfile else args.pswrd

    if args.encrypt:
        if base64 and args.authenticate:
            enc = SignedEncryption(input_text, password)
            output = enc.b64_signed_message()
        elif base64 and not args.authenticate:
            enc = Encryption(input_text, password)
            output = enc.b64_message()
        elif not base64 and args.authenticate:
            enc = SignedEncryption(input_text, password)
            output = enc.signed_message()
        else:
            enc = Encryption(input_text, password)
            output = enc.message()

        if args.verbose:
            print enc
            print

        elif not args.quiet:
            print 'Encrypting:', input_name
            print

        args.output.write(output)

    elif args.decrypt:
        if base64 and args.authenticate:
            dec = SignedDecryption(b64_signed_message=input_text, password=password)
            output = dec.dec.plaintext
        elif base64 and not args.authenticate:
            dec = Decryption(b64_message_string=input_text, password=password)
            output = dec.plaintext
        elif not base64 and args.authenticate:
            dec = SignedDecryption(signed_message=input_text, password=password)
            output = dec.dec.plaintext
        else:
            dec = Decryption(message_string=input_text, password=password)
            output = dec.plaintext

        if args.verbose:
            print dec
            print
        elif not args.quiet:
            print 'Decrypting:', input_name
            print

        args.output.write(output)

def main(inargs):
    """command line program"""

    # process arguments
    args = parse_args(inargs)

    if args.indir:
        directory_ende(args)
    else:
        file_or_string_ende(args)

if __name__ == '__main__':
    main(sys.argv[1:])
