"""
ende.File - File level encryption & decryption functions
"""

# external dependancies
from os import makedirs, walk, path
from shutil import rmtree

# ende dependencies
from ende.Data import SignedEncryption, SignedDecryption

def make_over_dir(dir_path=''):
    """write over directory"""

    if path.exists(dir_path):
        rmtree(dir_path)
    makedirs(dir_path)

def encrypt_folders(p_dir='', password='', c_dir=None):
    """recusively encrypt folders and files (including names)"""

    c_dir = c_dir if c_dir else p_dir + '_encrypted'
    p2c_hash = {}
    p2c_hash[p_dir] = c_dir
    make_over_dir(c_dir)
    for root, folders, files in walk(p_dir):
        for p_fldr in folders:
            c_fldr_path = path.join(p2c_hash[root], SignedEncryption(p_fldr, password).b64_signed_message())
            p2c_hash[path.join(root, p_fldr)] = c_fldr_path
            make_over_dir(c_fldr_path)
        for p_file in files:
            p_file_path = path.join(root, p_file)
            c_file_path = path.join(p2c_hash[root], SignedEncryption(p_file, password).b64_signed_message())
            rfile = open(p_file_path, 'r')
            wfile = open(c_file_path, 'w')
            wfile.write(SignedEncryption(rfile.read(), password).b64_signed_message())
    del p2c_hash
    return c_dir

def decrypt_folders(c_dir='', password='', p_dir=None):
    """recusively decrypt folders and files (including names)"""

    p_dir = p_dir if p_dir else c_dir.replace('_encrypted', '') + '_decrypted'
    c2p_hash = {}
    c2p_hash[c_dir] = p_dir
    make_over_dir(p_dir)
    for root, folders, files in walk(c_dir):
        for c_fldr in folders:
            p_fldr = SignedDecryption(b64_signed_message=c_fldr, password=password).dec.plaintext
            if p_fldr != 'invalidsignature':
                p_fldr_path = path.join(c2p_hash[root], p_fldr)
                c2p_hash[path.join(root, c_fldr)] = p_fldr_path
                make_over_dir(p_fldr_path)
        for c_file in files:
            p_file = SignedDecryption(b64_signed_message=c_file, password=password).dec.plaintext
            if p_file != 'invalidsignature':
                c_file_path = path.join(root, c_file)
                p_file_path = path.join(c2p_hash[root], p_file)
                rfile = open(c_file_path, 'r')
                wfile = open(p_file_path, 'w')
                wfile.write(SignedDecryption(b64_signed_message=rfile.read(), password=password).dec.plaintext)
    del c2p_hash
    return p_dir
