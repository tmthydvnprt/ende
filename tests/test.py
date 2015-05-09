"""
tests.test_file - nose tests for ende.File module

project    : ende
version    : 0.1.0
status     : development
modifydate : 2015-05-09 06:07:00 -0700
createdate : 2015-05-09 06:04:00 -0700
website    : https://github.com/tmthydvnprt/ende
author     : tmthydvnprt
email      : tmthydvnprt@users.noreply.github.com
maintainer : tmthydvnprt
license    : MIT
copyright  : Copyright 2015, ende
credits    :

"""

# test dependancies
import os
import random
import unittest
import numpy as np
from os import path
from shutil import rmtree
from Crypto import Random
from filecmp import dircmp
from difflib import ndiff, get_close_matches

# testing dependancies
from ende.Util import open_tar
from ende.File import encrypt_folders, decrypt_folders
from ende.Data import Encryption, Decryption, Signature, SignedEncryption, SignedDecryption

# test constants
IGNORES = ['.DS_Store', '.localized']
ALPHABET = np.array(list('`1234567890-=~!@#$%^&*()_+qwertyuiop[]\\QWERTYUIOP{}|adfghjkl;"ASDFGHJKL:\'zxcvbnm,./'))
BASE64_ALPHABET = np.array(list('0123456789qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM-_'))
FILE_TEST_COUNT = 1
DATA_TEST_COUNT = 1000

# test helper functions
def list_diff(list1, list2):
    """return list1 items not in list2"""

    return [x for x in list1 if x not in set(list2)]

def get_file_diffs(file1, file2):
    """ndiff file compare"""

    left_file = open(file1, 'r').read()
    right_file = open(file2, 'r').read()
    return [(i, s) for i, s in enumerate(ndiff(left_file, right_file)) if s[0] != ' ']

def get_dir_diffs(dcmp):
    """recursive directory and file compare"""

    diffs = []
    # compare different files
    for name in dcmp.diff_files:
        diffs.append({
            'name' : name,
            'left' : dcmp.left,
            'right': dcmp.right,
            'diffs': get_file_diffs(dcmp.left+'/'+name, dcmp.right+'/'+name)
        })

    # compare common subdirectories
    for sub_dcmp in dcmp.subdirs.values():
        diffs.extend(get_dir_diffs(sub_dcmp))

    # check for close file and subdirectory matches
    close_dirs = []
    close_files = []
    for left in dcmp.left_only:
        match = get_close_matches(left, dcmp.right_only, 1)
        if match:
            close_paths = (dcmp.left+'/'+left, dcmp.right+'/'+match[0])
            if all([path.isdir(x) for x in close_paths]):
                close_dirs.append(close_paths)
            else:
                close_files.append(close_paths)

    # compare close subdirectory matches
    for left_dir, right_dir in close_dirs:
        diffs.extend(get_dir_diffs(dircmp(left_dir, right_dir, IGNORES)))

    # compare close file matches
    for left_file, right_file in close_files:
        diffs.append({
            'name' : (path.basename(left_file), path.basename(right_file)),
            'left' : path.dirname(left_file),
            'right': path.dirname(right_file),
            'diffs': get_file_diffs(left_file, right_file)
        })

    # add no match files and directories to diffs
    for no_match in list_diff(dcmp.left_only, [path.basename(x[0]) for x in close_files+close_dirs]):
        diffs.append({
            'name' : no_match,
            'left' : dcmp.left,
            'right': '',
            'diffs': []
        })
    for no_match in list_diff(dcmp.right_only, [path.basename(x[1]) for x in close_files+close_dirs]):
        diffs.append({
            'name' : no_match,
            'left' : '',
            'right': dcmp.right,
            'diffs': []
        })

    return diffs

def compare_files_and_folders(dir1, dir2):
    """deep compare directories and files"""

    return get_dir_diffs(dircmp(dir1, dir2, IGNORES))


# test cases
class EncryptionDecryptionTests(unittest.TestCase):
    """test encrypt() and decrypt() of ende.Data module"""

    def setUp(self):
        """set up tests"""

        self.message = Random.get_random_bytes(random.randint(1000, 5000))
        self.password = ''.join(np.random.choice(ALPHABET, random.randint(8, 24)))
        self.enc = Encryption(self.message, self.password)
        self.dec = Decryption(self.enc.message_object(), self.password)

#    def test_a0(self):
#        """test object creation"""
#
#        enc = Encryption(self.message, self.password)
#        self.assertEqual(type(En), ende.Data.Encryption)
#
#    def test_a1(self):
#        """test object creation"""
#
#        dec = Decryption(self.enc.message_object(), self.password)
#        self.assertEqual(type(De), ende.Data.Decryption)

    def test_a2(self):
        """test ende.Data: one message and one password never encrypt the same"""

        for _ in range(DATA_TEST_COUNT):
            enc = Encryption(self.message, self.password)
            self.assertNotEqual(self.enc.ciphertext, enc.ciphertext)

    def test_a3(self):
        """test ende.Data: one message and one password always decrypt the same"""

        for _ in range(DATA_TEST_COUNT):
            enc = Encryption(self.message, self.password)
            dec = Decryption(enc.message_object(), self.password)
            self.assertEqual(self.dec.plaintext, dec.plaintext)

    def test_a4(self):
        """test ende.Data: many random messages and passwords encrypt/decrypt correctly"""

        for _ in range(DATA_TEST_COUNT):
            message = Random.get_random_bytes(random.randint(1, 5000))
            password = ''.join(np.random.choice(ALPHABET, random.randint(2, 24)))
            enc = Encryption(message, password)
            dec = Decryption(enc.message_object(), password)
            self.assertEqual(message, dec.plaintext)

    def test_a5(self):
        """test ende.Data: many random messages/passwords with bad passwords"""

        for _ in range(DATA_TEST_COUNT):
            message = Random.get_random_bytes(random.randint(1, 5000))
            password1 = ''.join(np.random.choice(ALPHABET, random.randint(2, 24)))
            password2 = ''.join(np.random.choice(ALPHABET, random.randint(2, 24)))
            enc = Encryption(message, password1)
            dec = Decryption(enc.message_object(), password2)
            self.assertNotEqual(message, dec.plaintext)


class SignatureTests(unittest.TestCase):
    """test sign() of ende.Data module"""

    def setUp(self):
        """set up tests"""

        self.message = Random.get_random_bytes(random.randint(1000, 5000))
        self.password = ''.join(np.random.choice(ALPHABET, random.randint(8, 24)))
        self.enc = Encryption(self.message, self.password)
        self.sig = Signature(self.enc.message(), self.password)

    def test_b1(self):
        """test ende.Data: signing a message with salt is good"""

        for _ in range(DATA_TEST_COUNT):
            sig1 = Signature(self.enc.message(), self.password)
            sig2 = Signature(self.enc.message(), self.password, sig1.salt)
            self.assertEqual(sig1, sig2)

    def test_b2(self):
        """test ende.Data: signing a message without salt is bad"""

        for _ in range(DATA_TEST_COUNT):
            sig1 = Signature(self.enc.message(), self.password)
            sig2 = Signature(self.enc.message(), self.password)
            self.assertNotEqual(sig1, sig2)


class EncryptionDecryptionSignTests(unittest.TestCase):
    """test encrypt_with_sig() and decrypt_with_sig() of ende.Data module"""

    def setUp(self):
        """set up tests"""

        self.message = Random.get_random_bytes(random.randint(1000, 5000))
        self.password = ''.join(np.random.choice(ALPHABET, random.randint(8, 24)))
        self.en_sig = SignedEncryption(self.message, self.password)
        self.de_sig = SignedDecryption(signed_message=self.en_sig.signed_message(), password=self.password)

    def test_c1(self):
        """test ende.Data: one message and one password never encrypt the same"""

        for _ in range(DATA_TEST_COUNT):
            en_sig = SignedEncryption(self.message, self.password)
            self.assertNotEqual(self.en_sig.signed_message(), en_sig.signed_message())

    def test_c2(self):
        """test ende.Data: one message and one password always decrypt the same"""

        for _ in range(DATA_TEST_COUNT):
            en_sig = SignedEncryption(self.message, self.password)
            de_sig = SignedDecryption(signed_message=en_sig.signed_message(), password=self.password)
            self.assertEqual(self.de_sig.dec.plaintext, de_sig.dec.plaintext)

    def test_c3(self):
        """test ende.Data: many random messages and passwords encrypt/decrypt correctly"""

        for _ in range(DATA_TEST_COUNT):
            message = Random.get_random_bytes(random.randint(1, 5000))
            password = ''.join(np.random.choice(ALPHABET, random.randint(2, 24)))
            en_sig = SignedEncryption(message, password)
            de_sig = SignedDecryption(signed_message=en_sig.signed_message(), password=password)
            self.assertEqual(message, de_sig.dec.plaintext)

    def test_c4(self):
        """test ende.Data: many random messages and passwords with bad passwords"""

        for _ in range(DATA_TEST_COUNT):
            message = Random.get_random_bytes(random.randint(1, 5000))
            password1 = ''.join(np.random.choice(ALPHABET, random.randint(2, 24)))
            password2 = ''.join(np.random.choice(ALPHABET, random.randint(2, 24)))
            en_sig = SignedEncryption(message, password1)
            de_sig = SignedDecryption(signed_message=en_sig.signed_message(), password=password2)
            self.assertNotEqual(message, de_sig.dec.plaintext)

    def test_c5(self):
        """test ende.Data: many random messages and passwords with bad sent messages"""

        attempt = []
        for _ in range(DATA_TEST_COUNT):
            message = Random.get_random_bytes(random.randint(1, 5000))
            password = ''.join(np.random.choice(ALPHABET, random.randint(2, 24)))
            en_sig = SignedEncryption(message, password)
            ciphertext = en_sig.signed_message()

            # disturb message
            rand_indx = random.randint(1, len(ciphertext)-1)
            bad_ciphertext = ciphertext[:(rand_indx-1)] + ''.join(np.random.choice(BASE64_ALPHABET, 1)) + ciphertext[rand_indx:]
            while bad_ciphertext == ciphertext:
                rand_indx = random.randint(1, len(ciphertext)-1)
                bad_ciphertext = ciphertext[:(rand_indx-1)] \
                               + ''.join(np.random.choice(BASE64_ALPHABET, 1)) \
                               + ciphertext[rand_indx:]

            de_sig = SignedDecryption(signed_message=bad_ciphertext, password=password)
            attempt.append('invalidsignature' == de_sig.dec.plaintext)

        self.assertEqual(True, attempt.count(True)/float(len(attempt)) > 0.95)


class EncryptFolderTests(unittest.TestCase):
    """test encrypt_folders() and decrypt_folders() of ende.File module"""

    def setUp(self):
        """set up tests"""
        os.chdir('tests')
        open_tar('test_dir_data.tar')
        os.chdir('..')

        self.test_dir = 'tests/test_dir'
        self.password = ''.join(np.random.choice(ALPHABET, random.randint(8, 24)))
        self.en_dir = encrypt_folders(self.test_dir, self.password, self.test_dir+'_encrypted')
        self.de_dir = decrypt_folders(self.en_dir, self.password, self.test_dir+'_decrypted')

    def tearDown(self):
        """tear down tests"""
        temp_files = ['test_dir', 'test_dir_encrypted', 'test_dir_decrypted', 'test_dir_copy', 'test_dir2']
        os.chdir('tests')
        for temp_file in temp_files:
            if path.isdir(temp_file):
                rmtree(temp_file)
        os.chdir('..')

    def test_a0(self):
        """ test ende.File: directory compare passes"""

        cmpr = compare_files_and_folders(self.test_dir, self.test_dir+'_copy')
        self.assertEqual(len(cmpr), 0)

    def test_a01(self):
        """ test ende.File: directory compare fails"""

        cmpr = compare_files_and_folders(self.test_dir, self.test_dir+'2')
        self.assertNotEqual(len(cmpr), 0)

    def test_a1(self):
        """ test ende.File: one directory and one password never encrypt the same"""

        for _ in range(FILE_TEST_COUNT):
            en_dir = encrypt_folders(self.test_dir, self.password, self.test_dir+'_encrypted_2')
            cmpr = compare_files_and_folders(self.en_dir, en_dir)
            rmtree(en_dir)
            self.assertNotEqual(len(cmpr), 0)

    def test_a2(self):
        """test ende.File: one directory and one password always decrypt the same"""

        for _ in range(FILE_TEST_COUNT):
            en_dir = encrypt_folders(self.test_dir, self.password, self.test_dir+'_encrypted_2')
            de_dir = decrypt_folders(en_dir, self.password, self.test_dir+'_decrypted_2')
            cmpr = compare_files_and_folders(self.de_dir, de_dir)
            rmtree(en_dir)
            rmtree(de_dir)
            self.assertEqual(len(cmpr), 0)

    def test_a3(self):
        """test ende.File: many directory and random passwords encrypt/decrypt correctly"""

        for _ in range(FILE_TEST_COUNT):
            en_dir = encrypt_folders(self.test_dir, self.password, self.test_dir+'_encrypted_2')
            de_dir = decrypt_folders(en_dir, self.password, self.test_dir+'_decrypted_2')
            cmpr = compare_files_and_folders(self.test_dir, de_dir)
            rmtree(en_dir)
            rmtree(de_dir)
            self.assertEqual(len(cmpr), 0)

    def test_a4(self):
        """test ende.File: many directory with bad passwords"""

        for _ in range(FILE_TEST_COUNT):
            password1 = ''.join(np.random.choice(ALPHABET, random.randint(2, 24)))
            password2 = ''.join(np.random.choice(ALPHABET, random.randint(2, 24)))
            en_dir = encrypt_folders(self.test_dir, password1, self.test_dir+'_encrypted_2')
            de_dir = decrypt_folders(en_dir, password2, self.test_dir+'_decrypted_2')
            cmpr = compare_files_and_folders(self.test_dir, de_dir)
            rmtree(en_dir)
            rmtree(de_dir)
            self.assertNotEqual(len(cmpr), 0)
