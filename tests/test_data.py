"""
tests.test_data - nose tests for ende.Data module

project    : Ende
version    : 0.1.0
status     : development
modifydate : 2015-05-06 19:28:00 -0700
createdate : 2015-05-05 05:36:00 -0700
website    : https://github.com/tmthydvnprt/ende
author     : tmthydvnprt
email      : tmthydvnprt@users.noreply.github.com
maintainer : tmthydvnprt
license    : MIT
copyright  : Copyright 2015, project
credits    : 

"""

# test dependancies
import unittest
import numpy as np
import random
from Crypto import Random

# testing dependancies
from ende.Data import Encryption, Decryption, Signature, SignedEncryption, SignedDecryption

# test constants
ALPHABET = np.array(list('`1234567890-=~!@#$%^&*()_+qwertyuiop[]\\QWERTYUIOP{}|adfghjkl;"ASDFGHJKL:\'zxcvbnm,./'))
BASE64_ALPHABET = np.array(list('0123456789qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM-_'))
TEST_COUNT = 1000

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
        """test one message and one password never encrypt the same"""

        for _ in range(TEST_COUNT):
            enc = Encryption(self.message, self.password)
            self.assertNotEqual(self.enc.ciphertext, enc.ciphertext)

    def test_a3(self):
        """test one message and one password always decrypt the same"""

        for _ in range(TEST_COUNT):
            enc = Encryption(self.message, self.password)
            dec = Decryption(enc.message_object(), self.password)
            self.assertEqual(self.dec.plaintext, dec.plaintext)

    def test_a4(self):
        """test many random messages and passwords encrypt/decrypt correctly"""

        for _ in range(TEST_COUNT):
            message = Random.get_random_bytes(random.randint(1, 5000))
            password = ''.join(np.random.choice(ALPHABET, random.randint(2, 24)))
            enc = Encryption(message, password)
            dec = Decryption(enc.message_object(), password)
            self.assertEqual(message, dec.plaintext)

    def test_a5(self):
        """test many random messages/passwords with bad passwords"""

        for _ in range(TEST_COUNT):
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
        """test signing a message with salt is good"""

        for _ in range(TEST_COUNT):
            sig1 = Signature(self.enc.message(), self.password)
            sig2 = Signature(self.enc.message(), self.password, sig1.salt)
            self.assertEqual(sig1, sig2)

    def test_b2(self):
        """test signing a message without salt is bad"""

        for _ in range(TEST_COUNT):
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
        """test one message and one password never encrypt the same"""

        for _ in range(TEST_COUNT):
            en_sig = SignedEncryption(self.message, self.password)
            self.assertNotEqual(self.en_sig.signed_message(), en_sig.signed_message())

    def test_c2(self):
        """test one message and one password always decrypt the same"""

        for _ in range(TEST_COUNT):
            en_sig = SignedEncryption(self.message, self.password)
            de_sig = SignedDecryption(signed_message=en_sig.signed_message(), password=self.password)
            self.assertEqual(self.de_sig.dec.plaintext, de_sig.dec.plaintext)

    def test_c3(self):
        """test many random messages and passwords encrypt/decrypt correctly"""

        for _ in range(TEST_COUNT):
            message = Random.get_random_bytes(random.randint(1, 5000))
            password = ''.join(np.random.choice(ALPHABET, random.randint(2, 24)))
            en_sig = SignedEncryption(message, password)
            de_sig = SignedDecryption(signed_message=en_sig.signed_message(), password=password)
            self.assertEqual(message, de_sig.dec.plaintext)

    def test_c4(self):
        """test many random messages and passwords with bad passwords"""

        for _ in range(TEST_COUNT):
            message = Random.get_random_bytes(random.randint(1, 5000))
            password1 = ''.join(np.random.choice(ALPHABET, random.randint(2, 24)))
            password2 = ''.join(np.random.choice(ALPHABET, random.randint(2, 24)))
            en_sig = SignedEncryption(message, password1)
            de_sig = SignedDecryption(signed_message=en_sig.signed_message(), password=password2)
            self.assertNotEqual(message, de_sig.dec.plaintext)

    def test_c5(self):
        """test many random messages and passwords with bad sent messages"""

        attempt = []
        for _ in range(TEST_COUNT):
            message = Random.get_random_bytes(random.randint(1, 5000))
            password = ''.join(np.random.choice(ALPHABET, random.randint(2, 24)))
            en_sig = SignedEncryption(message, password)
            ciphertext = en_sig.signed_message()

            # disturb message
            rand_indx = random.randint(1, len(ciphertext)-1)
            bad_ciphertext = ciphertext[:(rand_indx-1)] + ''.join(np.random.choice(BASE64_ALPHABET, 1)) + ciphertext[rand_indx:]
            while bad_ciphertext == ciphertext:
                rand_indx = random.randint(1, len(ciphertext)-1)
                bad_ciphertext = ciphertext[:(rand_indx-1)] + ''.join(np.random.choice(BASE64_ALPHABET, 1)) + ciphertext[rand_indx:]

            de_sig = SignedDecryption(signed_message=bad_ciphertext, password=password)
            attempt.append('invalidsignature' == de_sig.dec.plaintext)

        self.assertEqual(True, attempt.count(True)/float(len(attempt)) > 0.95 )
