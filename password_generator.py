#!/usr/bin/env python

import sys
import hmac
import hashlib
import base64
import string


key = 'a secret string' # customize this key string
digestmod = 'sha1' # support: 'md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512'


def generate_password(key, msg, digestmod):
    hmac_obj = hmac.new(key, msg, lambda: hashlib.new(digestmod))
    return base64.b64encode(hmac_obj.digest())


def translate_password(password):
    translation_table = string.maketrans('=+/', 'XYZ')
    return password.translate(translation_table)[::-1]


def truncate_password(password, length):
    if len(password) < length:
        password += password
        if len(password) < length:
            raise Exception('%s is too long for current settings' % length)

    start = (len(password) - length) / 2
    return password[start:start+length]


def main(argv):
    if len(argv) != 1:
        print >> sys.stderr, 'Usage: $ python password_generator.py google'
        sys.exit(2)

    msg = argv[0]

    original_password = generate_password(key, msg, digestmod)
    translated_password = translate_password(original_password)

    for length in (8, 12, 16, 32):
        password = truncate_password(translated_password, length)
        print '%2d bytes: %s' % (length, password)


if __name__ == '__main__':
    main(sys.argv[1:])
