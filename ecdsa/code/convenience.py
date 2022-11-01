# Imports
import logging
import os
import string
import binascii
import re




# Relative imports
from .. import util
from .. import submodules
from . import ecdsa
from . import curves
from . import keys




# Shortcuts
from binascii import hexlify, unhexlify
v = util.validate
SECP256k1 = curves.SECP256k1
SigningKey = keys.SigningKey
VerifyingKey = keys.VerifyingKey
SHA256 = submodules.sha256_python3.SHA256




# Notes:
# - I don't completely understand the ECDSA library.
# - This file contains the interface between my understanding and the library.




# Set up logger for this module. By default, it produces no output.
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())
logger.setLevel(logging.ERROR)
log = logger.info
deb = logger.debug




def setup(
    log_level = 'error',
    debug = False,
    log_timestamp = False,
    log_file = None,
    ):
  # Configure logger for this module.
  util.module_logger.configure_module_logger(
    logger = logger,
    logger_name = __name__,
    log_level = log_level,
    debug = debug,
    log_timestamp = log_timestamp,
    log_file = log_file,
  )
  deb('Setup complete.')




def verify_signature_low_s(public_key_hex, data_hex, signature_hex):
  if signature_s_is_high(signature_hex):
    raise ValueError('Signature contains a high S value.')
  signature_is_valid = verify_signature(public_key_hex, data_hex, signature_hex)
  return signature_is_valid



def verify_signature(public_key_hex, data_hex, signature_hex, hash_function=SHA256):
  v.validate_hex(public_key_hex)
  v.validate_hex(signature_hex)
  v.validate_hex(data_hex)
  public_key_bytes = unhexlify(public_key_hex)
  signature_bytes = unhexlify(signature_hex)
  data_bytes = unhexlify(data_hex)
  verifying_key = VerifyingKey.from_string(public_key_bytes, curve=SECP256k1, hashfunc=SHA256)
  signature_is_valid = verifying_key.verify(signature_bytes, data_bytes, hashfunc=SHA256)
  return signature_is_valid


def verify_signature_digest_low_s(public_key_hex, digest_hex, signature_hex):
  if signature_s_is_high(signature_hex):
    raise ValueError('Signature contains a high S value.')
  signature_is_valid = verify_signature_digest(public_key_hex, digest_hex, signature_hex)
  return signature_is_valid


def verify_signature_digest(public_key_hex, digest_hex, signature_hex):
  v.validate_hex(public_key_hex)
  v.validate_hex(signature_hex)
  v.validate_hex(digest_hex)
  public_key_bytes = unhexlify(public_key_hex)
  signature_bytes = unhexlify(signature_hex)
  digest_bytes = unhexlify(digest_hex)
  verifying_key = VerifyingKey.from_string(public_key_bytes, curve=SECP256k1, hashfunc=SHA256)
  signature_is_valid = verifying_key.verify_digest(signature_bytes, digest_bytes)
  return signature_is_valid


def create_deterministic_signature_low_s(private_key_hex, data_hex):
  signature_hex = create_deterministic_signature(private_key_hex, data_hex)
  if signature_s_is_high(signature_hex):
    signature_hex = ensure_low_s_value(signature_hex)
  return signature_hex


def create_deterministic_signature(private_key_hex, data_hex, hash_function=SHA256):
  # Validate input.
  private_key_hex = format_private_key_hex(private_key_hex)
  validate_private_key_hex(private_key_hex)
  v.validate_hex(data_hex)
  if hash_function != SHA256:
    # Only tested with SHA256 so far.
    raise ValueError
  # Derive signing key object from private key hex.
  private_key_int = int(private_key_hex, 16)
  signing_key = keys.SigningKey.from_secret_exponent(private_key_int, curve=SECP256k1)
  # Make the signature.
  data_bytes = unhexlify(data_hex)
  signature = signing_key.sign_deterministic(data_bytes, hashfunc=SHA256)
  signature_hex = hexlify(signature).decode('ascii')
  return signature_hex


def create_deterministic_signature_for_digest_low_s(private_key_hex, digest_hex):
  signature_hex = create_deterministic_signature_for_digest(private_key_hex, digest_hex)
  if signature_s_is_high(signature_hex):
    signature_hex = ensure_low_s_value(signature_hex)
  return signature_hex


def create_deterministic_signature_for_digest(private_key_hex, digest_hex):
  # This function signs data that has already been hashed externally.
  # We confirm that it's short enough to be signed using the selected curve.
  # Validate input.
  private_key_hex = format_private_key_hex(private_key_hex)
  validate_private_key_hex(private_key_hex)
  v.validate_hex(digest_hex)
  # Future: Is there any problem if the hash digest is shorter than the curve ?
  v.validate_hex_length(digest_hex, 32)  # hardcode for now.
  # Derive signing key object from private key hex.
  private_key_int = int(private_key_hex, 16)
  signing_key = keys.SigningKey.from_secret_exponent(private_key_int, curve=SECP256k1)
  # Confirm that the hash digest byte length is not greater than curve.baselen, where the curve is secp256k1.
  max_length = signing_key.curve.baselen
  if hex_len(digest_hex) > max_length:
    msg = "This curve ({}) has an order of length {}, which is not long enough to sign a digest of length {}."
    msg = msg.format("SECP256k1", max_length, hex_len(digest_hex))
    raise ValueError(msg)
  # Make the signature.
  digest_bytes = bytes.fromhex(digest_hex)
  signature_bytes = signing_key.sign_digest_deterministic(digest_bytes)
  signature_hex = signature_bytes.hex()
  validate_signature_hex(signature_hex)
  return signature_hex


def validate_signature_hex(signature_hex):
  # The domain for both r and s is the same as the domain for bitcoin private keys.
  r_hex, s_hex = signature_hex_to_r_and_s_hex(signature_hex)
  validate_private_key_hex(r_hex)
  validate_private_key_hex(s_hex)


def signature_s_is_high(signature_hex):
  r_hex, s_hex = signature_hex_to_r_and_s_hex(signature_hex)
  n_hex = get_secp256k1_n_hex()
  s_int = int(s_hex, 16)
  n_int = get_secp256k1_n_int()
  limit_int = int(n_int // 2)
  limit_hex = hex(limit_int)
  s_is_high = s_int > limit_int
  return s_is_high


def ensure_low_s_value(signature_hex):
  # An ECDSA signature including a low-S value is mathematically equivalent to the same signature that includes the corresponding high-S value.
  # Currently the Bitcoin network has converged on using low-S values in transaction signatures.
  # n is the order of the base point G of the elliptic curve secp256k1. n is 32 bytes (256 bits) long. The domain of a Bitcoin private key is [1, n-1].
  # low-S domain: [1, floor(n/2)].
  # high-S domain: [floor(n/2)+1, n-1].
  r_hex, s_hex = signature_hex_to_r_and_s_hex(signature_hex)
  n_hex = get_secp256k1_n_hex()
  r_int = int(r_hex, 16)
  s_int = int(s_hex, 16)
  n_int = get_secp256k1_n_int()
  limit_int = int(n_int // 2)  # Note the use of a Python3 floor division operator.
  if (1 <= s_int <= limit_int):
    # S-value is in the low-S domain.
    return signature_hex
  elif (limit_int < s_int < n_int):
    # S-value is in the high-S domain.
    # We convert the high-S value to a low-S value by using the following equation:
    # S_new = n - S
    s_new_int = n_int - s_int
    s_new_hex = hex(s_new_int)[2:]  # Convert to hex and remove '0x' prefix.
    s_new_hex = s_new_hex.rjust(64, '0')  # Add leading zeroes to reach 32 hex bytes.
    signature_hex_2 = r_hex + s_new_hex
    return signature_hex_2
  else:
    msg = 'S-value outside of expected domain. S-value: {}'.format(s_hex)
    raise ValueError(msg)


def signature_hex_to_r_and_s_hex(signature_hex):
  # The signature hex consists of R & S, concatenated. The signature is 64 bytes and R & S are each 32 bytes.
  # Each byte is 2 hex characters.
  r_hex = signature_hex[:64]
  s_hex = signature_hex[64:]
  return r_hex, s_hex


def private_key_hex_to_public_key_hex(private_key_hex):
  # Example private_key_hex:
  # '1234aabb'
  if private_key_hex == '':
    msg = "For private_key_hex, received empty string."
    raise ValueError(msg)
  private_key_hex = format_private_key_hex(private_key_hex)
  validate_private_key_hex(private_key_hex)
  private_key_int = int(private_key_hex, 16)
  signing_key = keys.SigningKey.from_secret_exponent(private_key_int, curve=SECP256k1)
  signing_key_bytes = signing_key.to_string()
  signing_key_hex = hexlify(signing_key_bytes)
  #print(signing_key_hex)
  # Example signing_key_hex:
  # b'000000000000000000000000000000000000000000000000000000001234aabb'
  # Note: Same as private_key_hex but left-padded with zeros to reach 64 characters (32 bytes).
  verifying_key = signing_key.verifying_key
  verifying_key_bytes = verifying_key.to_string()
  verifying_key_hex = hexlify(verifying_key_bytes).decode('ascii')
  # Example verifying_key_hex (128 characters, 64 bytes):
  # 49951cc5477fc8815a3050025b5bceaaa156941620f92eff76891a46d5d996fd521aefae6117baa5f6f0826bf8046e565c27653acc7bd892bd302cffd29c4401
  v.validate_hex_length(verifying_key_hex, 64)
  return verifying_key_hex


def validate_printable_ascii(data):
  # We want to be able to confirm that some data-to-be-signed consists only of printable ASCII characters.
  # http://edgecase.net/articles/printable_ascii
  data_characters = "!#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`abcdefghijklmnopqrstuvwxyz{|}~"
  escaped_characters = "\"" + "\\"
  whitespace_characters = " \t\n"
  permitted_data_characters = data_characters + escaped_characters + whitespace_characters
  if not isinstance(data, str):
    raise TypeError("Expected type 'str', but instead received '{}'.".format(type(data).__name__))
  line = 0
  index = 0
  for c in data:
    index += 1
    if c not in permitted_data_characters:
      msg = "Line {}, index {}: Character '{}' (ord={}) is not in the list of permitted data characters."
      msg = msg.format(line, index, c, ord(c))
      raise ValueError(msg)
    if c == '\n':
      line += 1
      index = 0


def validate_private_key_hex(private_key_hex):
  v.validate_hex_length(private_key_hex, 32)
  private_key_int = int(private_key_hex, 16)
  # Ensure that the private key integer is within the valid domain for Bitcoin private keys.
  n_int = get_secp256k1_n_int()
  if not (0 < private_key_int < n_int):
    msg = "A Bitcoin private key must be within the domain [1, n-1], where n is {}.".format(n_int)
    msg += " However, it is {}".format(private_key_int)
    comp = 'less' if private_key_int < 0 else 'greater'
    msg += ', which is {comp} than n.'.format(**vars())
    raise ValueError(msg)


def format_private_key_hex(private_key_hex):
  # Example private_key_hex values:
  # '1234aabb'
  # '1234 aa bb'
  # '1234 AABB'
  private_key_hex = remove_whitespace(private_key_hex).lower()
  if len(private_key_hex) < 64:
    private_key_hex = private_key_hex.zfill(64)
  return private_key_hex


def remove_whitespace(text):
  return re.sub(r"\s+", "", text)


def get_secp256k1_n_int():
  # n_int value:
  # 115792089237316195423570985008687907852837564279074904382605163141518161494337
  n_hex = get_secp256k1_n_hex()
  n_int = int(n_hex, 16)
  return n_int


def get_secp256k1_n_hex():
  # n is the order of the base point G of the elliptic curve secp256k1. In hex, n = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141. n is 32 bytes (256 bits) long. The domain of a Bitcoin private key is [1, n-1].
  n_hex = "FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141"
  n_hex = n_hex.lower()
  n_hex = n_hex.replace(' ','')
  return n_hex


def hex_len(x):
  # Divide hex length by 2 to get hex length in bytes.
  v.validate_hex(x)
  n = len(x) // 2
  return n

