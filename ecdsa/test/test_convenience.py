# Imports
import pytest
import pkgutil
import binascii




# Relative imports
from .. import code
from .. import util
from .. import submodules




# Shortcuts
from ..code import convenience
from binascii import hexlify, unhexlify




# Setup for this file.
@pytest.fixture(autouse=True, scope='module')
def setup_module(pytestconfig):
  # If log_level is supplied to pytest in the commandline args, then use it to set up the logging in the application code.
  log_level = pytestconfig.getoption('log_cli_level')
  if log_level is not None:
  log_level = log_level.lower()
  code.setup(log_level = log_level)
  submodules.setup(log_level = log_level)




# ### SECTION
# Basic checks.


def test_hello():
  private_key_ascii = 'hello world'
  private_key_bytes = private_key_ascii.encode('ascii')
  private_key_hex = hexlify(private_key_bytes).decode('ascii')
  x = convenience.private_key_hex_to_public_key_hex(private_key_hex)
  assert x == '405584433209ceb6c96353d8663f6f44dafbfed807d5eef9840ce3ccac73748cea25d68a7da711a1e29e63a796caff8e9b65e26902d2d0defc79688679a4b691'


def test_hello_data():
  data_file = '../data/data1.txt'
  data = pkgutil.get_data(__name__, data_file).decode('ascii').strip()
  assert data == 'hello world'
  private_key_bytes = data.encode('ascii')
  private_key_hex = hexlify(private_key_bytes).decode('ascii')
  x = convenience.private_key_hex_to_public_key_hex(private_key_hex)
  assert x == '405584433209ceb6c96353d8663f6f44dafbfed807d5eef9840ce3ccac73748cea25d68a7da711a1e29e63a796caff8e9b65e26902d2d0defc79688679a4b691'


def test_empty_string():
  with pytest.raises(ValueError):
  x = convenience.private_key_hex_to_public_key_hex('')


def test_0():
  with pytest.raises(ValueError):
  x = convenience.private_key_hex_to_public_key_hex('0')


def test_1():
  x = convenience.private_key_hex_to_public_key_hex('1')
  assert x == '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'


def test_max_32_byte_value():
  max_value = 'ff' * 32
  with pytest.raises(ValueError):
  x = convenience.private_key_hex_to_public_key_hex(max_value)


def test_secp256k1_order_n():
  n = 'FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141'
  n = n.replace(' ', '').lower()
  # fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
  with pytest.raises(ValueError):
  x = convenience.private_key_hex_to_public_key_hex(n)


def test_max_permitted_private_key():
  # The domain of a Bitcoin private key is [1, n-1].
  n = 'FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364140'
  n = n.replace(' ', '').lower()
  x = convenience.private_key_hex_to_public_key_hex(n)
  assert x == '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798b7c52588d95c3b9aa25b0403f1eef75702e84bb7597aabe663b82f6f04ef2777'


def test_a():
  x = convenience.private_key_hex_to_public_key_hex('a')
  assert x == 'a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7893aba425419bc27a3b6c7e693a24c696f794c2ed877a1593cbee53b037368d7'


def test_abc():
  x = convenience.private_key_hex_to_public_key_hex('abc')
  assert x == '3ef30130654689a64c864d6dd38760481c55fc525e2c6c7084e2d2d3d4d51be9f7d86b288c09ddb5311f292285168000e43e4b62201bd8de23a391daa8e00ce8'


def test_alphabet():
  private_key_ascii = 'abcdefghijklmnopqrstuvwxyz'
  private_key_hex = private_key_ascii.encode('ascii').hex()
  x = convenience.private_key_hex_to_public_key_hex(private_key_hex)
  assert x == '59fdff66227b982e81700782283e6f461447b2fb091699e0284f0c419199ddcde495be6dcfb37ef199c7c0e1ae618b5e5ba14f67c43f3591a6ec4f92dcd9c024'


def test_alphanumeric():
  private_key_ascii = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
  private_key_hex = private_key_ascii.encode('ascii').hex()
  with pytest.raises(ValueError) as exc_info:
  x = convenience.private_key_hex_to_public_key_hex(private_key_hex)
  assert str(exc_info.value) == 'A Bitcoin private key must be within the domain [1, n-1], where n is 115792089237316195423570985008687907852837564279074904382605163141518161494337. However, it is 52152751553716308763301261451955289837699979387937179883194000124698180158127126510677472592299463162814556178025286293724858735984083006576569825337, which is greater than n.'


def test_lorem_ipsum():
  private_key_ascii = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit.'
  private_key_hex = private_key_ascii.encode('ascii').hex()
  with pytest.raises(ValueError) as exc_info:
  x = convenience.private_key_hex_to_public_key_hex(private_key_hex)


def test_64_bytes():
  private_key_ascii = 'A string with a length of exactly 64 bytes. [filler text ......]'
  private_key_bytes = private_key_ascii.encode('ascii')
  assert len(private_key_bytes) == 64
  private_key_hex = hexlify(private_key_bytes).decode('ascii')
  with pytest.raises(ValueError):
  x = convenience.private_key_hex_to_public_key_hex(private_key_hex)


def test_32_bytes():
  private_key_ascii = 'A 32-byte string [filler text__]'
  private_key_hex = private_key_ascii.encode('ascii').hex()
  x = convenience.private_key_hex_to_public_key_hex(private_key_hex)
  assert x == '27eda89c83374fecd3f2b76127985cbc2e0e08ebad145227c3d9078ec763d87fcf0bfcfbe063bf158d95208c9a062d38e1237c57bfa142c0f04a7c9f35a9ca3d'


def test_fox_1():
  private_key_ascii = 'The quick brown fox jumps over the lazy dog'
  private_key_hex = private_key_ascii.encode('ascii').hex()
  with pytest.raises(ValueError):
  x = convenience.private_key_hex_to_public_key_hex(private_key_hex)


def test_fox_2():
  private_key_ascii = 'The quick brown fox jumps over the lazy cog'
  private_key_hex = private_key_ascii.encode('ascii').hex()
  with pytest.raises(ValueError):
  x = convenience.private_key_hex_to_public_key_hex(private_key_hex)


def test_signature():
  private_key_hex = '1'
  data_ascii = 'hello_world'
  data_hex = data_ascii.encode('ascii').hex()
  signature_hex = convenience.create_deterministic_signature(private_key_hex, data_hex)
  public_key_hex = convenience.private_key_hex_to_public_key_hex(private_key_hex)
  signature_is_valid = convenience.verify_signature_low_s(public_key_hex, data_hex, signature_hex)
  assert signature_is_valid


def test_signature_high_s():
  private_key_hex = '1'
  data_ascii = 'hello_world_1'
  data_hex = data_ascii.encode('ascii').hex()
  signature_hex = convenience.create_deterministic_signature(private_key_hex, data_hex)
  assert convenience.signature_s_is_high(signature_hex)
  public_key_hex = convenience.private_key_hex_to_public_key_hex(private_key_hex)
  signature_is_valid = convenience.verify_signature(public_key_hex, data_hex, signature_hex)
  assert signature_is_valid
  with pytest.raises(ValueError):
  signature_is_valid_2 = convenience.verify_signature_low_s(public_key_hex, data_hex, signature_hex)







