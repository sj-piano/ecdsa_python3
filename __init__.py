# Imports
import logging




# Relative imports
from . import ecdsa




# ### Notes
# Importing a package essentially imports the package's __init__.py file as a module.




# Collect up the things that we want in the immediate namespace of this module when it is imported.
# This file allows a parent package to run this:
# import ecdsa
# ecdsa.hello()
# public_key_hex = ecdsa.bitcoin_private_key_hex_to_public_key_hex(private_key_hex)
hello = ecdsa.code.hello.hello
validate = ecdsa.util.validate
configure_module_logger = ecdsa.util.module_logger.configure_module_logger
#submodules = ecdsa.submodules
format_private_key_hex = ecdsa.code.convenience.format_private_key_hex
validate_private_key_hex = ecdsa.code.convenience.validate_private_key_hex
private_key_hex_to_public_key_hex = ecdsa.code.convenience.private_key_hex_to_public_key_hex
create_deterministic_signature = ecdsa.code.convenience.create_deterministic_signature_low_s
verify_signature = ecdsa.code.convenience.verify_signature_low_s




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
  ecdsa.util.module_logger.configure_module_logger(
    logger = logger,
    logger_name = __name__,
    log_level = log_level,
    debug = debug,
    log_timestamp = log_timestamp,
    log_file = log_file,
  )
  deb('Setup complete.')
  # Configure modules further down in this package.
  ecdsa.setup(
    log_level = log_level,
    debug = debug,
    log_timestamp = log_timestamp,
    log_file = log_file,
  )

