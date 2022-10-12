# Description


A pure Python 3 implementation of the ECDSA digital signature scheme.

Uses the Bitcoin curve (secp256k1) by default.




# Sample commands


```bash

python3 cli.py

python3 cli.py --help

python3 cli.py --task hello

python3 cli.py --task hello --log-level=info

python3 cli.py --task hello --log-level=debug

python3 cli.py --task get_python_version

python3 cli.py --task get_public_key --private-key-hex "1234 aabb"

python3 cli.py --task get_public_key --private-key-hex-file ecdsa/data/private_key_hex1.txt

python3 cli.py --task sign_data --private-key-hex "1234 aabb" --data="hello world"

python3 cli.py --task sign_data --private-key-hex "1234 aabb" --data=ecdsa/data/data1.txt

```


Tests:

```bash

# Run all tests, including submodule tests.
pytest

# Run all tests in a specific test file
pytest ecdsa/test/test_hello.py

# Run tests with relatively little output
pytest --quiet ecdsa/test/test_hello.py

# Run a single test
pytest ecdsa/test/test_hello.py::test_hello

# Print log output in real-time during a single test
pytest --capture=no --log-cli-level=INFO ecdsa/test/test_hello.py::test_hello

# Note: The --capture=no option will also cause print statements within the test code to produce output.

```



Code style:


```bash

pycodestyle ecdsa/code/hello.py

pycodestyle --filename=*.py

pycodestyle --filename=*.py --statistics

pycodestyle --filename=*.py --exclude ecdsa/submodules

```

Settings for pycodestyle are stored in the file `tox.ini`.




# Environment


Successfully run under the following environments:

1:  
- Ubuntu 16.04 on WSL (Windows Subsystem for Linux) on Windows 10  
- Python 3.6.15
- pytest 6.1.2  

Recommendation: Use `pyenv` to install these specific versions of `python` and `pytest`.




# Installation


Install & configure `pyenv`.  

https://github.com/pyenv/pyenv-installer

https://github.com/pyenv/pyenv

Result: When you change into the `ecdsa_python3` directory, the versions of `python` and `pip` change appropriately.


```
git clone --recurse-submodules git@github.com/sj-piano/ecdsa_python3.git

cd ecdsa_python3

pyenv install 3.6.15

pyenv local 3.6.15

pip install -r requirements.txt
```




# Background


Original code:  
https://github.com/tlsfuzzer/python-ecdsa

Authors: Peter Pearson, Brian Warner, Hubert Kario

Re-formatted into its current package layout by StJohn Piano.


