# Disclaimer

Author is NOT an cyber security professional. I tried to do my best and I use this tool for my own data but I provide no guarantees of safety or consistency. At the moment, this tool have been used and tested only in Ubuntu 22.04.

# Description

Simple tool useful for deterministic encryption of folders and files. It utilizes AES-SIV encryption. It handles file contents, file names and folder names. It preserve the files and folders structure after decryption. Because of deterministic encryption it is possible to store encrypted data in git. Encrypted file dons't change if it's plaintext verion not changed. Thus, this will not result in generation of a large volume of VCS metadata.

# Dependencies

* [python3](https://www.python.org/downloads/) and it's standard library
* [pycryptodome](https://github.com/Legrandin/pycryptodome/tree/master) for aes-siv implementation
* [loguru](https://github.com/Delgan/loguru) because I hate writing standard boilerplate for logging in Python

# Initial set up

You have to generate key for AES encryption. Like this:

```shell
openssl rand -out aes_key 64
```

According to [documentation of SIV-mode](https://www.pycryptodome.org/src/cipher/modern#siv-mode) the cryptographic key must be twice the size of the key required by the underlying cipher (e.g. 32 bytes for AES-128), so I advise you to generate an encryption key of 64 bytes in size. File name "aes_key" is hardcoded in python script and .gitignore file to prevent possible key leakage.

Setup of python enviroment is standart:

```shell 
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

# How to use

1. python encrypt.py your_folder_to_encrypt
2. store folder named "0" and file named "meta" somewhere
3. python decrypt.py (it requires folder "0", file "meta" and your key in the file "aes_key")

You can find test data in this repo; "test_folder" is unencrypted directory, "0" and "meta" is the same data, but encrypted. 

```shell
> find test_folder -type f -exec md5sum {} \;
    d41d8cd98f00b204e9800998ecf8427e  test_folder/123123/q2eq2eq2e]
    4f4366e4ce515ed9772332ec49950b5b  test_folder/123123/12/esf
    c58c1d4a26aef2073b2fb189d76f9573  test_folder/qwe/wwww
    3bad6af0fa4b8b330d162e19938ee981  test_folder/qwe/qwe/qweqwe
    d583667ba83397298563a0cff25af133  test_folder/qwe/qweqwe

> python encrypt.py --folder test_folder
    Namespace(folder='test_folder', decrypt=False, log_level='INFO')
    2024-06-24 12:41:19.515 | INFO     | __main__:<module>:257 - LOGS ARE VERY UNSAFE, PLEASE, SECURE YOUR LOGS WELL
    2024-06-24 12:41:19.515 | INFO     | __main__:encrypt:167 - Encrypting test_folder
    2024-06-24 12:41:19.516 | INFO     | __main__:encrypt:167 - Encrypting test_folder/123123
    2024-06-24 12:41:19.517 | INFO     | __main__:encrypt:167 - Encrypting test_folder/123123/12
    2024-06-24 12:41:19.518 | INFO     | __main__:encrypt:167 - Encrypting test_folder/qwe
    2024-06-24 12:41:19.520 | INFO     | __main__:encrypt:167 - Encrypting test_folder/qwe/qwe
    2024-06-24 12:41:19.521 | INFO     | __main__:write_meta:21 - Writing meta started
    2024-06-24 12:41:19.522 | INFO     | __main__:write_meta:34 - Writing meta finished

> find 0 -type f -exec md5sum {} \;
    a14c75a31b4d0a481ba5be2818291ef3  0/2/7
    3246bca4a5f05ee4b40a4e0234d6ab16  0/2/2/7
    4eb2fe494e5023c499fdc4bb3ab06157  0/2/6
    05be6b6159b2a9f6b68e803b5f2aa505  0/1/3/5
    d41d8cd98f00b204e9800998ecf8427e  0/1/4

> rm -rf test_folder && python encrypt.py --decrypt && find test_folder -type f -exec md5sum {} \;
    Namespace(folder=None, decrypt=True, log_level='INFO')
    2024-06-24 12:42:59.037 | INFO     | __main__:<module>:257 - LOGS ARE VERY UNSAFE, PLEASE, SECURE YOUR LOGS WELL
    d41d8cd98f00b204e9800998ecf8427e  test_folder/123123/q2eq2eq2e]
    4f4366e4ce515ed9772332ec49950b5b  test_folder/123123/12/esf
    c58c1d4a26aef2073b2fb189d76f9573  test_folder/qwe/wwww
    3bad6af0fa4b8b330d162e19938ee981  test_folder/qwe/qwe/qweqwe
    d583667ba83397298563a0cff25af133  test_folder/qwe/qweqwe
```
For the sake of simplicity of my scenario I wrote a script that encrypts my data and puts it to git. Remember, thath meaningful commit message may cause some kind of insecurity.

```shell

./packer.sh push "directory to encrypt and push" "maybe commit message"

./packer pull

```