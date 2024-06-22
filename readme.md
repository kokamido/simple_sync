# Overview
A simple tool to encrypt (asymmetrically) directory via gpg and push it to git repo or pull from. By default the script works with the directory named "Root"

Depends on gpg and [gpgdir](https://github.com/mrash/gpgdir)@8a6f9a1bc8766f504041a0f6253220ce6c9c336a. You have to configre git before using the script.

```shell
bash packer.sh push "commit message"

bash pacher.sh pull
```