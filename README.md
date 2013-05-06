This is the RSA lab of group 2 for the cryptology course.

```
usage: rsa.py 

Generation of keys and encryption/decryption using the RSA algorithm.

optional arguments:
  -h, --help            show this help message and exit
  -g PRIV PUB           Generate keys and store them in the files PRIV and
                        PUB.
  -e PLAIN PUB CIPHER   Encrypt the file PLAIN using the key PRIV and save to
                        CIPHER.
  -d CIPHER PRIV CIPHER
                        Decrypt the file CIPHER using the key PUB and save to
                        PLAIN.
  -l L                  The chunksize in number of characters (only used for
                        encryption/decryption)
  -t STATS              Run tests and collect statistics in the file STATS.

examples:

  generate keys:
  rsa.py -g priv.key pub.key

  encrypt the file plain.txt:
  rsa.py -e plain.txt pub.key cipher.txt

  decrypt the file cipher.txt:
  rsa.py -d cipher.txt priv.key plain.txt
```
