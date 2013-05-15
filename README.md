This is the RSA lab of group 2 for the cryptology course.

```
usage: rsa.py [options] [-g|-e|-d|-c|-t] [args]

generation of keys and encryption/decryption using the RSA algorithm.

optional arguments:
  -h, --help            show this help message and exit
  -g PRIV PUB           generate keys and store them in the files PRIV and
                        PUB.
  -e PLAIN PUB CIPHER   encrypt the file PLAIN using the key PUB and save to
                        CIPHER.
  -d CIPHER PRIV PLAIN  decrypt the file CIPHER using the key PRIV and save to
                        PLAIN.
  -c CIPHER PUB PLAIN   crack the ciphertext in the file CIPHER using public
                        key PUB and save to PLAIN.
  -t STATS              run tests and collect statistics in the file STATS.
  -l L                  the chunksize in number of characters (only used while
                        generating keys or running tests)

examples:

  generate keys:
  rsa.py -g priv.key pub.key

  encrypt the file plain.txt:
  rsa.py -e plain.txt pub.key cipher.txt

  decrypt the file cipher.txt:
  rsa.py -d cipher.txt priv.key plain.txt

  collect statistics:
  rsa.py -t stats.txt

  break the file cipher.txt with L=3:
  rsa.py -l 3 -c cipher.txt pub.key plain.txt
```
