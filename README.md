# my_beid
Some experiments with the belgian electronic identity card / belgian e-id / beid

## [dump_beid.sh](https://github.com/xofc/my_beid/blob/main/dump_beid.sh)
This short shell script extracts all the readable electronic data from a Belpic v1.7 card.
It just uses *opensc-explorer(1)* from the [opensc](https://github.com/OpenSC/OpenSC) package with the right parameters (files ID) from the [FEDICT documentation](https://github.com/Fedict/eid-mw/tree/master/doc/sdk/documentation).

The picture is a standard JPEG file and the certificates are in DER format.
The certificates can be displayed with openssl(1SSL)
```
$ openssl x509 -in <cert>.der -inform DER -text
```
or converted in .PEM format with
```
$ openssl x509 -inform der -in <cert>.der -outform pem -out <cert>.pem
```

## [mybeid_sign.c](https://github.com/xofc/my_beid/blob/main/mybeid_sign.c)
This very short (<300 lines) program in 'C' just uses the *pcsclite* library and allows you to sign a <hash> with one of your two private using with one of the six allowed algorithm.  By default, it uses your non-repudiation keys with sha256.
In its simple invocation, it looks like :
```
$ cal 2023 |sha256sum
a10eb02d0bf0cde261d3292d059a186f2c5fa3e1c8819a73221e61af5b04712a  -
$   ./mybeid_sign -d a10eb02d0bf0cde261d3292d059a186f2c5fa3e1c8819a73221e61af5b04712a
$ ls -l a10*
-rw-rw-r-- 1 xxx xxx  32 Jun  4 11:58 a10eb02d0bf0cde261d3292d059a186f2c5fa3e1c8819a73221e61af5b04712a.bin
-rw-rw-r-- 1 xxx xxx 256 Jun  4 11:58 a10eb02d0bf0cde261d3292d059a186f2c5fa3e1c8819a73221e61af5b04712a.sig
```
You have to provide the PIN on the PC (it does not work (yet) with card readers with keyboard).  It generates 2 files : a binary of the <hash> (you need to verify with openssl) and a 256 bytes binary signature.
The signature can be verified with openssl(1SSL) :
```
$ openssl pkeyutl -verify -in <hash>.bin -inkey cert_3_sign-pubkey.pem -sigfile <hash>.sig -pubin -pkeyopt rsa_padding_mode:pss -pkeyopt digest:sha256
```
This is quick&dirty work.  The most dirty stuff lies in the file generation in the middle of the card interaction routines.  This is pure lazyness and the fact that the sloppy *pcsclite* library doesn't have a standard Linux 1980 look (using exotic arguments and, for example, using DWORD where 'int' should be used).  The Makefile is also in the simplest possible form.
  
See also this [blog entry](https://chipotons.blogspot.com/2023/01/beid.html).
