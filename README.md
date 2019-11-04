# Pre-requisites

Scheme has been successfully built and tested on CentOS 6.6. It uses OpenSSL, GMP, and PBC library to implement the entailed cryptographic operations. The build commands in CentOS are as follows.

## OpenSSL

```sh
$ wget http://www.openssl.org/source/openssl-1.1.1.tar.gz
$ tar -xvf openssl-1.1.1.tar.gz
$ cd openssl-1.1.1/
$ ./configure
$ make
$ make install
```

### Installing GMP
```sh
$ yum install gmp gmp-devel
```

### Installing PBC
```sh
$ wget http://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz
$ tar -xvf pbc-0.5.14.tar.gz
$ cd pbc-0.5.14
$ ./configure
$ make
$ make install
```

## Getting the code
The code is available *via* git:

```sh
 $ git clone git@github.com:YinFFF/Multi-keyword-SSE.git
```

# Usage

This project includes two source files: AES.cpp and PMCQueryScheme.cpp: the former contains interface functions for AES, and the latter contains the implement of the proposed scheme and the test functions.

## Build and run

```sh
$ cd Multi-keyword-SSE/
$ ./make
$ ./PMCQueryScheme

```
