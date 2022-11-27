# Generic Side-Channel Assisted Chosen-Ciphertext Attacks on NTRU-based KEMs:

This project contains protected implementations of Kyber and Dilithium against several known side-channel and fault injection attacks. The details of the attacks as well as countermeasures considered are present in the manuscript. The project also contains a python based setup for simulating several attacks against the Message_Poly_Sanity_Check countermeasure on parameters of Kyber KEM.

## Prerequisites

Some of the test programs require [OpenSSL](https://openssl.org). If the OpenSSL header files and/or shared libraries do not lie in one of the standard locations on your system, it is necessary to specify their location via compiler and linker flags in the environment variables `CFLAGS`, `NISTFLAGS`, and `LDFLAGS`.

For example, on macOS you can install OpenSSL via [Homebrew](https://brew.sh) by running
```sh
brew install openssl
```
Then, run
```sh
export CFLAGS="-I/usr/local/opt/openssl@1.1/include"
export NISTFLAGS="-I/usr/local/opt/openssl@1.1/include"
export LDFLAGS="-L/usr/local/opt/openssl@1.1/lib"
```
before compilation to add the OpenSSL header and library locations to the respective search paths.

## Execute Protected Kyber

* The protected implementation of Kyber is present in the `kyber/ref` folder. The wrapper script to test the implementation is `ref/test_kyber.c`. The different countermeasures can be enabled/disabled using compile time options defined in the `sca_fia_protection.h`. The variant of Kyber to be executed can be chosen using compile time options defined in `params.h`. Inside the `ref` folder,

* To compile `kyber512`, run the following command:
```
make test_kyber512
```
* To execute `kyber512`, run the following command:
```
./test_kyber512
```

The same can be done for other variants of Kyber as well (i.e.) `kyber768` and `kyber1024`. For more instructions on how to run the implementation, please refer to this github page of [Kyber](https://github.com/pq-crystals/kyber)

## Execute Protected Dilithium

* The protected implementation of Dilithium is present in the `dilithium/ref` folder. The wrapper script to test the implementation is `ref/test/test_dilithium.c`. The different countermeasures can be enabled/disabled using compile time options defined in the `sca_fia_protection.h`. The variant of Dilithium to be executed can be chosen using compile time options defined in `params.h`. Inside the `ref` folder,

* To compile `dilithium2`, run the following command:
```
make test/test_dilithium2
```
* To execute `dilithium2`, run the following command:
```
./test/test_dilithium2
```

The same can be done for other variants of Dilithium as well (i.e.) `dilithium3` and `dilithium5`. For more instructions on how to run the implementation, please refer to this github page of [Dilithium](https://github.com/pq-crystals/dilithium)

## Test Security of Message_Poly_Sanity_Check countermeasure:

The project also contains a python based setup for simulating several attacks against the Message_Poly_Sanity_Check countermeasure on the different parameters of Kyber KEM. This is present in `test_message_poly_sanity_check` folder.
There is a test benchwork that tests the following attacks to verify if they indeed trigger the countermeasure:
- (Kyber768) Pushing the Limits of Generic Side-Channel Attacks on LWE-based KEMs - Parallel PC Oracle Attacks on Kyber KEM and Beyond https://eprint.iacr.org/2022/931.pdf
- (Kyber512) Generic Side-channel attacks on CCA-securelattice-based PKE and KEMs https://tches.iacr.org/index.php/TCHES/article/view/8592/8159
- https://eprint.iacr.org/2020/1559.pdf

These attacks will with high probability trigger the countermeasure. To run the benchwork: simply execute
```
python3 main.py
```

## License
All code in this repository is released under the conditions of [CC0](http://creativecommons.org/publicdomain/zero/1.0/).
