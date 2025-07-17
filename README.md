## Large-Precision Plaintext Bootstrapping

### 1. Install and Configure the System Environment

(For details, see: https://github.com/FlorentCLMichel/palisade)
You will need a C++ compiler with OMP support, as well as `cmake`, `make`, and `autoconf`.
This implementation was developed and tested under the following environment:

- Windows 10
- g++ (Rev1, Built by MSYS2 project) 11.2.0
- cmake 3.21.3



### 2. Extract the code package and execute the following commands:

```bash
cd large-precision-plaintext-bootstrapping-master
mkdir build 
cd build 
cmake ..
make lptest -j4
```

### 3. To run the large-precision plaintext bootstrapping algorithm, enter the following command:

```bash
bin/examples/binfhe/lptest
```
