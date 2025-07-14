## Large-Precision Plaintext Bootstrapping

### 1. Install and Configure the System Environment

(For details, see: https://github.com/FlorentCLMichel/palisade)
You will need a C++ compiler with OMP support, as well as `cmake`, `make`, and `autoconf`.
Recommended compiler versions:

- GCC 11.2.0
- G++ 11.2.0

### 2. Unpack the PALISADE archive to a local folder on your computer. Then, extract and overwrite with our code package.

Create a subdirectory in the main directory—typically named "build". In this case, execute the following commands:

```bash
cd H:\large-precision-plaintext-bootstrapping-master
mkdir build 
cd build 
cmake ..
make lptest -j4
bin/examples/binfhe/lptest

make allbinfheexamples -j4
```

### 3. To run the large-precision plaintext bootstrapping algorithm, enter the following command:

```bash
bin/examples/binfhe/lptest
```