### Lama iterative bytecode interpreter
Make sure `lamac` is installed on your system. Also make sure your runtime was built with `-m32` flag. Please also do `export LAMA_RUNTIME=<path to runtime src>` to the directory of your 32-bit build of runtime.

##### How to build 32-bit runtime
- Clone Lama src
- make -C runtime
- add `-m32` flag to `gc.o` and `runtime.o` targets in `Lama/runtime/Makefile`

#### Build
```bash
make lamai
```

#### Regression tests
All regression tests are passed (see `test/regression`).

Run regression tests yourself:
```bash
make regression
```

#### Performance tests
Results for Sort.lama test:
| Interpreter | Time |
| ------------------ | ------- |
| Recursive source-level interpreter | 6.33 |
| Recursive bytecode interpreter     | 2.45 |
| Iterative bytecode interpreter     | 4.17 |

Run performance tests yourself:
```bash
export LAMA_RUNTIME=<path to Lama src>/runtime
make performance
```