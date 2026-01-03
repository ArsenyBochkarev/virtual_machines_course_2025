### Lama verifying iterative bytecode interpreter
Make sure `lamac` is installed on your system. The interpreter requires the runtime built with `-m32` flag.

#### Initialize the git submodule
```bash
git submodule update --init --recursive
```

Proper runtime will be built later.

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
| Recursive source-level interpreter               | 6.17 |
| Recursive bytecode interpreter                   | 2.22 |
| Iterative bytecode interpreter (no verifier)     | 7.92 |
| Iterative bytecode interpreter (with verifier)   | 6.59 |

Run performance tests yourself:
```bash
make performance
```