### Lama iterative bytecode interpreter
Make sure `lamac` is installed on your system.

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
| Iterative bytecode interpreter     | 3.50 |

Run performance tests yourself:
```bash
export LAMA_RUNTIME=<path to Lama src>/runtime
make performance
```