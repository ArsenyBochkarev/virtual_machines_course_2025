### Lama interpreter using Graal Truffle (JVM build)
Make sure `lamac` is installed on your system and you have compiled Lama runtime.

Unsupported features:
- First-class functions
- Custom infix operators
- Eta-expansion

#### Build
```bash
mvn package
```

#### Regression tests
All regression tests not related to unsupported features are passed (see `language/test/regression`).

Run regression tests yourself:
```bash
make regression
```

#### Performance tests
Results for Sort.lama test (1000 elements):
| Interpreter | Time |
| ------------------ | ------- |
| Recursive source-level interpreter | 5.89 |
| Recursive bytecode interpreter     | 2.18 |
| Graal Truffle interpreter (JVM build)     | 2.58 |

Results for Sort.lama test (5000 elements):
| Interpreter | Time |
| ------------------ | ------- |
| Recursive source-level interpreter | 172.24 |
| Recursive bytecode interpreter     | 53.01 |
| Graal Truffle interpreter (JVM build)     | 7.82 |

Run performance tests yourself:
```bash
LAMA_RUNTIME=<path to Lama runtime> make performance
```