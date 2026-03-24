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
| Recursive source-level interpreter | 5.81 |
| Recursive bytecode interpreter     | 2.18 |
| Graal Truffle interpreter (JVM build)     | 2.50 |

Results for Sort.lama test (5000 elements):
| Interpreter | Time |
| ------------------ | ------- |
| Recursive source-level interpreter | 169.45 |
| Recursive bytecode interpreter     | 53.45 |
| Graal Truffle interpreter (JVM build)     | 15.37 |

Run performance tests yourself:
```bash
LAMA_RUNTIME=<path to Lama runtime> make performance
```