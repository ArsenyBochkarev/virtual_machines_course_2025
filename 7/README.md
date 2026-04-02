### Different pools allocations experiments

#### Build
```bash
make test
```

#### Running test
Please note that the test should be run one at a time
```bash
./test.out
```

#### Results

| Allocator             | Time (usec) | Memory used (bytes) | Overhead |
| --------------------- | ----------- | ------------------- | -------- |
| Standard Allocator    | 8298970     | 5120040960          | 50.000%  |
| Global mutexed pool   | 27807480    | 2559938560          | -0.002%  |
| Global lock-free pool | 33529781    | 2560036864          | 0.001%   |
| Thread-local pools    | 171139      | 1654345728          | -54.744% |
