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
| Standard Allocator    | 7541898     | 5121003520          | 50.010%  |
| Global mutexed pool   | 29748883    | 2560958464          | 0.037%   |
| Global lock-free pool | 34478249    | 2560937984          | 0.037%   |
| Thread-local pools    | 241087      | 1667895296          | -53.487% |
