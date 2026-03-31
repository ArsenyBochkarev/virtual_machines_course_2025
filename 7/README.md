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
| Standard Allocator    | 8189450     | 5121122304          | 50.011%  |
| Global mutexed pool   | 26867819    | 2561138688          | 0.044%   |
| Global lock-free pool | 33366245    | 2561093632          | 0.043%   |
| Thread-local pools    | 226108      | 1483501568          | -72.565% |
