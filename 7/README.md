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
| Standard Allocator    | 7923194     | 5121101824          | 50.011%  |
| Global mutexed pool   | 27990903    | 2561089536          | 0.043%   |
| Global lock-free pool | 30559170    | 2561097728          | 0.043%   |
| Thread-local pools    | 214924      | 1699991552          | -50.589% |
