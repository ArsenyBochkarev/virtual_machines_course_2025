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
| Standard Allocator    | 7903575     | 5121241088          | 50.012%  |
| Global mutexed pool   | 28349006    | 2560950272          | 0.037%   |
| Global lock-free pool | 32227049    | 2561019904          | 0.040%   |
| Thread-local pools    | 210104      | 1639555072          | -56.140% |
