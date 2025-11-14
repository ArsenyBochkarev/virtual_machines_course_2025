#include <iostream>
#include <bits/stdc++.h>
#include <chrono>
#include <vector>
#include <numeric>
#include <random>
using namespace std::chrono;


// 1. Общий размер L1:
//   - Обходим массив с увеличением его размера. Когда время скакнёт -- значит, вышли за размер L1
//     - массив, значение элемента в котором является индексом следующего элемента -- чтобы запутать префетчер
// 2. Длина cache line
//   - Обходим массив, постепенно увеличивая stride
// 3. Ассоциативность:
//   - Массив цепочек индексов с шагом в размер L1. Постепенно увеличиваем число шагов по нему. Когда время начнёт скакать -- значит, вышли за степень ассоциативности

static size_t constexpr page_size = 4096;

static inline uint64_t now_ns() {
    return duration_cast<nanoseconds>(high_resolution_clock::now().time_since_epoch()).count();
}

struct Element {
    Element *next = nullptr;
    size_t data = 1;
};

double measure_stride_time(size_t N, size_t stride, size_t bench_tries = 5) {
    size_t elements = N / sizeof(size_t);
    if (elements < 16)
        elements = 16;
    std::vector<double> all_avg;

    for (size_t benches = 0; benches < bench_tries; benches++) {
        // Подготовка буфера для обхода
        Element* head = new Element();
        Element* current = head;
        alignas(page_size) Element** nodes = new Element*[elements];

        nodes[0] = head;
        for (size_t i = 1; i < elements; ++i) {
            current->next = new Element();
            current = current->next;
            nodes[i] = current;
        }
        current = head;
        for (size_t i = 0; i < elements; i += stride) {
            if (i + stride < elements)
                nodes[i]->next = nodes[i + stride]; 
            else
                nodes[i]->next = nullptr;
        }
        size_t counter = 1;
        Element* runner = head;

        // Прогрев
        while (runner != nullptr) {
            counter++;
            runner->data *= counter;
            runner = runner->next;
        }

        runner = head;
        counter = 1;
        uint64_t t0 = now_ns();
        while (runner != nullptr) {
            counter++;
            runner->data *= counter;
            runner = runner->next;
        }
        uint64_t t1 = now_ns();

        double avg_ns = double(t1 - t0); // Измеряем общее время
                                         // Укладывающиеся в одну L1 cache line будут иметь примерно одинаковое время
        all_avg.push_back(avg_ns);

        for (size_t i = 0; i < elements; ++i)
            delete nodes[i];
        delete[] nodes;
    }
    auto main_avg = std::accumulate(all_avg.begin(), all_avg.end(), 0.0) / double(bench_tries);

    return main_avg;
}

double measure_traverse_time(size_t N, size_t bench_tries = 1) {
    std::random_device rd;
    std::mt19937_64 rng(rd());

    double avg_sum = 0.0;
    const size_t trials = 64; 

    size_t num_elements = N / sizeof(Element);
    for (size_t benches = 0; benches < bench_tries; benches++) {
        // Подготовка буфера для обхода
        auto a = static_cast<Element*>(aligned_alloc(page_size, N));
        auto *cur = a;

        // Чтобы несколько элементов не выставили себе next в один и тот же
        std::vector<size_t> indices(num_elements); 
        size_t cur_idx = 0;
        for (size_t i = 0; i < num_elements; ++i) {
            indices[cur_idx] = i;
            cur_idx++;
        }
        std::shuffle(indices.begin(), indices.end(), rng);
        for (size_t i = 0; i < num_elements; i++) {
            cur->next = a + indices[i];
            cur = cur->next;
        }
        cur->next = a; // Чтобы избежать проверки на nullptr

        // Прогрев
        for (size_t j = 0; j < 4; j++) {
            volatile Element* runner = a;
            for (size_t i = 0; i < num_elements; ++i) {
                runner = runner->next;
            }
        }

        uint64_t t0 = now_ns();
        for (size_t j = 0; j < trials; j++) {
            volatile Element* runner = a;
            for (size_t i = 0; i < num_elements; i++) {
                runner = runner->next;
            }
        }
        uint64_t t1 = now_ns();

        double result = double(t1 - t0);
        result /= double(num_elements * trials); // Среднее время обращения к элементу массива
                                                 // Если массив полностью помещается в кэш -- время будет похожее
        avg_sum += result;

        free(a);
    }

    return avg_sum / double(bench_tries);
}

double measure_conflicts(size_t k, size_t stride, size_t bench_tries = 10) {
    size_t N = 64 * 1024 * 1024;
    size_t num_elements = N / sizeof(Element);
    size_t trials = 100;
    std::vector<double> all_avg;

    for (size_t benches = 0; benches < bench_tries; benches++) {
        // Подготовка буфера для обхода
        auto* a = static_cast<Element*>(aligned_alloc(page_size, N));
        Element* current = a;
        for (size_t i = 0, idx = 0; i < num_elements; ++i) {
            idx = ((idx + stride) % num_elements) + ((idx + stride >= num_elements) ? 1 : 0);
            current->next = a + idx;
            current = current->next;
        }

        // Прогрев
        for (size_t j = 0; j < trials; j++) {
            volatile Element* runner = a;
            for (size_t i = 0; i < k; i++)
                runner = runner->next;
        }

        uint64_t t0 = now_ns();
        for (size_t j = 0; j < trials; j++) {
            volatile Element* runner = a;
            for (size_t i = 0; i < k; i++)
                runner = runner->next;
        }
        uint64_t t1 = now_ns();

        double avg_ns = double(t1 - t0) / double(k * trials);
        all_avg.push_back(avg_ns);

        free(a);
    }
    auto main_avg = std::accumulate(all_avg.begin(), all_avg.end(), 0.0) / double(bench_tries);

    return main_avg;
}

int main() {
    const double line_threshold = 1.5;
    const double size_threshold = 1.5;
    const double assoc_threshold = 1.5;

    size_t max_test_bytes = 2 << 27;
    const size_t min_test_bytes = 1 << 10;

    size_t detected_line = 1;

    double prev_t = 0;
    size_t prev_s = 1;
    for (size_t s = 1; s <= 1024; s = (s >= 8) ? s*2 : s+1) {
        double t = measure_stride_time(max_test_bytes, s);
        // std::cout << "s: " << std::setw(2) << s << ", time:" << std::setw(11) << std::fixed << std::setprecision(0) << t << "\n";
        if (s == 1)
            prev_t = t;
        else {
            if (t * line_threshold < prev_t) {
                detected_line = prev_s;
                break;
            }
            prev_t = t;
            prev_s = s;
        }
    }
    std::cout << "Line size = " << detected_line * sizeof(size_t) << " bytes\n";

    max_test_bytes = 2 << 20;
    int counter = 0;
    int max_bench_tries = 5;
    size_t detected_L1 = 0;
    while(!detected_L1) {
        std::vector<size_t> tries;
        // std::cout << "try number: " << counter << "\n";
        for (int bench_num = 1; bench_num <= max_bench_tries; bench_num++) {
            // std::cout << "benchmark number: " << bench_num << "\n";
            std::vector<std::pair<size_t, double>> size_times;
            for (size_t size = min_test_bytes; size <= max_test_bytes; size *= 2) {
                for (size_t step = 0; step < size; step += size / 2) {
                    double t = measure_traverse_time(size + step, 32);
                    size_times.emplace_back(size + step, t);
                    // std::cout << "size: " << size + step << ", time: " << t << "\n";
                }
            }        

            for (size_t i = 1; i <= size_times.size(); i++) {
                double prev = size_times[i-1].second;
                double cur  = size_times[i].second;
                if (i > 3 && cur > prev * size_threshold) {
                    tries.push_back(size_times[i-1].first);
                    break;
                }
            }
        }

        counter++;
        if (tries.empty()) {
            // std::cout << "No threshold was exceeded, retrying...\n";
            if (counter >= 5) {
                // std::cout << "No threshold was exceeded after 5 tries \n";
                detected_L1 = 0;
                break;
            }
            continue;
        }
        // std::cout << "tries elements: \n";
        // for (int tr = 0; tr < tries.size(); tr++) {
        //     std::cout << "tries[i] = " << tries[tr] << "\n";
        // }
        if (tries.size() > max_bench_tries / 2) {
            // Возьмём наиболее часто встречающийся элемент
            int n = tries.size(), maxcount = 0;
            for (int freq_i = 0; freq_i < n; freq_i++) {
                int freq_count = 0;
                for (int freq_j = 0; freq_j < n; freq_j++) {
                    if (tries[freq_i] == tries[freq_j])
                        freq_count++;
                }
                if (freq_count > maxcount) {
                    maxcount = freq_count;
                    detected_L1 = tries[freq_i];
                }
            }
        }
    }
    std::cout << "L1 size = " << detected_L1 << " bytes = " << detected_L1 / 1024 << "KiB\n";

    size_t assoc = 1;
    if (detected_L1 >= 1024) {
        double prev_t = 0;
        double prev_k = 1;
        for (size_t k = 1; k <= 32; (k < 8) ? k+=1 : k+=4) {
            double t = measure_conflicts(k, detected_L1);
            // std::cout << "k: " << k << ", time: " << t << "\n";
            if (k > 1 && t > prev_t * assoc_threshold) {
                assoc = prev_k;
                break;
            }
            assoc = k;
            prev_t = t;
            prev_k = k;
        }
    }
    std::cout << "Associativity = " << assoc << "\n";

    return 0;
}
