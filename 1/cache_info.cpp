#include <iostream>
#include <bits/stdc++.h>
#include <chrono>
#include <vector>
using namespace std::chrono;


// 1. Общий размер L1:
//   - Обходим массив с увеличением его размера. Когда время скакнёт -- значит, вышли за размер L1
//     - массив, значение элемента в котором является индексом следующего элемента -- чтобы запутать префетчер
// 2. Длина cache line
//   - Обходим массив, постепенно увеличивая stride
// 3. Ассоциативность:
//   - Массив цепочек индексов с шагом в размер L1. Постепенно увеличиваем число шагов по нему. Когда время начнёт скакать -- значит, вышли за степень ассоциативности

static size_t constexpr page_size = size_t(4) * 1024 * 1024;

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

    for (size_t benches = 0; benches < bench_tries; benches++) {
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
    }
    auto main_avg = std::accumulate(all_avg.begin(), all_avg.end(), 0.0) / double(bench_tries);

    for (size_t i = 0; i < elements; ++i)
        delete nodes[i];
    delete[] nodes;

    return main_avg;
}

double measure_traverse_time(size_t N, size_t stride, size_t line_size, size_t bench_tries = 1) {
    size_t elements = N / sizeof(size_t);
    if (elements < 16)
        elements = 16;
    std::vector<double> all_avg;

    Element* head = new Element();
    Element* current = head;
    alignas(page_size) Element** nodes = new Element*[elements];
    
    nodes[0] = head;
    for (size_t i = 1; i < elements; ++i) {
        current->next = new Element();
        current = current->next;
        nodes[i] = current;
    }
    for (size_t i = 0; i < elements; ++i) {
        size_t next_idx = (i + stride) % elements;
        nodes[i]->next = nodes[next_idx];
    }

    for (size_t benches = 0; benches < bench_tries; benches++) {
        volatile size_t idx = 0;
        uint64_t steps = 64 * 1024 * 1024;
        volatile Element* runner = head;

        // Прогрев
        for (int i = 0; i < steps; i++)
            runner = runner->next;

        runner = head;
        uint64_t t0 = now_ns();
        for (int i = 0; i < steps; i++)
            runner = runner->next;
        uint64_t t1 = now_ns();

        (void)idx;
        double avg_ns = double(t1 - t0) / double(steps); // Среднее время обращения к элементу массива
                                                         // Если массив полностью помещается в кэш -- время будет похожее
        all_avg.push_back(avg_ns);
    }
    auto main_avg = std::accumulate(all_avg.begin(), all_avg.end(), 0.0) / double(bench_tries);

    for (size_t i = 0; i < elements; ++i)
        delete nodes[i];
    delete[] nodes;

    return main_avg;
}

double measure_conflicts(size_t k, size_t stride, size_t bench_tries = 10) {
    size_t elements = 64 * 1024 * 1024;
    alignas(page_size) size_t* a = new size_t[elements];
    for (size_t i = 0, idx = 0; i < elements; ++i) {
        auto idx_prev = idx;
        idx = ((idx + stride) % elements) + ((idx + stride >= elements) ? 1 : 0);
        a[idx_prev] = idx;
    }

    Element* head = new Element();
    Element* current = head;
    alignas(page_size) Element** nodes = new Element*[elements];

    nodes[0] = head;
    for (size_t i = 1; i < elements; ++i) {
        current->next = new Element();
        current = current->next;
        nodes[i] = current;
    }
    // Список в виде цепочек индексов с шагом stride
    size_t idx = 0;
    for (size_t i = 0; i < elements; ++i) {
        size_t next_idx = ((idx + stride) % elements) + ((idx + stride >= elements) ? 1 : 0);
        nodes[idx]->next = nodes[next_idx];
        idx = next_idx;
    }

    size_t trials = 100;
    std::vector<double> all_avg;
    for (size_t benches = 0; benches < bench_tries; benches++) {
        // Прогрев
        for (size_t j = 0; j < trials; j++) {
            volatile Element* runner = head;
            for (size_t i = 0; i < k; i++)
                runner = runner->next;
        }

        uint64_t t0 = now_ns();
        for (size_t j = 0; j < trials; j++) {
            volatile Element* runner = head;
            for (size_t i = 0; i < k; i++)
                runner = runner->next;
        }
        uint64_t t1 = now_ns();

        double avg_ns = double(t1 - t0) / double(k * trials);
        all_avg.push_back(avg_ns);
    }
    auto main_avg = std::accumulate(all_avg.begin(), all_avg.end(), 0.0) / double(bench_tries);

    for (size_t i = 0; i < elements; ++i)
        delete nodes[i];
    delete[] nodes;

    return main_avg;
}

int main() {
    const double line_threshold = 1.5;
    const double size_threshold = 1.25;
    const double assoc_threshold = 1.5;

    const size_t max_test_bytes = 2 << 27;
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

    std::vector<std::pair<size_t, double>> size_times;
    for (size_t size = min_test_bytes; size <= max_test_bytes; size *= 2) {
        double t = measure_traverse_time(size, detected_line, detected_line);
        size_times.emplace_back(size, t);
    }

    double base = size_times.front().second;
    size_t detected_L1 = size_times.back().first;
    for (size_t i = 1; i <= size_times.size(); ++i) {
        double prev = size_times[i-1].second;
        double cur  = size_times[i].second;
        // std::cout << "size: " << size_times[i - 1].first << ", time: " << prev << ", avg_all_prev: " << avg_all_prev << "\n";
        if (cur > prev * size_threshold) {
            // std::cout << "size: " << size_times[i].first << ", time: " << cur << " <-- found\n";
            detected_L1 = size_times[i-1].first;
            break;
        }
    }
    std::cout << "L1 size = " << detected_L1 << " bytes = " << detected_L1 / 1024 << "KiB\n";

    size_t assoc = 1;
    if (detected_L1 >= 1024) {
        double prev_t = 0;
        double prev_k = 1;
        for (size_t k = 1; k <= 64; k = (k >= 8) ? k*2 : k+1) {
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

    // Вывод результатов
    std::cout << "Associativity = " << assoc << "\n";

    return 0;
}
