LAMAC=lamac
LAMAI=$(PWD)/lamai
LAMAI_SRC=$(PWD)/lamai.cpp
TEST_DIR=$(PWD)/test/regression

LAMA_FILES := $(wildcard $(TEST_DIR)/*.lama)
TESTS := $(notdir $(basename $(LAMA_FILES)))
ORIG_DIR=$(PWD)/test/regression/orig

.PHONY: regression test clean lamai lamai.o

regression: test

test:
	@echo "Running regression tests..."
	@failed_tests=""; \
	total_tests=0; \
	passed_tests=0; \
	failed_tests_count=0; \
	for lama_file in $(LAMA_FILES); do \
		test_name=$$(basename $$lama_file .lama); \
		total_tests=$$((total_tests + 1)); \
		echo -n "Test $$test_name: "; \
		cd $(TEST_DIR) && \
		if $(LAMAC) -b $$test_name.lama 2>/dev/null; then \
			if [ -f "$$test_name.input" ]; then \
				cat "$$test_name.input" | $(LAMAI) "$$test_name.bc" 2>&1 > "$$test_name.actual.log"; \
			else \
				$(LAMAI) "$$test_name.bc" 2>&1 > "$$test_name.actual.log"; \
			fi; \
			if diff -q "orig/$$test_name.log" "$$test_name.actual.log" >/dev/null 2>&1; then \
				echo "PASS"; \
				passed_tests=$$((passed_tests + 1)); \
				rm -f "$$test_name.bc" "$$test_name.actual.log" "$$test_name.diff"; \
			else \
				echo "FAIL"; \
				failed_tests_count=$$((failed_tests_count + 1)); \
				failed_tests="$$failed_tests $$test_name"; \
				diff -u "orig/$$test_name.log" "$$test_name.actual.log" > "$$test_name.diff" 2>/dev/null || true; \
			fi; \
		else \
			echo "FAIL (compilation)"; \
			failed_tests_count=$$((failed_tests_count + 1)); \
			failed_tests="$$failed_tests $$test_name"; \
		fi; \
	done; \
	echo ""; \
	echo "Test results:"; \
	echo "  Total:  $$total_tests"; \
	echo "  Passed: $$passed_tests"; \
	echo "  Failed: $$failed_tests_count"; \
	echo ""; \
	if [ $$failed_tests_count -gt 0 ]; then \
		echo "Failed tests:$$failed_tests"; \
		echo ""; \
		exit 1; \
	else \
		echo "All tests passed!"; \
	fi

PERF_DIR=$(PWD)/test/performance
PERF_LAMA_FILES := $(wildcard $(PERF_DIR)/*.lama)
PERF_TESTS=$(sort $(basename $(PERF_LAMA_FILES)))
LAMA_RUNTIME=$(PWD)/Lama/runtime

performance: $(PERF_TESTS)

build-lama-runtime:
	@cp $(PWD)/lama_runtime_makefile $(LAMA_RUNTIME)/Makefile && cd $(LAMA_RUNTIME) && make all

$(PERF_TESTS): %: %.lama
	@echo "Recursive source-level interpreter:" $@
	@LAMA=$(LAMA_RUNTIME) time -f "$@\t%U" $(LAMAC) -i $< < /dev/null
	@echo "Recursive bytecode interpreter:" $@
	@LAMA=$(LAMA_RUNTIME) time -f "$@\t%U" $(LAMAC) -s $< < /dev/null
	@echo "Iterative bytecode interpreter:" $@
	@LAMA=$(LAMA_RUNTIME) && cd $(PERF_DIR) && $(LAMAC) -b $< && time -f "$@\t%U" $(LAMAI) $@.bc && rm $@.bc

lamai: build-lama-runtime lamai.o
	@g++ -m32 -std=c++17 -O2 -Wno-narrowing \
	    -Wl,--as-needed -Wl,--no-undefined -Wl,--defsym=__start_custom_data=0 -Wl,--defsym=__stop_custom_data=0 \
		lamai.o $(LAMA_RUNTIME)/runtime.a -o $(LAMAI)

lamai.o:
	g++ -m32 -std=c++17 -O2 -Wno-narrowing -c $(LAMAI_SRC)

clean-regression:
	@rm -f *.bc *.actual.log *.diff