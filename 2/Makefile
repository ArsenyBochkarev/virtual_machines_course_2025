LAMAC=lamac
LAMAI=$(PWD)/lamai
LAMAI_SRC=$(PWD)/lamai.cpp
TEST_DIR=$(PWD)/test/regression

LAMA_FILES := $(wildcard $(TEST_DIR)/*.lama)
TESTS := $(notdir $(basename $(LAMA_FILES)))
ORIG_DIR=$(PWD)/test/regression/orig

.PHONY: regression test clean lamai

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

lamai: $(LAMAI_SRC)
	@g++ -m32 -std=c++17 -O2 $(LAMAI_SRC) -o $(LAMAI)

clean-regression:
	@rm -f *.bc *.actual.log *.diff