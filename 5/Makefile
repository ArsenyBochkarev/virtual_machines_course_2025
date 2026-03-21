LAMAC=lamac
LAMA_TRUFFLE=$(PWD)/lama
TEST_DIR=$(PWD)/language/test/regression

# 063, 092, 093, 094, 096, 097, 099 -- first-class functions
# 095, 098 -- custom infix operator
# 105 -- eta-expansion
EXCLUDE_TESTS=" test063 test092 test093 test094 test095 test096 test097 test098 test099 test105 "
EXCLUDED_FILES := $(addprefix $(TEST_DIR)/, $(addsuffix .lama, $(EXCLUDE_TESTS)))
LAMA_FILES := $(filter-out $(EXCLUDED_FILES), $(wildcard $(TEST_DIR)/*.lama))

.PHONY: performance package regression test clean

regression: package test

package:
	mvn package

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
				cat "$$test_name.input" | $(LAMA_TRUFFLE) "$$test_name.lama" 2>&1 > "$$test_name.actual.log"; \
			else \
				$(LAMA_TRUFFLE) "$$test_name.lama" 2>&1 > "$$test_name.actual.log"; \
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

PERF_DIR=$(PWD)/language/test/performance
PERF_LAMA_FILES := $(wildcard $(PERF_DIR)/*.lama)
PERF_TESTS=$(sort $(basename $(PERF_LAMA_FILES)))
LAMA_RUNTIME ?=

performance: package $(PERF_TESTS)

$(PERF_TESTS): %: %.lama
	@echo "Recursive source-level interpreter:" $@
	@LAMA=$(LAMA_RUNTIME) time -f "$@\t%U" $(LAMAC) -i $< < /dev/null
	@echo "Recursive bytecode interpreter:" $@
	@LAMA=$(LAMA_RUNTIME) time -f "$@\t%U" $(LAMAC) -s $< < /dev/null
	@echo "Graal Truffle interpreter (JVM build):" $@
	@LAMA=$(LAMA_RUNTIME) time -f "$@\t%U" $(LAMA_TRUFFLE) $@.lama

clean:
	@rm -f language/test/performance/*.bc language/test/regression/*.bc language/test/regression/*.actual.log language/test/regression/*.diff