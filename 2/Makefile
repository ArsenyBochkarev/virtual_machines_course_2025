LAMAC=$(PWD)/Lama/src/lamac
LAMAI=$(PWD)/lamai
LAMAI_SRC=$(PWD)/lamai.cpp
TEST_DIR=$(PWD)/test/regression

LAMA_FILES := $(wildcard $(TEST_DIR)/*.lama)
TESTS := $(notdir $(basename $(LAMA_FILES)))
ORIG_DIR=./test/regression/orig

.PHONY: regression test clean

regression: test

test:
	@for lama_file in $(LAMA_FILES); do \
		test_name=$$(basename $$lama_file .lama); \
		echo "Running test: $$test_name"; \
		cd $(TEST_DIR) && \
		$(LAMAC) -b $$test_name.lama && \
		if [ -f "$$test_name.input" ]; then \
			cat "$$test_name.input" | $(LAMAI) "$$test_name.bc" > "$$test_name.actual.log" 2>&1; \
		else \
			$(LAMAI) "$$test_name.bc" > "$$test_name.actual.log" 2>&1; \
		fi && \
		if diff -q "orig/$$test_name.log" "$$test_name.actual.log" >/dev/null; then \
			echo "  $$test_name: PASS"; \
			rm -f "$$test_name.bc" "$$test_name.actual.log"; \
		else \
			echo "  $$test_name: FAIL"; \
			diff -u "orig/$$test_name.log" "$$test_name.actual.log" > "$$test_name.diff"; \
		fi; \
	done
	@echo "All tests passed"

lamai: $(LAMAI_SRC)
	@g++ -g -m32 -std=c++17 $(LAMAI_SRC) -o $(LAMAI)

clean-regression:
	@rm -f *.bc *.actual.log *.diff