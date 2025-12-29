LAMAC=lamac
LAMAA=$(PWD)/lamaa
LAMAA_SRC=$(PWD)/lamaa.cpp
TEST_DIR=$(PWD)/test
LAMA_FILES := $(wildcard $(TEST_DIR)/*.lama)

.PHONY: lamaa test

test:
	@for lama_file in $(LAMA_FILES); do \
		test_name=$$(basename $$lama_file .lama); \
		echo -n "Test $$test_name: \n"; \
		cd $(TEST_DIR) && \
		if $(LAMAC) -b $$test_name.lama 2>/dev/null; then \
			$(LAMAA) "$$test_name.bc" 2>&1; \
			rm -f "$$test_name.bc"; \
			echo "===========================================\n"; \
		else \
			echo "FAIL (compilation)"; \
			failed_tests_count=$$((failed_tests_count + 1)); \
			failed_tests="$$failed_tests $$test_name"; \
		fi; \
	done;

lamaa:
	g++ -m32 -std=c++17 -O2 $(LAMAA_SRC) -o $(LAMAA)
