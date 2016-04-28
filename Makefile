# Define directories
VENDOR_DIR ?= $(CURDIR)/vendor


# Global/default target
all: install test lint check-style

$(VENDOR_DIR):
	composer install --no-interaction --prefer-dist

install-deps: $(VENDOR_DIR)

clean-deps:
	rm -rf $(VENDOR_DIR)

test:
	./vendor/bin/phpunit

test-with-coverage:
	./vendor/bin/phpunit --coverage-text --coverage-html=report/

test-with-coverage-clover:
	./vendor/bin/phpunit --coverage-text --coverage-clover=coverage.xml

lint:
	# Lint all PHP files in parallel (across 8 threads)
	find . -name "*.php" -not -path "./vendor/*" -print0 | xargs -n 1 -0 -P 8 php -l

check-style:
	./vendor/bin/phpcs --standard=PSR2 --encoding=utf-8 -p src/ tests/

.PHONY: all install-deps clean-deps test test-with-coverage test-with-coverage-clover lint check-style
