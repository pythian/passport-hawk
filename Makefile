TESTS = $(shell find test -name "*test.js")
TESTTIMEOUT = 3000
REPORTER = spec

test:
	@NODE_ENV=test mocha \
	--require expect.js \
	--ui bdd \
	--growl \
	--reporter $(REPORTER) \
	--timeout $(TESTTIMEOUT) $(TESTS)

coverage:
	istanbul instrument --output lib-cov --no-compact --variable global.__coverage__ lib
	@COVER=1 mocha --reporter mocha-istanbul \
	--require expect.js \
	--ui bdd \
	--growl \
	--timeout $(TESTTIMEOUT) \
	$(TESTS)


.PHONY: test coverage
