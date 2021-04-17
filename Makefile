.PHONY: test

swift/spamhaus:
	cd swift && swiftc spamhaus.swift && cd ..

golang/spamhaus:
	cd golang && go build spamhaus.go && cd ..

test:	golang/spamhaus swift/spamhaus
	golang/spamhaus 196.16.11.222 x 8.8.8.8
	swift/spamhaus 196.16.11.222 x 8.8.8.8
	./R/spamhaus.R 196.16.11.222 x 8.8.8.8
	cat test/ips | golang/spamhaus
	cat test/ips | swift/spamhaus
	cat test/ips | R/spamhaus.R
	