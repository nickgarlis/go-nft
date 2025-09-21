.PHONY: testc-nftnl test-nftnl testc-nft test-nft clean

testc-nftnl:
	go test -c github.com/nickgarlis/go-nft/nftnl -o nftnl.test
test-nftnl:
	./nftnl.test -test.v -integration_tests
testc-nft:
	go test -c github.com/nickgarlis/go-nft -o nft.test
test-nft:
	./nft.test -test.v -integration_tests

clean:
	rm *.test
