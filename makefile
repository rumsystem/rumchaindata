PROTOC_GEN_GO = $(GOPATH)/bin/protoc-gen-go
PROTOC = $(shell which protoc)

compile: chain.proto activity_stream.proto rumexchange.proto

chain.proto:
	protoc -I=pkg/pb --go_out=pkg/pb pkg/pb/chain.proto
	mv pkg/pb/github.com/rumsystem/rumchaindata/pkg/pb/chain.pb.go pkg/pb/chain.pb.go
	sed -i 's/TimeStamp,omitempty/TimeStamp,omitempty,string/g' pkg/pb/chain.pb.go

activity_stream.proto:
	protoc -I=pkg/pb --go_out=pkg/pb pkg/pb/activity_stream.proto
	mv pkg/pb/github.com/rumsystem/rumchaindata/pkg/pb/activity_stream.pb.go pkg/pb/activity_stream.pb.go
	sed -i 's/TimeStamp,omitempty/TimeStamp,omitempty,string/g' pkg/pb/activity_stream.pb.go

rumexchange.proto:
	protoc -I=pkg/pb --go_out=pkg/pb pkg/pb/rumexchange.proto 
	mv pkg/pb/github.com/rumsystem/rumchaindata/pkg/pb/rumexchange.pb.go pkg/pb/rumexchange.pb.go
	sed -i 's/TimeStamp,omitempty/TimeStamp,omitempty,string/g' pkg/pb/rumexchange.pb.go

build: compile

buildall: compile

all: compile
