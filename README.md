# LIBPCAP RPC Muxer

Client app uses GRPC for libpcap call on remote hosts

## Quick start

0. Install wireshark on client host
1. Build executables:
```bash
# go mod download
# mkdir -p build
# go build -o build daemon/daemon.go; go build -o build client/*
```

2. Install and run daemon from build dir or releases to all remote servers and run
3. Start client app
4. Add remote hosts with running daemon to local config:
```
>>> devices add remote1 192.0.2.1
>>> devices add remote2 192.0.2.2
```
or do it by group
```
>>> devices add remote1 192.0.2.1 remote2 192.0.2.2
```
5. Set interface to capture (must be same on all devices)
```
>>> interface any
```
Default: any

6. Set pcap-filter
```
>>> pcap-filter tcp port 443
```
Default: ""

7. Start capture
```
>>> start
```
8. After done, press stop button in wireshark and/or close it