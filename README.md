# httpflow

[![Build Status](https://travis-ci.org/six-ddc/httpflow.svg?branch=master)](https://travis-ci.org/six-ddc/httpflow)

[![asciicast](https://asciinema.org/a/scdzwLDNytSPHtpbu1ECSv5FV.svg)](https://asciinema.org/a/scdzwLDNytSPHtpbu1ECSv5FV)

### Requires installation

- Install [zlib](http://www.zlib.net/),  [pcap](http://www.tcpdump.org/),  [pcre](http://pcre.org/), [icu](https://github.com/unicode-org/icu), [nlohmann_json](https://github.com/nlohmann/json), [boost](https://www.boost.org/), [hiredis](https://github.com/redis/hiredis), [yaml-cpp](https://github.com/jbeder/yaml-cpp), [cpprestsdk](https://github.com/microsoft/cpprestsdk)

```bash
## On CentOS
yum update
yum install boost-devel libicu-devel libpcap-devel zlib-devel pcre-devel


## On Ubuntu / Debian
apt-get update
apt-get install libboost-all-dev libicu-dev libpcap-dev zlib1g-dev libpcre3-dev 


## On MacOs
brew update
brew install boost icu4c libpcap zlib pcre

## install nlohmann_json
cd external
git clone https://github.com/nlohmann/json.git nlohmann_json 
```

- Building httpflow

```bash
> git clone https://github.com/xiaolushuo/httpflow
> cd httpflow/build &&  cmake .. && make
```

or directly download [Release](https://github.com/xiaolushuo/httpflow/releases) binary file.

## Usage

```
httpflow version 0.1.1

Usage: httpflow [-i interface | -r pcap-file] [-u url-filter] [-w output-path] [expression]

  -i interface      Listen on interface, This is same as tcpdump 'interface'
  -r pcap-file      Read packets from file (which was created by tcpdump with the -w option)
                    Standard input is used if file is '-'
  -u url-filter     Matches which urls will be dumped
  -w output-path    Write the http request and response to a specific directory
  -o output-json    Writes http requests and responses to a specific directory in a json file format
  -f yaml_file      Database configuration file, currently supporting only Elasticsearch and Redis
  -t threads         Setting the number of read threads for the queue.

  expression        Selects which packets will be dumped, The format is the same as tcpdump's 'expression' argument
                    If filter expression is given, only packets for which expression is 'true' will be dumped
                    For the expression syntax, see pcap-filter(7)

  For more information, see https://github.com/xiaolushuo/httpflow
```

- Capture default interface

```bash
> httpflow
```

- Capture all interfaces

```bash
> httpflow -i any
```

- Use the expression to filter the capture results

```bash
# If no expression is given, all packets on the net will be dumped.
# For the expression syntax, see pcap-filter(7).
> httpflow host httpbin.org or host baidu.com
```

- Use the regexp to filter request urls

```bash
> httpflow -u '/user/[0-9]+'
```

- Use the regexp to filter domain

```bash
> httpflow -d '.*demo.*'
```

- Setting the number of read threads for the queue, Default is 100

```bash
> httpflow -t 50
```

- Read packets from pcap-file

```bash
# tcpdump -w a.cap
> httpflow -r a.cap
```

- Read packets from input

```bash
> tcpdump -w - | httpflow -r -
```

- Write the HTTP request and response to directory `/tmp/http`

```bash
> httpflow -w /tmp/http
```

- Writes http requests and responses to a specific directory in a json file format `/tmp/http_json`

```bash
> httpflow -o /tmp/http_json
```

- Writes http requests and responses to Elasticsearch and Redis

```bash
> httpflow -d db.yaml
```

> 注意事项

如果想过滤黑白名单，要使用host 指定，如host 192.168.1.1 或 not host 192.168.1.1,如果单纯的指定dst 192.168.1.1是不行的。

当你设置过滤条件为 "dst 192.168.1.1" 时，你只会捕获到目标 IP 地址为 192.168.1.1 的网络流量。在大多数情况下，这意味着你只会捕获到发送到这个 IP 地址的请求，而不会捕获到从这个 IP 地址发送的响应。

这是因为在 TCP/IP 网络中，一个完整的 HTTP 交互包括一个请求和一个响应。请求的目标 IP 地址是服务器的 IP 地址，而响应的源 IP 地址是服务器的 IP 地址。所以，如果你只捕获目标 IP 地址为服务器 IP 地址的网络流量，你只会看到请求，而看不到响应。   

