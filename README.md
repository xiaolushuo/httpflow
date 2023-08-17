# httpflow

[![Build Status](https://travis-ci.org/six-ddc/httpflow.svg?branch=master)](https://travis-ci.org/six-ddc/httpflow)

[![asciicast](https://asciinema.org/a/scdzwLDNytSPHtpbu1ECSv5FV.svg)](https://asciinema.org/a/scdzwLDNytSPHtpbu1ECSv5FV)

### Linux

- Install [zlib](http://www.zlib.net/), [pcap](http://www.tcpdump.org/), [pcre](http://pcre.org/),[icu](https://github.com/unicode-org/icu),[nlohmann_json](https://github.com/nlohmann/json),[boost](https://www.boost.org/)

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
```

- Building httpflow

```bash
> git clone https://github.com/xiaolushuo/httpflow
> cd httpflow/build &&  cmake .. && make
```

or directly download [Release](https://github.com/xiaolushuo/httpflow/releases) binary file.

## Usage

```
libpcap version libpcap version 1.9.1
httpflow version 0.1.0

Usage: httpflow [-i interface | -r pcap-file] [-u url-filter] [-w output-path] [expression]

  -i interface      Listen on interface, This is same as tcpdump 'interface'
  -r pcap-file      Read packets from file (which was created by tcpdump with the -w option)
                    Standard input is used if file is '-'
  -u url-filter     Matches which urls will be dumped
  -w output-path    Write the http request and response to a specific directory
  -o output-json    Writes http requests and responses to a specific directory in a json file format

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
