#ifndef custom_parser_h
#define custom_parser_h

#include <iostream>
#include <fstream>
#include <string>
#include <pcre.h>
#include <map>
#include <queue>
#include <mutex>
#include <condition_variable>
#include "http_parser.h"
#include <yaml-cpp/yaml.h>

struct ElasticsearchConfig {
    std::string es_ip;
    int es_port;
    std::string es_username;
    std::string es_password;
};

struct RedisConfig {
    std::string redis_ip;
    int redis_port;
    std::string redis_username;
    std::string redis_password;
};

template <typename T>
class ThreadSafeQueue {
private:
    std::queue<T> queue_;
    std::mutex mutex_;
    std::condition_variable cond_;
public:
    void push(T value) {
        std::lock_guard<std::mutex> lock(mutex_);
        queue_.push(std::move(value));
        cond_.notify_one();
    }

    T pop() {
        std::unique_lock<std::mutex> lock(mutex_);
        cond_.wait(lock, [this]{ return !queue_.empty(); });
        T value = std::move(queue_.front());
        queue_.pop();
        return value;
    }
};

// 声明全局队列
extern ThreadSafeQueue<std::string> es_queue;
extern ThreadSafeQueue<std::string> redis_queue;

class stream_parser {
    friend std::ofstream &operator<<(std::ofstream &out, const stream_parser &f);
    friend std::ostream &operator<<(std::ostream &out, const stream_parser &f);
private:
    const pcre *url_filter_re;
    const pcre_extra *url_filter_extra;
    const pcre *domain_filter_re;
    const pcre_extra *domain_filter_extra;
    const std::string &output_path;
    const std::string &output_json;
    const std::string yaml_file;

    http_parser_settings settings;

    std::string method;
    std::string url;
    std::string host;
    std::string domain;  // 增加域名

    long last_ts_usc;
    long ts_usc[HTTP_BOTH];
    http_parser parser[HTTP_BOTH];
    std::string address[HTTP_BOTH];
    std::string raw[HTTP_BOTH];
    std::string header[HTTP_BOTH];
    std::string body[HTTP_BOTH];
    uint32_t next_seq[HTTP_BOTH];
    std::map<uint32_t, std::pair<std::string, uint32_t> > out_of_order_packet[HTTP_BOTH];

    std::string header_100_continue;
    std::string body_100_continue;

    std::string temp_header_field;
    bool gzip_flag;
    int dump_flag;

    uint32_t fin_nxtseq[HTTP_BOTH];

public:
    stream_parser(const pcre *url_filter_re, const pcre_extra *url_filter_extra,const pcre *domain_filter_re, const pcre_extra *domain_filter_extra, const std::string &output_path, const std::string &output_json,const std::string &yaml_file);

    bool parse(const struct packet_info &packet, enum http_parser_type type);

    inline bool is_request_address(const std::string &addr) const {
        return address[HTTP_REQUEST] == addr;
    }

    void set_addr(const std::string &req_addr, const std::string &resp_addr);

    bool match_url(const std::string &url);

    bool match_domain(const std::string &domain);

    void dump_http_request();

    bool is_stream_fin(const struct packet_info &packet, enum http_parser_type type);

    static int on_message_begin(http_parser *parser);

    static int on_url(http_parser *parser, const char *at, size_t length);

    static int on_header_field(http_parser *parser, const char *at, size_t length);
    
    static int on_header_value(http_parser* parser, const char* at, size_t length);

    static int on_headers_complete(http_parser *parser);

    static int on_body(http_parser *parser, const char *at, size_t length);

    static int on_message_complete(http_parser *parser);

    std::unordered_map<std::string, std::string> create_json_map();

    // body 在 raw[HTTP_RESPONSE] 中的开始位置和长度
    size_t body_start;
};

std::ostream &operator<<(std::ostream &out, const stream_parser &parser);

std::ofstream &operator<<(std::ofstream &out, const stream_parser &parser);

#endif