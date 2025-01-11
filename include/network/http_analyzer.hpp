#pragma once

#include <curl/curl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <chrono>
#include "network/protocol_analyzer.hpp"

namespace network_analyzer {
namespace network {

class HttpAnalyzer : public ProtocolAnalyzer {
public:
    HttpAnalyzer();
    ~HttpAnalyzer() override;

    metrics::ProtocolMetrics analyze(const std::string& url) override;
    std::string getProtocolName() const override { return "HTTP"; }

private:
    struct TransferData {
        size_t bytesReceived{0};
        size_t bytesSent{0};
        std::chrono::steady_clock::time_point startTime;
        bool initialized{false};
    };

    static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp);
    static size_t HeaderCallback(char* buffer, size_t size, size_t nitems, void* userdata);
    
    void calculateLatencyStats(const std::vector<double>& measurements);
    void analyzeSslDetails(CURL* curl, SSL* ssl);
    void analyzeHttp2Details(CURL* curl);
    void analyzeThroughputMetrics(const TransferData& transferData);
};

} // namespace network
} // namespace network_analyzer 