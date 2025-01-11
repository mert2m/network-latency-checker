#include "network/http_analyzer.hpp"
#include "utils/exceptions.hpp"
#include <algorithm>
#include <numeric>

namespace network_analyzer {
namespace network {

HttpAnalyzer::HttpAnalyzer() {
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
        throw utils::ProtocolException("Failed to initialize CURL");
    }
}

HttpAnalyzer::~HttpAnalyzer() {
    curl_global_cleanup();
}

size_t HttpAnalyzer::WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    auto* data = static_cast<TransferData*>(userp);
    size_t realSize = size * nmemb;
    
    if (!data->initialized) {
        data->startTime = std::chrono::steady_clock::now();
        data->initialized = true;
    }
    
    data->bytesReceived += realSize;
    return realSize;
}

size_t HttpAnalyzer::HeaderCallback(char* buffer, size_t size, size_t nitems, void* userdata) {
    auto* metrics = static_cast<metrics::ProtocolMetrics*>(userdata);
    std::string header(buffer, size * nitems);
    
    if (header.find("content-encoding: ") != std::string::npos) {
        metrics->http2Metrics.compressionAlgorithm = header.substr(header.find(": ") + 2);
        metrics->compressionEnabled = true;
    }
    
    return size * nitems;
}

void HttpAnalyzer::analyzeSslDetails(CURL* curl, SSL* ssl) {
    if (!ssl) return;

    const SSL_CIPHER* cipher = SSL_get_current_cipher(ssl);
    if (cipher) {
        metrics_.encryptionType = SSL_CIPHER_get_name(cipher);
        metrics_.securityDetails.keySize = SSL_CIPHER_get_bits(cipher, nullptr);
        metrics_.securityDetails.algorithm = std::string("TLS ") + SSL_get_version(ssl);

        char cipher_desc[256];
        SSL_CIPHER_description(cipher, cipher_desc, sizeof(cipher_desc));
        metrics_.recommendations.push_back(std::string("Current cipher suite: ") + cipher_desc);

        if (metrics_.securityDetails.keySize < 128) {
            metrics_.warnings.push_back("Weak cipher strength detected");
            metrics_.recommendations.push_back("Consider upgrading to ciphers with at least 128-bit strength");
        }
    }
}

void HttpAnalyzer::analyzeHttp2Details(CURL* curl) {
    long http_version;
    curl_easy_getinfo(curl, CURLINFO_HTTP_VERSION, &http_version);
    metrics_.http2Metrics.enabled = (http_version >= CURL_HTTP_VERSION_2_0);

    if (metrics_.http2Metrics.enabled) {
        metrics_.http2Metrics.multiplexingEnabled = true;
        
        char* protocol = nullptr;
        curl_easy_getinfo(curl, CURLINFO_SCHEME, &protocol);
        if (protocol) {
            metrics_.http2Metrics.alpnProtocol = std::string(protocol) + "/2";
        }
    }
}

void HttpAnalyzer::analyzeThroughputMetrics(const TransferData& transferData) {
    auto endTime = std::chrono::steady_clock::now();
    double duration = std::chrono::duration<double>(endTime - transferData.startTime).count();
    
    if (duration > 0) {
        metrics_.throughputMetrics.downloadSpeed = transferData.bytesReceived / duration;
        metrics_.throughputMetrics.totalBytesReceived = transferData.bytesReceived;
        
        if (metrics_.throughputMetrics.downloadSpeed < 1000000) {
            metrics_.recommendations.push_back("Low download speed detected. Consider:");
            metrics_.recommendations.push_back("- Enabling HTTP/2 if not already enabled");
            metrics_.recommendations.push_back("- Implementing content compression");
            metrics_.recommendations.push_back("- Using a CDN for static content");
        }
    }
}

void HttpAnalyzer::calculateLatencyStats(const std::vector<double>& measurements) {
    if (measurements.empty()) return;

    std::lock_guard<std::mutex> lock(metricsMutex_);
    metrics_.latencyStats.min = *std::min_element(measurements.begin(), measurements.end());
    metrics_.latencyStats.max = *std::max_element(measurements.begin(), measurements.end());
    
    double sum = std::accumulate(measurements.begin(), measurements.end(), 0.0);
    metrics_.latencyStats.avg = sum / measurements.size();

    double sumJitter = 0.0;
    for (size_t i = 1; i < measurements.size(); ++i) {
        sumJitter += std::abs(measurements[i] - measurements[i-1]);
    }
    metrics_.latencyStats.jitter = measurements.size() > 1 ? 
        sumJitter / (measurements.size() - 1) : 0.0;

    if (metrics_.latencyStats.avg > 1000) {
        metrics_.recommendations.push_back("High latency detected. Consider:");
        metrics_.recommendations.push_back("- Using a CDN");
        metrics_.recommendations.push_back("- Optimizing server response time");
        metrics_.recommendations.push_back("- Checking network configuration");
    }
    
    if (metrics_.latencyStats.jitter > 100) {
        metrics_.recommendations.push_back("High jitter detected. Consider:");
        metrics_.recommendations.push_back("- Implementing QoS policies");
        metrics_.recommendations.push_back("- Checking for network congestion");
    }
}

metrics::ProtocolMetrics HttpAnalyzer::analyze(const std::string& url) {
    metrics_ = metrics::ProtocolMetrics();
    std::vector<double> latencyMeasurements;
    TransferData transferData;

    CURL* curl = curl_easy_init();
    if (!curl) {
        throw utils::ProtocolException("Failed to initialize CURL");
    }

    try {
        // Basic setup
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &transferData);
        curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, HeaderCallback);
        curl_easy_setopt(curl, CURLOPT_HEADERDATA, &metrics_);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, config_.getConnectionTimeout());
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, config_.getConnectionTimeout());
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
        curl_easy_setopt(curl, CURLOPT_CERTINFO, 1L);
        curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0);
        
        if (config_.isVerboseLoggingEnabled()) {
            curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
        }

        // Perform request with retry logic
        CURLcode res = CURLE_OK;
        int retries = 0;
        do {
            auto start = std::chrono::high_resolution_clock::now();
            res = curl_easy_perform(curl);
            auto end = std::chrono::high_resolution_clock::now();

            if (res == CURLE_OK) {
                double latency = std::chrono::duration<double, std::milli>(end - start).count();
                latencyMeasurements.push_back(latency);
                break;
            } else if (res == CURLE_OPERATION_TIMEDOUT) {
                metrics_.warnings.push_back("Request timeout on attempt " + std::to_string(retries + 1));
            } else {
                metrics_.warnings.push_back(std::string("CURL error: ") + curl_easy_strerror(res));
            }
            
            retries++;
            if (retries < config_.getMaxRetries()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(1000 * retries));
            }
        } while (retries < config_.getMaxRetries());

        if (res != CURLE_OK) {
            throw utils::ProtocolException(std::string("Failed after ") + 
                std::to_string(config_.getMaxRetries()) + " attempts: " + 
                curl_easy_strerror(res));
        }

        // Get SSL/TLS information
        SSL* ssl = nullptr;
        res = curl_easy_getinfo(curl, CURLINFO_TLS_SSL_PTR, &ssl);
        if (res == CURLE_OK) {
            analyzeSslDetails(curl, ssl);
        }

        analyzeHttp2Details(curl);
        analyzeThroughputMetrics(transferData);
        measurePacketLoss(url);
        calculateLatencyStats(latencyMeasurements);

    } catch (const std::exception& e) {
        metrics_.warnings.push_back(std::string("HTTPS error: ") + e.what());
        curl_easy_cleanup(curl);
        throw;
    }

    curl_easy_cleanup(curl);
    return metrics_;
}

} // namespace network
} // namespace network_analyzer 