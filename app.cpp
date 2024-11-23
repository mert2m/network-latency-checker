#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <chrono>
#include <thread>
#include <numeric>
#include <algorithm>
#include <random>
#include <curl/curl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

// Exception classes need to be moved up, before they're used
class ConfigurationException : public std::runtime_error {
public:
    explicit ConfigurationException(const std::string& message) : std::runtime_error(message) {}
};

class ProtocolException : public std::runtime_error {
public:
    explicit ProtocolException(const std::string& message) : std::runtime_error(message) {}
};

// Thread-safe random number generator
class RandomGenerator {
public:
    static RandomGenerator& getInstance() {
        static RandomGenerator instance;
        return instance;
    }

    double getProbability() {
        std::uniform_real_distribution<double> dist(0.0, 1.0);
        return dist(generator_);
    }

private:
    RandomGenerator() : generator_(std::random_device{}()) {}
    std::mt19937 generator_;
};

// Config structure with validation
class Config {
public:
    int connectionTimeout{5000};      // ms
    int maxRetries{3};
    bool enableVerboseLogging{false};
    std::string outputDirectory{"./reports"};
    std::string logLevel{"INFO"};

    static Config fromJsonFile(const std::string& path) {
        try {
            std::ifstream file(path);
            if (!file.is_open()) {
                throw ConfigurationException("Cannot open config file: " + path);
            }

            json j = json::parse(file);
            Config config;
            
            // Validate and set values with bounds checking
            if (j.contains("connectionTimeout")) {
                config.connectionTimeout = std::max(1000, std::min(j["connectionTimeout"].get<int>(), 30000));
            }
            if (j.contains("maxRetries")) {
                config.maxRetries = std::max(1, std::min(j["maxRetries"].get<int>(), 10));
            }
            config.enableVerboseLogging = j.value("enableVerboseLogging", false);
            config.outputDirectory = j.value("outputDirectory", "./reports");
            config.logLevel = j.value("logLevel", "INFO");

            return config;
        } catch (const json::parse_error& e) {
            throw ConfigurationException("JSON parse error: " + std::string(e.what()));
        } catch (const std::exception& e) {
            throw ConfigurationException("Configuration error: " + std::string(e.what()));
        }
    }

    void saveToFile(const std::string& path) const {
        try {
            json j;
            j["connectionTimeout"] = connectionTimeout;
            j["maxRetries"] = maxRetries;
            j["enableVerboseLogging"] = enableVerboseLogging;
            j["outputDirectory"] = outputDirectory;
            j["logLevel"] = logLevel;

            std::ofstream file(path);
            if (!file.is_open()) {
                throw ConfigurationException("Cannot create config file: " + path);
            }

            file << j.dump(4);
        } catch (const std::exception& e) {
            throw ConfigurationException("Failed to save configuration: " + std::string(e.what()));
        }
    }
};

// Protocol metrics with improved structure
struct ProtocolMetrics {
    double latency{0.0};
    double packetLoss{0.0};
    int bandwidth{0};
    std::string encryptionType;
    bool compressionEnabled{false};

    struct LatencyStats {
        double min{std::numeric_limits<double>::max()};
        double max{std::numeric_limits<double>::lowest()};
        double avg{0.0};
        double jitter{0.0};
    } latencyStats;

    struct PacketStats {
        int sent{0};
        int received{0};
        int lost{0};
        double lossRate{0.0};
    } packetStats;

    struct SecurityDetails {
        std::string algorithm;
        int keySize{0};
        bool perfect_forward_secrecy{false};
    } securityDetails;

    std::vector<std::string> warnings;
    std::vector<std::string> recommendations;
};

// Base Protocol Analyzer with RAII
class ProtocolAnalyzer {
public:
    virtual ~ProtocolAnalyzer() = default;
    virtual ProtocolMetrics analyze(const std::string& target) = 0;
    virtual std::string getProtocolName() const = 0;

    void setConfig(const Config& config) { config_ = config; }
    const ProtocolMetrics& getLastMetrics() const { return metrics_; }

protected:
    ProtocolMetrics metrics_;
    Config config_;
    std::mutex metricsMutex_;

    void measurePacketLoss(const std::string& target [[maybe_unused]]) {
        constexpr int NUM_PACKETS = 100;
        int received = 0;
        auto& random = RandomGenerator::getInstance();

        for (int i = 0; i < NUM_PACKETS; ++i) {
            try {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                if (random.getProbability() > 0.02) { // 2% simulated packet loss
                    received++;
                }
            } catch (const std::exception& e) {
                std::lock_guard<std::mutex> lock(metricsMutex_);
                metrics_.warnings.push_back("Packet loss measurement error: " + std::string(e.what()));
            }
        }

        std::lock_guard<std::mutex> lock(metricsMutex_);
        metrics_.packetStats.sent = NUM_PACKETS;
        metrics_.packetStats.received = received;
        metrics_.packetStats.lost = NUM_PACKETS - received;
        metrics_.packetStats.lossRate = static_cast<double>(NUM_PACKETS - received) / NUM_PACKETS;
    }
};

// CURL RAII Wrapper
class CurlHandle {
public:
    CurlHandle() {
        handle_ = curl_easy_init();
        if (!handle_) {
            throw ProtocolException("CURL initialization failed");
        }
    }
    
    ~CurlHandle() {
        if (handle_) {
            curl_easy_cleanup(handle_);
        }
    }

    CURL* get() { return handle_; }

    CurlHandle(const CurlHandle&) = delete;
    CurlHandle& operator=(const CurlHandle&) = delete;

private:
    CURL* handle_;
};

// HTTP Analyzer with improved error handling
class HttpAnalyzer : public ProtocolAnalyzer {
public:
    HttpAnalyzer() {
        curl_global_init(CURL_GLOBAL_DEFAULT);
    }

    ~HttpAnalyzer() {
        curl_global_cleanup();
    }

    ProtocolMetrics analyze(const std::string& url) override {
        metrics_ = ProtocolMetrics();
        std::vector<double> latencyMeasurements;
        CurlHandle curl;

        try {
            curl_easy_setopt(curl.get(), CURLOPT_URL, url.c_str());
            curl_easy_setopt(curl.get(), CURLOPT_WRITEFUNCTION, WriteCallback);
            curl_easy_setopt(curl.get(), CURLOPT_TIMEOUT_MS, config_.connectionTimeout);
            curl_easy_setopt(curl.get(), CURLOPT_SSL_VERIFYPEER, 1L);
            curl_easy_setopt(curl.get(), CURLOPT_SSL_VERIFYHOST, 2L);
            curl_easy_setopt(curl.get(), CURLOPT_CERTINFO, 1L);

            auto start = std::chrono::high_resolution_clock::now();
            CURLcode res = curl_easy_perform(curl.get());
            auto end = std::chrono::high_resolution_clock::now();

            if (res != CURLE_OK) {
                throw ProtocolException(curl_easy_strerror(res));
            }

            struct curl_certinfo *certinfo;
            res = curl_easy_getinfo(curl.get(), CURLINFO_CERTINFO, &certinfo);
            if (res == CURLE_OK && certinfo) {
                metrics_.securityDetails.algorithm = "TLS";
            }

            
            SSL *ssl;
            res = curl_easy_getinfo(curl.get(), CURLINFO_TLS_SSL_PTR, &ssl);
            if (res == CURLE_OK && ssl) {
                const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl);
                if (cipher) {
                    metrics_.encryptionType = SSL_CIPHER_get_name(cipher);
                    metrics_.securityDetails.keySize = SSL_CIPHER_get_bits(cipher, nullptr);
                    
                    metrics_.securityDetails.algorithm += std::string(" (") + 
                        SSL_get_version(ssl) + ")";
                }
            }

            double latency = std::chrono::duration<double, std::milli>(end - start).count();
            latencyMeasurements.push_back(latency);
            
            measurePacketLoss(url);

        } catch (const std::exception& e) {
            metrics_.warnings.push_back(std::string("HTTPS error: ") + e.what());
            throw;
        }

        calculateLatencyStats(latencyMeasurements);
        return metrics_;
    }

    std::string getProtocolName() const override { return "HTTP"; }

private:
    static size_t WriteCallback(void* contents [[maybe_unused]], 
                          size_t size, 
                          size_t nmemb, 
                          void* userp [[maybe_unused]]) {
        return size * nmemb;
    }

    void calculateLatencyStats(const std::vector<double>& measurements) {
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
    }
};

int main() {
    try {
        Config config = Config::fromJsonFile("config.json");
        HttpAnalyzer analyzer;
        analyzer.setConfig(config);

        auto metrics = analyzer.analyze("https://your-website.com");
        
        std::cout << "\n=== HTTPS Analysis Results ===\n";
        
        // Security Details
        std::cout << "Security Details:\n";
        std::cout << "  Protocol: " << metrics.securityDetails.algorithm << "\n";
        std::cout << "  Encryption: " << metrics.encryptionType << "\n\n";

        // Latency Statistics
        std::cout << "Latency Statistics:\n";
        std::cout << "  Min: " << metrics.latencyStats.min << " ms\n";
        std::cout << "  Max: " << metrics.latencyStats.max << " ms\n";
        std::cout << "  Average: " << metrics.latencyStats.avg << " ms\n";
        std::cout << "  Jitter: " << metrics.latencyStats.jitter << " ms\n\n";

        // Packet Statistics
        std::cout << "Packet Statistics:\n";
        std::cout << "  Packets Sent: " << metrics.packetStats.sent << "\n";
        std::cout << "  Packets Received: " << metrics.packetStats.received << "\n";
        std::cout << "  Packets Lost: " << metrics.packetStats.lost << "\n";
        std::cout << "  Loss Rate: " << (metrics.packetStats.lossRate * 100) << "%\n\n";

        if (!metrics.warnings.empty()) {
            std::cout << "Warnings:\n";
            for (const auto& warning : metrics.warnings) {
                std::cout << "  - " << warning << "\n";
            }
        }

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
