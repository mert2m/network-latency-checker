#include <iostream>
#include <iomanip>
#include "config/config.hpp"
#include "network/http_analyzer.hpp"
#include "utils/exceptions.hpp"

using namespace network_analyzer;

void printMetrics(const metrics::ProtocolMetrics& metrics) {
    std::cout << "\n=== HTTPS Analysis Results ===\n";
    
    // Security Details
    std::cout << "Security Details:\n";
    std::cout << "  Protocol: " << metrics.securityDetails.algorithm << "\n";
    std::cout << "  Encryption: " << metrics.encryptionType << "\n";
    if (!metrics.securityDetails.certificateIssuer.empty()) {
        std::cout << "  Certificate Issuer: " << metrics.securityDetails.certificateIssuer << "\n";
        std::cout << "  Certificate Expiry: " << metrics.securityDetails.certificateExpiry << "\n";
    }
    std::cout << "\n";

    // HTTP/2 Details
    std::cout << "HTTP/2 Details:\n";
    std::cout << "  Enabled: " << (metrics.http2Metrics.enabled ? "Yes" : "No") << "\n";
    if (metrics.http2Metrics.enabled) {
        std::cout << "  Protocol: " << metrics.http2Metrics.alpnProtocol << "\n";
        std::cout << "  Multiplexing: " << (metrics.http2Metrics.multiplexingEnabled ? "Yes" : "No") << "\n";
        if (!metrics.http2Metrics.compressionAlgorithm.empty()) {
            std::cout << "  Compression: " << metrics.http2Metrics.compressionAlgorithm;
        }
    }
    std::cout << "\n";

    // Throughput Metrics
    std::cout << "Throughput Metrics:\n";
    std::cout << "  Download Speed: " << std::fixed << std::setprecision(2) 
             << metrics.throughputMetrics.downloadSpeed / 1024.0 << " KB/s\n";
    std::cout << "  Total Received: " << std::fixed << std::setprecision(2) 
             << metrics.throughputMetrics.totalBytesReceived / 1024.0 << " KB\n";
    if (metrics.compressionEnabled) {
        std::cout << "  Compression Ratio: " << metrics.throughputMetrics.compressionRatio << "\n";
    }
    std::cout << "\n";

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

    // Warnings and Recommendations
    if (!metrics.warnings.empty()) {
        std::cout << "Warnings:\n";
        for (const auto& warning : metrics.warnings) {
            std::cout << "  - " << warning << "\n";
        }
        std::cout << "\n";
    }

    if (!metrics.recommendations.empty()) {
        std::cout << "Recommendations:\n";
        for (const auto& recommendation : metrics.recommendations) {
            std::cout << "  - " << recommendation << "\n";
        }
    }
}

int main() {
    try {
        config::Config config = config::Config::fromJsonFile("config.json");
        network::HttpAnalyzer analyzer;
        analyzer.setConfig(config);

        auto metrics = analyzer.analyze("https://acedemand.com");
        printMetrics(metrics);

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
} 