#pragma once

#include <string>
#include <vector>
#include <limits>

namespace network_analyzer {
namespace metrics {

struct LatencyStats {
    double min{std::numeric_limits<double>::max()};
    double max{std::numeric_limits<double>::lowest()};
    double avg{0.0};
    double jitter{0.0};
};

struct PacketStats {
    int sent{0};
    int received{0};
    int lost{0};
    double lossRate{0.0};
};

struct SecurityDetails {
    std::string algorithm;
    int keySize{0};
    bool perfect_forward_secrecy{false};
    std::string certificateIssuer;
    std::string certificateExpiry;
    bool certificateValid{false};
};

struct Http2Metrics {
    bool enabled{false};
    int streams{0};
    std::string alpnProtocol;
    bool multiplexingEnabled{false};
    bool serverPushEnabled{false};
    std::string compressionAlgorithm;
};

struct ThroughputMetrics {
    double downloadSpeed{0.0};  // bytes per second
    double uploadSpeed{0.0};    // bytes per second
    double totalBytesReceived{0.0};
    double totalBytesSent{0.0};
    double compressionRatio{1.0};
};

struct ProtocolMetrics {
    double latency{0.0};
    double packetLoss{0.0};
    int bandwidth{0};
    std::string encryptionType;
    bool compressionEnabled{false};

    LatencyStats latencyStats;
    PacketStats packetStats;
    SecurityDetails securityDetails;
    Http2Metrics http2Metrics;
    ThroughputMetrics throughputMetrics;

    std::vector<std::string> warnings;
    std::vector<std::string> recommendations;
};

} // namespace metrics
} // namespace network_analyzer 