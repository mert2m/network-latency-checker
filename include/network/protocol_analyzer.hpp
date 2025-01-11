#pragma once

#include <string>
#include <mutex>
#include <thread>
#include "config/config.hpp"
#include "metrics/protocol_metrics.hpp"
#include "utils/random_generator.hpp"

namespace network_analyzer {
namespace network {

class ProtocolAnalyzer {
public:
    virtual ~ProtocolAnalyzer() = default;
    virtual metrics::ProtocolMetrics analyze(const std::string& target) = 0;
    virtual std::string getProtocolName() const = 0;

    void setConfig(const config::Config& config) { config_ = config; }
    const metrics::ProtocolMetrics& getLastMetrics() const { return metrics_; }

protected:
    metrics::ProtocolMetrics metrics_;
    config::Config config_;
    std::mutex metricsMutex_;

    void measurePacketLoss(const std::string& target);
};

} // namespace network
} // namespace network_analyzer 