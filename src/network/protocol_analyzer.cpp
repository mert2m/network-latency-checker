#include "network/protocol_analyzer.hpp"

namespace network_analyzer {
namespace network {

void ProtocolAnalyzer::measurePacketLoss(const std::string& target [[maybe_unused]]) {
    constexpr int NUM_PACKETS = 100;
    int received = 0;
    auto& random = utils::RandomGenerator::getInstance();

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

} // namespace network
} // namespace network_analyzer 