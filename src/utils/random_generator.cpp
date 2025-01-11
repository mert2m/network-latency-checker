#include "utils/random_generator.hpp"

namespace network_analyzer {
namespace utils {

RandomGenerator& RandomGenerator::getInstance() {
    static RandomGenerator instance;
    return instance;
}

RandomGenerator::RandomGenerator() 
    : generator_(std::random_device{}()) {}

double RandomGenerator::getProbability() {
    std::uniform_real_distribution<double> dist(0.0, 1.0);
    return dist(generator_);
}

} // namespace utils
} // namespace network_analyzer 