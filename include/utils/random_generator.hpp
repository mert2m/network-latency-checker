#pragma once

#include <random>

namespace network_analyzer {
namespace utils {

class RandomGenerator {
public:
    static RandomGenerator& getInstance();
    double getProbability();

private:
    RandomGenerator();
    RandomGenerator(const RandomGenerator&) = delete;
    RandomGenerator& operator=(const RandomGenerator&) = delete;

    std::mt19937 generator_;
};

} // namespace utils
} // namespace network_analyzer 