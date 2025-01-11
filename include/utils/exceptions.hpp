#pragma once

#include <stdexcept>
#include <string>

namespace network_analyzer {
namespace utils {

class ConfigurationException : public std::runtime_error {
public:
    explicit ConfigurationException(const std::string& message) 
        : std::runtime_error(message) {}
};

class ProtocolException : public std::runtime_error {
public:
    explicit ProtocolException(const std::string& message) 
        : std::runtime_error(message) {}
};

} // namespace utils
} // namespace network_analyzer 