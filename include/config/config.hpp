#pragma once

#include <string>
#include "utils/exceptions.hpp"

namespace network_analyzer {
namespace config {

class Config {
public:
    static Config fromJsonFile(const std::string& path);
    void saveToFile(const std::string& path) const;

    // Getters
    int getConnectionTimeout() const { return connectionTimeout_; }
    int getMaxRetries() const { return maxRetries_; }
    bool isVerboseLoggingEnabled() const { return enableVerboseLogging_; }
    const std::string& getOutputDirectory() const { return outputDirectory_; }
    const std::string& getLogLevel() const { return logLevel_; }

    // Setters with validation
    void setConnectionTimeout(int timeout);
    void setMaxRetries(int retries);
    void setVerboseLogging(bool enable) { enableVerboseLogging_ = enable; }
    void setOutputDirectory(const std::string& dir) { outputDirectory_ = dir; }
    void setLogLevel(const std::string& level) { logLevel_ = level; }

private:
    int connectionTimeout_{5000};      // ms
    int maxRetries_{3};
    bool enableVerboseLogging_{false};
    std::string outputDirectory_{"./reports"};
    std::string logLevel_{"INFO"};
};

} // namespace config
} // namespace network_analyzer 