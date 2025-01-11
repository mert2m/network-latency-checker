#include "config/config.hpp"
#include <fstream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace network_analyzer {
namespace config {

Config Config::fromJsonFile(const std::string& path) {
    try {
        std::ifstream file(path);
        if (!file.is_open()) {
            throw utils::ConfigurationException("Cannot open config file: " + path);
        }

        json j = json::parse(file);
        Config config;
        
        if (j.contains("connectionTimeout")) {
            config.setConnectionTimeout(j["connectionTimeout"].get<int>());
        }
        if (j.contains("maxRetries")) {
            config.setMaxRetries(j["maxRetries"].get<int>());
        }
        config.setVerboseLogging(j.value("enableVerboseLogging", false));
        config.setOutputDirectory(j.value("outputDirectory", "./reports"));
        config.setLogLevel(j.value("logLevel", "INFO"));

        return config;
    } catch (const json::parse_error& e) {
        throw utils::ConfigurationException("JSON parse error: " + std::string(e.what()));
    } catch (const std::exception& e) {
        throw utils::ConfigurationException("Configuration error: " + std::string(e.what()));
    }
}

void Config::saveToFile(const std::string& path) const {
    try {
        json j;
        j["connectionTimeout"] = connectionTimeout_;
        j["maxRetries"] = maxRetries_;
        j["enableVerboseLogging"] = enableVerboseLogging_;
        j["outputDirectory"] = outputDirectory_;
        j["logLevel"] = logLevel_;

        std::ofstream file(path);
        if (!file.is_open()) {
            throw utils::ConfigurationException("Cannot create config file: " + path);
        }

        file << j.dump(4);
    } catch (const std::exception& e) {
        throw utils::ConfigurationException("Failed to save configuration: " + std::string(e.what()));
    }
}

void Config::setConnectionTimeout(int timeout) {
    if (timeout < 1000 || timeout > 30000) {
        throw utils::ConfigurationException("Connection timeout must be between 1000 and 30000 ms");
    }
    connectionTimeout_ = timeout;
}

void Config::setMaxRetries(int retries) {
    if (retries < 1 || retries > 10) {
        throw utils::ConfigurationException("Max retries must be between 1 and 10");
    }
    maxRetries_ = retries;
}

} // namespace config
} // namespace network_analyzer 