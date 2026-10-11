#pragma once
#include <string>
#include <mutex>
#include <fstream>
#include <optional>
#include <iostream>

namespace osf {

enum class LogLevel { Debug, Info, Warn, Error };

// Simple thread-safe logger. Writes to stderr and, optionally, a log file.
// Not a replacement for a real structured-logging library (spdlog, etc.) —
// swap this out if you need JSON lines, rotation, or async sinks.
class Logger {
public:
    static Logger& instance();

    void setLevel(LogLevel level);
    void setLogFile(const std::string& path);

    void debug(const std::string& component, const std::string& msg);
    void info(const std::string& component, const std::string& msg);
    void warn(const std::string& component, const std::string& msg);
    void error(const std::string& component, const std::string& msg);

private:
    Logger() = default;
    void log(LogLevel level, const std::string& component, const std::string& msg);
    static const char* levelName(LogLevel level);

    std::mutex mutex_;
    LogLevel minLevel_ = LogLevel::Info;
    std::optional<std::ofstream> fileStream_;
};

} // namespace osf
