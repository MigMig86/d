#include "osf/logging.hpp"
#include <chrono>
#include <ctime>
#include <sstream>
#include <iomanip>

namespace osf {

Logger& Logger::instance() {
    static Logger inst;
    return inst;
}

void Logger::setLevel(LogLevel level) {
    std::lock_guard<std::mutex> lock(mutex_);
    minLevel_ = level;
}

void Logger::setLogFile(const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);
    fileStream_.emplace(path, std::ios::out | std::ios::app);
}

const char* Logger::levelName(LogLevel level) {
    switch (level) {
        case LogLevel::Debug: return "DEBUG";
        case LogLevel::Info:  return "INFO";
        case LogLevel::Warn:  return "WARN";
        case LogLevel::Error: return "ERROR";
    }
    return "?";
}

void Logger::log(LogLevel level, const std::string& component, const std::string& msg) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (static_cast<int>(level) < static_cast<int>(minLevel_)) return;

    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
    localtime_r(&t, &tm);

    std::ostringstream line;
    line << std::put_time(&tm, "%Y-%m-%dT%H:%M:%S")
         << " [" << levelName(level) << "] "
         << "(" << component << ") " << msg;

    std::cerr << line.str() << std::endl;
    if (fileStream_) {
        *fileStream_ << line.str() << std::endl;
        fileStream_->flush();
    }
}

void Logger::debug(const std::string& component, const std::string& msg) { log(LogLevel::Debug, component, msg); }
void Logger::info(const std::string& component, const std::string& msg)  { log(LogLevel::Info, component, msg); }
void Logger::warn(const std::string& component, const std::string& msg)  { log(LogLevel::Warn, component, msg); }
void Logger::error(const std::string& component, const std::string& msg) { log(LogLevel::Error, component, msg); }

} // namespace osf
