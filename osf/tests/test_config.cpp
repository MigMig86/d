#include "test_harness.hpp"
#include "osf/config.hpp"
#include <fstream>
#include <cstdio>

using namespace osf;

TEST_CASE(ConfigParsesKeyValueFile) {
    const char* path = "/tmp/osf_test_config.conf";
    {
        std::ofstream f(path);
        f << "# comment\n";
        f << "port_range = 1-1000\n";
        f << "max_rate = 50\n";
        f << "verbose = true\n";
        f << "enabled_modules = example_noop, another_module\n";
    }
    Config cfg;
    std::string err;
    REQUIRE(cfg.loadFromFile(path, err));
    REQUIRE(cfg.getString("port_range") == "1-1000");
    REQUIRE(cfg.getInt("max_rate", -1) == 50);
    REQUIRE(cfg.getBool("verbose", false) == true);

    auto modules = cfg.getList("enabled_modules");
    REQUIRE(modules.size() == 2);
    REQUIRE(modules[0] == "example_noop");
    REQUIRE(modules[1] == "another_module");

    std::remove(path);
}

TEST_CASE(ConfigOverridesWork) {
    Config cfg;
    cfg.setOverride("foo", "bar");
    REQUIRE(cfg.getString("foo") == "bar");
    REQUIRE(cfg.getString("missing", "default") == "default");
}

TEST_CASE(MissingConfigFileFails) {
    Config cfg;
    std::string err;
    REQUIRE_FALSE(cfg.loadFromFile("/nonexistent/path.conf", err));
    REQUIRE_FALSE(err.empty());
}
