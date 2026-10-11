#pragma once
#include "osf/attack_module.hpp"
#include <functional>
#include <map>
#include <string>
#include <vector>

namespace osf {

using ModuleFactory = std::function<AttackModulePtr()>;

// Self-registration registry for attack modules. Modules register
// themselves at static-init time via REGISTER_ATTACK_MODULE(ClassName),
// so adding a new module means writing one .cpp file and adding it to
// CMakeLists.txt — nothing else in the framework needs to change.
class ModuleRegistry {
public:
    static ModuleRegistry& instance();

    void registerFactory(const std::string& moduleName, ModuleFactory factory);
    AttackModulePtr create(const std::string& moduleName) const;
    std::vector<std::string> listNames() const;

private:
    std::map<std::string, ModuleFactory> factories_;
};

struct ModuleRegistrar {
    ModuleRegistrar(const std::string& name, ModuleFactory factory) {
        ModuleRegistry::instance().registerFactory(name, std::move(factory));
    }
};

} // namespace osf

#define REGISTER_ATTACK_MODULE(ClassName)                                         \
    static ::osf::ModuleRegistrar _registrar_##ClassName(                        \
        ClassName().name(),                                                       \
        []() -> ::osf::AttackModulePtr { return std::make_shared<ClassName>(); })
