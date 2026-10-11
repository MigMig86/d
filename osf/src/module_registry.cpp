#include "osf/module_registry.hpp"

namespace osf {

ModuleRegistry& ModuleRegistry::instance() {
    static ModuleRegistry inst;
    return inst;
}

void ModuleRegistry::registerFactory(const std::string& moduleName, ModuleFactory factory) {
    factories_[moduleName] = std::move(factory);
}

AttackModulePtr ModuleRegistry::create(const std::string& moduleName) const {
    auto it = factories_.find(moduleName);
    if (it == factories_.end()) return nullptr;
    return it->second();
}

std::vector<std::string> ModuleRegistry::listNames() const {
    std::vector<std::string> names;
    names.reserve(factories_.size());
    for (const auto& [name, _] : factories_) names.push_back(name);
    return names;
}

} // namespace osf
