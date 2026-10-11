cmake_minimum_required(VERSION 3.20)
project(offensive_sec_framework CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

add_compile_options(-Wall -Wextra -Wpedantic)

find_package(Threads REQUIRED)

# ---- Core library (everything except main.cpp) ----
add_library(osf_core STATIC
  src/logging.cpp
  src/config.cpp
  src/target.cpp
  src/recon.cpp
  src/analysis.cpp
  src/module_registry.cpp
  src/reporting.cpp
  src/modules/example_module.cpp
)
target_include_directories(osf_core PUBLIC include)
target_link_libraries(osf_core PUBLIC Threads::Threads)

# Attack modules self-register via static initializers (REGISTER_ATTACK_MODULE),
# but a static library only pulls in .o files that something else actually
# references. Since nothing calls into a module's .o directly, the linker
# would otherwise silently drop it and the module would vanish from the
# registry. --whole-archive forces every object file in osf_core to be
# linked in, so self-registration works no matter how many modules you add.
function(link_whole_osf_core target)
  if(APPLE)
    target_link_libraries(${target} PRIVATE -Wl,-force_load osf_core)
  else()
    target_link_libraries(${target} PRIVATE -Wl,--whole-archive osf_core -Wl,--no-whole-archive)
  endif()
endfunction()

# ---- CLI executable ----
add_executable(osf src/main.cpp)
link_whole_osf_core(osf)

# ---- Tests ----
enable_testing()
add_executable(osf_tests
  tests/test_main.cpp
  tests/test_target.cpp
  tests/test_config.cpp
  tests/test_scope.cpp
)
link_whole_osf_core(osf_tests)
add_test(NAME osf_unit_tests COMMAND osf_tests)

install(TARGETS osf RUNTIME DESTINATION bin)
