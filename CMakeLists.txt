cmake_minimum_required(VERSION 3.15)
project(PublicKeyCollector)

set(CMAKE_CXX_STANDARD 11)
include_directories(/usr/local/include)
link_directories(/usr/local/lib)

# TODO: Prepared for boost testing
enable_testing()
set(Boost_ADDITIONAL_VERSIONS "1.XX" "1.XX.0")

# TODO: SSHCollector and it's test cases
set(SSHCollectorSrcs ./src/SSHCollector.cpp ./src/AbstractCollector.cpp ./src/SSHsCollector.cpp)
set(SSHCollectorLinks gmpxx gmp spdlog ssh)
add_library(SSHCollector ${SSHCollectorSrcs})
target_include_directories(SSHCollector
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include/>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/
)
set_target_properties(SSHCollector
    PROPERTIES
        LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/lib
        ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/lib
)
target_link_libraries(SSHCollector ${SSHCollectorLinks})

add_executable(SSHCollectorTestCases ./test/SSHCollectorTestCases.cpp ${SSHCollectorSrcs})
target_link_libraries(SSHCollectorTestCases boost_unit_test_framework ${SSHCollectorLinks})