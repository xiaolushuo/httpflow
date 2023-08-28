cmake_minimum_required(VERSION 3.11)  # FetchContent is available in 3.11+
project(httpflow)

include_directories(/usr/local/include)
include_directories(/usr/include/)
link_directories(/usr/lib64/)

include(FetchContent)

set(ICU_INCLUDE_DIR /usr/local/opt/icu4c/include)
set(ICU_LIBRARY /usr/local/opt/icu4c/lib)

include_directories(${ICU_INCLUDE_DIR})
link_directories(${ICU_LIBRARY})

find_package(ICU REQUIRED)

# Find Boost on your system
find_package(Boost REQUIRED filesystem system)

# Include Boost's header files
include_directories(${Boost_INCLUDE_DIRS})

add_subdirectory(external/nlohmann_json)
add_executable(httpflow http_flow.cpp stream_parser.cpp util.cpp data_link.cpp http_parser.cpp)

# Find C++ REST SDK on your system
find_package(cpprestsdk REQUIRED)

# Find OpenSSL on your system
find_package(OpenSSL REQUIRED)

# Find yaml-cpp on your system
find_path(YAMLCPP_INCLUDE_DIR NAMES yaml-cpp/yaml.h)
find_library(YAMLCPP_LIBRARY NAMES yaml-cpp)

include_directories(${YAMLCPP_INCLUDE_DIR})
link_directories(${YAMLCPP_LIBRARY})

# Find hiredis on your system
find_library(HIREDIS_LIBRARY NAMES hiredis)

target_link_libraries(httpflow 
    nlohmann_json::nlohmann_json 
    pcap 
    z 
    pcre 
    ${Boost_FILESYSTEM_LIBRARY} 
    ${Boost_SYSTEM_LIBRARY} 
    icuuc 
    icudata 
    cpprestsdk::cpprest 
    ${OPENSSL_LIBRARIES} 
    ${YAMLCPP_LIBRARY} 
    ${HIREDIS_LIBRARY}
    Boost::regex
)