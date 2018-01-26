cmake_minimum_required(VERSION 2.8) 
project(CAB_DAEMON)

set(CMAKE_CXX_COMPILER /usr/bin/g++)
set(CMAKE_CXX_FLAGS "-std=c++11 -g")

find_package(Boost 1.54.0 REQUIRED COMPONENTS system thread filesystem iostreams log log_setup)
if(Boost_FOUND)
	message(STATUS "Boost found")
	message(STATUS "BOOST_LIBRARIES: " ${Boost_LIBRARIES})
endif()

add_definitions(-DBOOST_LOG_DYN_LINK)

set(CAB Bucket.cpp MicRuleTree.cpp RuleList.cpp BucketTree.cpp)
add_library(cab SHARED ${CAB})
set_property(TARGET cab PROPERTY POSITION_INDEPENDENT_CODE ON)

# add_executable(CABDaemon CABDaemon.cpp)
# 
# if(UNIX)
#     target_link_libraries(
#         CABDaemon
#         cab
#         ${Boost_LIBRARIES}
#         pthread
#         )
# elseif(WIN32)
# elseif(APPLE)
# endif(UNIX)

message(STATUS "c++ flag : " ${CMAKE_CXX_FLAGS}) 
message(STATUS "this is source dir " ${project_source_dir})
message(STATUS "this is binary dir " ${project_binary_dir})
