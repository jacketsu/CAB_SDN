cmake_minimum_required(VERSION 2.8) 
project(CAB_TRACEGEN)

set(CMAKE_CXX_COMPILER /usr/bin/g++)
set(CMAKE_CXX_FLAGS "-std=c++11 -g")

find_package(Boost 1.54.0 REQUIRED COMPONENTS system thread filesystem iostreams log log_setup)
if(Boost_FOUND)
	message(STATUS "Boost found")
	message(STATUS "BOOST_LIBRARIES: " ${Boost_LIBRARIES})
endif()

add_definitions(-DBOOST_LOG_DYN_LINK)

#add_executable(TracePrepare_blk TracePrepare_blk.cpp TraceGen.cpp)
add_executable(TracePrepare TracePrepare.cpp TraceGen.cpp)
add_executable(FlowGen FlowGen.cpp)
add_executable(FlowEcho FlowEcho.cpp)
add_executable(CalTrace CalTrace.cpp)

if(UNIX)
    target_link_libraries(
        TracePrepare
        cab
        ${Boost_LIBRARIES}
        pthread
        z
        pcap
        )
    # target_link_libraries(
    #     TracePrepare_blk
    #     cab
    #     ${Boost_LIBRARIES}
    #     pthread
    #     z
    #     pcap
    #     )
    target_link_libraries(
        FlowGen
        cab
        pcap
        rt
        ${Boost_LIBRARIES}
        )
    target_link_libraries(
        FlowEcho
        pcap
        rt
        ${Boost_LIBRARIES}
        )
    target_link_libraries(
        CalTrace
        pcap
        rt
        ${Boost_LIBRARIES}
        )

elseif(WIN32)
elseif(APPLE)
endif(UNIX)

message(STATUS "c++ flag : " ${CMAKE_CXX_FLAGS}) 
message(STATUS "this is source dir " ${project_source_dir})
message(STATUS "this is binary dir " ${project_binary_dir})
