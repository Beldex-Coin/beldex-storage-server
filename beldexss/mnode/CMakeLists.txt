
add_library(mnode STATIC
    reachability_testing.cpp
    serialization.cpp
    master_node.cpp
    stats.cpp
    swarm.cpp)

target_link_libraries(mnode
    PUBLIC
    oxenmq::oxenmq
    cpr::cpr
    PRIVATE
    crypto
    utils
    server
    logging
    rpc
    oxenc::oxenc
    sodium)
