
pybind11_add_module(pyoxenmq MODULE
  bencode.cpp
  oxenmq.cpp
  module.cpp
)

target_link_libraries(pyoxenmq PUBLIC PkgConfig::oxenmq)


