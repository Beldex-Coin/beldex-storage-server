#include "common.hpp"

PYBIND11_MODULE(oxenmq, m) {
    oxenmq::OxenMQ_Init(m);
    oxenmq::BEncode_Init(m);
}
