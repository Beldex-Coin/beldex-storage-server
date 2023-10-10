from setuptools import setup

# Available at setup time due to pyproject.toml
from pybind11.setup_helpers import Pybind11Extension, build_ext

__version__ = "1.0.2"

# Note:
#   Sort input source files if you glob sources to ensure bit-for-bit
#   reproducible builds (https://github.com/pybind/python_example/pull/53)

ext_modules = [Pybind11Extension(
        "oxenmq",
        ["src/bencode.cpp", "src/module.cpp", "src/oxenmq.cpp"],
        cxx_std=17,
        libraries=["oxenmq"],
        ),
]

setup(
    name="oxenmq",
    version=__version__,
    author="Jason Rhinelander",
    author_email="jason@oxen.io",
    url="https://github.com/oxen-io/oxen-mq",
    description="Python wrapper for oxen-mq message passing library",
    long_description="",
    ext_modules=ext_modules,
    zip_safe=False,
)
