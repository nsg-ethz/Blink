from distutils.core import setup, Extension
import numpy.distutils.misc_util

setup(ext_modules=[Extension("_murmur3", ["_murmur3.c", "murmur3.c"])])
setup(ext_modules=[Extension("_murmur3str", ["_murmur3str.c", "murmur3.c"])])


## Website: http://dfm.io/posts/python-c-extensions/
