#include <Python.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>

#include "murmur3.h"

static PyObject *murmur3str_murmur3str(PyObject *self, PyObject *args);

static char module_docstring[] = "This module provides an interface for calculating a hash using murmur3.";
static char murmur3str_docstring[] = "Compute a 32 bits hash with murmur3.";

static PyMethodDef module_methods[] = {
    {"murmur3str", murmur3str_murmur3str, METH_VARARGS, murmur3str_docstring},
    {NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC init_murmur3str(void)
{
    PyObject *m = Py_InitModule3("_murmur3str", module_methods, module_docstring);
    if (m == NULL)
        return;
}

static PyObject *murmur3str_murmur3str(PyObject *self, PyObject *args) {

    //uint16_t key;
    char *key;
    uint32_t len;
    uint32_t seed;

    /* Parse the input tuple */
    if (!PyArg_ParseTuple(args, "sII", &key, &len, &seed))
        return NULL;

    uint32_t hash = murmur3(key, len, seed);

    PyObject *ret = Py_BuildValue("I", hash);
    return ret;
}
