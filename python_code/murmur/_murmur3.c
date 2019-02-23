#include <Python.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>

#include "murmur3.h"

static PyObject *murmur3_murmur3(PyObject *self, PyObject *args);

static char module_docstring[] = "This module provides an interface for calculating a hash using murmur3.";
static char murmur3_docstring[] = "Compute a 32 bits hash with murmur3.";

static PyMethodDef module_methods[] = {
    {"murmur3", murmur3_murmur3, METH_VARARGS, murmur3_docstring},
    {NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC init_murmur3(void)
{
    PyObject *m = Py_InitModule3("_murmur3", module_methods, module_docstring);
    if (m == NULL)
        return;
}

static PyObject *murmur3_murmur3(PyObject *self, PyObject *args) {

    uint16_t key;
    //char *key;
    uint32_t len;
    uint32_t seed;

    /* Parse the input tuple */
    if (!PyArg_ParseTuple(args, "III", &key, &len, &seed))
        return NULL;

    uint32_t hash = murmur3((char *)&key, len, seed);

    PyObject *ret = Py_BuildValue("I", hash);
    return ret;
}
