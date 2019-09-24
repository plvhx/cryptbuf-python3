#include <Python.h>
#include <stdint.h>

#include "./src/base64.h"
#include "./src/murmur3.h"
#include "./src/xxtea.h"

#ifndef CRYPTBUF_HASH_SEED
# define CRYPTBUF_HASH_SEED	0x01020304
#endif

static PyObject *CryptbufEncryptionRoutineError;
static PyObject *CryptbufDecryptionRoutineError;
static PyObject *CryptbufEncodingRoutineError;
static PyObject *CryptbufAllocationError;

static PyObject *
_cryptbuf_encrypt(PyObject *self, PyObject *args)
{
	PyObject *ret;
	const char *data, *key;
	int dlen, klen;
	uint32_t hash;
	uint8_t *tmp;
	char *hs, *ebuf, *fin;
	size_t olen;

	if (!PyArg_ParseTuple(args, "s#s#", &data, &dlen, &key, &klen))
		return NULL;

	hash = murmur3_x86_32(key, klen, (uint32_t)(CRYPTBUF_HASH_SEED >> 16));

	hs = calloc(9, sizeof(char));
	if (hs == NULL) {
		PyErr_Format(CryptbufAllocationError, "<%s> Virtual memory exhausted.", __FUNCTION__);
		return NULL;
	}

	sprintf(hs, "%08x", hash);

	tmp = xxtea_encrypt((const uint8_t *)data, dlen, (const uint8_t *)hs, &olen);
	if (tmp == NULL) {
		PyErr_Format(CryptbufEncryptionRoutineError, "<%s> Encryption routine failed.", __FUNCTION__);
		free(hs);
		return NULL;
	}

	ebuf = base64_encode((const char *)tmp, olen);
	if (ebuf == NULL) {
		PyErr_Format(CryptbufEncodingRoutineError, "<%s> Encoding routine failed.", __FUNCTION__);
		{ free(tmp); free(hs); }
		return NULL;
	}

	free(tmp);

	fin = calloc(
		strlen(hs) + strlen(ebuf) + 3,
		sizeof(char)
	);

	if (fin == NULL) {
		PyErr_Format(CryptbufAllocationError, "<%s> Virtual memory exhausted.", __FUNCTION__);
	}

	// copy serialized hash
	strncpy(fin, hs, 8);
	// copy '##'
	strncpy(fin + 8, "##", 2);
	// copy ebuf
	strncpy(fin + 10, ebuf, strlen(ebuf));

	ret = PyUnicode_FromString(fin);

	// free unused heap
	{ free(fin); free(ebuf); free(hs); }

	return ret;
}

static PyObject *
_cryptbuf_decrypt(PyObject *self, PyObject *args)
{
	PyObject *ret;
	const char *data, *key = NULL;
	int dlen, klen;
	uint32_t hash;
	char *hs, *tmp, *tmp2;
	uint8_t *dbuf;
	size_t olen;

	if (!PyArg_ParseTuple(args, "s#|z#", &data, &dlen, &key, &klen))
		return NULL;

	hs = calloc(9, sizeof(char));
	if (hs == NULL) {
		PyErr_Format(CryptbufAllocationError, "<%s> Virtual memory exhausted.", __FUNCTION__);
		return NULL;
	}

	if (key != NULL) {
		hash = murmur3_x86_32(key, klen, (uint32_t)(CRYPTBUF_HASH_SEED >> 16));
		sprintf(hs, "%08x", hash);
	} else if (key == NULL) {
		strncpy(hs, data, 8);
	}

	tmp = calloc(dlen - 9, sizeof(char));
	if (tmp == NULL) {
		PyErr_Format(CryptbufAllocationError, "<%s> Virtual memory exhausted.", __FUNCTION__);
		free(hs);
		return NULL;
	}

	strncpy(tmp, data + 10, dlen - 10);

	tmp2 = base64_decode(tmp, strlen(tmp), &olen);
	if (tmp2 == NULL) {
		PyErr_Format(CryptbufEncodingRoutineError, "<%s> Encoding routine failed.", __FUNCTION__);
		{ free(tmp); free(hs); }
		return NULL;
	}

	free(tmp);

	dbuf = xxtea_decrypt((const uint8_t *)tmp2, olen, (const uint8_t *)hs, &olen);
	if (dbuf == NULL) {
		PyErr_Format(CryptbufDecryptionRoutineError, "<%s> Decryption routine failed.", __FUNCTION__);
		{ free(tmp2); free(hs); }
		return NULL;
	}

	ret = PyUnicode_FromString((const char *)dbuf);

	// free unused heap
	{ free(dbuf); free(tmp2); free(hs); }

	return ret;
}

static PyMethodDef CryptbufMethods[] = {
	{ .ml_name = "cryptbuf_encrypt", .ml_meth = _cryptbuf_encrypt, .ml_flags = METH_VARARGS, .ml_doc = NULL },
	{ .ml_name = "cryptbuf_decrypt", .ml_meth = _cryptbuf_decrypt, .ml_flags = METH_VARARGS, .ml_doc = NULL },
	{ .ml_name = NULL, .ml_meth = NULL, .ml_flags = 0, .ml_doc = NULL }
};

static struct PyModuleDef cryptbuf_module = {
	.m_base = PyModuleDef_HEAD_INIT,
	.m_name = "cryptbuf",
	.m_doc = NULL,
	.m_size = sizeof(struct PyModuleDef),
	.m_methods = CryptbufMethods,
};

PyMODINIT_FUNC
PyInit_cryptbuf(void)
{
	PyObject *q;

	q = PyModule_Create(&cryptbuf_module);
	if (q == NULL)
		return NULL;

	CryptbufEncryptionRoutineError = PyErr_NewException("cryptbuf.encrypt_error", PyExc_BaseException, NULL);
	Py_INCREF(CryptbufEncryptionRoutineError);
	PyModule_AddObject(q, "error", CryptbufEncryptionRoutineError);

	CryptbufDecryptionRoutineError = PyErr_NewException("cryptbuf.decrypt_error", PyExc_BaseException, NULL);
	Py_INCREF(CryptbufDecryptionRoutineError);
	PyModule_AddObject(q, "error", CryptbufDecryptionRoutineError);

	CryptbufEncodingRoutineError = PyErr_NewException("cryptbuf.encoding_error", PyExc_BaseException, NULL);
	Py_INCREF(CryptbufEncodingRoutineError);
	PyModule_AddObject(q, "error", CryptbufEncodingRoutineError);

	CryptbufAllocationError = PyErr_NewException("cryptbuf.allocation_error", PyExc_BaseException, NULL);
	Py_INCREF(CryptbufAllocationError);
	PyModule_AddObject(q, "error", CryptbufAllocationError);

	return q;
}
