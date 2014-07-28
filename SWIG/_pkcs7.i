/* Copyright (c) 2000 Ng Pheng Siong. All rights reserved.
 * Copyright (c) 2009-2010 Heikki Toivonen. All rights reserved.
*/
/* $Id: _pkcs7.i 723 2010-02-13 06:53:13Z heikki $ */

%{
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pkcs7.h>
%}

%apply Pointer NONNULL { BIO * };
%apply Pointer NONNULL { EVP_CIPHER * };
%apply Pointer NONNULL { EVP_PKEY * };
%apply Pointer NONNULL { PKCS7 * };
%apply Pointer NONNULL { STACK_OF(X509) * };
%apply Pointer NONNULL { X509 * };

%rename(pkcs7_new) PKCS7_new;
extern PKCS7 *PKCS7_new(void);
%rename(pkcs7_free) PKCS7_free;
extern void PKCS7_free(PKCS7 *);
%rename(pkcs7_add_certificate) PKCS7_add_certificate;
extern void PKCS7_add_certificate(PKCS7 *, X509 *);

/* S/MIME operation */
%constant int PKCS7_TEXT       = 0x1;
%constant int PKCS7_NOCERTS    = 0x2;
%constant int PKCS7_NOSIGS     = 0x4;
%constant int PKCS7_NOCHAIN    = 0x8;
%constant int PKCS7_NOINTERN   = 0x10;
%constant int PKCS7_NOVERIFY   = 0x20;
%constant int PKCS7_DETACHED   = 0x40;
%constant int PKCS7_BINARY     = 0x80;
%constant int PKCS7_NOATTR     = 0x100;

%constant int PKCS7_SIGNED            = NID_pkcs7_signed;
%constant int PKCS7_ENVELOPED         = NID_pkcs7_enveloped;
%constant int PKCS7_SIGNED_ENVELOPED  = NID_pkcs7_signedAndEnveloped;
%constant int PKCS7_DATA              = NID_pkcs7_data;

%inline %{
static PyObject *_pkcs7_err, *_smime_err;

void pkcs7_init(PyObject *pkcs7_err) {
    Py_INCREF(pkcs7_err);
    _pkcs7_err = pkcs7_err;
}

void smime_init(PyObject *smime_err) {
    Py_INCREF(smime_err);
    _smime_err = smime_err;
}
%}

%threadallow pkcs7_encrypt;
%inline %{
PKCS7 *pkcs7_encrypt(STACK_OF(X509) *stack, BIO *bio, EVP_CIPHER *cipher, int flags) {
    return PKCS7_encrypt(stack, bio, cipher, flags);
}

PyObject *pkcs7_decrypt(PKCS7 *pkcs7, EVP_PKEY *pkey, X509 *cert, int flags) {
    int outlen;
    char *outbuf;
    BIO *bio;
    PyObject *ret; 

    if (!(bio=BIO_new(BIO_s_mem()))) {
        PyErr_SetString(PyExc_MemoryError, "pkcs7_decrypt");
        return NULL;
    }
    if (!PKCS7_decrypt(pkcs7, pkey, cert, bio, flags)) {
        PyErr_SetString(_pkcs7_err, ERR_reason_error_string(ERR_get_error()));
        BIO_free(bio);
        return NULL;
    }
    outlen = BIO_ctrl_pending(bio);
    if (!(outbuf=(char *)PyMem_Malloc(outlen))) {
        PyErr_SetString(PyExc_MemoryError, "pkcs7_decrypt");
        BIO_free(bio);
        return NULL;
    }
    BIO_read(bio, outbuf, outlen);
    ret = PyString_FromStringAndSize(outbuf, outlen);
    BIO_free(bio);
    PyMem_Free(outbuf);
    return ret;
}
%}

%threadallow pkcs7_sign0;
%inline %{
PKCS7 *pkcs7_sign0(X509 *x509, EVP_PKEY *pkey, BIO *bio, int flags) {
    return PKCS7_sign(x509, pkey, NULL, bio, flags);
}
%}

%threadallow pkcs7_sign1;
%inline %{
PKCS7 *pkcs7_sign1(X509 *x509, EVP_PKEY *pkey, STACK_OF(X509) *stack, BIO *bio, int flags) {
    return PKCS7_sign(x509, pkey, stack, bio, flags);
}
%}

%inline %{
PyObject *pkcs7_verify1(PKCS7 *pkcs7, STACK_OF(X509) *stack, X509_STORE *store, BIO *data, int flags) {
    int res, outlen;
    char *outbuf;
    BIO *bio;
    PyObject *ret; 

    if (!(bio=BIO_new(BIO_s_mem()))) {
        PyErr_SetString(PyExc_MemoryError, "pkcs7_verify1");
        return NULL;
    }
    Py_BEGIN_ALLOW_THREADS
    res = PKCS7_verify(pkcs7, stack, store, data, bio, flags);
    Py_END_ALLOW_THREADS
    if (!res) {
        ERR_print_errors_fp(stderr);
        PyErr_SetString(_pkcs7_err, ERR_reason_error_string(ERR_get_error()));
        BIO_free(bio);
        return NULL;
    }
    outlen = BIO_ctrl_pending(bio);
    if (!(outbuf=(char *)PyMem_Malloc(outlen))) {
        PyErr_SetString(PyExc_MemoryError, "pkcs7_verify1");
        BIO_free(bio);
        return NULL;
    }
    BIO_read(bio, outbuf, outlen);
    ret = PyString_FromStringAndSize(outbuf, outlen);
    BIO_free(bio);
    PyMem_Free(outbuf);
    return ret;
}

PyObject *pkcs7_verify0(PKCS7 *pkcs7, STACK_OF(X509) *stack, X509_STORE *store, int flags) {
    return pkcs7_verify1(pkcs7, stack, store, NULL, flags);
}
%}

%threadallow smime_write_pkcs7_multi;
%inline %{
int smime_write_pkcs7_multi(BIO *bio, PKCS7 *pkcs7, BIO *data, int flags) {
    return SMIME_write_PKCS7(bio, pkcs7, data, flags | PKCS7_DETACHED);
}
%}

%threadallow smime_write_pkcs7;
%inline %{
int smime_write_pkcs7(BIO *bio, PKCS7 *pkcs7, int flags) {
    return SMIME_write_PKCS7(bio, pkcs7, NULL, flags);
}

PyObject *smime_read_pkcs7(BIO *bio) {
    BIO *bcont = NULL;
    PKCS7 *p7;
    PyObject *tuple, *_p7, *_BIO;

    if (BIO_method_type(bio) == BIO_TYPE_MEM) {
        /* OpenSSL FAQ explains that this is needed for mem BIO to return EOF,
         * like file BIO does. Might need to do this for more mem BIOs but
         * not sure if that is safe, so starting with just this single place.
         */
        BIO_set_mem_eof_return(bio, 0);
    }

    Py_BEGIN_ALLOW_THREADS
    p7=SMIME_read_PKCS7(bio, &bcont);
    Py_END_ALLOW_THREADS
    if (!p7) {
        PyErr_SetString(_smime_err, ERR_reason_error_string(ERR_get_error()));
        return NULL;
    }
    if (!(tuple=PyTuple_New(2))) {
        PyErr_SetString(PyExc_RuntimeError, "PyTuple_New() fails");
        return NULL;
    }
    _p7 = SWIG_NewPointerObj((void *)p7, SWIGTYPE_p_PKCS7, 0);
    PyTuple_SET_ITEM(tuple, 0, _p7);
    if (!bcont) {
        Py_INCREF(Py_None);
        PyTuple_SET_ITEM(tuple, 1, Py_None);
    } else {
        _BIO = SWIG_NewPointerObj((void *)bcont, SWIGTYPE_p_BIO, 0);
        PyTuple_SET_ITEM(tuple, 1, _BIO);
    }
    return tuple;
}
%}

%threadallow pkcs7_read_bio;
%inline %{
PKCS7 *pkcs7_read_bio(BIO *bio) {
    return PEM_read_bio_PKCS7(bio, NULL, NULL, NULL);
}
%}

%threadallow pkcs7_read_bio_der;
%inline %{
PKCS7 *pkcs7_read_bio_der(BIO *bio) {
    return d2i_PKCS7_bio(bio, NULL);
}
%}

%threadallow pkcs7_write_bio;
%inline %{
int pkcs7_write_bio(PKCS7 *pkcs7, BIO* bio) {
    return PEM_write_bio_PKCS7(bio, pkcs7);
}
%}

%threadallow pkcs7_write_bio_der;
%inline %{
int pkcs7_write_bio_der(PKCS7 *pkcs7, BIO *bio) {
    return i2d_PKCS7_bio(bio, pkcs7);
}

int pkcs7_type_nid(PKCS7 *pkcs7) {
    return OBJ_obj2nid(pkcs7->type);
}

const char *pkcs7_type_sn(PKCS7 *pkcs7) {
    return OBJ_nid2sn(OBJ_obj2nid(pkcs7->type));
}
%}

%threadallow smime_crlf_copy;
%inline %{
int smime_crlf_copy(BIO *in, BIO *out) {
    return SMIME_crlf_copy(in, out, PKCS7_TEXT);
}

/* return STACK_OF(X509)* */     
STACK_OF(X509) *pkcs7_get0_signers(PKCS7 *p7, STACK_OF(X509) *certs, int flags) {     
    return PKCS7_get0_signers(p7, certs, flags);      
}

/* return STACK_OF(X509)* */     
STACK_OF(X509) *pkcs7_get_certs(PKCS7 *p7, STACK_OF(X509) *certs) {     
    if(p7){
        int type = OBJ_obj2nid(p7->type);
        if(type==NID_pkcs7_signed) {
            certs = p7->d.sign->cert;
        }else if(type==NID_pkcs7_signedAndEnveloped) {
            certs = p7->d.signed_and_enveloped->cert;
        }
    }
    return certs;
}
%}

%inline %{
PKCS7 * pkcs7_sign_raw1(X509* cert, EVP_PKEY* pkey, STACK_OF(X509) *certs, BIO* data_bio, int flags ,int md){
    PKCS7_SIGNER_INFO* info = NULL;
    BIO* p7bio = NULL;
    int outlen = 0;
    char* outbuf = NULL;
    EVP_MD* MD = NULL;
    int i = 0;
    PKCS7* p7 = PKCS7_new();
	if (p7 == NULL){
		PyErr_SetString(PyExc_MemoryError, "pkcs7_sign_raw1");
		return NULL;
	}
    outlen = BIO_ctrl_pending(data_bio);
    outbuf = NULL;
    if (!(outbuf=(char *)PyMem_Malloc(outlen))) {
        PyErr_SetString(PyExc_MemoryError, "pkcs7_sign_raw1");
        return NULL;
    }
    BIO_read(data_bio, outbuf, outlen);

    switch(md){
        case NID_sha1: MD = EVP_sha1(); break;
        case NID_sha224: MD = EVP_sha224(); break;
        case NID_sha256: MD = EVP_sha256(); break;
        case NID_sha384: MD = EVP_sha384(); break;
        case NID_sha512: MD = EVP_sha512(); break;
        case NID_md5: MD = EVP_md5(); break;
        case NID_ripemd160: MD = EVP_ripemd160(); break;
        default: MD = EVP_sha1(); break;
    }
    
	PKCS7_set_type(p7, NID_pkcs7_signed);
	PKCS7_content_new(p7, NID_pkcs7_data);
	PKCS7_set_detached(p7, 1);
	info = PKCS7_add_signature(p7, cert, pkey, MD);
	if (info == NULL){
        goto outerr;
	}
    
    for(i = 0; i < sk_X509_num(certs); i++) {
		if (!PKCS7_add_certificate(p7, sk_X509_value(certs, i))) {
            goto outerr;
		}
	}
	
	p7bio = PKCS7_dataInit(p7, NULL);
	if (p7bio == NULL){
		goto outerr;
	}
    
	BIO_write(p7bio, outbuf, outlen);
	PKCS7_dataFinal(p7, p7bio);
	return p7;
    
outerr:{
        ERR_print_errors_fp(stderr);
        PyErr_SetString(_pkcs7_err, ERR_reason_error_string(ERR_get_error()));
        PKCS7_free(p7);
        return NULL;
    }   
}


%}

