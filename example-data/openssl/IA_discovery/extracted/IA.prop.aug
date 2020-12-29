Base64 BIO does not support BIO_gets_APIName or BIO_puts_APIName
The behavior of this function is similar to CMS_verify, but the flag values ​​CMS_DETACHED, CMS_BINARY, CMS_TEXT and CMS_STREAM are not supported
In order to successfully conduct transparent negotiation, SSL_write_APIParam_1 must have been initialized to client or server mode.
The calling process must be repeated after taking appropriate measures to meet the requirements of SSL_accept
Parameters and restrictions are the same as encryption operations, except that
The string is returned as des_read_pw_APIParam_1 des_read_pw_APIParam_1, the string must have at least des_read_pw_APIParam_3 des_read_pw_APIParam_3 bytes of space
The EVP_PKEY_CTX_set_rsa_pss_saltlen macro sets the RSA PSS salt length to EVP_PKEY_CTX_set_rsa_pss_saltlen_APIParam_2 because its name implies that only PSS padding is supported
SSL_CTX_new_APIParam_1 can be of the following types
EVP_DecryptFinal will return an error code
Certificate and CRL storage area is used internally in the associated X509_STORE_CTX_set0_param_APIParam_1 X509_STORE_CTX_get0_param_APIParam_1 X509_STORE_CTX_free_APIParam_1 X509_STORE_CTX_set_default_API_Par_up_Clean_API_ST_Clean_API_up_Clean_API_up_Cert_up_Cert_up_Cert_API_up_Clean_API_ST_Clean_API_ST_Clean_CAPI_UP_Clean_API_Par__1C
If successful, ECDSA_sign_setup_APIName and ECDSA_sign_APIName return 1, if error returns 0
Host can be "", interpreted as any interface
The contents of the signed receipt should only be considered meaningful
ASN1_OBJECT_new_APIName is almost never used in applications
This function will return the length of the decoded data, or -1 if there is an error
The SSL_SESSION object must be converted to binary ASN1 representation
d2i_X509_APIName, d2i_X509_bio_APIName and d2i_X509_fp_APIName return valid d2i_X509_APIParam_1 d2i_X509_bio_APIParam_2 d2i_X509_fp_APIParam_2 structure or NULL if an error occurs
If the structure indicates the use of any other algorithm, an error is returned
CMS_ContentInfo structure CMS_add0_crl_APIParam_1 CMS_add1_crl_APIParam_1 CMS_add0_cert_APIParam_1 CMS_add1_cert_APIParam_1 type must be signature data or package data, otherwise an error will be returned
BN_CTX_init_APIName should not be used for new programs
The API is only called on the SSL/TLS server with the session ID suggested by the client
The certificate will never be used
If the public key parameter of EVP_PKEY_missing_parameters_APIParam_1 is missing, the function EVP_PKEY_missing_parameters_APIName returns 1; if it exists, it returns 0; if it exists, or the algorithm does not use parameters, it returns 0.
The validity of the certificate and its trust level must be checked by other means
An SSL_SESSION object, regardless of its reference count, can only be used with an SSL_CTX object
Must call CMS_final_APIName to determine the structure
The OpenSSL library uses your callback function to help implement the general TLS ticket construction state according to RFC5077 Section 4, so that each session state is unnecessary, and the callback function implementation needs to maintain a small group of password variables
This is probably very inefficient
Session should be deleted from cache to save resources
You can pass any of the following signs in the PKCS7_sign_add_signer_APIParam_5 parameter
Please note that SSL_shutdown_APIName must not be called
If the decryption fails, EVP_OpenFinal_APIName returns 0, otherwise it returns 1.
It is currently not possible to store attributes in the private key PKCS12_parse_APIParam_3 structure
Session must be explicitly deleted using SSL_SESSION_free_APIName
Behavior is uncertain
After successful decryption, EOF is performed, and the final read will return zero.
BN_init_APIParam_1 should be considered opaque and should not modify or directly access fields
CMS_sign_receipt_APIName returns a valid CMS_ContentInfo structure, or NULL if an error occurs
If the peer does not provide a certificate, it returns NULL
If the allocation fails, X509_new_APIName returns NULL and sets the error code that can be obtained by ERR_get_error_APIName.
Callback must return 1
It is not recommended to use EVP_PKEY_size_APIName with these functions
It is the caller's responsibility to free this memory and then call OPENSSL_free_APIName.
Use socket BIO instead
X509_STORE_CTX_get0_param_APIName returns a pointer to the X509_STORE_CTX_get0_param_APIParam_0 structure; if an error occurs, it returns NULL
BIO_should_retry_APIName is true
Only when f is in ternary form, you must call the function EC_GROUP_get_trinomial_basis_APIName and return the value of EC_GROUP_get_trinomial_basis_APIParam_2
Some advanced attributes are not supported, such as counter signature
Usually missing configuration files will return errors
After successful path verification, the API returns success
Once SSL_write_APIName returns r, r bytes have been successfully written, and the next call to SSL_write_APIName must send only the remaining n-r bytes, thus mimicking the behavior of write_APIName.
For lh _ <type> _ doall and lh _ <type> _ doall_arg, you should avoid conversion of function pointers in callbacks-instead use declaration/implementation macros to create type-checking wrappers that call type-specific Convert callbacks before type
Before calling this function, EVP_MD_CTX_init must be used to initialize EVP_DigestVerifyInit_APIParam_1
If an error occurs while checking the key, -1 is returned
All other passwords require corresponding certificates and keys
CMS_add1_recipient_cert_APIName and CMS_add0_recipient_key_APIName return an internal pointer to the CMS_RecipientInfo structure just added; if an error occurs, NULL is returned
New applications should use ASN1_TIME_adj_APIName and pass the offset values ​​in the ASN1_TIME_adj_APIParam4 and ASN1_TIME_adj_APIParam3 parameters instead of directly manipulating the ASN1_TIME_adj_APIParam2 value
To this end, the client should call the SSL_set_tlsext_status_type function before the handshake begins.
Since CMS_add0_cert_APIParam_2 CMS_add1_cert_APIParam_2 mean, CMS_add0_cert_APIName increase internal CMS_add0_cert_APIParam_2 CMS_add1_cert_APIParam_2 to CMS_add0_cert_APIParam_1 CMS_add1_cert_APIParam_1, and CMS_add0_cert_APIParam_1 CMS_add1_cert_APIParam_1 can not be released after a call against CMS_add1_cert_APIName which CMS_add0_cert_APIParam_2 CMS_add1_cert_APIParam_2 must be released
X509_STORE_CTX_get_error returns the error code of X509_STORE_CTX_get_error_APIParam_1. For a complete description of all error codes, please see the ERROR CODES section.
EC_KEY_copy returns a pointer to the target key, or NULL on error
Don't call this function
ECDSA_size_APIName returns the maximum length signature or returns 0 on error
EVP_CIPHER_CTX_cleanup_APIName returns 1 for success, 0 for failure
In either case, the curve is valid, and the discriminant must not be zero
EVP_SignInit_ex_APIName, EVP_SignUpdate_APIName and EVP_SignFinal_APIName return 1 for success, 0 for failure
If the allocation fails, the allocation returns NULL and sets an error code that can be obtained by ERR_get_error_APIName.
However, the significance of this result depends on whether the ENGINE API is used, so this feature is no longer recommended
SSL_CTX_set_alpn_protos_APIName and SSL_set_alpn_protos_APIName return 0 on success, non-zero on failure
EVP_DigestVerifyInit_APIName and EVP_DigestVerifyUpdate_APIName return 1 for success, 0 for failure, or a negative value
The pointer can no longer be used
SSL_get_tlsext_status_ocsp_resp_APIParam_2 SSL_get_tlsext_status_ocsp_resp_APIParam_2 will be NULL, and the return value of SSL_get_tlsext_status_ocsp_resp_APIName will be -1
It only makes sense to establish a new connection with the exact same peer sharing these settings, and may fail
Otherwise, EVP_DecodeFinal_APIName returns 1 successfully
After taking appropriate measures to meet the requirements of SSL_read, the calling process must be called repeatedly
CMS_add1_ReceiptRequest_APIName returns 1 successfully, or 0 if an error occurs
PKCS7_sign_APIName returns a valid PKCS7 structure, or NULL if an error occurs
BIO_read_filename_APIName, BIO_write_filename_APIName, BIO_append_filename_APIName and BIO_rw_filename_APIName return 1 for success, 0 for failure
The integer must be initialized to zero
After taking appropriate measures to meet the requirements of SSL_write_APIName, the calling process must be repeated
For other functions, return 1 for success and 0 for errors
Before calling this function, EVP_MD_CTX_init must be used to initialize EVP_DigestSignInit_APIParam_1
The functions EC_GROUP_get_basis_type_APIName, EC_GROUP_get_trinomial_basis_APIName and EC_GROUP_get_pentanomial_basis_APIName functions should only be called for curves defined on the F2^m field
In order to better control the output format, the certs, signcert and pkey parameters can be NULL and set the CMS_PARTIAL flag
If the passed key is a weak key, DES_is_weak_key_APIName returns 1; if the passed key is correct, DES_is_weak_key_APIName returns 0.
The SSL_select_next_proto_APIParam_1 value will point to the server or client, so it should be copied immediately.
SSL_set_session_APIName is only useful for TLS/SSL clients
EVP_PKEY_type will return EVP_PKEY_RSA
Does not support BIO_puts
The bit mask of the closed state of the SSL connection is 0, SSL_SENT_SHUTDOWN and SSL_RECEIVED_SHUTDOWN.
BN_BLINDING_create_param_APIName returns the newly created BN_BLINDING_create_param_APIParam_1 parameter, or NULL if wrong
A common mistake is to try to use the buffer directly as follows
The functions EVP_EncryptInit_APIName, EVP_EncryptFinal_APIName, EVP_DecryptInit_APIName, EVP_CipherInit_APIName and EVP_CipherFinal_APIName are obsolete, but reserved for compatibility with existing code
Must provide an implementation method
A pointer to SSL_get_shared_ciphers_APIParam_2 is returned on success, and NULL is returned on error.
In previous versions, they also cleaned up EVP_EncryptFinal_APIParam_1 EVP_DecryptFinal_APIParam_1 EVP_CipherFinal_APIParam_1 EVP_EncryptFinal_ex_APIParam_1 EVP_DecryptFinal_ex_APIParam_1 EVP_CipherFinal_ex_APIParam_1 E_C_free_Cat_free_eg_E_C_free_Category
CMS_uncompress_APIName returns 1 for success or 0 for failure
Newer applications should call
ENGINE_CTRL_GET_FLAGS returns the bitwise or mask of the following possible values
EC_GROUP_dup_APIParam_1 EC_GROUP_copy_APIParam_2 and EC_GROUP_copy_APIParam_1 must use the same EC_METHOD
After reusing the session, the peer certificate chain may not be available, in which case, a NULL pointer will be returned
EVP_DigestSignInit_APIName EVP_DigestSignUpdate_APIName and EVP_DigestSignaFinal_APIName return 1 for success, and 0 for failure.
The random number generator must be seeded before calling RSA_blinding_on_APIName
BIO_seek_APIName and BIO_tell_APIName both return the current file position when successful and -1 when they fail, but for BIO_seek_APIName, the file BIO always returns 0 for failure and -1 for failure.
This function should only be used
BIO_set_close_APIName always returns 1
Newer applications should use more modern algorithms, such as PBKDF2 as defined in PKCS#5v2.1 and provided by pkcs5_pbkdf2_hmac_APIName, pkcs5_pbkdf2_hmac_sha1_APIName
If successful, RAND_bytes_APIName and RAND_priv_bytes_APIName return 1; if the current RAND method does not support, then return -1; otherwise, return 0.
BIO_find_type_APIName returns matching BIO or NULL (no match)
The parameters generated by DH_generate_parameters_ex_APIName and DH_generate_parameters_APIName are not used in the signature scheme
This also means that OPENSSL_instrument_bus2_APIParam_1 and OPENSSL_instrument_bus_APIParam_1 should be cleared when called.
ERR_remove_state is deprecated and replaced by ERR_remove_thread_state
The public key must be RSA
All functions return the following values
These functions are usually called after a failed BIO_read_APIName or BIO_write_APIName call
So don't use these functions
If no match is found, the first item client_len of the client is returned in SSL_select_next_proto_APIParam_1, SSL_select_next_proto_APIParam_2.
Prior to this, the results returned from the function may not be reliable
SSL_CTX_set_generate_session_id_APIName and SSL_set_generate_session_id_APIName always return 1
Applications should generally avoid using DSA structural elements directly, but should use API functions to query or modify keys
They can support any operation through ENGINE_ctrl_APIName, including passing back and forth between any type of control command data.
X509_cmp_time_APIName error returns 0
Supports two special values
X509_NAME_get_index_by_NID_APIName and X509_NAME_get_index_by_OBJ_APIName return the index of the next matching entry; if not found, return -1
The ivec variable has changed, and the newly changed value needs to be passed to the next call of the function
Prime numbers may have to meet other requirements used in Diffie-Hellman key exchange
For longer chains, the customer must send the complete chain
 Returns a NULL pointer
All these functions return 1 for success and 0 for failure.
Currently the only supported type is TLSEXT_NAMETYPE_host_name
All EC_GROUP_new functions return a pointer to the newly constructed group, or NULL on error
But this situation is problematic
EVP_PKEY_set1_RSA_APIName, EVP_PKEY_set1_DSA_APIName, EVP_PKEY_set1_DH_APIName and EVP_PKEY_set1_EC_KEY_APIName return 1 for success or 0 for failure
These functions return 1 for success and 0 for errors
RSA_get_ex_data returns application data or 0 on failure
PEM_write_bio_CMS_stream_APIName returns 1 for success and 0 for failure
In new applications, SHA-1 or RIPEMD-160 should be preferred
This should not happen
ek [i] must reserve space for EVP_PKEY_size (pubk [i]) bytes.
RSA_sign_ASN1_OCTET_STRING_APIParam_4 must point to the RSA_size bytes of memory
Make sure that no expired certificates are mixed with valid certificates
The reason for this is that the variable i2d_X509_bio_APIParam_2 i2d_re_X509_tbs_APIParam_1 i2d_X509_fp_APIParam_2 i2d_X509_AUX_APIParam_1 i2d_X509_APIParam_1 d2i_X509_fp_APIParam_2 is set to the value of _Bio_APIParam_2
The session may be completely deleted, and the obtained pointer will become invalid.
Every time a small number of large BIO reads should not be copied to improve efficiency
An SSL_get_error call with the return value SSL_do_handshake will produce SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE
Supports the following SSLeay_version_APIParam_1 values
After completing all operations using passwords, EVP_CIPHER_CTX_cleanup_APIName should be called so that sensitive information will not be kept in memory
Related INTEGER or ENUMERATED utility functions should be used
SSL_set_current_cert also supports the option SSL_CERT_SET_SERVER
CRYPTO_set_ex_data returns 1 on success and 0 on failure
A pointer to the response data should be provided in the SSL_set_tlsext_status_ocsp_resp_APIParam_2 parameter, and the length of the data should be in the SSL_set_tlsext_status_ocsp_resp_APIParam_3 parameter
BN_BLINDING_new_APIName returns the newly allocated BN_BLINDING_new_APIParam_0 structure, or NULL if an error occurs
Do not explicitly release these indirectly released items before or after calling SSL_free, because trying to release the content twice may cause the program to fail
The server application must provide a callback function, which is called when the server receives the ClientKeyExchange message from the client
An error condition has occurred
This feature may fail
You may need to do the latter
EVP_DigestVerifyFinal_APIParam_1 with digital signature EVP_DigestVerifyUpdate_APIParam_1 EVP_DigestVerifyInit_APIParam_1 interface should almost always be used in preference to low-level interfaces
For special applications, it may be necessary to extend the maximum certificate chain size allowed by the peer, please refer to "Internet X.509 Public Key Infrastructure Proxy Certificate Configuration File" and "TLS Delegation Protocol" at the following locations Work http
Before calling this function, EVP_DigestInit_ex_APIParam_1 must be initialized
The key must first be associated with the structure
EVP_DecodeFinal_APIName must be called at the end of the decoding operation
After taking appropriate measures to meet the needs of SSL_connect, the calling process must be repeated
Applications can use this function to access, modify or create embedded content in CMS_get0_type_APIParam_1 CMS_set1_eContentType_APIParam_1 CMS_get0_content_APIParam_1 CMS_get0_eContentType_APIParam_1 structure
To use these passwords with RSA keys of the usual length, a temporary key exchange must be performed because regular keys cannot be used directly
Other attributes are discarded
Return NID_undef
DH_compute_key_APIName successfully returns the size of the shared key, error returns -1
BF_cfb64_encrypt_APIParam5 must point to an 8-byte initialization vector
It may be practical to ask for a password once, save it in memory and use it multiple times
RSA_public_encrypt_APIParam_1 must be smaller than RSA_size
Use the sequence SSL_get_session_APIName; SSL_new_APIName; SSL_set_session_APIName; SSL_free_APIName instead of SSL_clear_APIName to avoid such failures
BIO_new_file_APIName and BIO_new_fp_APIName return the file BIO, or NULL if an error occurs
This option is no longer implemented and is considered as no operation
The buffer ASN1_STRING_to_UTF8_APIParam_1 should be released using OPENSSL_free_APIName
EVP_DigestVerifyFinal_APIName returns 1 successfully
Returns 0
OBJ_obj2txt_APIName is awkward and confusing to use
For other types of BIO, it may not be supported
Truncated byte string is invalid
Some attributes like counter signature are not supported
Lack of support for BIO_puts_APIName and non-standard behavior of BIO_gets_APIName can be regarded as abnormal
They all have an initialization vector ivec that needs to be passed to the next call of the same message in the same function.
The size of EVP_SignFinal_APIParam_2 must be at least EVP_PKEY_size bytes
Most applications should use these methods and avoid the version-specific methods described below
The following error resolution options are available
Don't use SSLv2 protocol
The encrypted PRNG must be seeded with unpredictable data, such as mouse movements or keystrokes that the user moves freely
CMS_RecipientInfo_ktri_get0_signer_id retrieves the certificate receiver identifier associated with the specific CMS_RecipientInfo structure CMS_RecipientInfo_ktri_get0_signer_id_APIParam_1, which must be of type CMS_RECIPINFO_TRANS
The returned value is an internal pointer and cannot be released
On failure, the function returns 0
This is not thread safe, but it never happens
A buffer length of 80 should be sufficient to handle any OIDs actually encountered
Standard terminology recommended
SSL_write_APIName will only return successfully
A timeout value is assigned to the new session, after which the new session will not be accepted for session reuse.
The d2i_PrivateKey_APIParam_1 parameter should be a public key algorithm constant, such as EVP_PKEY_RSA
EVP_SealInit error or npubk returns 0 successfully
Unable to perform SSL_clear_APIName operation
Please note that OpenSSL is not completely thread-safe. Unfortunately, not all global resources have the necessary locks.
It should be called with BIO_should_retry_APIName and take appropriate measures when the call fails
It is only recommended that MD2_APIName, MD4_APIName and MD5_APIName are compatible with existing applications
EVP_SealInit_APIParam_5 must contain enough space for the IV of the corresponding password, which is determined by EVP_CIPHER_iv_length
These two parts must usually be handled by the same application thread
By setting the basic BIO, the communication channel must have been set up and assigned to SSL_connect_APIParam_1
The application should release the configuration by calling CONF_modules_free_APIName when closing the application
If the connection is successfully established, BIO_do_handshake_APIName returns 1
The application should use the higher-level function EVP_EncryptInit_APIName instead of directly calling RC4_set_key_APIName and RC4_APIName.
That is, the OpenSSL ASN1 function cannot be retried after partial reading or writing
So the key is 24 bytes
Also collide
CMS_final_APIName returns 1 for success or 0 for failure
The actual length of the password must be returned to the calling function
Can return the following string
Several functions will behave abnormally, and complain that several functions cannot find the algorithm
Starting with OpenSSL 0.9.8 q and 1.0.0 c, this option has no effect
For BN_div_word_APIName and BN_mod_word_APIName, BN_div_word_APIParam_2 BN_mod_word_APIParam_2 must not be 0
The lower 8 bits of the last 12 bits are taken from the third input byte, and the upper 4 bits are taken from the fourth input byte
OBJ_txt2nid_APIParam_1 can be the long name, short name or numeric representation of the object
SSL_CTX_build_cert_chain and SSL_build_cert_chain return 1 for success, 0 for failure
These commands are supported in the discovery mechanism only to allow the application to determine whether ENGINE supports certain specific commands that it may want to use.
Once BN_CTX_get_APIName fails, subsequent calls will also return NULL, so it is sufficient to check the return value of the last BN_CTX_get_APIName call.
OPENSSL_config_APIName is deprecated and should be avoided
Passwords with DSA keys also always use temporary DH keys
For applications that can capture Windows events, seeding PRNG by calling RAND_event_APIName is a significantly better source of randomness
The application should take appropriate measures to wait for the underlying socket to accept the connection and retry the call
When the session is not established, SSL_get_current_cipher_APIName returns the actual password or NULL
These functions return 1 on success and zero or negative values ​​on failure
BIO_get_cipher_status_APIName returns 1 for successful decryption and 0 for failure
RAND_write_file_APIName returns the number of bytes written, or -1 if the generated bytes do not have an appropriate seed.
The following session cache modes and modifiers are available
The following function returns 1 for success and 0 for errors
It must be released after the call
The following modification options are available
 Return this result code
X509_STORE_CTX_set_default_APIName returns 1 successfully, or 0 if an error occurs
All BN_CTX_get_APIName calls must be made before calling any other function that uses BN_CTX_start_APIParam_1 BN_CTX_get_APIParam_1 BN_CTX_get_APIParam_1 as a parameter.
i2d_X509_bio_APIName and i2d_X509_fp_APIName return 1 successfully, or 0 if an error occurs. The error code can be obtained through ERR_get_error_APIName.
The random number generator must be seeded, otherwise the operation will fail.
All structure references should be released by calling the corresponding item of the ENGINE_free_APIName function.
point_conversion_form_t is an enum defined as follows
The caller is responsible for ensuring that the buffer at EVP_DecodeUpdate_APIParam_2 EVP_DecodeUpdate_APIParam_2 is large enough to accommodate the output data
CMS_RecipientInfo_encrypt_APIName returns 1 successfully, or 0 if an error occurs
BN_generate_prime_ex_APIName returns 1 on success, 0 on error
Error returns zero, it will abort the handshake with a fatal internal error alert
Calling SSL_get_error with the return value of SSL_shutdown will produce SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE
First, the library must be initialized
Certain conditions must be observed to use stream ciphers safely
The buffer SHA512_Final_APIParam_1 SHA384_Final_APIParam_1 SHA256_Final_APIParam_1 SHA1_Final_APIParam_1 SHA224_Final_APIParam_1 must have space for the output of the used SHA variable
X509_verify_cert_APIName must be called before every call
EVP_DecodeUpdate_APIName error returns -1, successfully returns 0 or 1
EC_KEY_new, EC_KEY_new_by_curve_name and EC_KEY_dup return pointers to newly created EC_KEY objects, or NULL on error
There are currently two supported flags BN_BLINDING_NO_UPDATE and BN_BLINDING_NO_RECREATE
If key generation fails, RSA_generate_key_APIName returns NULL
Applications that directly use the configuration function will need to call OPENSSL_load_builtin_modules themselves before using any other configuration code
Attackers can use it in timed attacks
All other functions return 1 for success, and 0 for failure.
If the allocation fails, RSA_new_APIName returns NULL and sets the error code that can be obtained by ERR_get_error_APIName.
BIO_ctrl_APIParam_3 must be at least 512 bytes
SSL_check_chain_APIName must be called in the server after the client greeting message in the server or after the certificate request message
The complete set of flags supported by X509_NAME_print_ex_APIName is listed below
SSL_CTX_set_tlsext_ticket_key_cb_APIName returns 0 means the callback function has been set
RSA_sign_APIParam_1 RSA_verify_APIParam_1 is usually one of NID_sha1, NID_ripemd160 and NID_md5
After completing all configuration operations, the function SSL_CONF_finish_APIName must be called
Discourage the use of low-level algorithm specific features
Password IV must be set
HMAC_Init_ex_APIName, HMAC_Update_APIName and HMAC_Final_APIName return 1 to indicate success, or 0 if an error occurs
BIO_get_fd_APIName returns the file descriptor; if BIO has not been initialized, it returns -1
d2i_ECPKParameters_APIName, d2i_ECPKParameters_bio_APIName and d2i_ECPKParameters_fp_APIName return a valid d2i_ECPKParameters_APIParam_1 structure, or NULL if an error occurs.
Should avoid a lot of lowercase operations through the chain
All parties must use SSL_shutdown_APIName to send a shutdown notification alert message for a clean shutdown
Generally, the verification callback should not return 1 unconditionally in all cases
Returns a pointer to the constant value "NONE"
The client must still use the same SSLv3. 1 = TLSv1 announcement
PKCS7_decrypt_APIName must pass the correct recipient key and certificate
Except that the flag values ​​CMS_DETACHED, CMS_BINARY, CMS_NOATTR, CMS_TEXT, and CMS_STREAM are not supported, the behavior of this function is similar to CMS_sign.
Password callback (must be provided by the application) will return the password to be used
Applications should generally avoid using DH structure elements directly, but should use API functions to query or modify keys
The server application must also call the SSL_CTX_set_tlsext_status_cb_APIName function
Each successful call to RSA_get_ex_new_index will return an index that is larger than the previously returned index, which is important
The extension must be concatenated into a sequence of bytes
EC_KEY_set_asn1_flag_APIParam_1 EC_KEY_set_conv_form_APIParam_1 must have an EC_GROUP object associated with it before it can call EC_KEY_generate_key_APIName
The handshake routine must be explicitly set using SSL_set_connect_state_APIName or SSL_set_accept_state_APIName in advance
EVP_PKEY_keygen_init_APIName, EVP_PKEY_paramgen_init_APIName, EVP_PKEY_keygen_APIName and EVP_PKEY_paramgen_APIName return 1 for success, 0 for failure.
This may cause problems because the time_t value may overflow on some systems, leading to unexpected results
As described in PKCS7_sign_APIName, the lack of single pass processing and the need to keep all data in memory also applies to PKCS7_verify_APIName
The successful return value of fseek_APIName is 0. If an error occurs, -1 is returned, which is different from other types of BIO. The latter usually returns 1 successfully, and returns a non-positive value if an error occurs.
Instead, select should be used in conjunction with non-blocking I/O so that continuous reads will retry the request instead of blocking
If the keys match each other, X509_check_private_key_APIName and X509_REQ_check_private_key_APIName return 1, otherwise 0.
Multi-threaded applications may crash randomly
Also note that for the above SHA1_APIName function, the SHA224_APIName, SHA256_APIName, SHA384_APIName, and SHA512_APIName functions are not thread safe
Race conditions may occur because another thread generated the same session ID
The server must use the DH group and generate a DH key
The CMS_ContentInfo structure should be obtained from the initial call to CMS_encrypt (with the flag CMS_PARTIAL set)
This function should not be called on untrusted input
Usually, the application is only interested in whether the signature verification operation is successful, in this case, the EVP_verify_APIName function should be used
The "get_default" call will return NULL, and the caller will operate with a NULL ENGINE handle
EC_GROUP_have_precompute_mult returns 1 if the precalculation is completed, otherwise it returns 0
Do not allow multiple encryptions using the same keystream
BIO_get_fd_APIParam_2 should be of type
Certificate and CRL context is used internally in the associated X509_STORE_CTX_set0_param_APIParam_1 X509_STORE_CTX_get0_param_APIParam_1 X509_STORE_CTX_free_APIParam_1 X509_STORE_CTX_set_default_API_Par_up_Clean_API_ST_Clean_API_ST_Clean_API_up_Cert_up_Cert_up_Cert_API_up_Clean_API_ST_Clean_CAPI_up_Clean_API_ST_Clean_API_Clean_API_APM_Clean_Clean_API_Clean
If the time is successfully printed, ASN1_TIME_print_APIName returns 1; if an error occurs, it returns 0
The random number generator must be seeded before calling EVP_SealInit_APIName
RSA_private_decrypt_APIParam_3 must point to a portion of memory large enough to hold the decrypted data
Dynamic parent structure members should not be accessed
 Returns 0
The second password is stored in des_read_pw_APIParam_2 des_read_pw_APIParam_2, the password must also be at least des_read_pw_APIParam_3 des_read_pw_APIParam_3 bytes
BN_bn2hex_APIName and BN_bn2dec_APIName return NULL
CMS_RecipientInfo_type_APIName will currently return CMS_RECIPINFO_TRANS, CMS_RECIPINFO_AGREE, CMS_RECIPINFO_KEK, CMS_RECIPINFO_PASS or CMS_RECIPINFO_OTHER
Generally, it cannot be assumed that the data returned by ASN1_STRING_data_APIName ends with null or does not contain embedded null
No need to release results
SMIME_read_PKCS7_APIName returns a valid SMIME_read_PKCS7_APIParam_0 structure, or NULL if an error occurs
The acceptable value of X509_NAME_get_entry_APIParam_2 is from 0 to -1
BN_MONT_CTX_new_APIName returns the newly allocated BN_MONT_CTX_new_APIParam_0, error returns NULL
BIO_set_close_APIParam_2 can take the value BIO_CLOSE or BIO_NOCLOSE
Each PEM extension must start with the phrase ``BEGIN SERVERINFO FOR''
Any or all of these parameters can be NULL, see "Note" below
ek is an array of buffers in which the secret key encrypted by the public key will be written, and each buffer must contain enough space to hold the corresponding encryption key
If the content is not a text/plain text type, an error is returned
Currently, CMS_add0_recipient_key_APIParam_2 only supports AES-based key wrapping algorithms, especially
EVP_MD_CTX_destroy_APIName should only be called on the context created with EVP_MD_CTX_create_APIName
SSL_get_error_APIName returns the result code of SSL_connect_APIName, SSL_accept_APIName, SSL_do_handshake_APIName, SSL_read_APIName, SSL_peek_APIName, or SSL_write_APIName that was previously called on SSL_get_error_APIParam_1 SSL_get_error_APIParam_1.
If there is no signed receipt request, CMS_get1_ReceiptRequest_APIName returns 0; if it exists but the format is incorrect, it returns -1
EVP_OpenInit_APIName returns 0 on error, non-zero integer if successful
SSL_get_verify_result_APIName is only useful when combined with SSL_get_peer_certificate_APIName
The maximum length of IV is EVP_MAX_IV_LENGTH bytes defined in evp.h
Applications wishing to encrypt or decrypt private keys should use other functions, such as d2i_PKC8PrivateKey_APIName
SSL_select_next_proto_APIName returns one of the following
It is no longer recommended to use RAND_set_default_method_APIName
On error 0, returned by EC_GROUP_set_seed
SSL_get_tlsext_status_ocsp_resp_APIName returns the length of the OCSP response data, or -1 if there is no OCSP response data
This may crash somewhere in d2i_X509
However, new applications should generally not use this feature
BIO_get_cipher_ctx_APIName currently always returns 1
It is recommended that modern servers that do not support exporting cipher suites use SSL_CTX_set_tmp_dh or alternative methods, use callbacks, but ignore keylength and is_export and only provide at least 2048-bit parameters in the callback
The certificate/private key combination must be set using x509 and pkey parameters, and must return "1"
X509_NAME_delete_entry_APIName returns the deleted X509_NAME_delete_entry_APIParam_0 structure, or NULL if an error occurs.
BIO_set_mem_buf_APIName sets the internal BUF_MEM structure to BIO_set_mem_buf_APIParam_2 and sets the close flag to BIO_set_mem_buf_APIParam_3, that is, BIO_set_mem_buf_APIParam_3 should be BIO_CLOSE or BIO_NOCLOSE
An error occurred
This means that SHA1 and DSA are required to sign ``clone'' digests such as EVP_dss1_APIName
To add the private key to this empty structure, the function described in EVP_PKEY_set1_RSA_APIName should be used
Find files by CA username hash value, so it must be available
If the peer supports secure renegotiation, SSL_get_secure_renegotiation_support_APIName returns 1; if the peer does not support secure renegotiation, it returns 0
The BIO chain must not be released after this call
, The return value NID_X9_62_characteristic_two_field
CMS_decrypt_APIName returns 1 for success or 0 for failure
It is strongly recommended that applications prefer to use this interface instead of explicitly calling X509_check_host, host name checking is beyond the scope of DANE-EE certificate usage, and
EVP_CipherFinal_ex_APIName returns 0 for decryption failure and 1 for success
The CMS_ContentInfo structure should be obtained from the initial call to CMS_sign_APIName (when the flag CMS_PARTIAL is set), or in cases or when re-signing a valid CMS_ContentInfo SignedData structure
Hash values ​​are usually truncated to a power of 2, so make sure that your hash function returns well-mixed low-order bits
Generally, the reference count does not increase, and SSL_SESSION_free must not be used to explicitly free the session
After use, the context must be cleared by calling EVP_MD_CTX_cleanup_APIName, otherwise a memory leak will occur
Returns 0, the current certificate remains unchanged
After the summary context is no longer needed, EVP_MD_CTX_cleanup_APIName should be called
If the signing certificate has been found, OCSP_resp_get0_signer_APIName returns 1, otherwise it returns 0
New applications should use the SHA2 digest algorithm, such as SHA256
BN_bn2bin_APIParam_2 must point to BN_num_bytes bytes of memory
X509_cmp_time_APIParam_1 must meet the ASN1_TIME format specified by RFC 5280, that is, the X509_cmp_time_APIParam_1 format must be YYMMDDHHMMSSZ or YYYYMMDDHHMMSSZ
i2d_ECPKParameters_bio_APIName, i2d_ECPKParameters_fp_APIName, ECPKParameters_print and ECPKParameters_print_fp return 1 successfully, or 0 if an error occurs
PKCS7_verify_APIName returns 1 to successfully pass verification, and returns 0 if an error occurs.
The pseudo-random number generator must be seeded before calling RSA_generate_key_ex
DH_bits_APIParam_1 cannot be NULL.
Due to the format of base64 encoding, the end of the encoding block cannot always be determined reliably
The extension must be in PEM format
BN_is_prime_ex_APIName, BN_is_prime_fasttest_ex_APIName, BN_is_prime_APIName and BN_is_prime_fasttest_APIName return 0 if the number is a composite number; if the number is a prime number, the error probability is less than 0.25 ^ BN_is_prime_ex_APIParam_2 BNtest_am,
On different plaintexts, using the same dsa->kinv and dsa->r pair twice under the same private key will result in the permanent disclosure of the DSA private key
After setting the key algorithm and components, EVP_PKEY_set1_engine_APIName must be called
-1. Back
PKCS7_sign_add_signer_APIParam0 is not completed, it must be done by streaming or calling PKCS7_final
EC_METHOD_get_field_type identifies which field type the EC_METHOD structure supports, ie F2^m or Fp
Instead, OBJ_obj2txt_APIParam_1 must point to a valid buffer, and OBJ_obj2txt_APIParam_2 should be set to a positive value
CMS_RecipientInfo_kekri_id_cmp compares CMS_RecipientInfo_kekri_id_cmp_APIParam_2 and CMS_RecipientInfo_kekri_id_cmp_APIParam_3 parameter ID and keyIdentifier CMS_RecipientInfo structure CMS_REC_Info_ke_Park type
If there are missing parameters in EVP_PKEY_copy_parameters_APIParam_2 or if there are parameters in EVP_PKEY_copy_parameters_APIParam_2 and EVP_PKEY_copy_parameters_APIParam_1 and there is no match, an error is returned
Struct CRYPTO_dynlock_value must be defined to contain any structure needed to process the lock
It is recommended to use SSLv3 protocol, the application should set this option
It returns an index, which should be stored and passed in the RSA_set_ex_data_APIParam_2 RSA_get_ex_data_APIParam_2 parameter of the remaining functions
The files dh1024.pem and dh512.pem contain old parameters that the application must not use
The certificate must be in PEM format and must be sorted
It should consider using the SSL_CONF interface instead of manually parsing options
After returning the callback function, the buffer is no longer valid
DES_3cbc_encrypt_APIName is defective and cannot be used in the application
The functions X509_NAME_oneline_APIName and X509_NAME_print_APIName are legacy functions that produce non-standard output forms
This value should be passed in the SSL_set_tlsext_status_type_APIParam_2 parameter
Curve_name must also be set
EVP_EncryptUpdate_APIParam_2 should contain enough space
If the data is set correctly, BIO_set_buffer_read_data_APIName returns 1; if an error occurs, it returns 0
ERR_error_string_APIParam_2 ERR_error_string_n_APIParam_2 ERR_error_string_APIParam_2 ERR_error_string_n_APIParam_2 must be at least 120 bytes long
EVP_PKEY_decrypt_init_APIName and EVP_PKEY_decrypt_APIName return 1 for success, and 0 for failure.
EVP_DecodeFinal_APIName returns -1 on error or 1 on success
The pre-calculated value from DSA_sign_setup_APIName cannot be used for multiple signatures
The only compression algorithm currently supported is zlib using NID NID_zlib_compression
BN_bn2mpi_APIName stores the representation of BN_bn2mpi_APIParam_1 at BN_bn2mpi_APIParam_2, where BN_bn2mpi_APIParam_2 must be large enough to hold the result
Returns -1, the default value will be used
The d2i_RSAPrivateKey_APIParam_1 i2d_RSAPrivateKey_APIParam_2 structure passed to the private key encoding function should have all PKCS#1 private key components
The following return values ​​may currently appear
The following flag can be passed in the SMIME_write_CMS_APIParam_4 parameter
The key type used must match EVP_PKEY_CTX_ctrl_APIParam_2
The implementation of this callback should not directly fill in CRYPTO_THREADID_set_numeric_APIParam_1 CRYPTO_THREADID_set_pointer_APIParam_1
OCSP_resp_get0_APIParam_2 runs from 0 to OCSP_resp_count-1
Ensure that the output buffer of each block contains 65 bytes of storage space, plus an additional byte of NUL terminator
Each extension must consist of a 2-byte Extension Type, a 2-byte length and an extension_data length byte
The following flags can be passed in the PKCS7_decrypt_APIParam_5 parameter
EC_GROUP_get0_seed returns a pointer to the seed used to generate parameter b; if no seed is specified, NULL is returned
SSL_CONF_CTX_new_APIName returns the newly allocated SSL_CONF_CTX_new_APIParam_0 structure, or NULL if an error occurs
The underlying stream should not normally be closed
The SSL_SESSION object consists of several malloc_APINameed parts, and cannot directly move, copy, or store the SSL_SESSION object.
Need to explicitly call PKCS7_SIGNER_INFO_sign to complete this situation
Customers should avoid creating ``vulnerabilities'' in customer-supported agreements
The verify_callback function must be provided by the application and receives two parameters
You should know that BF_encrypt_APIName and BF_decrypt_APIName get each 32-bit block in host byte order, which is little-endian on little-endian platforms and big-endian on big-endian platforms.
Before generating a text error message, one of these functions should be called
More data must be read from basic BIO layer operations
Only call EVP_PKEY_CTX_gen_keygen_info_APIName in the generation callback and EVP_PKEY_CTX_get_keygen_info_APIParam_2 is a non-negative name
HMAC_cleanup_APIName is an alias of HMAC_CTX_cleanup_APIName for backward compatibility with 0.9.6 b, HMAC_cleanup_APIName is not recommended
BIO_flush_APIName may need to be retried
The EVP_MD_CTX_init_APIParam_1 EVP_MD_size_APIParam_1 EVP_DigestInit_APIParam_1 EVP_MD_block_size_APIParam_1 EVP_MD_CTX_md_APIParam_1 EVP_MD_CTX_destroy_APIParam_1 EVP_MD_pkey_type_APIParam_1 EVP_MD_CTX_copy_APIParam_1 EVP_MD_CTX_cleanup_APIParam_1 EVP_MD_type_APIParam_1 EVP_DigestFinal_ex_APIParam_1 EVP_DigestInit_ex_APIParam_1 EVP_DigestUpdate_APIParam_1 EVP_MD_CTX_copy_ex_APIParam_1 EVP_DigestFinal_APIParam_1 interface message digest should always used when the low-level interface
bn_mul_recursive_APIParam_4 bn_sqr_recursive_APIParam_3 must be a power of 2
Only a single increment can be used, and the constructed CRL is not maintained
This mode is recommended for all new applications
Do not call SSL_SESSION_free_APIName on other SSL_SESSION objects, as this will cause incorrect reference counting and program failure
These functions must never be called directly
The previous version must be used
SSL_set_current_cert with SSL_CERT_SET_SERVER returns 1 to indicate success, 2 if the server certificate is not used, and 0 if it fails
The control string SSL_CTX_set_cipher_list_APIParam_2 SSL_set_cipher_list_APIParam_2 should be common and not dependent on the details of the library configuration
The random number generator must be seeded before calling RSA_public_encrypt_APIName
Support BIO_puts_APIName, but not BIO_gets_APIName
The signed content must be kept in memory
EVP_PKEY_base_id, EVP_PKEY_id and EVP_PKEY_type return the key type or NID_undef when an error occurs
X509_STORE_CTX_get_current_cert_APIName returns the certificate in X509_STORE_CTX_get_current_cert_APIParam_1, which will cause an error; if there is no related certificate, it is NULL
The currently defined standard flags are EC_FLAG_NON_FIPS_ALLOW and EC_FLAG_FIPS_CHECKED
All other functions return 1 for success, and 0 for error
DSA_do_sign_APIName returns the signature, NULL when error
new_func and dup_func should return 0 for failure and 1 for success
Need dyn_lock_function to perform the lock with dynamic lock number
dsa->q cannot be NULL
SSLv3 protocol is deprecated and should not be used
Applications should use higher-level functions EVP_DigestInit_APIName, etc.
DSA passwords always use DH key exchange and require DH parameters
BIO_flush_APIName returns 1 for success and 0 or -1 for failure
CMS_verify_receipt_APIName returns 1 for successful verification, or 0 if an error occurs
Please use BN_CTX_new_APIName instead
A typical application will call OpenSSL_add_all_algorithms_APIName and EVP_cleanup_APIName before exiting
If the allocation fails, ASN1_OBJECT_new_APIName returns NULL and sets the error code that can be obtained by ERR_get_error_APIName.
BN_CTX_get_APIName returns a pointer to BN_CTX_get_APIParam_0 BN_CTX_get_APIParam_0 BN_CTX_get_APIParam_0, or NULL on error
The CMS_uncompress_APIParam_2 parameter will usually be set to NULL
BF_ofb64_encrypt_APIName uses the same parameters as BF_cfb64_encrypt_APIName and must be initialized in the same way
Some data in the SSL buffer must be written to the basic BIO layer
SSL_SESSION_free_APIName must be called only for SSL_SESSION objects
BN_bn2mpi_APIName and BN_mpi2bn_APIName convert BN_bn2mpi_APIParam_1 BN_mpi2bn_APIParam_3s to a format that consists of the length of the number (represented by a 4-byte big-endian number) and the number itself in big-endian format, where the most significant digit represents a negative number. number
It is necessary to use the ENGINE_cleanup_APIName function to clean up before the program exits
You must explicitly call SSL_SESSION_free_APIName once to reduce the reference count again
The automatic allocation feature is only available for OpenSSL 0.9.7 and later
The callback function should return 1 for success or 0 for errors
New applications should use cryptographic hash functions
You must sow PRNG before calling BN_rand_APIName or BN_rand_range_APIName.
If the sessions are actually the same, SSL_CTX_add_session_APIName is no operation and the return value is 0
Return 0, do nothing
Please note that lh _ <type> _ insert_APIName stores the pointer and does not copy the data
The function has returned success
Don't use TLSv1 protocol
Handshake will fail
The following functions can be used
The client application must provide a callback function, which is called when the client sends the ClientKeyExchange message to the server.
In addition, it indicates that the session ticket is within the renewal period and should be replaced
Both SSL_CTX_set_tlsext_servername_callback_APIName and SSL_CTX_set_tlsext_servername_arg_APIName always return 1 to indicate success
Trying to use it on an earlier version usually results in a segmentation violation
The TLS client must send the session ticket extension to the server
CMS_RecipientInfo_ktri_get0_signer_id_APIName, CMS_RecipientInfo_set0_pkey_APIName, CMS_RecipientInfo_kekri_get0_id_APIName, CMS_RecipientInfo_set0_key_APIName and CMS_RecipientInfo_decrypt_APIName return 1 to indicate success, otherwise return 0.
EC_POINT_point2oct returns the length of the required buffer, or 0 if an error occurs
Don't use SSLv3 protocol
Therefore, it is strongly recommended not to use this "reuse" of the d2i_X509_APIName behavior
RSA_public_encrypt_APIParam_3 must point to a portion of memory sufficient to hold the message digest
RAND_file_name_APIName returns a pointer to RAND_file_name_APIParam_1 on success, or NULL on error
For this, you need the following
Each string is limited to 255 bytes
BN_print_fp_APIName and BN_print_APIName return 1 successfully, and 0 for write errors
EVP_DecodeFinal_APIName will return -1
This is rarely used in practice, SMIME_write_CMS does not support
This flag can only be set
Please note that BN_lshift_APIParam_3 must be non-negative
Parameters PKCS12_parse_APIParam_3 and PKCS12_parse_APIParam_4 cannot be NULL
CMS_RecipientInfo_set0_pkey_APIName associates the private key CMS_RecipientInfo_set0_pkey_APIParam_2 with the CMS_RecipientInfo structure CMS_RecipientInfo_set0_pkey_APIParam_1, which must be of type CMS_RECIPINFO_TRANS
SMIME_write_PKCS7_APIName returns 1 for success or 0 for failure
This list is not affected by the contents of SSL_CTX_load_verify_locations_APIParam_2 or CApath, and must be explicitly set using the SSL_CTX_set_client_CA_list function family
SSL_SESSION_set_time_APIName and SSL_SESSION_set_timeout_APIName return 1 successfully
EVP_CIPHER_asn1_to_param_APIName will be called, and finally EVP_CipherInit_APIName will be called again with all parameters (except for the key set to NULL)
It is currently not recommended to integrate compression into the application
Digitally signed EVP interfaces should almost always be preferred over low-level interfaces
MDC2_Final_APIName puts the message digest in MDC2_Final_APIParam_1, the message digest must have MDC2_DIGEST_LENGTH == 16 bytes of output space, and erase MDC2_Final_APIParam_2
ERR_PACK_APIName returns an error code
In the case of renegotiation, please do not request client certificates again
Applications usually do not call EVP_PKEY_CTX_ctrl_APIName directly, but call one of the following algorithm-specific macros
CMS_sign_APIName returns a valid CMS_ContentInfo structure, or NULL if an error occurs
Must perform a complete shutdown procedure
It is not necessary to generate a new DH key during each handshake, but it is also recommended
Then CMS_compress_APIName will return an error
If the comparison is successful, CMS_SignerInfo_cert_cmp_APIName returns zero, otherwise it returns non-zero
Applications that contain a solution to this bug should be modified to handle this fix, otherwise they may release BIO that has been released
RSA_generate_key_APIName enters an infinite loop of illegal input values
Please note that ENGINE_ctrl_cmd_string_APIName accepts a Boolean parameter that relaxes the semantics of the function-if set to non-zero, ENGINE_ctrl_cmd_string_APIName will only fail if ENGINE supports the given command name but fails when executing the command name, if ENGINE does not, it will return failure. Command name, it will not perform any operation and only return success
The following signs are currently recognized
The application should use the openssl dhparam_APIName application to generate its own DH parameters
It is wrong to try to set the key length to any value other than a fixed value
The reuse behavior of d2i_X509_APIName is broken
bn_dump_APIParam_1 bn_div_words_APIParam_3 field can be NULL, and top == 0
The number of checks needs to be higher to reach the same level of guarantee
If any cipher can be selected, SSL_CTX_set_cipher_list_APIName and SSL_set_cipher_list_APIName return 1, if they fail completely, return 0
This function uses the EVP_PKEY_CTX_set_rsa_keygen_pubexp_APIParam_2 pointer internally, so EVP_PKEY_CTX_set_rsa_keygen_pubexp_APIParam_2 should not be modified or released after the call
SSL_set_rfd_APIName and SSL_set_wfd_APIName perform corresponding operations, but only for read channels or write channels that can be set independently
Do not enable this feature
This option has no effect on connections using other passwords
If an error occurs, X509_NAME_add_entry_by_txt_APIName, X509_NAME_add_entry_by_OBJ_APIName, X509_NAME_add_entry_by_NID_APIName and X509_NAME_add_entry_APIName return 1, indicating success is 0
EVP_MD_CTX_copy_ex_APIParam_1 must be initialized before EVP_DigestInit_ex_APIName is called
The returned value is an internal pointer, which must not be released after the call
DSA_SIG_new_APIName returns NULL and sets the error code that can be obtained by ERR_get_error_APIName
This "reuse" feature is for historical compatibility, but it is strongly recommended not to use it
The PKCS7 structure should be obtained from the initial call to PKCS7_sign with the flag PKCS7_PARTIAL, or in the case of a resigned PKCS7 signature data structure
It should be equal to half of the target security level (in bits)
i2d_X509_bio_APIName is similar to i2d_X509_APIName, the difference is that i2d_X509_bio_APIName writes the code of structure i2d_X509_bio_APIParam_2 i2d_X509_APIParam_1 to BIO i2d_X509_bio_APIParam_1 and i2d_X509_bio_APIName fail, and return 1 for success.
It is important to call BIO_flush_APIName
Does not support seed length> 20
Therefore, if you pass the public key to these functions in X509_REQ_check_private_key_APIParam_2 X509_REQ_check_private_key_APIParam_2, it will return success.
Currently API can only fail
Then return -2
EC_GROUP_get0_generator returns the generator of the given curve, or NULL on error
EC_POINT_point2bn returns a pointer to the provided BIGNUM, or NULL if an error occurs
First execute the servername callback, then execute the ALPN callback
X509_CRL_get0_lastUpdate returns a pointer to the X509_CRL_get0_lastUpdate_APIParam_0 structure; if the lastUpdate field is missing, it returns NULL
The first call should set EVP_OpenInit_APIParam_6 to NULL, and should be called again with EVP_OpenInit_APIParam_2 set to NULL
CMS_set1_eContentType_APIName returns 1 successfully, or 0 if an error occurs
X509 objects must be explicitly released using X509_free_APIName
Applications wishing to support multiple certificate chains can call this function on each chain in turn
If the basic BIO is non-blocking, then when the basic BIO cannot meet the SSL_connect requirement to continue the handshake, SSL_connect will also return, indicating the problem with a return value of -1
If SSL_get_cipher_list_APIParam_1 is NULL or no cipher is available, NULL is returned
This is a mistake
RSA_padding_check_xxx_APIName function returns the length of the recovered data, -1 when error
This is no longer necessary and cloning digests are not recommended now
If the comparison is successful, it returns zero; otherwise, it returns zero.
Length is 4 or 16
Call SSL_get_cipher_list_APIName with SSL_get_cipher_list_APIParam_2 from 0 to get a sorted list of available ciphers until it returns NULL.
Applications must not rely on the wrong value of SSL_operation_APIName, but must ensure that the write buffer is always flushed first
Preferred PKCS1_OAEP padding
The API should be called with the RAND_event_APIParam_1, RAND_event_APIParam_2, and RAND_event_APIParam_3 parameters of all messages sent to the window procedure
Memory BIO supports BIO_gets_APIName and BIO_puts_APIName
rsa-> n cannot be NULL
Each application must set its own session ID context SSL_CTX_set_session_id_context_APIParam_2 SSL_set_session_id_context_APIParam_2 is used to distinguish the context and store in the exported session
The application usually does not need to modify the embedded content because it is usually set by a higher-level function
Session ID must be unique
SSL_set_quiet_shutdown_APIParam_2 SSL_set_quiet_shutdown_APIParam_2 can be 0 or 1
The dup_APIName function uses OPENSSL_malloc_APIName below, so it should be used in preference to the standard library for memory leak checking or to replace the malloc_APIName function
Typically, RSA_padding_add_PKCS1_type_1_APIName RSA_padding_check_PKCS1_type_1_APIName RSA_padding_add_PKCS1_type_2_APIName RSA_padding_check_PKCS1_type_2_APIName RSA_padding_add_PKCS1_OAEP_APIName RSA_padding_check_PKCS1_OAEP_APIName RSA_padding_add_SSLv23_APIName RSA_padding_check_SSLv23_APIName RSA_padding_add_none_APIName RSA_padding_check_none_APIName function should not be called from application
Elements of Fp are integers from 0 to p-1, where p is a prime number
CMS_get0_RecipientInfos_APIName returns all CMS_RecipientInfo structures, or NULL if an error occurs
i2d_ECPKParameters_bio_APIName is similar to i2d_ECPKParameters_APIName, except that i2d_ECPKParameters_bio_APIName writes the code of structure i2d_ECPKParameters_APIParam_1 to BIO ECPKParameters_print_APIParam_1, and returns 1 if successful, or 0 if it fails.
The functions of copying, releasing and "clearing_release" data items must be provided again, and these functions must be the same as the functions when inserting data items
If zlib support is not compiled into OpenSSL, CMS_uncompress_APIName will always return an error
Otherwise, EVP_BytesToKey returns the size of the derived key in bytes, or 0 if an error occurs
OCSP_basic_verify_APIName returns 1 on success, 0 on error, or -1 on fatal errors (such as malloc failure).
BN_add_word_APIName, BN_sub_word_APIName and BN_mul_word_APIName return 1 means success, 0 means error
For RC5, currently only the round number can be set to 8, 12 or 16
SSL_CTX_add_client_custom_ext_APIName and SSL_CTX_add_server_custom_ext_APIName return 1 for success, 0 for failure
DH_generate_parameters_ex_APIParam_3 is a very small number, greater than 1, usually 2 or 5
There may be RSA keys that are only applicable to some RSA_METHOD implementations, and attempting to change the RSA_METHOD of the key may lead to unexpected results
Applications should generally avoid using RSA structural elements directly, but should use API functions to query or modify keys
In order to reach the 128-bit security level, BN_is_prime_ex_APIParam_2 BN_is_prime_fasttest_ex_APIParam_2 should be set to 64
OBJ_obj2nid, OBJ_ln2nid, OBJ_sn2nid and OBJ_txt2nid return NID or NID_undef when an error occurs
Return error
Follow the guidance in draft-ietf-tls-downgrade-scsv-00, use this option only in explicit fallback retries
This call should be made before the password is actually ``used''
This means that there is no limit to the size of the numbers manipulated by these functions, but the return value must always be checked to prevent memory allocation errors
It is recommended to use the ENGINE API to control the default implementation for RAND and other encryption algorithms
The only compression algorithm currently supported is zlib
 Return value NID_X9_62_prime_field
PKCS7_decrypt_APIName returns 1 for success or 0 for failure
File BIO is an exception, returns 0 on success, -1 on failure
The internal pointer returned by the API cannot be released by the application.
In a non-blocking environment, the application must be prepared to handle incomplete read/write operations
BIO_reset_APIName returns zero successfully, or -1 if an error occurs
SSL_OP_SINGLE_DH_USE should be enabled
i2d_PKCS7_bio_stream_APIName returns 1 for success and 0 for failure
No further I/O operations should be performed on that connection, and SSL_shutdown_APIName must not be called
The memory allocated by these functions should be released using the OPENSSL_free_APIName function
EVP_get_cipherbyname_APIName, EVP_get_cipherbynid_APIName and EVP_get_cipherbyobj_APIName return EVP_get_cipherbyname_APIParam_0 structure or NULL on error
BIO_set_md_APIName, BIO_get_md_APIName and BIO_md_ctx_APIName return 1 for success, 0 for failure
For the F2^m curve, there is only one implementation choice, namely EC_GF2_simple_method
ASN1_STRING_new_APIName and ASN1_STRING_type_new_APIName return a valid ASN1_STRING structure, or NULL if an error occurs
These functions EVP_PKEY_copy_parameters_APIName return 1 for success and 0 for failure
SSL_export_keying_material_APIName returns 0 or -1 if it fails, 1 if it succeeds
The only type currently supported is TLSEXT_STATUSTYPE_ocsp
BIO_new_socket_APIName returns a newly allocated BIO or NULL error
BIO_set_APIName, BIO_free_APIName returns 1 for success, 0 for failure
Unlike other functions, the return value 0 of EVP_PKEY_verify_APIName only indicates that the signature was not successfully verified and does not indicate a more serious error.
Some return values ​​are ambiguous, you should be careful
The extension must be different
If BN_cmp_APIParam_1 BN_ucmp_APIParam_1 <BN_cmp_APIParam_2 BN_ucmp_APIParam_2 BN_ucmp_APIParam_1 BN_ucmp_APIParam_1 == BN_cmp_APIParam_2 BN_ucmp_APIParam_2 BN_ucmp_APIParam_2 BN_ucmp_APIParam_2 BN_ucmp_APIParam_2 BN_ucmp_APIParam_1
The SSL/TLS engine must parse the record, including the title and body
SSL_CONF_finish_APIName returns 1 for success and 0 for failure
Recipient certificate is required to find the appropriate recipient in the CMS structure
Some unrecoverable fatal I/O error has occurred
The SSL_get1_curves_APIParam_2 array takes the form of a set of curvilinear NIDs arranged by priority
On success, the function returns 1
The application must check the wrong return value
CMS_get1_certs_APIName and CMS_get1_crls_APIName return the stack of certificates or CRLs, or NULL if they do not exist or an error occurs
The parameter EC_get_builtin_curves_APIParam_1 should be an array of EC_builtin_curve structures of size EC_get_builtin_curves_APIParam_2
The application should not release the SSL_CTX_add_extra_chain_cert_APIParam_2 object
If the nextUpdate field is missing in X509_CRL_get0_lastUpdate_APIParam_1, then return X509_CRL_get0_nextUpdate_APIParam_1
You may need to consider the method of verifying the RSA key using the opaque RSA API function
CMS_get0_signers_APIName returns NULL
d2i_ECPrivateKey_APIName returns a valid d2i_ECPrivateKey_APIParam_1 structure, or NULL if an error occurs.
This code will cause buf to obviously contain garbage
Data must be read twice
If the input format is wrong, all functions can also return -2
Therefore, the BIO_NOCLOSE flag should be set
As a result, some objects cannot be encoded or decoded as part of the ASN.1 structure
It is recommended to use functions that do not depend on global variables
SSL_state_string_APIName returns a 6-letter string indicating the current state of the SSL object SSL_state_string_APIParam_1
RSA_public_encrypt_APIParam_3 must point to the RSA_size bytes of memory
There may be a DSA key only applicable to some DSA_METHOD implementations, and attempting to change the DSA_METHOD of this key may lead to unexpected results
In OpenSSL versions prior to 1.0, the current certificate returned by X509_STORE_CTX_get_current_cert_APIName will never be NULL.
RSA_blinding_on_APIName returns 1 successfully, or 0 if an error occurs
This alert should be followed by a close_notify
The maximum length of SSL_CTX_set_session_id_context_APIParam_2 is limited to SSL_MAX_SSL_SESSION_ID_LENGTH
BIO_pop_APIName should be used to remove BIO from the chain, and BIO_free_APIName should be used to release it until BIO_new_CMS_APIParam_1 is reached
If an operation is not supported, an error occurs, EOF is not reached, and BIO_seek_APIName on the file BIO is a successful operation, you can return a return value of 0
sigret must point to the DSA_size bytes of memory
After taking appropriate measures to meet the needs of SSL_shutdown, the calling process must be called repeatedly
You can pass any of the following flags in the flags parameter
The job of cert_cb is to store information about the status of the last call
The format of the certificate must be specified from the known types SSL_FILETYPE_PEM, SSL_FILETYPE_ASN1 SSL_CTX_use_certificate_file_APIParam_3
X509_NAME_get_index_by_NID_APIParam_3 X509_NAME_get_index_by_OBJ_APIParam_3 should initially be set to -1
APIs and APIs have been deprecated in OpenSSL 1.1.0
Currently, the following SSL_CONF_CTX_clear_flags_APIParam_2 value can be recognized SSL_CONF_CTX_set_flags_APIParam_2 value
If the curves are equal, EC_GROUP_cmp returns 0; if the curves are not equal, it returns 1; if it is wrong, it returns -1.
CMS_compress_APIName returns the CMS_ContentInfo structure, or NULL if an error occurs
This mode should only be used to implement encrypted sound fill mode in application code
HMAC_CTX_cleanup_APIName must be called
The length of the vector pointed to by BF_ecb_encrypt_APIParam_1 and BF_ecb_encrypt_APIParam_2 must be 64 bits, and not less than
EVP_PKEY_verify_recover_init_APIName and EVP_PKEY_verify_recover_APIName return 1 for success, 0 for failure.
Temporary variables must be used
If an error occurs, CMS_encrypt_APIName returns the CMS_ContentInfo structure or NULL
Before the DES key can be used, the DES key must be converted to an architecture-dependent DES_key_schedule through the DES_set_key_checked or DES_set_key_unchecked function
OCSP_single_get0_status_APIName returns the status of OCSP_single_get0_status_APIParam_1; if an error occurs, it returns -1
HMAC_Init_ex_APIParam_1 HMAC_Init_APIParam_1 HMAC_Init_ex_APIParam_1 must be created by HMAC_CTX_new before using HMAC_Init_ex_APIParam_1 for the first time.
The user should explicitly cancel the setting callback by calling SSL_CTX_sess_set_remove_cb before calling SSL_CTX_free_APIName
pem_passwd_cb must write the password to the provided buffer pem_passwd_cb_APIParam_1, its size is pem_passwd_cb_APIParam_2
The value of BN_rand_APIParam_2 must be zero or greater
i2d_CMS_bio_stream_APIName returns 1 for success and 0 for failure
Calling SSL_get_error with the return value of SSL_read will produce SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE
For EC parameter generation, EVP_PKEY_CTX_set_ec_paramgen_curve_nid_APIName must be called or an error will occur
SSL_new_APIName creates a new SSL_new_APIParam_1 structure, which is used to save data for TLS/SSL connections
RSA_generate_key is deprecated
This is only used for multi-line format
The context value is left to the application, but it must be the same on both ends of the communication
BN_BLINDING_update_APIName, BN_BLINDING_invert_APIName, BN_BLINDING_invert_APIName, BN_BLINDING_convert_ex_APIName and BN_BLINDING_invert_ex_APIName return 1 successfully, and return 0 if an error occurs.
The purpose of the latter two is to simulate stream ciphers, and they require the parameter num, which is a pointer to an integer, where the current offset in ivec is stored between two calls
The application-specific context should be provided where the context points, and the length of the context should be lenslen bytes
BIO_get_close_APIName returns the close flag value BIO_CLOSE or BIO_NOCLOSE.
The current EVP_PKEY_CTX_set_rsa_keygen_pubexp_APIParam_2 should be an odd number
This feature is invalid
The above function should be used to manipulate verification parameters, not the old functions that work in specific structures such as X509_STORE_CTX_set_flags_APIName.
PKCS7_sign_add_signers_APIName returns NULL
OCSP_resp_get0_APIName returns NULL
The callback should return a negative value on error
It may be necessary to explicitly set the handshake routine using SSL_set_connect_state_APIName or SSL_set_accept_state_APIName in advance
EVP_get_digestbyname_APIName, EVP_get_digestbynid_APIName and EVP_get_digestbyobj_APIName return the EVP_get_digestbyname_APIParam_0 structure, or NULL if an error occurs
Padding means one of the following modes
This is no longer possible
The calling process must be called repeatedly after taking appropriate measures to meet the requirements of SSL_do_handshake_APIName
BIO_s_null_APIName returns the empty receiver BIO method
The macro version of this feature is the only version available before OpenSSL 1.0.0.
Context must not be shared between threads
Passing a NULL value for HMAC_Final_APIParam_2 to use a static array is not thread safe
If the callback is not explicitly set, return a NULL pointer and use the default callback
In parallel, the session forms a linked list, which is maintained separately from the lhash_APIName operation, so the database cannot be modified directly, and the SSL_CTX_add_session_APIName function set must be used
CMS_RecipientInfo_kekri_get0_id retrieves key information from the CMS_RecipientInfo structure CMS_RecipientInfo_kekri_get0_id_APIParam_1, the type must be CMS_RECIPINFO_KEK type
This usually outputs garbage, and eventually may only return stuffing errors
EC_GROUP_method_of returns the EC_METHOD implementation used by the given curve, or NULL on error
Related to this, those audit codes should pay special attention to any instances of DECLARE / IMPLEMENT _ LHASH_DOALL _ -LSB- ARG _ -RSB- _ FN macros, the types provided by these instances do not have any “const” qualifier
The currently supported flag is UI_INPUT_FLAG_ECHO, which is related to UI_add_input_string_APIName and will echo the user's response
The session ID context must be set by the server
CMS_verify_APIName returns 1 for successful verification, or 0 if an error occurs.
Before attempting a TLS/SSL I/O operation, the error queue of the current thread must be empty, otherwise SSL_get_error_APIName will not work reliably
The return value should always check goto err
Returns the parsed PKCS#7 structure, or NULL if an error occurs
The generation of custom DH parameters should still be preferred in order to prevent attackers from researching commonly used groups
MIME headers of type text/plain are added to the content, which makes sense
RSA_get_ex_new_index returns new index or -1 on failure
SSL_CONF_cmd_argv_APIName returns the number of command parameters processed, 0, 1, 2 or negative error code.
The ENGINE_get_next_APIName and ENGINE_get_prev_APIName functions are used to iterate over the internal ENGINE list-The ENGINE_get_next_APIName and ENGINE_get_prev_APIName functions will return a new structure reference to the next ENGINE in the list, or NULL if at the end of the list. The operation passed to the function will be released on behalf of the caller
The above function should be used instead of directly referencing the fields in the X509_VERIFY_CTX structure
EVP_PKEY_encrypt_APIParam_3 should contain the length of the output buffer
You must use SSL_get_peer_certificate_APIName to separately obtain the peer's certificate
The application should use the higher-level functions EVP_EncryptInit_APIName, etc. instead of directly calling the blowfish function.
Error queue data structure must be released
The application must not use OPENSSL_free_APIName to release the data pointer
At the most basic level, each ENGINE pointer is essentially a structure reference-a structure reference must fully use the pointer value, because such a reference guarantees that the structure cannot be released before the reference is released.
Misconfigured applications sending incorrect certificate chains often cause problems for peers
It is recommended to use the ENGINE API to control the default implementation for DH and other encryption algorithms
SSL function should be called again
The timeout value SSL_CTX_set_timeout_APIParam_2 must be in seconds
CMS_RecipientInfo_set0_key_APIName will associate a symmetric key CMS_RecipientInfo_set0_key_APIParam_3 with a length of CMS_RecipientInfo_set0_key_APIParam_2 to the CMS_RecipientInfo structure CMS_RecipientInfo_set0_key_APIParam_1, the type of the symmetric key must be CMS_RECIPINFO_KE
RSA_set_ex_data returns 1 on success, 0 on failure
BIO_seek_APIName and BIO_tell_APIName return the current file location; if an error occurs, it returns -1
EC_POINT_point2hex returns a pointer to a hexadecimal string, or NULL if an error occurs
Accept BIO support BIO_puts_APIName, but not BIO_gets_APIName
Use SSL_CIPHER_description instead
EVP_PKEY_new_APIName returns the newly allocated EVP_PKEY_new_APIParam_0 structure, or NULL if an error occurs
BN_bin2bn_APIName returns BN_bn2bin_APIParam_1 BN_bin2bn_APIParam_3, NULL on error
Certificates added using SSL_CTX_add_extra_chain_cert_APIName will not be used
d2i_PrivateKey and d2i_AutoPrivateKey return a valid EVP_KEY structure, or NULL if an error occurs
Cannot set a list of available compression methods for a specific SSL_CTX or SSL object
After a failed BIO I/O call, the application does not need to call BIO_should_retry_APIName
SSL_CTX_set_session_id_context_APIName and SSL_set_session_id_context_APIName return the following values
Both CMS_decrypt_APIParam_3 and CMS_decrypt_APIParam_2 should be set to NULL
X509_NAME_oneline_APIName and X509_NAME_print_APIName are strongly recommended in new applications
Subsequent bits are important
The returned result code is X509_V_OK
This format has some serious security holes and should be avoided
The content must be provided in the SMIME_write_CMS_APIParam_3 parameter
The callback must call SSL_has_matching_session_id_APIName and generate another ID
PKCS7_decrypt_APIName would be better
EVP_CIPHER_param_to_asn1_APIName and EVP_CIPHER_asn1_to_param_APIName return 1 (for success) or 0 (for failure)
You can use the -C option of the dhparam application to convert these files to C code.
Due to the connection between the message digest and the public key algorithm, the correct digest algorithm must be used with the correct public key type
X509_STORE_CTX_get_current_cert_APIName returns the certificate that caused the error; if no certificate is associated with the error, it returns NULL
This option must be used to prevent small group attacks
Calling SSL_get_error with the return value of SSL_accept will produce SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE
On error, return -1
If the allocation fails, DH_new_APIName returns NULL and sets the error code that can be obtained by ERR_get_error_APIName.
RSA_private_decrypt_APIParam_5 RSA_public_encrypt_APIParam_5 represents one of the following modes
EVP_PKEY_get0_hmac, EVP_PKEY_get0_poly1305, EVP_PKEY_get0_siphash, EVP_PKEY_get0_RSA, EVP_PKEY_get0_DSA, EVP_PKEY_get0_DH and EVP_PKEY_get0_EC_KEY also returns a reference key EVP_PKEY_get0_hmac_APIParam_1 EVP_PKEY_get0_poly1305_APIParam_1 EVP_PKEY_get0_siphash_APIParam_1 EVP_PKEY_get0_RSA_APIParam_1 EVP_PKEY_get0_DSA_APIParam_1 EVP_PKEY_get0_DH_APIParam_1 EVP_PKEY_get0_EC_KEY_APIParam_1 or NULL, if the key is not the correct type, but the reference count does not increase the return key, and therefore may not be released after use
If there is already another session with the same ID in the cache, SSL_has_matching_session_id_APIName returns 1
MD2_Final_APIName puts the message digest in MD2_Final_APIParam_1, the digest must have 16 bytes of output space, and erase MD2_Final_APIParam_2
OBJ_cleanup_APIName should be called before the application exits
The logo can be: BIO_CLOSE, BIO_NOCLOSE BIO_FP_TEXT
Need to add KEKRecipientInfo structure
It is important to use the correct implementation type of the selected curve form
lh_ <type> _insert_APIName returns NULL for both success and error
The random number generator must be seeded before calling RSA_padding_add_xxx_APIName
SSL_get_version_APIName should only be called after the initial handshake is complete
Then return to EVP_CIPH_STREAM_CIPHER
The application can directly specify the key or provide the key through the callback function
Be careful to avoid small group attacks
Please note that BN_rshift_APIParam_3 must be non-negative
The length of the session ID is between 1 and 32 bytes.
i2d_ECPKParameters_fp_APIName is similar to i2d_ECPKParameters_APIName, the difference is that it writes the code of the structure i2d_ECPKParameters_APIParam_1 to BIO ECPKParameters_print_APIParam_1, returns 1 on success, and returns 0 on failure
ADH password does not require a certificate, but DH parameters must be set
SSL_CTX_set_tlsext_status_cb_APIName, SSL_CTX_set_tlsext_status_arg_APIName, SSL_set_tlsext_status_type_APIName and SSL_set_tlsext_status_ocsp_resp_APIName return 0 or successfully return 1
If PSK identity prompt is not used during connection establishment, SSL_get_psk_identity_hint_APIName may return NULL
In order to successfully conduct transparent negotiation, SSL_read_APIParam_1 must have been initialized to client or server mode.
The protocol list must be wire-format, defined as a vector of non-empty 8-bit prefix byte strings
You must provide a function that returns the password
This setting will remain in effect until you use SSL_free_APIName or call SSL_set_quiet_shutdown_APIName again to delete SSL_set_quiet_shutdown_APIParam_1 SSL_set_quiet_shutdown_APIParam_1.
If the keys match, the functions EVP_PKEY_cmp_parameters_APIName and EVP_PKEY_cmp_APIName return 1; if they do not match, return 0; if the key types are different, return -1; if the operation is not supported, return -2
BIO_set_cipher_APIParam_5 should be set to 1 for encryption and 0 for decryption
It is strongly recommended not to use temporary RSA key exchange, but DHE key exchange
For the description of the method's attributes, this may cause the connection to fail.
DSA_dup_DH_APIName returns the new DSA_dup_DH_APIParam_0 structure, error returns NULL
DSA_sign_APIName and DSA_sign_setup_APIName return 1 for success, 0 for errors
BN_BLINDING_get_flags returns the BN_BLINDING flag
You must call EC_GROUP_set_curve_GFp or EC_GROUP_set_curve_GF2m respectively to create curves defined on Fp or F2^m, respectively
"0" must be returned and no certificate will be sent
The format of the certificate must be specified from the known types SSL_FILETYPE_PEM, SSL_FILETYPE_ASN1 SSL_CTX_use_certificate_file_APIParam_3 SSL_use_certificate_file_APIParam_3
BIO_new_mem_buf_APIParam_1 is assumed to be null terminated
New applications should use EVP_DigestInit_ex_APIName, EVP_DigestFinal_ex_APIName and EVP_MD_CTX_copy_ex_APIName
For some key types and parameters, you must seed the random number generator
After writing everything through the chain, you must call BIO_flush_APIName to finalize the structure
BN_rand_APIParam_3 also cannot be 1
An application only needs to add them
EC_POINT_new and EC_POINT_dup return the newly allocated EC_POINT or NULL when an error occurs
The SSL_CTX_set_session_id_context_APIName and SSL_set_session_id_context_APIName functions are only useful on the server side
This list must be explicitly set using SSL_CTX_set_client_CA_list_APIName of SSL_CTX_add_client_CA_APIParam_1 and SSL_set_client_CA_list_APIName of the specific SSL_add_client_CA_APIParam_1.
These were released after containing SSL_CTX_set0_verify_cert_store_APIParam_2 SSL_set0_chain_cert_store_APIParam_2 SSL_CTX_set1_chain_cert_store_APIParam_2 SSL_set1_verify_cert_store_APIParam_2 SSL_set1_chain_cert_store_APIParam_2 SSL_set0_verify_cert_store_APIParam_2 SSL_CTX_set0_chain_cert_store_APIParam_2 SSL_CTX_set1_verify_cert_store_APIParam_2 does not increase the reference count and incidental shop must not operate
Need to call CMS_SignerInfo_sign explicitly to complete
HMAC_CTX_init_APIName must be called
Call BIO_should_retry_APIName should be used for non-blocking connection BIO to determine whether the call should be retried
ASN1_TIME_set_string_APIName sets the ASN1_TIME structure ASN1_TIME_set_string_APIParam_1 to the time represented by the string ASN1_TIME_set_string_APIParam_2, which must be in the appropriate ASN .1 time format
Returning 0 or -1 does not necessarily indicate an error
BIO_new_fd_APIName returns a newly allocated BIO or NULL error
It is recommended to check the return value of SSL_shutdown_APIName, and then call SSL_shutdown_APIName again
OCSP_resp_get0_id_APIParam_1 OCSP_resp_count_APIParam_1 is considered an untrusted certificate used to build the verification path of the signer certificate
If there is no curve name associated with the curve, EC_GROUP_get_curve_name will return 0
Use only the default RAND_set_rand_method_APIParam_1 set by RAND_set_rand_method_APIName and returned by RAND_get_rand_method_APIName
Callback should return 0
The client should additionally provide a callback function to decide how to handle the returned OCSP response by calling SSL_CTX_set_tlsext_status_cb.
The initialization vector iv should be a random value
An unrecoverable fatal error has occurred in the SSL library, usually a protocol error
BUF_MEM_new_APIName returns NULL when returning buffer or error
Similarly, the function EC_GROUP_get_pentanomial_basis_APIName must be called only when f is a five-term form, and the values ​​of EC_GROUP_get_pentanomial_basis_APIParam_2, k2, and k3 are respectively returned.
If the size of the buffer is successfully adjusted, BIO_set_read_buffer_size_APIName, BIO_set_write_buffer_size_APIName and BIO_set_buffer_size_APIName return 1, otherwise 0.
CMS_encrypt_APIName only supports CMS_encrypt_APIParam_1 with RSA, Diffie-Hellman or EC key
New programs should prefer to use the "new" style, while the "old" style is provided for backward compatibility
Acceptable only in digital form
This function should be called after setting the basic password type but before setting the key
This function performs an integrity check on all RSA key materials, so the RSA key structure must also contain all private key data
The SSLv2 protocol provides little security, so it should not be used
It is recommended to use the maximum id_len and fill the bytes not used to encode special information with random data to avoid conflicts
It is recommended to use the ENGINE API to control the default implementation for RSA and other encryption algorithms
Before calling this function, EVP_EncryptInit_ex_APIParam_1 must be initialized
If SSL_CIPHER_get_bits_APIParam_1 is NULL, return 0
The content is output in BER format using an encoding constructed with an uncertain length, unless the signed data has separate content (the content is missing and uses the DER format)
The last piece will fail and subsequent decryption
If the allocation fails, DSA_new_APIName returns NULL and sets the error code that can be obtained by ERR_get_error_APIName.
If the method is successfully added, EVP_PKEY_meth_add0_APIName returns 1; if an error occurs, it returns 0
These functions are currently the only way to store encrypted private keys in DER format
Under normal operation, lh_ <type> _insert_APIName returns NULL
It should be noted that neither of these two methods can be used on a server running without user interaction
The BN_CTX_get_APIParam_0 pointer obtained from BN_CTX_get_APIName becomes invalid
The caller is responsible for ensuring that EVP_EncodeFinal_APIParam_2 is large enough to accommodate the output data, which will never exceed 65 bytes, plus an additional NUL terminator
It should point to an 8-byte buffer or NULL
Must seed PRNG before calling DSA_sign_APIName
Similar measures should be taken to ensure the data format is correct
The use of temporary RSA key exchange for other purposes violates the standard and may disrupt interoperability with clients
Finally, BN_CTX_end_APIName must be called before returning from the function
All these functions use DER format and unencrypted keys
It is not recommended to use the compression API in the current state
Then return 2
Multi-threaded applications will crash randomly
EVP_SealUpdate_APIName and EVP_SealFinal_APIName return 1 for success, 0 for failure
The type of func should be LHASH_DOALL_ARG_FN_TYPE
SMIME_read_CMS_APIName returns a valid SMIME_read_CMS_APIParam_0 structure, or NULL if an error occurs
 SSL_rstate_string_APIName should always return "RD" / "Read completed"
For the "new" style callback, the BN_GENCB structure should be initialized by calling BN_GENCB_set, where gencb is BN_is_prime_ex_APIParam_4 BN_GENCB_call_APIParam_1, the type of callback is int, and cb_arg is invalid
The suggested way to control the default implementation is to use the ENGINE API function
DSA_generate_parameters_APIName returns a pointer to the DSA structure, if the parameter generation fails, it returns NULL
Under normal circumstances, it is never necessary to set a value less than the default value, because the buffer is processed dynamically and only uses the memory actually required by the data sent by the peer
DSA_do_verify_APIName returns 1 for a valid signature, 0 for an incorrect signature, and -1 for an error
However, the significance of this result depends on whether the ENGINE API is used, so DSA_get_default_method_APIName is no longer recommended
As a result, applications may wish to use multiple keys and avoid using long-term keys stored in files
Some old ``export-grade'' clients may only support weak encryption using 40 or 64-bit RC2
When calling SSL_get1_curves_APIParam_1 SSL_set1_curves_list_APIParam_1 SSL_set1_curves_APIParam_1 on the client, SSL_get_shared_curve_APIName is meaningless and returns -1
Therefore, this feature cannot be used with any arbitrary RSA key object
Any FILE pointer or BIO should be opened in binary mode
Library crash
EC_GROUP_get_seed_len returns the length of the seed; if no seed is specified, returns 0
Even if the application explicitly does not want to set any prefix, it must be explicitly set to ""
A special label shall be provided at the position pointed to by the label, and the length of the label shall be llen bytes
SSLv2 does not support closing the alarm protocol, so it can only detect SSLv2 and whether the basic connection is closed
An error occurred, please check the error stack for detailed error messages
mul_add_APIParam_1 sqr_APIParam_1 mul_APIParam_1 bn_div_words_APIParam_1 bn_mul_words_APIParam_4 can be 16, 32 or 64 bits, depending on the "number of bits" specified in openssl/bn
The callback function should return 2
The callback should return 1 for successful verification, and 0 for failed verification
BF_encrypt_APIName and BF_decrypt_APIName should not be used
EVP_EncryptInit_ex_APIName, EVP_EncryptUpdate_APIName and EVP_EncryptFinal_ex_APIName return 1 for success, 0 for failure
The following return values ​​may appear
HMAC_APIName returns a pointer to the message authentication code; if an error occurs, it returns NULL
The following flags can be passed in the flags parameter
The risk of reusing DH parameters is that an attacker may focus on very commonly used DH groups
BIO_set_accept_name_APIParam_1 is represented by a string of the form "host: port", where "host" is the interface to be used and "port" is the port.
After this call, X509_STORE_CTX_set0_param_APIParam_2 should not be used
The ok parameter of the callback indicates the value that the callback should return to retain the default behavior
Another socket cannot be bound to the same port
16 bytes can be used, but 32 bytes can be used
The application should call CONF_modules_load instead
Supported protocols are SSLv2, SSLv3, TLSv1, TLSv1.1 and TLSv1.2
DH_set_default_method_APIName is no longer recommended
OBJ_txt2nid_APIParam_1 can be the long name, short name or numeric representation of the object
X509_VERIFY_PARAM_set1_ip_APIParam_2 is a binary format, network byte order, for IPv4, iplen must be set to 4; for IPv6, iplen must be set to 16
The following flag can be passed in the CMS_uncompress_APIParam_4 parameter
When using the callback on the server side, it should return SSL_TLSEXT_ERR_OK, SSL_TLSEXT_ERR_NOACK or SSL_TLSEXT_ERR_ALERT_FATAL
OCSP_resp_find_status_APIParam_3 value will be one of V_OCSP_CERTSTATUS_GOOD, V_OCSP_CERTSTATUS_REVOKED or V_OCSP_CERTSTATUS_UNKNOWN
BIO_set_fd_APIName always returns 1
When the basic BIO cannot meet the SSL_accept requirement to continue the handshake, SSL_accept will also be returned, and the problem is indicated by a return value of -1
OpenSSL ASN1 function cannot handle non-blocking I/O normally
Bytes are sent, and a new SSL_write_APIName operation with a new buffer must be initiated
CMS_RecipientInfo_ktri_cert_cmp_APIName compares the certificate CMS_RecipientInfo_ktri_cert_cmp_APIParam_2 with the CMS_RecipientInfo structure CMS_RecipientInfo_ktri_cert_cmp_APIParam_1, the type of the certificate must be CMS_RECIPINFO_TRANS
SSL_get_servername_type returns the server name type; if the server name does not exist, it returns -1
RSA_private_decrypt_APIParam_3 must point to the RSA_size bytes of memory
Rates are 2^-80 starting at 308 bits, 2^-112 starting at 852 bits, 2^-128 starting at 1080 bits, 2^-192 starting at 3747 bits and 2^-256 starting at 6394 bits
To avoid ambiguity with normal positive return values, BIO_set_mem_eof_return_APIParam_2 should be set to a negative value, usually -1
This may lead to unexpected results
Support the following signs
EVP_DigestInit_ex_APIName, EVP_DigestUpdate_APIName and EVP_DigestFinal_ex_APIName return 1 for success, 0 for failure
SSL_want_APIName may present the following return value
DSA_verify_APIName returns 1 for valid signature, 0 for incorrect signature, -1 for error
The data to be stored in EC_KEY_insert_key_method_data is provided in the EC_KEY_insert_key_method_data_APIParam_2 parameter, which must have associated functions for copying, releasing, and "clearing" data items.
This method must be called to initialize the digest BIO before passing any data to the digest BIO
BN_copy_APIName successfully returns BN_copy_APIParam_1, error returns NULL
You must call SSL_library_init_APIName before you can perform any other operations
EC_POINT_hex2point returns a pointer to the provided EC_POINT, or NULL if an error occurs
If the comparison is successful, CMS_RecipientInfo_ktri_cert_cmp_APIName returns zero, otherwise it returns non-zero
BN_mod_word and BN_div_word return BN_mod_word_APIParam_1 BN_div_word_APIParam_1% BN_mod_word_APIParam_2 successfully return BN_div_word_APIParam_2, if an error occurs return -1
The following string may appear in SSL_alert_type_string_APIName or SSL_alert_type_string_long_APIName
You can pass any of the following signs in the CMS_add1_signer_APIParam_5 parameter
RSA key will return EVP_PKEY_RSA
Should make a copy or increase the reference count
EVP_CIPHER_mode_APIName and EVP_CIPHER_CTX_mode_APIName return the block password mode EVP_CIPH_ECB_MODE, EVP_CIPH_CBC_MODE, EVP_CIPH_CFB_MODE or EVP_CIPH_OFB_MODE.
Only RSA password can be selected
The constant EVP_MAX_IV_LENGTH is the maximum IV length of all passwords
Once new data is written to satisfy the read request or partial read request, BIO_get_read_request_APIName and BIO_ctrl_get_read_request_APIName will also return zero.
The callback should return a positive value
Otherwise, the callback should return 0 when an error occurs
To handle the KEKRecipientInfo type, you should first call CMS_set1_key_APIName or CMS_RecipientInfo_set0_key_APIName and CMS_ReceipientInfo_decrypt_APIName, and then set CMS_decrypt_APIName and CMS_decrypt_APIParam_3 and CMS_decrypt_APIParam_2 to NULL.
EVP_DigestInit_APIName, EVP_DigestFinal_APIName and EVP_MD_CTX_copy_APIName functions are obsolete, but reserved to maintain compatibility with existing code
SSL_rstate_string_APIName and SSL_rstate_string_long_APIName can return the following values
DES_fcrypt_APIParam_1 must be at least 14 bytes long
EVP_VerifyInit_ex_APIName and EVP_VerifyUpdate_APIName return 1 for success, 0 for failure
Unable to safely pass the BIO_find_type_APIName in OpenSSL 0.9.5 a and earlier to the NULL pointer of the BIO_find_type_APIParam_1 parameter
X509_add1_trust_object_APIParam_1 and X509_add1_trust_object_APIParam_2 should be released
File BIO supports BIO_gets_APIName and BIO_puts_APIName
Applications rarely call this function directly, but OpenSSL uses it internally for certificate verification in S/MIME and SSL/TLS codes
BUF_MEM_grow_APIName error or new size returns zero
If an error occurs, PKCS7_encrypt_APIName returns the PKCS7 structure or NULL
BIO_new_CMS_APIName returns the BIO chain when successful, or NULL if an error occurs
SMIME_write_CMS_APIName returns 1 for success or 0 for failure
X509_STORE_CTX_init_APIName returns 1 successfully, or 0 if an error occurs
The context returned by BIO_get_md_ctx_APIName can be used for calls to EVP_DigestFinal_APIName, and can also be used for signature routines EVP_SignFinal_APIName and EVP_VerifyFinal_APIName
OBJ_nid2ln_APIName and OBJ_nid2sn_APIName return valid string or NULL when error
CRYPTO_get_ex_data returns application data or 0 on failure
This may lead to unexpected behavior
The first client_len in the client is returned in SSL_select_next_proto_APIParam_1, SSL_select_next_proto_APIParam_2
SSL_CTX_set1_param_APIName and SSL_set1_param_APIName return 1 for success, 0 for failure
Two types of BN_is_prime_ex_APIParam_4 BN_GENCB_call_APIParam_1 structures are supported: "new" style and "old" style.
If the callback fails to generate a session ID for some reason, the callback must return 0, or 1 if successful.
Client certificate can only be sent
The application should check the return value before printing out any debugging information related to the current certificate
After loading the new certificate and private key, the application should appropriately call SSL_CTX_check_private_key_APIName or SSL_check_private_key_APIName to confirm that the certificate and key match
BN_mpi2bn_APIName returns BN_bn2mpi_APIParam_1 BN_mpi2bn_APIParam_3, NULL is returned on error
You can also use the returned CMS_SignerInfo structure and the CMS attribute utility function or CMS signature receipt request function to add new attributes.
An SSL_get_error call with the return value SSL_write will produce SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE
The error number is stored in verify_callback_APIParam_2, and verify_callback is called with verify_callback_APIParam_1 = 0
DH_new_method_APIName returns NULL and sets an error code. If the allocation fails, the error code can be obtained by ERR_get_error_APIName
Session ID is not critical to security, but must be unique to the server
The CMS_STREAM flag must be included in the corresponding flag parameter of the BIO_new_CMS_APIParam_2 creation function
As a result, EVP_PKEY_size_APIName must return a value indicating the maximum possible signature of any set of parameters
It may be argued that BIO_gets_APIName and BIO_puts_APIName should be passed to the next BIO in the chain and the passed data should be summarized, and a separate BIO_ctrl_APIName call should be used to retrieve the summary.
Before using this function, you should call OpenSSL_add_all_algorithms_APIName, otherwise an error about unknown algorithm will occur
The returned pointer cannot be released by the calling application
These functions are much more efficient than ordinary BIGNUM arithmetic operations.
Setting SHA256_Final_APIParam_1 SHA512_Final_APIParam_1 SHA384_Final_APIParam_1 SHA224_Final_APIParam_1 SHA1_Final_APIParam_1 to NULL is not thread safe
It is the responsibility of this function to create or retrieve password parameters and maintain their status
After this call, BIO_ctrl_get_write_guarantee_APIParam_1 BIO_ctrl_get_read_request_APIParam_1 BIO_ctrl_reset_read_request_APIParam_1 is no longer allowed to be written on BIO
DES_enc_write and DES_enc_read cannot handle non-blocking sockets
Finally, use UI_process_APIName to actually execute the prompt, and use UI_get0_result_APIName to find the result of the prompt
You can set all parameters except EVP_EncryptInit_ex_APIParam_2 to NULL in the initial call, and provide the remaining parameters in subsequent calls, all of which set EVP_EncryptInit_ex_APIParam_2 to NULL.
According to the SSLv3 specification, the challenge should use 32 bytes, but as mentioned above, this destroys the server, so 16 bytes is a viable method.
Since the size of the SSL/TLS record may exceed the maximum packet size of the underlying transmission, it may be necessary to read multiple packets from the transport layer before the recording is completed and the SSL_read_APIName is successful
RSA_padding_add_xxx_APIName function returns 1 successfully, and error returns 0
It should not be released or modified in any way
RSA password using DHE requires certificate and key and additional DH parameters
EVP_MD_CTX_copy_ex_APIName returns 1 if it succeeds, 0 if it fails
Later you must use OPENSSL_free_APIName to release the string
This feature does not apply to RSA public keys filled with modulus and public exponent elements only
EC_POINT_bn2point returns a pointer to the provided EC_POINT, or NULL if an error occurs
Before using this feature, you must sow PRNG
EVP_PKEY_CTX_new_APIName, EVP_PKEY_CTX_new_id_APIName, EVP_PKEY_CTX_dup_APIName returns the newly allocated EVP_PKEY_CTX_dup_APIParam_1 structure, or NULL if an error occurs
Older applications may implicitly use X509_STORE_CTX_set0_param_APIParam_1 X509_STORE_CTX_get0_param_APIParam_1 X509_STORE_CTX_free_APIParam_1 X509_STORE_CTX_set_default_APIParam_1 X509_STORE_CTX_cleanup_API_Param_1 X509_API_Param_1 X509_API_Param_1
Because generating DH parameters is very time-consuming, the application should not generate parameters immediately, but should provide parameters
Since auto-finding is only applicable to SSL/TLS servers, the flag SSL_SESS_CACHE_NO_INTERNAL_LOOKUP has no effect on the client.
Fatal errors will be marked and handshake will fail
Cannot be shared between threads
SSL_CONF_CTX_set1_prefix_APIName returns 1 for success and 0 for failure
Or, if an error occurs, return 0
The same TLS/SSL I/O function should be called again later
Returns the parsed CMS_ContentInfo structure, or NULL if an error occurs
SSL_write_APIName will also return successfully
The error condition cannot be processed and must be handled using SSL_get_error_APIName
BIO_find_type returns the next matching BIO or NULL (if not found)
However, this return value may be ignored
The client must send the same information about the acceptable SSL/TLS protocol level as during the first greeting
Invalid byte string length is 0
EVP_PKEY_get_default_digest_nid_APIName returns 0 or a negative value indicating failure
Make sure you have also disabled all previous or all future protocol versions
The source/sink may only indicate that no data is currently available, and the application should retry the operation later
Callers who only have const access to the indexed data in the table, but declare that there is no callback type of constant type, are creating their own risks/errors, and the API discourages this
SSL_rstate_string_long_APIName and SSL_rstate_string_APIName are hardly needed in the application
These functions return 1 for success, and 0 for failure.
The integer used for point multiplication will be between 0 and n-1, where n is EC_GROUP_set_generator_APIParam_3 EC_GROUP_get_order_APIParam_2
OpenSSL error strings should be loaded by calling ERR_load_crypto_strings_APIName, or for SSL applications, first call SSL_load_error_strings_APIName to load.
ASN1_STRING_cmp_APIName compares ASN1_STRING_cmp_APIParam_1 and ASN1_STRING_cmp_APIParam_2 returns 0 if both are the same
The value returned by this TLS/SSL I/O function must be passed to the parameter SSL_get_error_APIParam_2 SSL_get_error_APIParam_2 in SSL_get_error_APIName
Otherwise it should be any other value
To use the serverinfo extension for multiple certificates, you need to call SSL_CTX_use_serverinfo multiple times, each time you load the certificate
The following flag can be passed in the SMIME_write_PKCS7_APIParam_4 parameter
SSL_CTX_add_client_CA_APIName and SSL_add_client_CA_APIName have the following return values
Expect to call this function from the application callback cb
Applications are encouraged to use X509_VERIFY_PARAM_set1_host_APIName instead of explicitly calling X509_check_host_APIName.
Low-level algorithm-specific functions cannot be used with ENGINE, and the ENGINE version of the new algorithm cannot be accessed using low-level functions
The actual verification process is performed using the built-in verification process, or using the verification function provided by other applications set through SSL_CTX_set_cert_verify_callback_APIName
If the allocation fails, ECDSA_SIG_new_APIName returns NULL
The protocol data in server, server_len and client, client_len must use the protocol list format described below
-2 return
The new code should use EVP_EncryptInit_ex_APIName, EVP_EncryptFinal_ex_APIName, EVP_DecryptInit_ex_APIName, EVP_DecryptFinal_ex_APIName, EVP_CipherInit_ex_APIName and EVP_CipherFinal_ex_APIName
PKCS7_get0_signers_APIName returns all signers, or NULL if an error occurs
ASN1_STRING_new_APIName type is undefined
For successful matches, the function returns 1; for failed matches, it returns 0; for internal errors, it returns -1.
Other applications should use EVP_DigestInit_APIName
Do not retry the application
The first byte of the plaintext buffer should be the algorithm identifier byte
These features are only useful for TLS/SSL servers
Do not mix the verification callback described in this function with the verify_callback function called
Password BIO does not support BIO_gets_APIName or BIO_puts_APIName
The public key is encoded using the SubjectPublicKeyInfo structure, and an error occurs
The function EC_POINT_point2oct must be provided with a buffer sufficient to store the octet string
SSL_CTX_set1_curves_APIName, SSL_CTX_set1_curves_list_APIName, SSL_set1_curves_APIName, SSL_set1_curves_list_APIName, SSL_CTX_set_ecdh_auto_APIName and SSL_set_ecdh_auto_APIName return 0 means failure
SSL_CTX_set_alpn_protos_APIParam_2 SSL_set_alpn_protos_APIParam_2 must be in the protocol list format, as described below
Therefore, the memory area provided must remain unchanged until the BIO is released
One should get a new reference
SSL_library_init_APIName always returns "1", so the return value can be safely discarded
ECDSA_sign_ex_APIParam_2 must point to the memory bytes of ECDSA_size
By setting the basic BIO, the communication channel must have been set and assigned to SSL_accept_APIParam_1
RSA_blinding_on_APIParam_2 RSA_blinding_on_APIParam_2 is NULL or RSA_blinding_on_APIParam_2 RSA_blinding_on_APIParam_2 that has been pre-allocated and initialized
EVP_PKEY_set_alias_type_APIName returns 1 for success, 0 for error
First call i2d_SSL_SESSION by setting pp to NULL to get the required amount of space and get the required size, allocate memory, and then call i2d_SSL_SESSION again
X509_STORE_CTX_get_error returns X509_V_OK or error code
SMIME_read_CMS_APIParam_2 should be initialized to NULL
The meaning of the following return value
The function must first call BN_CTX_start_APIName
For the corresponding key type, the return value will be EVP_PKEY_RSA, EVP_PKEY_DSA, EVP_PKEY_DH or EVP_PKEY_EC; if no key type is assigned, the return value is NID_undef
CMS_ReceiptRequest_create0_APIName returns the signed receipt request structure, or NULL if an error occurs
The return values ​​of SSL_CTX_get_read_head_APIName and SSL_get_read_ahead_APIName are not defined for DTLS
OCSP_resp_find_APIName returns the index of OCSP_resp_find_APIParam_2 in OCSP_resp_find_APIParam_1; if OCSP_resp_find_APIParam_2 is not found, -1 is returned.
API and API return 1 if successful, 0 if failed
It is strongly recommended to use string type such as MBSTRING_ASC or MBSTRING_UTF8 for X509_NAME_add_entry_by_OBJ_APIParam_3 X509_NAME_add_entry_by_txt_APIParam_3 X509_NAME_add_entry_by_NID_APIParam_3 parameter
BN_mod_APIName corresponds to BN_div_APIName with BN_div_APIParam_1 set to NULL
Not all BIOs support these calls
If the client does not send a supported curve extension, SSL_get1_curves_APIName can return zero
The application may need to securely establish the context in which this key material will be used
EVP_PKEY_derive_init_APIName and EVP_PKEY_derive_APIName return 1 for success, and 0 for failure.
EVP_CipherInit_ex_APIName and EVP_CipherUpdate_APIName return 1 for success, 0 for failure
Each prompt will get an index number, which is returned by the UI_add and UI_dup functions, and must be used to obtain the corresponding result through UI_get0_result_APIName
CMS_add0_cert_APIName, CMS_add1_cert_APIName and CMS_add0_crl_APIName and CMS_add1_crl_APIName return 1 for success, 0 for failure
The following return values ​​may appear for SSL_CTX_set_ssl_version_APIName and SSL_set_ssl_method_APIName
BIO_get_fd_APIName returns the socket; if BIO has not been initialized, it returns -1
BN_mod_inverse_APIName returns BN_mod_inverse_APIParam_1 with inverse, NULL if error
The OpenSSL library expects the function to set an arbitrary name, initialize iv, and set the password context ctx and hash context hctx
EVP_PKEY_CTX_ctrl_APIName and its macro return a positive value for success and a 0 or negative value for failure
Usually, the application will first decrypt the appropriate CMS_RecipientInfo structure to make the content encryption key available. It will use features like CMS_add1_recipient_cert_APIName to add new recipients, and finally use CMS_RecipientInfo_encrypt_APIName to encrypt the content encryption key.
CMS_get0_signers_APIName must be called after successful CMS_verify operation
It should be released using sk_X509_pop_free_APIName
Use DES_ncbc_encrypt instead
CMS_SignerInfo_get0_signer_id_APIName returns 1 for success, 0 for failure
The SSL engine must know whether the SSL engine must call the connect or accept routine
PKCS#7 and envelope data only support RSA keys, so the recipient certificate provided to this function must all contain the RSA public key
EVP_CipherInit_ex_APIParam_6 should be set to 1 for encryption, set to 0 for decryption, set to -1 to remain unchanged
These functions should not be used to check or modify ASN1_INTEGER or ASN1_ENUMERATED types
EVP_PKEY_sign_init_APIName and EVP_PKEY_sign_APIName return 1 for success, and 0 for failure.
The following mode changes can be made
They should be set to NULL
It can be said that the chain verification should be performed using the signature time instead of the current time.
If the value of SSL_CONF_cmd_APIParam_2 is recognized and SSL_CONF_cmd_APIParam_3 is not used, SSL_CONF_cmd returns 1; if both SSL_CONF_cmd_APIParam_2 and SSL_CONF_cmd_APIParam_3 are used, SSL_CONF_cmd returns 2.
ECB mode is not suitable for most applications
DSA_new_method_APIName returns NULL and sets an error code. If the allocation fails, the error code can be obtained by ERR_get_error_APIName
The PRNG must be seeded before calling BN_generate_prime_ex_APIName
Applications should use this flag with extreme caution, especially in automated gateways, as it may make them vulnerable to attacks
Any encryption algorithm required by OpenSSL should be used
The values ​​of SSL_select_next_proto_APIParam_1 and SSL_select_next_proto_APIParam_2 vectors should be set to the value of a single protocol selected from SSL_select_next_proto_APIParam_0 SSL_CTX_set_alpn_protos_APIParam_0 SSL_set_alpn_protos_APIParam_0
Password context ctx should use initialization vector iv
The constant EVP_MAX_KEY_LENGTH is the maximum key length of all passwords
At least the flag CERT_PKEY_VALID must be set to make the chain available
SSL_get_servername_APIName returns the specified type of server name extension value (if provided in the client Hello) or NULL
If there is no such value in the hash table, it returns NULL
PKCS12_parse_APIName returns 1 for success, 0 for error
For all functions, returns 1 for success and 0 for errors
SSL_CTX_set_quiet_shutdown_APIParam_2 can be 0 or 1
After the call, X509_STORE_CTX_free_APIParam_1 is no longer valid
Return the deleted item, it must be released
Use SSL_shutdown_apiparam0 to call SSL_get_error (3) to find out the reason
If the points are not equal, EC_POINT_cmp returns 1; if the points are not equal, it returns 0; if it is wrong, it returns -1.
X509_NAME_get_index_by_NID_APIName can also return -2
The actual X509 structure cannot simply be fed using an empty structure (such as the structure returned by X509_new)
BIO_should_write_APIName is true
The caller can discard ``const'' or use a macro to declare/implement a wrapper function that does not have a ``const'' type
If the allocation fails, it returns a pointer to the string "OPENSSL_malloc error"
nid_key and nid_cert are encryption algorithms applied to keys and certificates, respectively
BN_value_one_APIName returns a constant
Cannot release SSL_get0_alpn_selected_APIParam_2
If BIO has read EOF, BIO_eof_APIName returns 1, and the exact meaning of "EOF" varies depending on the type of BIO
BN_CTX_end_APIName must be called before BN_CTX_free_APIName to release BN_CTX_new_APIParam_0.
If the verification is successful, EVP_PKEY_verify_init_APIName and EVP_PKEY_verify_APIName return 1, if the verification fails, return 0
Generally, the current time should be between these two values
DSA_generate_parameters_ex_APIParam_1 allows up to 1024 bits
Care should be taken to refresh all data in the write buffer
The return value is 1
This flag must be used with SSL_VERIFY_PEER
The RSA key has a 512-bit RSA derived password. A temporary 512-bit RSA key is required because the length of the key provided is usually 1024 bits
After a successful read, BIO_get_read_request_APIName and BIO_ctrl_get_read_request_APINamel will return zero
ASN1_generate_nconf_APIName and ASN1_generate_v3_APIName return the encoded data in the form of ASN1_generate_nconf_APIParam_0 ASN1_generate_v3_APIParam_0; if an error occurs, NULL is returned
Modes can be combined from 1,2,4,8
ERR_lib_error_string_APIName, ERR_func_error_string_APIName and ERR_reason_error_string_APIName return a string, or NULL if no error code is registered.
X509_STORE_CTX_new_APIName returns the newly allocated context, or NULL when an error occurs
ECDSA_verify_APIName and ECDSA_do_verify_APIName return 1 for valid signature, 0 for invalid signature, and -1 for error
Will be signed in clear text, this option is only meaningful for signedData with PKCS7_DETACHED also set
New applications should use the PEM_write_bio_PKCS8PrivateKey or PEM_write_PKCS8PrivateKey routine to write private keys
Any code that mixes the two will not work on all platforms
The algorithm passed in the password parameter must support the ASN1 encoding of its parameter
This information can only be used for normal operation under non-blocking I/O
EVP_PKEY_assign_RSA_APIName, EVP_PKEY_assign_DSA_APIName, EVP_PKEY_assign_DH_APIName and EVP_PKEY_assign_EC_KEY_APIName return 1 for success, 0 for failure
SSL_get_shared_ciphers_APIName is only a server-side function and must be called after the initial handshake is completed
If the password does not have an object identifier or does not support ASN1, this function will return NID_undef
The TLS/SSL I/O function should be called again later
Don't use TLSv1.2 protocol
If HMAC_Init_ex_API_amName is called with HMAC_Init_ex_APIParam_2 NULL, and HMAC_APIParam_1 is different from the previous summary used by HMAC_Init_ex_APIParam_1, return error is not supported
Violation will cause the program to be aborted
It must be released sometime after the operation
Key size of num <1024 should be considered insecure
BIO_new_bio_pair_APIName returns 1 successfully, provides new BIO in BIO_new_bio_pair_APIParam_1 and BIO_new_bio_pair_APIParam_3, returns 0 on failure, and stores the NULL pointer to the location of BIO_new_bio_pair_APIParam_1 and BIO_new_bio_pair_APIParam_3
The code should not assume that i2d_X509_APIName will always succeed
RAND_query_egd_bytes_APIName returns the number of bytes read from the daemon when successful; if the connection fails, it returns -1
EVP_PKEY_encrypt_init_APIName and EVP_PKEY_encrypt_APIName return 1 for success, 0 for failure, or a negative value
X509_NAME_add_entry_APIParam_2 must be released after the call
In this case, the leak will be minimal, which will allow the attacker to observe memory access patterns with byte granularity, and the timing analysis performed afterwards will not work
EVP_OpenUpdate_APIName returns 1 for success or 0 for failure
This option sets the certificate as the current certificate and returns 1
Therefore, SSL_get_error_APIName must be used in the same thread that performs TLS/SSL I/O operations, and no other OpenSSL function calls should appear between the two.
BN_dup_APIName returns new BN_copy_APIParam_1 BN_dup_APIParam_1, error returns NULL
RSA_new_method_APIName returns NULL and sets an error code. If the allocation fails, the error code can be obtained by ERR_get_error_APIName
The actual X509 structure passed to i2d_X509 must be a validly filled i2d_X509_APIParam_1 structure
X509_set1_notBefore_APIName, X509_set1_notAfter_APIName, X509_CRL_set1_lastUpdate_APIName and X509_CRL_set1_nextUpdate_APIName return 1 for success or 0 for failure
The returned chain may be incomplete or invalid
It is recommended to use the ENGINE API to control the default implementation for DSA and other cryptographic algorithms
It is the caller's responsibility to ensure that EVP_EncodeUpdate_APIParam_2 EVP_EncodeUpdate_APIParam_2 EVP_EncodeFinal_APIParam_2 EVP_EncodeUpdate_APIParam_2 EVP_EncodeUpdate_APIParam_2 buffer is large enough to accommodate the output data
The PRNG must be seeded before calling DSA_generate_key_APIName
CMS_get1_ReceiptRequest_APIName returns 1, indicating that the signed receipt request was found and decoded
If the source/receive BIO cannot recognize the BIO_ctrl_APIName operation, they return 0.
In settings where an attacker can measure the RSA decryption or signature operation time, the blind method must be used to protect the RSA operation from attack
CRYPTO_set_dynlock_create_callback_APIParam_1 is required to create a lock
The input data cannot be a multiple of 4 and an error occurs
BIO_free_APIName will release only one BIO, resulting in a memory leak
The recovered key length must match the fixed password length
EVP_VerifyFinal_APIName returns 1 for the correct signature, 0 for failure, and -1 if other errors occur.
If the message digest is advisory, the EVP_PKEY_get_default_digest_nid_APIName function returns 1, if the message digest is required, it returns 2
EVP_DecryptInit_ex_APIName and EVP_DecryptUpdate_APIName return 1 for success, 0 for failure
client_cert_cb's job is to store information about the status of the last call
The constant EVP_MAX_IV_LENGTH is also the maximum block length of all passwords
X509_check_host_APIName checks whether the subject alternate name or subject common name of the certificate matches the specified host name, which must be encoded according to the preferred name syntax described in Section 3.5 of RFC 1034
In server mode, the server must send a list of CAs that will accept client certificates.
It should be released using UI_free_APIName
Since the reference counter does not increase, the return value of SSL_get0_session_APIName is only valid
CMS_get0_SignerInfos_APIName returns all CMS_SignerInfo structures, if NULL, no signer or error
Need to use HMAC_Init_ex to set hctx
num must point to an integer that is initially zero
CMS_final_APIParam_3 is only used for separated data, usually set it to NULL
EVP_CIPHER_CTX_set_padding_APIName always returns 1
More like RSA_PKCS1_OAEP_PADDING
SSL_CTX_set_tmp_rsa_APIName and SSL_set_tmp_rsa_APIName return 1 on success and 0 on failure
locking_function_APIName must be able to handle up to CRYPTO_num_locks_APIName mutex locks
Don't use TLSv1.1 protocol
BIO_get_cipher_status_APIName should be called to determine whether the decryption was successful
After enabling "quiet shutdown", SSL_shutdown_APIName will always succeed and return 1
CMS_add1_signer_APIName returns NULL
Applications that may pass invalid NID to X509_NAME_get_index_by_NID_APIName should check the return value -2
File descriptor BIO should not be used for socket I/O
BIO is set to read-only, so it cannot be written
Otherwise, it is recommended to fill the f with zero to make fl equal to rsa_len, and set RSA_padding_check_PKCS1_type_2_APIParam_2 to the expected length
If SSL_get_cipher_list_APIParam_1 is NULL, no password is available, or the password is less than the available SSL_get_cipher_list_APIParam_2, then NULL is returned.
This feature is only recommended
HMAC_Final_APIName puts the message authentication code in HMAC_Final_APIParam_2, the code must have space for hash function output
The returned pointer is an internal pointer and cannot be released
If the password does not use IV, the API and API will return zero
SHA1_Final_APIName puts the message digest in SHA1_Final_APIParam_1, the digest must have 20 bytes of output space, and erase SHA1_Final_APIParam_2
The encrypted final data will be written to EVP_EncryptFinal_ex_APIParam_2 EVP_EncryptUpdate_APIParam_2, the space should have enough space for a cipher block
Certificates that include SSL_CTX_select_current_cert_APIParam_2 SSL_CTX_add0_chain_cert_APIParam_2 SSL_add0_chain_cert_APIParam_2 SSL_CTX_add1_chain_cert_APIParam_2 SSL_select_current_cert_APIParam_2 SSL_add1_chain_cert_API_Param_2 are not referenced and are not incremented after the reference count is provided or not provided, and are not incremented after the reference count or provision is provided.
The application must not release the return value
EVP_PKEY_set1_engine_APIName returns 1 for success and 0 for failure
BIO_set_fp_APIName and BIO_get_fp_APIName return 1 for success or 0 for failure
BIO_do_handshake_APIName is invalid
The total amount of data encrypted or decrypted must be a multiple of the block size, otherwise an error will occur
One of SSL_CTX_set_verify_APIParam_2 SSL_set_verify_APIParam_2 flag SSL_VERIFY_NONE and SSL_VERIFY_PEER must be set at any time
SSL_rstate_string_APIName returns a 2-letter string that indicates the current reading state of the SSL object SSL_rstate_string_APIParam_1.
If the point is on the curve, EC_POINT_is_on_curve returns 1; otherwise, it returns 0; if it is wrong, it returns -1
EC_GROUP_set_curve_GFp, EC_GROUP_get_curve_GFp, EC_GROUP_set_curve_GF2m, EC_GROUP_get_curve_GF2m successfully returns 1 or error returns 0
For some implementations, this is needed for the solution
Using different compression methods with the same identifier will cause the connection to fail
Verification callbacks can be used to customize certificate verification operations by overriding error conditions or logging errors for debugging
Unlike many standard comparison functions, X509_cmp_time returns 0 when an error occurs
SSL_CTX_add_extra_chain_cert_APIName and SSL_CTX_clear_extra_chain_certs_APIName return 1 on success and 0 on failure
The pseudo-random number generator must set the seed before calling DH_generate_parameters_APIName
These are flexible SSL/TLS methods for the universal version
Trying to use this function in SSLv3 will result in an error
A common cause of problems is trying to use such PEM routines
The first call should set npubk to 0, and should be called again with EVP_SealInit_APIParam_2 set to NULL
Consider using lh_<type>_doall to release all remaining entries in the hash table
However, be sure to also compare the library numbers
The lack of single-pass processing and the need to keep all data in memory mentioned in CMS_verify_APIName also apply to CMS_decrypt_APIName
Extension types cannot be handled internally by OpenSSL, otherwise an error will occur
It supports non-blocking I/O
The second best way to solve this problem is to set hash->down_load = 0 before starting
If an error occurs, it returns NULL
One or both of SSL_CONF_FLAG_CLIENT and SSL_CONF_FLAG_SERVER must be set
EC_POINT_dup_APIParam_1 EC_POINT_copy_APIParam_2 and EC_POINT_copy_APIParam_1 must use the same EC_METHOD
After such trimming, the data length in EVP_DecodeBlock_APIParam_2 must be divided by 4
EC_GROUP_dup returns a pointer to the repeated curve, or NULL if an error occurs
The first thing to do is to create a UI using UI_new_APIName or UI_new_method_APIName and add information to it using the UI_add or UI_dup function
This behavior ensures that each callback is called at most once, and the application never sends unsolicited extensions
EVP_MD_type returns NID_sha1
Write revtime, OCSP_check_validity_APIParam_1 and the values ​​written by OCSP_resp_find_status and OCSP_single_get0_status nextupd are internal pointers, the calling application must not release them
However, on all other systems, the application is responsible for seeding PRNG by calling RAND_add, RAND_egd, or RAND_load_file.
ALPN selects callback SSL_CTX_set_alpn_select_cb_APIParam_2, must return one of SSL_TLSEXT_ERR_OK, SSL_TLSEXT_ERR_ALERT_FATAL or SSL_TLSEXT_ERR_NOACK
This kind of reference can be regarded as a special form of structural reference, but in order to avoid programming errors that are difficult to find, it is recommended to deal with the two references separately.
Therefore, these two functions are no longer the recommended way to control the default values
After calling this function, the encryption operation is completed and EVP_EncryptUpdate should not be called again.
To change the certificate, you need to use SSL_use_certificate_APIName or SSL_CTX_use_certificate_APIName to set the private key pair of the new certificate, and then use SSL_CTX_use_PrivateKey_APIName or SSL_use_PrivateKey_APIName to set the private key
The requirements mentioned in CMS_verify_APIName for lack of single-pass processing and keeping all data in memory also apply to CMS_decompress_APIName
SSL_CTX_sess_set_cache_size_APIParam_2 is a hint, not absolute
Before calling EVP_DigestSignInit_APIName, EVP_SignInit_ex_APIParam_1 must be initialized with EVP_MD_CTX_init_APIName
It is not recommended to change id_len for SSLv2 sessions
The output is always an integer multiple of eight bytes
Unable to load private key without parameter encoding using d2i_ECPrivateKey_APIName
This will never happen
The SSLv2 and SSLv3 protocols have been deprecated and should generally not be used
The data format used by DES_enc_write and DES_enc_read has encryption weaknesses
The algorithm to be used is specified in the PEM_write_bio_PKCS8PrivateKey_nid_APIParam_3 PEM_write_PKCS8PrivateKey_nid_APIParam_3 parameter, and should be the NID of the corresponding OBJECT IDENTIFIER
So SSL_get_shared_curve_APIParam_2 is usually set to zero
You should call SSL_get_error_APIName instead to find
Only DSA password can be selected
SSL_get_read_ahead_APIName SSL_set_read_ahead_APIName has no effect
ASN1_TIME_diff_APIName returns 1 for success and 0 for failure
BIO_pop_APIName returns the next BIO in the chain; if there is no next BIO, it returns NULL
SSL_get_error will return SSL_ERROR_WANT_X509_LOOKUP to indicate that the handshake has been suspended
The accepted BIO must be made available for further incoming connections
The error string will have the following format
Should not use the same function as BIO and may block
DSA_PUBKEY function should be used in preference to DSAPublicKey function
It should be noted that it is necessary to include the password to be used in the list
In any case, you must use the wrong member of x509_store_ctx to set the verification result
If the curve has no NID associated with it, EC_GROUP_get_curve_name will return 0
PEM_write_bio_PKCS7_stream_APIName returns 1 for success and 0 for failure
The callback must never increase id_len or write position SSL_has_matching_session_id_APIParam_2 exceeds the given limit
After retrieving the abstract from the abstract BIO, you must first reinitialize the abstract by calling BIO_reset_APIName or BIO_set_md_APIName, and then pass other data
Application developers do not want to implement it, but use the compiler of their choice to compile the provided module and link it to the target application
EVP_PKEY_get1_RSA_APIName, EVP_PKEY_get1_DSA_APIName, EVP_PKEY_get1_DH_APIName and EVP_PKEY_get1_EC_KEY_APIName return the referenced key; if an error occurs, return NULL
Since 0 means CMS_get0_type, CMS_get0_eContentType and CMS_get0_content return internal pointers that should not be released
BN_value_one_APIName returns the value 1 BN_value_one_APIParam_0 constant
However, please note that these implementations are not available on all platforms
In order to set SSL_SENT_SHUTDOWN, the application must still call SSL_shutdown_APIName or SSL_set_shutdown_APIName itself
EVP_DecodeBlock_APIName returns the length of the decoded data, or -1 if there is an error
X509_NAME_get_entry_APIName returns the X509_NAME_get_entry_APIParam_1 pointer to the requested entry; if the index is invalid, it returns NULL
EVP_CIPHER_iv_length_APIName and EVP_CIPHER_CTX_iv_length_APIName return the IV length, or zero if the password does not use IV.
DES_enc_read uses internal state, so it cannot be used on multiple files
Free the memory we used to save it
It will never succeed!
SSL_read_APIName or SSL_write_APIName will return -1 and indicate the need to retry using SSL_ERROR_WANT_READ
BN_RECP_CTX_new_APIName returns the newly allocated BN_RECP_CTX_new_APIParam_0, error returns NULL
OBJ_nid2obj_APIName returns OBJ_nid2obj_APIParam_0 structure or NULL error
The content must be provided in the SMIME_write_PKCS7_APIParam_3 parameter
SSL_CTX_set_tmp_dh_APIName and SSL_set_tmp_dh_APIName return 1 on success and 0 on failure
Most applications that want to know the key type will only call EVP_PKEY_base_id_APIName, not the actual type
Applications should generally use the SSL_CTX_set_options and SSL_OP_NO_SSLv3 flags to disable SSLv3 negotiation through the above-mentioned version of the flexible SSL/TLS method
This can only be achieved by adding the intermediate CA certificate to the trusted certificate store of the SSL_CTX object, or adding a chain certificate by using the SSL_CTX_add_extra_chain_cert_APIName function (applies only to the entire SSL_CTX object, and possibly only) for one client certificate , Making the concept of callback functions doubtful
The above behavior is modified and returns an error
The application must use the SSL_set_session_APIName function to select the session to be reused
At least one of these flags must be set
The callback function should determine whether the returned OCSP response is acceptable
DH_compute_key_APIParam_1 must point to DH_size memory bytes
EVP_PKEY_assign_RSA_APIName, EVP_PKEY_assign_DSA_APIName, EVP_PKEY_assign_DH_APIName, EVP_PKEY_assign_EC_KEY_APIName, EVP_PKEY_assign_POLY1305_APIName and EVP_PKEY_assign_SIPHASH_APIName return 1 for success, return 1
SSL_COMP_add_compression_method_APIName may return the following values
May malfunction
If the call fails, BIO_new_APIName returns the newly created BIO or NULL
SHA-1 and SHA should only be used
For a more general solution, X509_NAME_get_index_by_NID_APIName or X509_NAME_get_index_by_OBJ_APIName should be used on any matching indexes, followed by X509_NAME_get_entry_APIName, and various X509_NAME_get_entry_APIParam_0 utility functions should be used on the results
If the provided X509_check_host_APIParam_2 contains an embedded NUL, X509_check_host_APIName returns -2
The callback function must provide some random data to psk and return the length of the random data, so before the connection is completely completed, the connection will fail with a decryption error
Both halves of the BIO pair should be released
EVP_EncodeFinal_APIName must be called at the end of the encoding operation
This feature has been implemented this way, because once the pull-in bytes are separated from the input bytes, things become ugly!
Please note that this will advance the values ​​contained in i2d_SSL_SESSION_APIParam_2 i2d_SSL_SESSION_APIParam_2 i2d_SSL_SESSION_APIParam_2, so it is necessary to save the original assigned copy
Before calling this function, EVP_VerifyInit_ex_APIParam_1 must be initialized by calling EVP_MD_CTX_init_APIName
ASN1_OBJECT_free_APIName is invalid
DH_generate_parameters_APIName returns a pointer to the DH structure, if the parameter generation fails, it returns NULL
UI_free_APIName should be used to release new UI
The application usually waits until the necessary conditions are met
i2d_X509_fp_APIName is similar to i2d_X509_APIName, except that i2d_X509_fp_APIName writes the code of structure i2d_X509_fp_APIParam_2 i2d_X509_APIParam_1 to BIO i2d_X509_bio_APIdParam_1 d2i_X509_success and bio2
Applications wishing to avoid this situation should use EVP_MD_CTX_create_APIName instead
The random number generator must be seeded before calling RSA_sign_ASN1_OCTET_STRING_APIName
If successful, it returns a new NID for the created object, if it fails, it returns a NID_undef
Add a padding extension to ensure that the size of ClientHello will never be between 256 and 511 bytes
HMAC_Init_APIName is obsolete and only included for backward compatibility with OpenSSL 0.9.6 b
CMS_set1_eContentType copies the provided OID, and it should be released after use
Applications that need more control over their configuration functions should use the configuration functions directly, such as CONF_modules_load
Return this result code
Due to the modular nature of the ENGINE API, pointers to ENGINE need to be treated as handles-that is, not only as pointers, but also as references to the underlying ENGINE objects
By i2d_DSAPublicKey_APIParam_1 d2i_DSA_PUBKEY_APIParam_1 d2i_DSAPublicKey_APIParam_1 d2i_DSA_SIG_APIParam_1 i2d_DSA_SIG_APIParam_1 i2d_DSA_PUBKEY_APIParam_1 i2d_DSAparams_APIParam_1 d2i_DSAparams_APIParam_1 i2d_DSAPrivateKey_APIParam_1 d2i_DSAPrivateKey_APIParam_1 encoding a functional structure of the private key should have a dedicated key for all components present
The same certificate or CRL cannot be added to the same cms structure multiple times
If decryption fails, EVP_DecryptFinal_ex_APIName returns 0, otherwise it returns 1.
DSA_set_default_method_APIName is no longer recommended
SSL_library_init_APIName is not reentrant
The returned CMS_ContentInfo structure is incomplete and must be completed by streaming or calling CMS_final
For the currently supported content types, return the following values
BIO_reset_APIName usually returns 1 for success and 0 or -1 for failure
EC_KEY_up_ref, EC_KEY_set_group, EC_KEY_set_private_key, EC_KEY_set_public_key, EC_KEY_precompute_mult, EC_KEY_generate_key, EC_KEY_check_key and EC_KEY_set_public_key_affine_coordinates return 1 means error, return 0 means error
RSA_set_default_method_APIName is no longer recommended
The returned EVP_PKEY_CTX value cannot be released directly by the application
It should also be noted that many ENGINE API function calls that accept structure references will internally obtain another reference-usually, this will happen as long as OpenSSL needs to provide the ENGINE after the function returns
BIO_eof_APIName is true
The following flag can be passed in the CMS_decrypt_APIParam_6 parameter
