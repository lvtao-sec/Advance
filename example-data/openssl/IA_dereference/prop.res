The following return values of SSL_connect_APIName can occur, 0, 1, <0
X509_get_notBefore_APIName and X509_get_notAfter_APIName were deprecated in OpenSSL 1.1.0
X509_get_notBefore_APIName and X509_get_notAfter_APIName were deprecated in OpenSSL 1.1.0
RAND_pseudo_bytes_APIName was deprecated in OpenSSL 1.1.0
Only meaningful for client authentication
This alert is always fatal and should never be observed in communication between proper implementations
Only use this in explicit fallback retries , following the guidance in draft-ietf-tls-downgrade-scsv-00
This is only meaningful for client authentication
Previous versions had to use
the SSL/TLS engine must parse the record , consisting of header and body
it will never succeed
it will never succeed
Both BIO_gets_APIName and BIO_puts_APIName are supported
Do not use the SSLv3 protocol
Do not use the TLSv1 .1 protocol
Do not use the TLSv1 protocol
Do not use the SSLv2 protocol
Do not use the TLSv1 .2 protocol
DO NOT ENABLE THIS
The supported protocols are SSLv2 , SSLv3 , TLSv1 , TLSv1 .1 and TLSv1 .2
This is needed as a workaround for some implementations
for any cryptographic algorithm required by OpenSSL, it should be used
the random number generator must be seeded or the operation will fail
At first the library must be initialized
The SSL_CTX_new_APIParam2_1 is deprecated and should not be used
the client must still use the same SSLv3 .1 = TLSv1 announcement
this is no longer possible
The contents of a signed receipt should only be considered meaningful
no certificates added using SSL_CTX_add_extra_chain_cert_APIName will be used
One SSL_get0_session_APIParam2_1 , regardless of its reference count , must only be used with one SSL_get0_session_APIParam2_1
One SSL_get0_session_APIParam2_1 , regardless of its reference count , must only be used with one SSL_get0_session_APIParam2_1
One SSL_get0_session_APIParam2_1 , regardless of its reference count , must only be used with one SSL_get0_session_APIParam2_1
This mode should only be used to implement cryptographically sound padding modes in the application code
The ERR_error_string_n_APIParam_3 should be loaded by calling ERR_load_crypto_strings_APIName or , for SSL applications , SSL_load_error_strings_APIName first
the extension type must not be handled by OpenSSL internally or an error occurs
the SSL engine must know whether the SSL engine must call the connect or accept routines
SSLv2 does not support a shutdown alert protocol , so SSLv2 can only be detected , whether the call SSL_shutdown_APIName was closed
use SSL_CIPHER_description instead
use DES_ncbc_encrypt instead
Use BN_CTX_new_APIName instead
In new applications , SHA-1 or RIPEMD-160 should be preferred
Callers that only have  const  access to lh_retrieve_APIParam_2 they 're indexing in a lh_retrieve_APIParam_1 , yet declare callbacks without constant types , are creating their own risks/bugs without being encouraged to do so by the API
The dynamic parent structure members should not be accessed
BIO_ssl_copy_session_id_APIParam_1 which included workarounds for this bug should be modified to handle this fix or they may free up an call BIO_free_APIName
nid_key and nid_cert are the encryption algorithms that should be used for the key and certificate respectively
The equivalent with BIOs should not be used and may block as a result
An application just needs to add them
Applications usually will not need to modify the embedded content as it is normally set by higher level functions
EC_METHOD_get_field_type identifies what type of field the EC_METHOD structure supports , which will be either F2 ^ m or Fp
Clients should avoid creating  holes  in the set of protocols Clients support
make sure that you also disable either all previous or all subsequent protocol versions
This kind of reference can be considered a specialised form of structural reference , - however to avoid difficult-to-find programming bugs , it is recommended to treat the two kinds of reference independently
The files are looked up by the CA subject name hash value , which must hence be available
one should obtain a new reference
The verify_callback function must be supplied by the application and receives two arguments
a SSL_read_APIName or SSL_write_APIName would return with -1 and indicate the need to retry with SSL_ERROR_WANT_READ
func should be of type LHASH_DOALL_ARG_FN_TYPE
The auto allocation feature only works on OpenSSL 0.9.7 and later
"0" has to be returned and no certificate will be sent
The SSLv2 and SSLv3 protocols are deprecated and should generally not be used
New programs should prefer the  new  style , whilst the  old  style is provided for backwards compatibility purposes
For other types of BIO they may not be supported
Any code mixing the two will not work on all platforms
It is the job of the client_cert_cb to store information about the state of the last call
It is the job of the cert_cb to store information about the state of the last call
You might have to do the latter
the extension must be different
Some old  export grade  clients may only support weak encryption using 40 or 64 bit RC2
This can lead to unexpected behaviour
the curve_name must also be set
the caller can either cast the  const  away or use the macros to declare/implement the wrapper functions without  const  types
the BN_is_prime_ex_APIParam2_1 of checks needs to be much higher to reach the same level of assurance
The extensions must be concatenated into a sequence of bytes
Newer SSL_get_shared_curve_APIParam_2 should just call
This should never happen
A common mistake is to attempt to use a buffer directly as follows
attempting to call EVP_CIPHER_CTX_set_key_length_APIName to any value other than the fixed value is an error
release the memory we were using to hold it
A frequent cause of problems is attempting to use the PEM routines like this
Attempts to use it on earlier versions will typically cause a segmentation violation
The BIO_new_accept_APIParam_1 can be can be   which is interpreted as meaning any BIO_set_nbio_accept_APIParam_2
Note , however , that these implementations are not available on all platforms
Prefer PKCS1_OAEP padding
To enable this , the following is required
The second best solution to this problem is to set hash - > down_load = 0 before you start
As a result Some objects can not be encoded or decoded as part of ASN .1 structures
The public call i2d_PrivateKey_APIName a SubjectPublicKeyInfo structure and an error occurs
This can cause problems as the time_t value can overflow on some systems resulting in unexpected results
These files can be converted into C code using the - C option of the dhparam application
an error condition occurred
In such case leakage would be minimal , it would take attacker  ability to observe memory access pattern with byte granilarity as it occurs , post-factum timing analysis will not do
BIO_puts is not supported
Some non-recoverable , fatal I/O error occurred
This will probably crash somewhere in d2i_X509
A violation will cause the program to abort
This function may fail
This case should not occur
Copies should be made or reference counts increased instead
Additionally it indicates that the session ticket is in a renewal period and should be replaced
However , this return value should probably be ignored
Some attributes such as counter signatures are not supported
The handshake routines may have to be explicitly set in advance using either SSL_set_connect_state_APIName or SSL_set_accept_state_APIName
It is recommended to use the standard terminology
The information must only be used for normal operation under non-blocking I/O
the server must use a DH group and call DH_generate_key_APIName
KEKRecipientInfo structures need to be added
It supports non blocking I/O
The prime may have to fulfill additional BN_generate_prime_ex_APIParam_1 for use in Diffie-Hellman key exchange
All other ciphers need a corresponding certificate and key
This is not thread safe but will never happen
RSA ciphers using DHE need a certificate and key and additional DH-parameters
These commands are supported in the discovery mechanisms simply to allow applications determinie if an ENGINE supports certain specific commands it might want to use
These can support arbitrary operations via ENGINE_ctrl_APIName , including passing to and/or from the ENGINE_set_STORE_APIParam2_2 commands data of any arbitrary type
Both halves must usually by handled by the same application thread
Both halves must usually by handled by the same application thread
This meant that  clone  digests such as EVP_dss1_APIName needed to be used to sign using SHA1 and DSA
This meant that  clone  digests such as EVP_dss1_APIName needed to be used to sign using SHA1 and DSA
DSA ciphers always use DH key exchange and need DH-parameters
It should be noted , that inclusion of a cipher to be used into the list is a necessary SSL_CTX_set_cipher_list_APIParam2_2
Each successful call to RSA_get_ex_new_index will return an index greater than any previously returned , this is important
the certificate will never be used
Currently there are two supported flags BN_BLINDING_NO_UPDATE and BN_BLINDING_NO_RECREATE
no freeing of the results is necessary
This behaviour ensures that each callback is called at most once and that an application can never send unsolicited extensions
SSL_set_current_cert also supports the option SSL_CERT_SET_SERVER
Due to the modular nature of the ENGINE API , pointers to ENGINE_get_load_privkey_function_APIParam2_1 need to be treated as handles - ie not only as pointers , but also as references to the underlying ENGINE_get_load_privkey_function_APIParam2_1
This functions behaves in a similar way to CMS_verify except the flag values CMS_DETACHED , CMS_BINARY , CMS_TEXT and CMS_STREAM are not supported
This functions behaves in a similar way to CMS_sign except the flag values CMS_DETACHED , CMS_BINARY , CMS_NOATTR , CMS_TEXT and CMS_STREAM are not supported
It should also be noted that many ENGINE API function calls that accept a structural reference will internally obtain another reference - typically this happens whenever the call EVP_PKEY_set1_engine_APIName will be needed by OpenSSL after the function has returned
On a related note , those auditing code should pay special attention to any instances of DECLARE/IMPLEMENT _ LHASH_DOALL _ -LSB- ARG _ -RSB- _ FN macros that provide types without any  const  qualifiers
the signed content must all be held in memory
application developers are not expected to implement it , but to compile provided module with compiler of their choice and link it into the target application
Be careful to avoid small subgroup attacks
Because of the format of base64 encoding , the end of the encoded block can not always be reliably determined
New applications should use the SHA2 digest algorithms such as SHA256
another socket can not be bound to the same BIO_new_accept_APIParam_1
the callback must provide some random data to psk and return the length of the random data, so the connection will fail with decryption_error before the connection will be finished completely
this is likely to be very inefficient
A failure can occur
an error occurs
the behaviour is undefined
The ok parameter to the callback indicates the value the callback should return to retain the default behaviour
A non-recoverable , fatal error in the SSL_get_error_APIParam_1 occurred , usually a protocol error
 SSL_rstate_string_APIName should always return "RD"/"read done
The callback should return a positive value
This  reuse  capability is present for historical compatibility but its use is strongly discouraged
The returned pointer must not be freed by the calling application
The actual length of the SSL_CTX_set_default_passwd_cb_APIParam_2 must be returned to the calling function
The callback should return 0
As the reference counter is not incremented , the return value of SSL_get0_session_APIName is only valid
Applications should check the return value before printing out any debugging information relating to the current certificate
Some of the return values are ambiguous and care should be taken
The deleted entry is returned and must be freed up
Applications must not free the return value
It is recommended, to check the return value of SSL_shutdown_APIName and call SSL_shutdown_APIName again
The value returned by that SSL_get_error_APIParam_1 must be passed to SSL_get_error_APIName in parameter SSL_get_error_APIParam_2 SSL_get_error_APIParam_2
The value returned is an internal pointer which must not be freed
Applications must check for return value on error
In general it cannot be assumed that the data returned by ASN1_STRING_data_APIName is null terminated or does not contain embedded nulls
It returns an index which should be stored and passed used in the RSA_set_ex_data_APIParam_2 RSA_get_ex_data_APIParam_2 parameter in the remaining functions
The EVP_PKEY_CTX value returned must not be freed directly by the application
That means that there is no limit on the size of the BN_is_bit_set_APIParam2_1 manipulated by these functions, but return values must always be checked in case a memory allocation error has occurred
callback should return 1 to indicate verification success and 0 to indicate verification failure
In general a verification callback should NOT unconditionally return 1 in all circumstances
Applications which could pass invalid NIDs to X509_NAME_get_index_by_NID_APIName should check for the return value of -2
the callback function should return 2
the returned CMS_ContentInfo structure is not complete and must be finalized either by streaming or a call to CMS_final
the callback MUST return 1
The callback must return 0 if The callback cannot generate a SSL_has_matching_session_id_APIParam_2 for whatever reason and return 1 on success
Otherwise or on errors callback should return 0
the PKCS7_sign_add_signer_APIParam0 is not complete and must be finalized either by streaming or a call to PKCS7_final
The callback should return a negative value on error
The return values for SSL_CTX_get_read_head_APIName and SSL_get_read_ahead_APIName are undefined for DTLS
BIO_eof_APIName is true
BIO_eof_APIName is true
BIO_eof_APIName is true
BIO_should_retry_APIName is true
BIO_should_write_APIName is true
BIO_should_io_special_APIName is true
BIO_should_read_APIName is true
The return value should always be checked goto err
Callback functions should return 1 on success or 0 on error
, the value NID_X9_62_characteristic_two_field is returned
 the value NID_X9_62_prime_field is returned
X509_check_host_APIName return 1 for a successful match, 0 for a failed match and -1 for an internal error
CMS_compress_APIName returns either a CMS_ContentInfo structure or NULL if an error occurred
CMS_encrypt_APIName returns either a CMS_ContentInfo structure or NULL if an error occurred
EVP_PKEY_get0_hmac, EVP_PKEY_get0_poly1305, EVP_PKEY_get0_siphash, EVP_PKEY_get0_RSA, EVP_PKEY_get0_DSA, EVP_PKEY_get0_DH and EVP_PKEY_get0_EC_KEY also return the referenced key in EVP_PKEY_get0_hmac_APIParam_1 EVP_PKEY_get0_poly1305_APIParam_1 EVP_PKEY_get0_siphash_APIParam_1 EVP_PKEY_get0_RSA_APIParam_1 EVP_PKEY_get0_DSA_APIParam_1 EVP_PKEY_get0_DH_APIParam_1 EVP_PKEY_get0_EC_KEY_APIParam_1 or NULL if the key is not of the correct type but the reference count of the returned key is not incremented and so must not be freed up after use
OCSP_resp_get0_id() and OCSP_resp_get1_id() return 1 in case of success and 0 in case of failure
CMS_sign_receipt_APIName returns either a valid CMS_ContentInfo structure or NULL if an error occurred
CMS_sign_APIName returns either a valid CMS_ContentInfo structure or NULL if an error occurred
After successful path validation  OCSP_basic_verify() returns success
SSL_CONF_cmd_argv_APIName returns the number of command arguments processed, 0, 1, 2 or a negative error code
X509_NAME_delete_entry_APIName returns either the deleted X509_NAME_delete_entry_APIParam_0 structure or NULL if an error occurred
After a successful read BIO_get_read_request_APIName and BIO_ctrl_get_read_request_APINamel will return zero
CMS_decrypt_APIName returns either 1 for success or 0 for failure
PKCS7_decrypt_APIName returns either 1 for success or 0 for failure
CMS_uncompress_APIName returns either 1 for success or 0 for failure
EVP_PKEY_CTX_new_APIName, EVP_PKEY_CTX_new_id_APIName, EVP_PKEY_CTX_dup_APIName returns either the newly allocated EVP_PKEY_CTX_dup_APIParam_1 structure or NULL if an error occurred
EVP_PKEY_new_APIName returns either the newly allocated EVP_PKEY_new_APIParam_0 structure or NULL if an error occurred
SSL_CONF_CTX_new_APIName returns either the newly allocated SSL_CONF_CTX_new_APIParam_0 structure or NULL if an error occurs
In versions of OpenSSL before 1.0 the current certificate returned by X509_STORE_CTX_get_current_cert_APIName was never NULL
new_func and dup_func should return 0 for failure and 1 for success
EVP_get_digestbyname_APIName, EVP_get_digestbynid_APIName and EVP_get_digestbyobj_APIName return either an EVP_get_digestbyname_APIParam_0 structure or NULL if an error occurs
PKCS7_encrypt_APIName returns either a PKCS7 structure or NULL if an error occurred
then CMS_compress_APIName will return an error
an error is returned
an error is returned
an error is returned
An error is returned if the parameters are missing in EVP_PKEY_copy_parameters_APIParam_2 or present in both EVP_PKEY_copy_parameters_APIParam_2 and EVP_PKEY_copy_parameters_APIParam_1 and mismatch
BIO_s_null_APIName returns the null BIO_s_null_APIParam_0
BIO_s_null_APIName returns the null BIO_s_null_APIParam_0
BN_bn2hex_APIName and BN_bn2dec_APIName return NULL
CMS_get0_signers_APIName returns NULL
OCSP_resp_get0_APIName returns NULL
PKCS7_sign_add_signers_APIName returns NULL
ECDSA_SIG_new_APIName returns NULL if the allocation fails
CMS_add1_signer_APIName returns NULL
PKCS7_sign_APIName returns either a valid PKCS7 structure or NULL if an error occurred
A successful decrypt followed by EOF will also return zero for the final read
If the underlying BIO is non-blocking, SSL_connect will also return when the underlying BIO could not satisfy the needs of SSL_connect to continue the handshake, indicating the problem by the return value -1
SSL_accept will also return when the underlying BIO could not satisfy the needs of SSL_accept to continue the handshake, indicating the problem by the return value -1
Prior to that the results returned from this function may be unreliable
a "get_default" call will return NULL and the caller will operate with a NULL ENGINE handle
RAND_bytes_APIName and RAND_priv_bytes_APIName return 1 on success, -1 if not supported by the current RAND method, or 0 on other failure
SSL_CTX_set_alpn_protos_APIName and SSL_set_alpn_protos_APIName return 0 on success, and non-0 on failure
BIO_reset_APIName returns zero for success and -1 if an error occurred
X509_NAME_add_entry_by_txt_APIName, X509_NAME_add_entry_by_OBJ_APIName, X509_NAME_add_entry_by_NID_APIName and X509_NAME_add_entry_APIName return 1 for success of 0 if an error occurred
BN_BLINDING_update_APIName, BN_BLINDING_convert_APIName, BN_BLINDING_invert_APIName, BN_BLINDING_convert_ex_APIName and BN_BLINDING_invert_ex_APIName return 1 on success and 0 if an error occurred
CMS_add1_ReceiptRequest_APIName returns 1 for success or 0 if an CMS_add1_ReceiptRequest_APIParam_2 occurred
CMS_RecipientInfo_ktri_get0_signer_id_APIName, CMS_RecipientInfo_set0_pkey_APIName, CMS_RecipientInfo_kekri_get0_id_APIName, CMS_RecipientInfo_set0_key_APIName and CMS_RecipientInfo_decrypt_APIName return 1 for success or 0 if an error occurs
CMS_RecipientInfo_encrypt_APIName return 1 for success or 0 if an error occurs
HMAC_Init_ex_APIName, HMAC_Update_APIName and HMAC_Final_APIName return 1 for success or 0 if an error occurred
CMS_set1_eContentType_APIName returns 1 for success or 0 if an error occurred
i2d_X509_bio_APIName and i2d_X509_fp_APIName return 1 for success and 0 if an error occurs The error code can be obtained by ERR_get_error_APIName
X509_STORE_CTX_set_default_APIName returns 1 for success or 0 if an error occurred
PKCS12_parse_APIName returns 1 for success and zero if an error occurred
X509_STORE_CTX_init_APIName returns 1 for success or 0 if an error occurred
i2d_ECPKParameters_bio_APIName, i2d_ECPKParameters_fp_APIName, d2i_ECPKParameters_APIParam_2 and ECPKParameters_print_fp return 1 for success and 0 if an error occurs
DH_new_method_APIName returns NULL and sets an error code that can be obtained by ERR_get_error_APIName if the allocation fails
DSA_SIG_new_APIName returns NULL and sets an error code that can be obtained by ERR_get_error_APIName
If the allocation fails, X509_new_APIName returns NULL and sets an error code that can be obtained by ERR_get_error_APIName
If the allocation fails, RSA_new_APIName returns NULL and sets an error code that can be obtained by ERR_get_error_APIName
If the allocation fails, DH_new_APIName returns NULL and sets an error code that can be obtained by ERR_get_error_APIName
RSA_new_method_APIName returns NULL and sets an error code that can be obtained by ERR_get_error_APIName if the allocation fails
DSA_new_method_APIName returns NULL and sets an error code that can be obtained by ERR_get_error_APIName if the allocation fails
If the allocation fails, DSA_new_APIName returns NULL and sets an error code that can be obtained by ERR_get_error_APIName
If the allocation fails, ASN1_OBJECT_new_APIName returns NULL and sets an error code that can be obtained by ERR_get_error_APIName
SSL_get_secure_renegotiation_support_APIName returns 1 if the peer supports secure renegotiation and 0 if the peer does not supports secure renegotiation
EVP_PKEY_verify_init_APIName and EVP_PKEY_verify_APIName return 1 if the verification was successful and 0 if the verification failed
SSL_CTX_set_cipher_list_APIName and SSL_set_cipher_list_APIName return 1 if any cipher could be selected and 0 on complete failure
EC_POINT_is_on_curve returns 1 if the EC_POINT_cmp_APIParam2_3 is on the curve, 0 if not, or -1 on error
EC_POINT_cmp returns 1 if the EC_POINT_cmp_APIParam2_3 are not equal, 0 if the EC_POINT_cmp_APIParam2_3 are, or -1 on error
EVP_PKEY_meth_add0_APIName returns 1 if EVP_PKEY_meth_copy_APIParam2_2 is added successfully or 0 if an error occurred
BIO_do_handshake_APIName returns 1 if the connection was established successfully
EC_GROUP_have_precompute_mult return 1 if a precomputation has been done, or 0 if not
CMS_SignerInfo_cert_cmp_APIName  returns zero if the comparison is successful and non zero if not
BN_is_prime_ex_APIName, BN_is_prime_fasttest_ex_APIName, BN_is_prime_APIName and BN_is_prime_fasttest_APIName return 0 if the BN_is_prime_ex_APIParam2_1 is composite, 1 if the BN_is_prime_ex_APIParam2_1 is prime with an error probability of less than 0.25^BN_is_prime_ex_APIParam_2 BN_is_prime_fasttest_ex_APIParam_2, and -1 on error
ASN1_TIME_print_APIName returns 1 if the ASN1_TIME_check_APIParam2_1 is successfully printed out and 0 if an error occurred
CMS_get1_ReceiptRequest_APIName returns 0 if a signed receipt request is not present and -1 if it is present but malformed
BN_cmp_APIName returns -1 if BN_cmp_APIParam_1 BN_ucmp_APIParam_1 < BN_cmp_APIParam_2 BN_ucmp_APIParam_2, 0 if BN_cmp_APIParam_1 BN_ucmp_APIParam_1 == BN_cmp_APIParam_2 BN_ucmp_APIParam_2 and 1 if BN_cmp_APIParam_1 BN_ucmp_APIParam_1 > BN_cmp_APIParam_2 BN_ucmp_APIParam_2
DES_is_weak_key_APIName returns 1 if the passed key is a weak key, 0 if the passed key is ok
BIO_set_buffer_read_data_APIName returns 1 if the data was set correctly or 0 if there was an error
BIO_set_read_buffer_size_APIName, BIO_set_write_buffer_size_APIName and BIO_set_buffer_size_APIName return 1 if the buffer was successfully resized or 0 for failure
BN_value_one_APIName returns the constant
EVP_DecryptFinal_ex_APIName returns 0 if the decrypt failed or 1 for success
OCSP_resp_get0_signer_APIName returns 1 if the OCSP_resp_get0_signer_APIParam_2 was located, or 0 on error
CMS_RecipientInfo_ktri_cert_cmp_APIName returns zero if the comparison is successful and non zero if not
X509_check_host_APIName returns -2 if the provided X509_check_host_APIParam_2 contains embedded NULs
EVP_OpenFinal_APIName returns 0 if the decrypt failed or 1 for success
SSL_has_matching_session_id_APIName returns 1 if another session with the same id is already in the cache
EVP_DecodeFinal_APIName will return -1
EC_GROUP_cmp returns 0 if the curves are equal, 1 if they are not equal, or -1 on error
EVP_PKEY_type will return EVP_PKEY_RSA
SSL_CONF_cmd returns 1 if the value of SSL_CONF_cmd_APIParam_2 is recognised and SSL_CONF_cmd_APIParam_3 is NOT used and 2 if both SSL_CONF_cmd_APIParam_2 and SSL_CONF_cmd_APIParam_3 are used
EVP_CIPHER_iv_length() and EVP_CIPHER_CTX_iv_length() will return zero if the cipher does not use an IV
DH_set_method_APIName returns non-zero if the provided DH_set_method_APIParam_2 was successfully set as the DH_set_method_APIParam2_2 for DH_set_method_APIParam_1
DSA_set_method_APIName returns non-zero if the provided DSA_set_method_APIParam_2 was successfully set as the DSA_set_default_method_APIParam2_1 for DSA_set_method_APIParam_1
EC_KEY_get_conv_form return the EC_KEY_set_conv_form_APIParam_2 for the EC_KEY
0 is returned
-1 is returned if an error occurs while checking the key
-2 is returned
-1 is returned
-1 is returned
then -2 is returned
0 is returned
then 2 is returned
 0 is returned
then EVP_CIPH_STREAM_CIPHER is returned
PEM_write_bio_CMS_stream_APIName returns 1 for success or 0 for failure
i2d_CMS_bio_stream_APIName returns 1 for success or 0 for failure
EVP_PKEY_set1_RSA_APIName, EVP_PKEY_set1_DSA_APIName, EVP_PKEY_set1_DH_APIName and EVP_PKEY_set1_EC_KEY_APIName return 1 for success or 0 for failure
EVP_PKEY_set1_RSA_APIName, EVP_PKEY_set1_DSA_APIName, EVP_PKEY_set1_DH_APIName and EVP_PKEY_set1_EC_KEY_APIName return 1 for success or 0 for failure
EVP_DigestInit_ex_APIName, EVP_DigestUpdate_APIName and EVP_DigestFinal_ex_APIName return 1 for success and 0 for failure
i2d_PKCS7_bio_stream_APIName returns 1 for success or 0 for failure
CMS_add0_cert_APIName, CMS_add1_cert_APIName and CMS_add0_crl_APIName and CMS_add1_crl_APIName return 1 for success and 0 for failure
SSL_CTX_set_tmp_dh_APIName and SSL_set_tmp_dh_APIName do return 1 on success and 0 on failure
SSL_CONF_CTX_set1_prefix_APIName returns 1 for success and 0 for failure
SSL_CONF_finish_APIName returns 1 for success and 0 for failure
BIO_read_filename_APIName, BIO_write_filename_APIName, BIO_append_filename_APIName and BIO_rw_filename_APIName return 1 for success or 0 for BIO_new_fp_APIParam_1
EVP_PKEY_assign_RSA_APIName, EVP_PKEY_assign_DSA_APIName, EVP_PKEY_assign_DH_APIName, EVP_PKEY_assign_EC_KEY_APIName, EVP_PKEY_assign_POLY1305_APIName and EVP_PKEY_assign_SIPHASH_APIName return 1 for success and 0 for failure
EVP_CipherInit_ex_APIName and EVP_CipherUpdate_APIName return 1 for success and 0 for failure
SMIME_write_PKCS7_APIName returns 1 for success or 0 for failure
EVP_CIPHER_param_to_asn1_APIName and EVP_CIPHER_asn1_to_param_APIName return 1 for success or zero for failure
SSL_CTX_add_extra_chain_cert_APIName and SSL_CTX_clear_extra_chain_certs_APIName return 1 on success and 0 for failure
SSL_CTX_add_client_custom_ext_APIName and SSL_CTX_add_server_custom_ext_APIName return 1 for success and 0 for failure
EVP_CIPHER_CTX_cleanup_APIName returns 1 for success and 0 for failure
EVP_EncryptInit_ex_APIName, EVP_EncryptUpdate_APIName and EVP_EncryptFinal_ex_APIName return 1 for success and 0 for failure
X509_set1_notBefore_APIName, X509_set1_notAfter_APIName, X509_CRL_set1_lastUpdate_APIName and X509_CRL_set1_nextUpdate_APIName return 1 for success or 0 for failure
SSL_CTX_set_tmp_rsa_APIName and SSL_set_tmp_rsa_APIName do return 1 on success and 0 on failure
BIO_flush_APIName returns 1 for success and 0 or -1 for failure
EVP_DecryptInit_ex_APIName and EVP_DecryptUpdate_APIName return 1 for success and 0 for failure
EVP_PKEY_set1_engine_APIName returns 1 for success and 0 for failure
BIO_set_md_APIName, BIO_get_md_APIName and BIO_md_ctx_APIName return 1 for success and 0 for failure
EVP_VerifyInit_ex_APIName and EVP_VerifyUpdate_APIName return 1 for success and 0 for failure
CMS_SignerInfo_get0_signer_id_APIName returns 1 for success and 0 for failure
EVP_SignInit_ex_APIName, EVP_SignUpdate_APIName and EVP_SignFinal_APIName return 1 for success and 0 for failure
BIO_set_APIName, BIO_free_APIName return 1 for success and 0 for failure
EVP_OpenUpdate_APIName returns 1 for success or 0 for failure
EVP_PKEY_assign_RSA_APIName, EVP_PKEY_assign_DSA_APIName, EVP_PKEY_assign_DH_APIName and EVP_PKEY_assign_EC_KEY_APIName return 1 for success and 0 for failure
SSL_CTX_set1_param_APIName and SSL_set1_param_APIName return 1 for success and 0 for failure
SMIME_write_CMS_APIName returns 1 for success or 0 for failure
CMS_final_APIName returns 1 for success or 0 for failure
BIO_set_fp_APIName and BIO_get_fp_APIName return 1 for success or 0 for BIO_new_fp_APIParam_1
PEM_write_bio_PKCS7_stream_APIName returns 1 for success or 0 for failure
EVP_SealUpdate_APIName and EVP_SealFinal_APIName return 1 for success and 0 for failure
CRYPTO_set_ex_data returns 1 on success or 0 on failure
RSA_set_ex_data returns 1 on success or 0 on failure
SSL_CTX_build_cert_chain and SSL_build_cert_chain return 1 for success and 0 for failure
SSL_CTX_set1_curves_APIName, SSL_CTX_set1_curves_list_APIName, SSL_set1_curves_APIName, SSL_set1_curves_list_APIName, SSL_CTX_set_ecdh_auto_APIName and SSL_set_ecdh_auto_APIName return 1 for success and 0 for failure
RAND_query_egd_bytes_APIName returns the number of bytes read from the daemon on success, and -1 if the RAND_query_egd_bytes_APIParam2_1 failed
RAND_egd_APIName and RAND_egd_bytes_APIName return the number of bytes read from the daemon on success, and -1 if the RAND_query_egd_bytes_APIParam2_1 failed or the daemon did not return enough data to fully seed the PRNG
BIO_seek_APIName and BIO_tell_APIName return the current file position or -1 if an error occurred
EVP_MD_CTX_copy_ex_APIName returns 1 if successful or 0 for failure
0 is returned and no call BN_mod_mul_reciprocal_APIName
BIO_reset_APIName normally returns 1 for success and 0 or -1 for failure
File BIOs are an exception, they return 0 for success and -1 for failure
SSL_CTX_set_tlsext_ticket_key_cb_APIName returns 0 to indicate the callback function was set
DH_compute_key_APIName returns the size of the shared secret on success, -1 on error
SSL_get_tlsext_status_ocsp_resp_APIParam_2 SSL_get_tlsext_status_ocsp_resp_APIParam_2 will be NULL and the return value from SSL_get_tlsext_status_ocsp_resp_APIName will be -1
Unlike other functions the return value 0 from EVP_PKEY_verify_APIName only indicates that the signature did not not verify successfully  it is not an indication of a more serious error
BN_BLINDING_new_APIName returns the newly allocated BN_BLINDING_new_APIParam_0 structure or NULL in case of an error
EVP_PKEY_set_alias_type_APIName returns 1 for success and 0 for error
BN_generate_prime_ex_APIName return 1 on success or 0 on error
 the NULL pointer is returned
BIO_get_cipher_status_APIName returns 1 for a successful decrypt and 0 for failure
OBJ_nid2obj_APIName returns an OBJ_nid2obj_APIParam_0 structure or NULL is an error occurred
OBJ_nid2obj_APIName returns an OBJ_nid2obj_APIParam_0 structure or NULL is an error occurred
BN_CTX_get_APIName returns a pointer to the BN_CTX_get_APIParam_0 BN_CTX_get_APIParam_0 BN_CTX_get_APIParam_0, or NULL on error
BIO_get_fd_APIName returns the BIO_new_fd_APIParam_1 or -1 if the BIO has not been initialized
EC_GROUP_get_degree_APIParam2_1 returns the EC_GROUP_set_seed_APIParam_3 of the EC_GROUP_method_of_APIParam_0 or 0 if the EC_GROUP_method_of_APIParam_0 is not specified
These functions return 1 on success, 0 on error
All other functions return 1 for success, 0 on error
Source/sink BIOs return an 0 if they do not recognize the BIO_ctrl_APIName operation
Alternatively in the event of an error a 0 is returned
EC_GROUP_get_degree_APIParam2_1 returns a EC_GROUP_set_generator_APIParam2_2 to the EC_GROUP_method_of_APIParam_0 that was used to generate the parameter b, or NULL if the EC_GROUP_method_of_APIParam_0 is not specified
For the other functions, 1 is returned for success, 0 on error
For the other functions, 1 is returned for success, 0 on error
For all functions, 1 is returned for success, 0 on error
X509_NAME_get_index_by_NID_APIName and X509_NAME_get_index_by_OBJ_APIName return the index of the next matching entry or -1 if not found
SSL_CTX_set_tlsext_servername_callback_APIName and SSL_CTX_set_tlsext_servername_arg_APIName both always return 1 indicating success
BIO_new_fd_APIName returns the newly allocated BIO or NULL is an error occurred
BIO_new_socket_APIName returns the newly allocated BIO or NULL is an error occurred
Once BN_CTX_get_APIName has failed, the subsequent calls will return NULL as well, so it is sufficient to check the return value of the last BN_CTX_get_APIName call
X509_NAME_get_index_by_NID_APIName can also return -2
SSL_get1_curves_APIName can return zero if the client did not send a supported curves extension
EVP_PKEY_sign_init_APIName and EVP_PKEY_sign_APIName return 1 for success and 0 or a negative value for failure
EVP_DigestVerifyInit_APIName and EVP_DigestVerifyUpdate_APIName return 1 for success and 0 or a negative value for failure
EVP_PKEY_derive_init_APIName and EVP_PKEY_derive_APIName return 1 for success and 0 or a negative value for failure
EVP_PKEY_verify_recover_init_APIName and EVP_PKEY_verify_recover_APIName return 1 for success and 0 or a negative value for failure
EVP_PKEY_decrypt_init_APIName and EVP_PKEY_decrypt_APIName return 1 for success and 0 or a negative value for failure
EVP_DigestSignInit_APIName EVP_DigestSignUpdate_APIName and EVP_DigestSignaFinal_APIName return 1 for success and 0 or a negative value for failure
EVP_PKEY_keygen_init_APIName, EVP_PKEY_paramgen_init_APIName, EVP_PKEY_keygen_APIName and EVP_PKEY_paramgen_APIName return 1 for success and 0 or a negative value for failure
EVP_PKEY_encrypt_init_APIName and EVP_PKEY_encrypt_APIName return 1 for success and 0 or a negative value for failure
If the peer did not present a certificate, NULL is returned
If the peer did not present a certificate, NULL is returned
ERR_PACK_APIName return the error code
EVP_DecryptFinal will return an error code
RSA_blinding_on_APIName returns 1 on success, and 0 if an error occurred
i2d_X509_fp_APIName is similar to i2d_X509_APIName except i2d_X509_fp_APIName writes the encoding of the structure i2d_X509_fp_APIParam_2 i2d_X509_APIParam_1 to BIO i2d_X509_bio_APIParam_1 d2i_X509_bio_APIParam_1 and i2d_X509_fp_APIName returns 1 for success and 0 for failure
i2d_X509_bio_APIName is similar to i2d_X509_APIName except i2d_X509_bio_APIName writes the encoding of the structure i2d_X509_bio_APIParam_2 i2d_X509_APIParam_1 to BIO i2d_X509_bio_APIParam_1 and i2d_X509_bio_APIName returns 1 for success and 0 for failure
EVP_DigestVerifyFinal_APIName returns 1 for success
SSL_SESSION_set_time_APIName and SSL_SESSION_set_timeout_APIName return 1 on success
DSA_dup_DH_APIName returns the new DSA_dup_DH_APIParam_0 structure, and NULL on error
d2i_ECPKParameters_APIName, d2i_ECPKParameters_bio_APIName and d2i_ECPKParameters_fp_APIName return a valid d2i_ECPKParameters_APIParam_1 structure or NULL if an error occurs
d2i_X509_APIName, d2i_X509_bio_APIName and d2i_X509_fp_APIName return a valid d2i_X509_APIParam_1 d2i_X509_bio_APIParam_2 d2i_X509_fp_APIParam_2 structure or NULL if an error occurs
SMIME_read_CMS_APIName returns a valid SMIME_read_CMS_APIParam_0 structure or NULL if an error occurred
d2i_ECPrivateKey_APIName returns a valid d2i_ECPrivateKey_APIParam_1 structure or NULL if an error occurs
SMIME_read_PKCS7_APIName returns a valid SMIME_read_PKCS7_APIParam_0 structure or NULL if an error occurred
If the session is actually identical , SSL_CTX_add_session_APIName is a no-op, and the return value is 0
i2d_ECPKParameters_bio_APIName is similar to i2d_ECPKParameters_APIName except i2d_ECPKParameters_bio_APIName writes the encoding of the structure i2d_ECPKParameters_APIParam_1 to BIO ECPKParameters_print_APIParam_1 and it returns 1 for success and 0 for failure
The RSA_padding_add_xxx_APIName functions return 1 on success, 0 on error
The RSA_padding_check_xxx_APIName functions return the length of the recovered data, -1 on error
The parsed PKCS#7 structure is returned or NULL if an error occurred
ASN1_TIME_diff_APIName returns 1 for sucess and 0 for failure
EC_GROUP_get_degree_APIParam2_1 returns a EC_GROUP_set_generator_APIParam2_2 to the duplicated curve, or NULL on error
The following return values can currently occur for SSL_want_APIName
ASN1_STRING_new_APIName and ASN1_STRING_type_new_APIName return a valid ASN1_STRING structure or NULL if an error occurred
d2i_PrivateKey and d2i_AutoPrivateKey return a valid EVP_KEY structure or NULL if an error occurs
BUF_MEM_grow_APIName returns zero on error or the new size
BIO_find_type_APIName returns a matching BIO or NULL for no match
BIO_new_file_APIName and BIO_new_fp_APIName return a file BIO or NULL if an error occurred
CMS_RecipientInfo_type_APIName will currently return CMS_RECIPINFO_TRANS, CMS_RECIPINFO_AGREE, CMS_RECIPINFO_KEK, CMS_RECIPINFO_PASS, or CMS_RECIPINFO_OTHER
EC_KEY_new, EC_KEY_new_by_curve_name and EC_KEY_get0_private_key_APIParam2_1 return a EC_KEY_set_public_key_APIParam2_2 to the newly created EC_KEY object, or NULL on error
SSL_CTX_set_generate_session_id_APIName and SSL_set_generate_session_id_APIName always return 1
BIO_set_close_APIName always returns 1
BIO_set_fd_APIName always returns 1
BIO_set_fd_APIName always returns 1
EVP_CIPHER_CTX_set_padding_APIName always returns 1
On error, -1 is returned
On error, -1 is returned
X509_NAME_get_entry_APIName returns an X509_NAME_get_entry_APIParam_1 pointer to the requested X509_NAME_get_entry_APIParam_0 or NULL if the index is invalid
BIO_new_APIName returns a newly created BIO or NULL if the call fails
SSL_get_current_cipher_APIName returns the SSL_get_current_cipher_APIParam_0 actually used or NULL, when no session has been established
BN_MONT_CTX_new_APIName returns the newly allocated BN_MONT_CTX_new_APIParam_0, and NULL on error
BN_RECP_CTX_new_APIName returns the newly allocated BN_RECP_CTX_new_APIParam_0, and NULL on error
EC_KEY_copy returns a EC_KEY_set_public_key_APIParam2_2 to the destination key, or NULL on error
BIO_new_CMS_APIName returns a BIO chain when successful or NULL if an error occurred
CMS_get0_SignerInfos_APIName returns all CMS_SignerInfo structures, or NULL there are no signers or an error occurs
BN_value_one_APIName returns a BN_value_one_APIParam_0 constant of value 1
The function EVP_PKEY_missing_parameters_APIName returns 1 if the public key parameters of EVP_PKEY_missing_parameters_APIParam_1 are missing and 0 if they are present or the algorithm does not use parameters
The function EVP_PKEY_missing_parameters_APIName returns 1 if the public key parameters of EVP_PKEY_missing_parameters_APIParam_1 are missing and 0 if they are present or the algorithm does not use parameters
The function EVP_PKEY_cmp_parameters_APIName and EVP_PKEY_cmp_APIName return 1 if the keys match, 0 if they do not match, -1 if the key types are different and -2 if the EVP_PKEY_copy_parameters_APIParam_1 is not supported
EVP_PKEY_CTX_ctrl_APIName and its macros return a positive value for success and 0 or a negative value for failure
If no call SSL_CTX_set_psk_client_callback_APIName, the NULL pointer is returned and the default callback will be used
If no call SSL_CTX_set_psk_client_callback_APIName, the NULL pointer is returned and the default callback will be used
SSL_CTX_set_session_id_context_APIName and SSL_set_session_id_context_APIName return the following values
EVP_PKEY_get1_RSA_APIName, EVP_PKEY_get1_DSA_APIName, EVP_PKEY_get1_DH_APIName and EVP_PKEY_get1_EC_KEY_APIName return the referenced key or NULL if an error occurred
EVP_PKEY_get1_RSA_APIName, EVP_PKEY_get1_DSA_APIName, EVP_PKEY_get1_DH_APIName and EVP_PKEY_get1_EC_KEY_APIName return the referenced key or NULL if an error occurred
BIO_get_cipher_ctx_APIName currently always returns 1
The following return values can currently occur
The following return values can currently occur
ECDSA_verify_APIName and ECDSA_do_verify_APIName return 1 for a valid signature, 0 for an invalid ECDSA_do_verify_APIParam2_1 and -1 on error
EVP_CipherFinal_ex_APIName returns 0 for a EVP_CIPHER_CTX_ctrl_APIParam_4 or 1 for success
When called on a client SSL_get1_curves_APIParam_1 SSL_set1_curves_list_APIParam_1 SSL_set1_curves_APIParam_1, SSL_get_shared_curve_APIName has no meaning and returns -1
OCSP_single_get0_status_APIName returns the OCSP_resp_find_status_APIParam_3 of OCSP_single_get0_status_APIParam_1 or -1 if an error occurred
SSL_select_next_proto_APIName returns one of the following
SSL_CTX_set_tlsext_status_cb_APIName, SSL_CTX_set_tlsext_status_arg_APIName, SSL_set_tlsext_status_type_APIName and SSL_set_tlsext_status_ocsp_resp_APIName return 0 on error or 1 on success
EVP_DecodeUpdate_APIName returns -1 on error and 0 or 1 on success
EVP_DecodeFinal_APIName returns -1 on error or 1 on success
BN_mod_inverse_APIName returns the BN_mod_inverse_APIParam_1 containing the inverse, and NULL on error
These functions all return 1 for success and 0 or a negative value for failure
These functions return 1 for success and a zero or negative value for failure
ECDSA_sign_setup_APIName and ECDSA_sign_APIName return 1 if successful or 0 on error
All other functions return 1 for success and 0 for failure
All these functions return 1 for success and 0 for failure
CMS_get1_ReceiptRequest_APIName returns 1 is a signed receipt request is found and decoded
The following functions return 1 on success or 0 on error
The following functions return 1 on success or 0 on error
The following functions return 1 on success or 0 on error
BN_add_word_APIName, BN_sub_word_APIName and BN_mul_word_APIName return 1 for success, 0 on error
DSA_sign_APIName and DSA_sign_setup_APIName return 1 on success, 0 on error
SSL_get_servername_APIName returns a servername extension value of the specified SSL_get_servername_APIParam_2 if provided in the Client Hello or NULL
These EVP_PKEY_copy_parameters_APIParam_1 EVP_PKEY_copy_parameters_APIName returns 1 for success and 0 for failure
BIO_new_bio_pair_APIName returns 1 on success, with the new BIOs available in BIO_new_bio_pair_APIParam_1 and BIO_new_bio_pair_APIParam_3, or 0 on failure, with NULL pointers stored into the locations for BIO_new_bio_pair_APIParam_1 and BIO_new_bio_pair_APIParam_3
BIO_new_bio_pair_APIName returns 1 on success, with the new BIOs available in BIO_new_bio_pair_APIParam_1 and BIO_new_bio_pair_APIParam_3, or 0 on failure, with NULL pointers stored into the locations for BIO_new_bio_pair_APIParam_1 and BIO_new_bio_pair_APIParam_3
EC_POINT_copy_APIParam2_2 returns a EC_POINT_copy_APIParam2_2 to the hex string, or NULL on error
SSL_get_tlsext_status_ocsp_resp_APIName returns the SSL_set_tlsext_status_ocsp_resp_APIParam_3 of the OCSP response data or -1 if there is no OCSP response data
X509_STORE_CTX_get0_param_APIName returns a pointer to an X509_STORE_CTX_get0_param_APIParam_0 structure or NULL if an error occurred
DSA_do_sign_APIName returns the signature, NULL on error
DSA_do_verify_APIName returns 1 for a valid signature, 0 for an incorrect DSA_do_verify_APIParam2_1 and -1 on error
DSA_verify_APIName returns 1 for a valid signature, 0 for an incorrect DSA_sign_APIParam2_2 and -1 on error
If there is no curve name associated with a curve ,then EC_GROUP_get_curve_name will return 0
NULL is returned if there is no such value in the lh_retrieve_APIParam_1
CMS_ReceiptRequest_create0_APIName returns a signed receipt request structure or NULL if an CMS_add1_ReceiptRequest_APIParam_2 occurred
BN_BLINDING_create_param_APIName returns the newly created BN_BLINDING_create_param_APIParam_1 parameters or NULL on error
If an error occurred ,then NULL is returned
EVP_OpenInit_APIName returns 0 on error or a non zero integer  if successful
The call PKCS12_parse_APIName is returned or NULL if an error occurred
X509_check_private_key_APIName and X509_REQ_check_private_key_APIName return 1 if the keys match each other, and 0 if not
lh_<type>_insert_APIName returns NULL both for success and error
EVP_DecodeBlock_APIName returns the length of the data decoded or -1 on error
EC_GROUP_set_curve_GFp, EC_GROUP_get_curve_GFp, EC_GROUP_set_curve_GF2m, EC_GROUP_get_curve_GF2m return 1 on success or 0 on error
EC_KEY_up_ref, EC_KEY_set_group, EC_KEY_set_private_key, EC_KEY_set_public_key, EC_KEY_precompute_mult, EC_KEY_generate_key, EC_KEY_get0_private_key_APIParam2_1 and EC_KEY_get0_private_key_APIParam2_1 return 1 on success or 0 on error
Call SSL_get_cipher_list_APIName with SSL_get_cipher_list_APIParam_2 starting from 0 to obtain the sorted list of available ciphers, until NULL is returned
CMS_verify_APIName returns 1 for a successful verification and zero if an error occurred
CMS_verify_receipt_APIName returns 1 for a successful verification and zero if an error occurred
The following return values can occur
The following return values can occur
The following return values can occur
The following return values can occur
The following return values can occur
The following return values can occur
The following return values can occur
The following return values can occur
The following return values can occur
The following return values can occur
The following return values can occur
The following return values can occur
The following return values can occur
The following return values can occur
The following return values can occur
The following return values can occur
The following return values can occur
The following return values can occur
The following return values can occur
The following return values can occur
A 0 or -1 return is not necessarily an indication of an error
EC_GROUP_get_degree_APIParam2_1 returns the EC_GROUP_set_seed_APIParam_3 in use for the given curve or NULL on error
ERR_lib_error_string_APIName, ERR_func_error_string_APIName and ERR_reason_error_string_APIName return the strings, and NULL if none is registered for the error code
The following strings can be returned
a return value of 0 can be returned if an bio_info_cb_APIParam_2 is not supported, if an error occurred, if EOF has not been reached and in the case of BIO_seek_APIName on a file BIO for a successful bio_info_cb_APIParam_2
i2d_ECPKParameters_fp_APIName is similar to i2d_ECPKParameters_APIName except it writes the d2i_ECPKParameters_APIParam_2 of the structure i2d_ECPKParameters_APIParam_1 to BIO ECPKParameters_print_APIParam_1 and it returns 1 for success and 0 for ECPKParameters_print_fp_APIParam_1
EVP_CIPHER_mode_APIName and EVP_CIPHER_CTX_mode_APIName return the block cipher mode EVP_CIPH_ECB_MODE, EVP_CIPH_CBC_MODE, EVP_CIPH_CFB_MODE or EVP_CIPH_OFB_MODE
SSL_library_init_APIName always returns "1", so it is safe to discard the return value
This function will return the length of the data decoded or -1 on error
X509_STORE_CTX_get_current_cert_APIName returns the cerificate which caused the error or NULL if no certificate is relevant to the error
EC_POINT_copy_APIParam2_2 and EC_POINT_copy_APIParam2_2 return the newly allocated EC_POINT or NULL on error
If key generation fails, RSA_generate_key_APIName returns NULL
BUF_MEM_new_APIName returns the buffer or NULL on error
If the allocation fails, the allocation returns NULL and sets an error code that can be obtained by ERR_get_error_APIName
If the allocation fails, the allocation returns NULL and sets an error code that can be obtained by ERR_get_error_APIName
If SSL_get_cipher_list_APIParam_1 is NULL, no ciphers are available, or there are less ciphers than SSL_get_cipher_list_APIParam_2 available, NULL is returned
A pointer to SSL_get_shared_ciphers_APIParam_2 is returned on success or NULL on error
All functions can also return -2 if the input is malformed
The return value for fseek_APIName is 0 for success or -1 if an error occurred this differs from other types of BIO which will typically return 1 for success and a non positive value if an error occurred
The following values are returned by all functions
On error 0 is returned by EC_GROUP_set_seed
SSL_get_psk_identity_hint_APIName may return NULL if no PSK identity hint was used during the SSL_get_psk_identity_APIParam2_1
BN_print_fp_APIName and BN_print_APIName return 1 on success, 0 on write errors
PKCS7_verify_APIName returns one for a successful verification and zero if an error occurs
the return value will be 1
BN_dup_APIName returns the new BN_copy_APIParam_1 BN_dup_APIParam_1, and NULL on error
BN_bin2bn_APIName returns the BN_bn2bin_APIParam_1 BN_bin2bn_APIParam_3, NULL on error
BN_mpi2bn_APIName returns the BN_bn2mpi_APIParam_1 BN_mpi2bn_APIParam_3, and NULL on error
X509_cmp_time_APIName returns 0 on error
A new NID is returned for the created OBJ_length_APIParam2_1 in case of success and NID_undef in case of failure
BN_copy_APIName returns BN_copy_APIParam_1 on success, NULL on error
If SSL_get_cipher_list_APIParam_1 is NULL or no ciphers are available, NULL is returned
EVP_VerifyFinal_APIName returns 1 for a correct signature, 0 for failure and -1 if some other error occurred
CMS_get0_RecipientInfos_APIName returns all CMS_RecipientInfo structures, or NULL if an error occurs
PKCS7_get0_signers_APIName returns all signers or NULL if an error occurred
On success, the functions return 1
On success, the functions return 1
On failure, the functions return 0
NULL is returned on normal operation and on error by  lh_<type>_insert_APIName
EC_POINT_copy_APIParam2_2 returns the EC_POINT_copy_APIParam2_2 to the BIGNUM supplied, or NULL on error
When "quiet shutdown" is enabled, SSL_shutdown_APIName will always succeed and return 1
the returned result code is X509_V_OK
SSL_CTX_add_client_CA_APIName and SSL_add_client_CA_APIName have the following return values
SSL_CTX_add_client_CA_APIName and SSL_add_client_CA_APIName have the following return values
DH_generate_parameters_APIName  returns a pointer to the DH structure, or NULL if the parameter generation fails
SSL_COMP_add_compression_method_APIName may return the following values
DSA_generate_parameters_APIName returns a pointer to the DSA structure, or NULL if the parameter generation fails
OCSP_resp_find_APIName returns the index of OCSP_resp_find_APIParam_2 in OCSP_resp_find_APIParam_1  or -1 if OCSP_resp_find_APIParam_2 was not found
SSL_get_error_APIName returns a SSL_get_error_APIParam_2  for a preceding call to SSL_connect_APIName, SSL_accept_APIName, SSL_do_handshake_APIName, SSL_read_APIName, SSL_peek_APIName, or SSL_write_APIName on SSL_get_error_APIParam_1 SSL_get_error_APIParam_1
All EC_GROUP_get_curve_GFp_APIParam2_1 functions return a pointer to the newly constructed group, or NULL on error
OBJ_nid2ln_APIName and OBJ_nid2sn_APIName returns a valid string or NULL on error
OBJ_nid2ln_APIName and OBJ_nid2sn_APIName returns a valid string or NULL on error
The context returned by BIO_get_md_ctx_APIName can be used in calls to EVP_DigestFinal_APIName and also the signature routines EVP_SignFinal_APIName and EVP_VerifyFinal_APIName
X509_STORE_CTX_new_APIName returns an newly allocates X509_STORE_CTX_set_default_APIParam2_2 or NULL is an error occurred
ASN1_generate_nconf_APIName and ASN1_generate_v3_APIName return the encoded data as an ASN1_generate_nconf_APIParam_0 ASN1_generate_v3_APIParam_0 structure or NULL if an error occurred
BIO_eof_APIName returns 1 if the BIO has read EOF, the precise meaning of "EOF" varies according to the BIO type
Otherwise EVP_DecodeFinal_APIName returns 1 on success
EC_GROUP_get_degree_APIParam2_1 returns the EC_GROUP_set_generator_APIParam_2 for the given curve or NULL on error
BIO_get_fd_APIName returns the BIO_new_socket_APIParam_1 or -1 if the BIO has not been initialized
EVP_get_cipherbyname_APIName, EVP_get_cipherbynid_APIName and EVP_get_cipherbyobj_APIName return an EVP_get_cipherbyname_APIParam_0 structure or NULL on error
If a curve does not have a NID associated with it, EC_GROUP_get_curve_name will return 0
OCSP_basic_verify_APIName returns 1 on success, 0 on error, or -1 on fatal error such as malloc failure
ASN1_STRING_cmp_APIName compares ASN1_STRING_cmp_APIParam_1 and ASN1_STRING_cmp_APIParam_2 returning 0 if the two are identical
CMS_add1_recipient_cert_APIName and CMS_add0_recipient_key_APIName return an internal pointer to the CMS_RecipientInfo structure just added or NULL if an error occurs
If SSL_CIPHER_get_bits_APIParam_1 is NULL, 0 is returned
Unlike many standard comparison functions, X509_cmp_time returns 0 on error
RAND_file_name_APIName returns a pointer to RAND_file_name_APIParam_1 on success, and NULL on error
ECDSA_size_APIName returns the ECDSA_do_verify_APIParam2_1 or 0 on error
EC_POINT_copy_APIParam2_2 returns the EC_POINT_copy_APIParam2_2 to the EC_POINT supplied, or NULL on error
EC_POINT_copy_APIParam2_2 returns the EC_POINT_copy_APIParam2_2 to the EC_POINT supplied, or NULL on error
RAND_write_file_APIName returns the RAND_file_name_APIParam_2 of RAND_load_file_APIParam_2 written, and -1 if the RAND_load_file_APIParam_2 written were generated without appropriate seed
The peer certificate chain is not necessarily available after reusing a session, in which case a NULL pointer is returned
SSL_export_keying_material_APIName returns 0 or -1 on failure or 1 on success
BIO_get_close_APIName returns the close flag value BIO_CLOSE or BIO_NOCLOSE
NID_undef is returned
EC_POINT_copy_APIParam2_2 returns the length of the required buffer, or 0 on error
a pointer to the constant value "NONE" is returned
EVP_PKEY_get_default_digest_nid_APIName  returns 0 or a negative value for failure
The EVP_PKEY_get_default_digest_nid_APIName function returns 1 if the message digest is advisory  and 2 if the message digest is mandatory
BN_BLINDING_get_flags returns the BN_BLINDING flags
CRYPTO_get_ex_data returns the application data or 0 on failure
RSA_get_ex_data returns the application data or 0 on failure
BIO_seek_APIName and BIO_tell_APIName both return the current file position on success and -1 for failure, except file BIOs which for BIO_seek_APIName always return 0 for success and -1 for failure
Otherwise, EVP_BytesToKey returns the size of the derived key in bytes, or 0 on error
EVP_MD_type returns NID_sha1
RSA_get_ex_new_index returns a new index or -1 on failure
an RSA key will return EVP_PKEY_RSA
BIO_find_type returns the next matching BIO or NULL if none is found
EVP_PKEY_base_id, EVP_PKEY_id and EVP_PKEY_type return a key type or NID_undef on error
OBJ_obj2nid, OBJ_ln2nid, OBJ_sn2nid and OBJ_txt2nid return a NID or NID_undef on error
Normally a missing configuration file return an error
If the allocation fails, a pointer to the string "OPENSSL_malloc Error" is returned
BN_mod_word and BN_div_word return BN_mod_word_APIParam_1 BN_div_word_APIParam_1%BN_mod_word_APIParam_2 BN_div_word_APIParam_2 on success and -1 if an error occurred
If the nextUpdate field is absent from X509_CRL_get0_lastUpdate_APIParam_1 X509_CRL_get0_nextUpdate_APIParam_1 NULL is returned
EVP_SealInit returns 0 on error or npubk if successful
SSL_get_error will return SSL_ERROR_WANT_X509_LOOKUP to indicate, that the handshake was suspended
It returns zero if the comparison is successful and non zero if not
It returns zero if the comparison is successful and non zero if not
If the cipher does not have an object identifier or does not have ASN1 support ,this function will return NID_undef
X509_STORE_CTX_get_error returns X509_V_OK or an error code
SSL_get_servername_type returns the servername type or -1 if no servername is present
So if you pass a public key to these functions in X509_REQ_check_private_key_APIParam_2 X509_check_private_key_APIParam_2, it will return success
the returned chain may be incomplete or invalid
If the content is not of type text/plain an error is returned
X509_CRL_get0_lastUpdate return a pointer to an X509_CRL_get0_lastUpdate_APIParam_0 structure or NULL if the lastUpdate field is absent
X509_STORE_CTX_get_error returns the error code of X509_STORE_CTX_get_error_APIParam_1, see the ERROR CODES section for a full description of all error codes
A zero is returned on error which will abort the handshake with a fatal internal error alert
0 is returned and the current certificate is unchanged
This result code is returned
 this result code is returned
this option sets that certificate to the current certificate and returns 1
this will typically output garbage and may ultimately return a padding error only
SSL_set_current_cert with SSL_CERT_SET_SERVER return 1 for success , 2 if no server certificate is used and 0 for failure
the function already returns success
if the structure indicates the use of any other algorithm ,an error is returned
if HMAC_Init_ex_APIName is called with HMAC_Init_ex_APIParam_2 NULL and HMAC_APIParam_1 is not the same as the previous digest used by HMAC_Init_ex_APIParam_1 , an error is returned  is not supported
If zlib support is not compiled into OpenSSL ,then CMS_uncompress_APIName will always return an error
X509_STORE_CTX_get_current_cert_APIName returns the certificate in X509_STORE_CTX_get_current_cert_APIParam_1 which caused the error or NULL if no certificate is relevant
The callback when used on the server side should return with either SSL_TLSEXT_ERR_OK , SSL_TLSEXT_ERR_NOACK  or SSL_TLSEXT_ERR_ALERT_FATAL
For the currently supported content types the following values are returned
New attributes can also be added using the returned CMS_SignerInfo structure and the CMS attribute utility functions or the CMS call CMS_add1_ReceiptRequest_APIName
The following return values have meaning
a call to SSL_get_error with the return value of SSL_do_handshake will yield SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE
a call to SSL_get_error with the return value of SSL_shutdown will yield SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE
a call to SSL_get_error with the return value of SSL_accept will yield SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE
a call to SSL_get_error with the return value of SSL_read will yield SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE
a call to SSL_get_error with the return value of SSL_write will yield SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE
EVP_CIPHER_iv_length_APIName and EVP_CIPHER_CTX_iv_length_APIName return the IV length or zero if the EVP_EncryptInit_ex_APIParam2_2 does not use an IV
SSL_rstate_string_APIName and SSL_rstate_string_long_APIName can return the following values
CMS_get1_certs_APIName and CMS_get1_crls_APIName return the STACK of certificates or CRLs or NULL if there are none or an error occurs
SSL_write_APIName will only return with success
SSL_write_APIName will also return with success
SSL_state_string_APIName returns a 6 letter string indicating the current state of the SSL object SSL_state_string_APIParam_1
Note that ENGINE_ctrl_cmd_string_APIName accepts a boolean argument that can relax the semantics of the function - if set non-zero ,ENGINE_ctrl_cmd_string_APIName will only return failure if the ENGINE supported the given command name but failed while executing the command name, if the ENGINE does not support the command name ,it will simply return success without doing anything
SSL_rstate_string_APIName returns a 2 letter string indicating the current read state of the SSL object SSL_rstate_string_APIParam_1
The following return values can occur for SSL_CTX_set_ssl_version_APIName and SSL_set_ssl_method_APIName
The first item in client, client_len is returned in SSL_select_next_proto_APIParam_1, SSL_select_next_proto_APIParam_2
If no match is found, the first item in client, client_len is returned in SSL_select_next_proto_APIParam_1, SSL_select_next_proto_APIParam_2
a function returning the passphrase must have been supplied
SSL_rstate_string_long_APIName and SSL_rstate_string_APIName should only seldom be needed in applications
This option is no longer implemented and is treated as no op
locking_function_APIName must be able to handle up to CRYPTO_num_locks_APIName different mutex locks
The SSL_get_error_APIParam_1 should be called again later
the same SSL_get_error_APIParam_1 should be called again later
Most applications wishing to call EVP_PKEY_type_APIName will simply call EVP_PKEY_base_id_APIName and will not care about the actual type
EVP_CIPHER_asn1_to_param_APIName will be called and finally EVP_CipherInit_APIName again with all parameters except the key set to NULL
the functions for duplicating , freeing and  clear_freeing  the data item must be provided again , and they must be the same as they were when the data item was inserted
For EC parameter generation EVP_PKEY_CTX_set_ec_paramgen_curve_nid_APIName  must be called or an error occurs
New code should use EVP_EncryptInit_ex_APIName , EVP_EncryptFinal_ex_APIName , EVP_DecryptInit_ex_APIName , EVP_DecryptFinal_ex_APIName , EVP_CipherInit_ex_APIName and EVP_CipherFinal_ex_APIName
Use the sequence SSL_get_session_APIName ; SSL_new_APIName ; SSL_set_session_APIName ; SSL_free_APIName instead of SSL_clear_APIName to avoid such failures
This alert should be followed by a close_notify
A function must call BN_CTX_start_APIName first
The SSL_get_error_APIParam_1 should be called again
Applications will not normally call EVP_PKEY_CTX_ctrl_APIName directly but will instead call one of the algorithm specific macros below
HMAC_CTX_init_APIName must be called
HMAC_CTX_cleanup_APIName must be called
These functions are only useful for TLS/SSL servers
The macro version of this function was the only one available before OpenSSL 1.0.0
SSL_SESSION_free_APIName must be explicitly called once to decrement the reference count again
a TLS client must send the a session ticket extension to the server
New applications should use EVP_DigestInit_ex_APIName , EVP_DigestFinal_ex_APIName and EVP_MD_CTX_copy_ex_APIName
Other applications should use EVP_DigestInit_APIName
no further I/O operations should be performed on the SSL_get_error_APIParam2_1 and SSL_shutdown_APIName must not be called
Finally , use UI_process_APIName to actually perform the prompting and UI_get0_result_APIName to find the result to the prompt
The first thing to do is to create a UI with UI_new_APIName or UI_new_method_APIName , add UI_get0_result_APIParam_2 to it with the UI_add or UI_dup functions
The random number generator must be seeded prior to calling RSA_sign_ASN1_OCTET_STRING_APIName
The random number generator must be seeded prior to calling RSA_blinding_on_APIName
The random number generator must be seeded prior to calling RSA_public_encrypt_APIName
The random number generator must be seeded prior to calling RSA_padding_add_xxx_APIName
the random number generator must be seeded before calling EVP_SealInit_APIName
The PRNG must be seeded prior to calling BN_rand_APIName or BN_rand_range_APIName
The PRNG must be seeded prior to calling BN_generate_prime_ex_APIName
The PRNG must be seeded prior to calling DSA_generate_key_APIName
For a more general solution X509_NAME_get_index_by_NID_APIName or X509_NAME_get_index_by_OBJ_APIName should be used followed by X509_NAME_get_entry_APIName on any matching indices and the various X509_NAME_get_entry_APIParam_0 utility functions on the result
BIO_get_cipher_status_APIName should be called to determine if the decrypt was successful
Prefer RSA_PKCS1_OAEP_PADDING
Applications wishing to encrypt or call RSA_private_decrypt_APIName should use other functions such as d2i_PKC8PrivateKey_APIName instead
the source/sink may merely be an indication that no data is currently available and that the application should retry the operation later
These functions are currently the only way to call RSA_private_decrypt_APIName using DER format
New applications should use ASN1_TIME_adj_APIName instead and pass the offset value in the ASN1_TIME_adj_APIParam4 and ASN1_TIME_adj_APIParam3 parameters instead of directly manipulating a ASN1_TIME_adj_APIParam2 value
it is recommended to use a function that does not depend on a global variable
the ENGINE API is the recommended way to control default implementations for use in RAND and other cryptographic algorithms
Applications should use the higher level functions EVP_EncryptInit_APIName etc instead of calling the blowfish functions directly
BIO_do_handshake_APIName has no effect
ASN1_OBJECT_free_APIName will have no effect
The DES_quad_cksum_APIParam_1 of EVP_PKEY_size_APIName with these call DES_quad_cksum_APIName
code should not assume that i2d_X509_APIName will always succeed
OBJ_cleanup_APIName should be called before an application exits
BN_CTX_init_APIName should not be used for new programs
the ENGINE API is the recommended way to control default implementations for use in RSA and other cryptographic algorithms
the BIO_set_nbio_accept_APIParam_2 should take appropriate action to wait until the underlying socket has call SSL_shutdown_APIName and retry the call
SSL_set_session_APIName is only useful for TLS/SSL clients
EVP_PKEY_CTX_gen_keygen_info_APIName with a non-negative value for EVP_PKEY_CTX_get_keygen_info_APIParam_2 should only be called within the generation callback
One of these functions should be called before generating textual error messages
The DH_generate_parameters_ex_APIParam_3 must be seeded prior to calling DH_generate_parameters_APIName
The pseudo-random number generator must be seeded prior to calling RSA_generate_key_ex
The servername callback is executed first , followed by the ALPN callback
HMAC_Init_APIName is deprecated and only included for backward compatibility with OpenSSL 0.9.6 b
the handshake routines must be explicitly set in advance using either SSL_set_connect_state_APIName or SSL_set_accept_state_APIName
SSL_library_init_APIName is not reentrant
SSL_check_chain_APIName must be called in servers after a client hello message or in clients after a certificate request message
The SSL_CTX_set_session_id_context_APIName and SSL_set_session_id_context_APIName functions are only useful on the server side
a new UI should be freed using UI_free_APIName
The EVP_DigestVerifyFinal_APIParam_1 EVP_DigestVerifyUpdate_APIParam_1 EVP_DigestVerifyInit_APIParam_1 interface to digital signatures should almost always be used in preference to the low level interfaces
the parties must send out close notify alert messages using SSL_shutdown_APIName for a clean shutdown
Applications should free up OPENSSL_config_APIParam2_1 at application closedown by calling CONF_modules_free_APIName
It is the caller  responsibility to free this memory with a subsequent call to OPENSSL_free_APIName
The SSL_get_peer_certificate_APIParam_0 must be explicitly freed using X509_free_APIName
the recommended way of controlling default implementations is by using the ENGINE API functions
EVP_EncodeFinal_APIName must be called at the end of an encoding operation
BIO_flush_APIName may need to be retried
To change a certificate , private key pair the new certificate needs to be set with SSL_use_certificate_APIName or SSL_CTX_use_certificate_APIName before setting the private key with SSL_CTX_use_PrivateKey_APIName or SSL_use_PrivateKey_APIName
The functions EVP_EncryptInit_APIName , EVP_EncryptFinal_APIName , EVP_DecryptInit_APIName , EVP_CipherInit_APIName and EVP_CipherFinal_APIName are obsolete but are retained for compatibility with existing code
It is important to call BIO_flush_APIName
the use of X509_NAME_oneline_APIName and X509_NAME_print_APIName is strongly discouraged in new applications
CRYPTO_set_dynlock_create_callback_APIParam_1 is needed to create a lock
applications should generally avoid call i2d_DSA_PUBKEY_APIName directly and instead use API functions to query or modify keys
care should be taken to flush any data in the call DES_enc_write_APIName
i2d_RSA_PUBKEY_APIParam_2 should generally avoid call i2d_RSA_PUBKEY_APIName directly and instead use API functions to query or modify keys
the application need not call BIO_should_retry_APIName after a failed BIO I/O call
EVP_VerifyInit_ex_APIParam_1 must be initialized by calling EVP_MD_CTX_init_APIName before calling this function
The EVP interface to digital signatures should almost always be used in preference to the low level interfaces
To process KEKRecipientInfo types CMS_set1_key_APIName or CMS_RecipientInfo_set0_key_APIName and CMS_ReceipientInfo_decrypt_APIName should be called before CMS_decrypt_APIName and CMS_decrypt_APIParam_3 and CMS_decrypt_APIParam_2 set to NULL
Applications should generate their own DH parameters using the openssl dhparam_APIName application
it can be practical to ask for the SSL_CTX_set_default_passwd_cb_APIParam_2 once , keep it in memory and use it several times
low level algorithm specific functions can not be used with an ENGINE and ENGINE versions of new algorithms can not be accessed using the low level functions
SSL_get_shared_ciphers_APIName is a server side function only and must only be called after the completion of the initial handshake
an implementation method must be provided
Applications wishing to avoid this should use EVP_MD_CTX_create_APIName instead
The bytes are sent and a new SSL_write_APIName operation with a new SSL_write_APIParam_2 must be started
A typical application will call OpenSSL_add_all_algorithms_APIName initially and EVP_cleanup_APIName before exiting
The string must be freed later using OPENSSL_free_APIName
Applications should call SSL_CTX_check_private_key_APIName or SSL_check_private_key_APIName as appropriate after loading a new certificate and private key to confirm that the certificate and key match
BIO_find_type_APIName in OpenSSL 0.9.5 a and earlier could not be safely passed a NULL pointer for the BIO_find_type_APIParam_1 argument
SSL_get_verify_result_APIName is only useful in SSL_get_verify_result_APIParam2_1 with SSL_get_peer_certificate_APIName
The dup_APIName functions use OPENSSL_malloc_APIName underneath and so should be used in preference to the standard library for BUF_MEM_grow_APIParam_2 or replacing the malloc_APIName function
it should consider using the SSL_CONF interface instead of manually parsing options
In a non-blocking environment applications must be prepared to handle incomplete read/write operations
New applications should use a cryptographic hash function
Never bother the application with retries
it should be freed using UI_free_APIName
it should be free up using sk_X509_pop_free_APIName
EVP_DecodeFinal_APIName must be called at the end of a decoding operation
the application must select the session to be reused by using the SSL_set_session_APIName function
the complete shutdown procedure must be performed
All structural references should be released by a corresponding to call to the ENGINE_free_APIName function
BIO_puts_APIName is supported but BIO_gets_APIName is not supported
It should be noted that both methods can not be used on servers that run without user interaction
SSL_get_version_APIName should only be called after the initial handshake has been completed
To call SSL_CTX_use_PrivateKey_APIName to this empty structure the functions described in EVP_PKEY_set1_RSA_APIName should be used
EVP_MD_CTX_destroy_APIName should be called only on a EVP_DigestInit_ex_APIParam2_2 created using EVP_MD_CTX_create_APIName
EVP_MD_CTX_cleanup_APIName should be called after a call EVP_MD_CTX_init_APIName is no longer needed
After this call X509_STORE_CTX_set0_param_APIParam_2 should not be used
All BN_CTX_get_APIName calls must be made before calling any other functions that use the BN_CTX_start_APIParam_1 BN_CTX_get_APIParam_1 BN_CTX_get_APIParam_1 as an argument
To use these ciphers with RSA keys of usual length , an ephemeral key exchange must be performed , as the normal key can not be directly used
OpenSSL_add_all_algorithms_APIName should be called before using this function or errors about unknown algorithms will occur
OpenSSL_add_all_algorithms_APIName should be called before using this function or errors about unknown algorithms will occur
BIOs should be removed from the chain using BIO_pop_APIName and freed with BIO_free_APIName until BIO_new_CMS_APIParam_1 is reached
As a result the use of this  reuse  of d2i_X509_APIName behaviour is strongly discouraged
for call X509_VERIFY_PARAM_set_trust_APIName the application must however still call SSL_shutdown_APIName or SSL_set_shutdown_APIName itself
SSL_library_init_APIName must be called before any other action takes place
The function SSL_CONF_finish_APIName must be called after all SSL_CONF_cmd_APIParam2_3 have been completed
Normally The RSA_padding_add_PKCS1_type_1_APIName RSA_padding_check_PKCS1_type_1_APIName RSA_padding_add_PKCS1_type_2_APIName RSA_padding_check_PKCS1_type_2_APIName RSA_padding_add_PKCS1_OAEP_APIName RSA_padding_check_PKCS1_OAEP_APIName RSA_padding_add_SSLv23_APIName RSA_padding_check_SSLv23_APIName RSA_padding_add_none_APIName RSA_padding_check_none_APIName functions should not be called from application programs
this must be called to initialize a call BIO_set_md_APIName before any data is passed through call BIO_set_md_APIName
In parallel , the sessions form a linked list which is maintained separately from the lhash_APIName operations , so that the database must not be modified directly but by using the SSL_CTX_add_session_APIName family of functions
Newer applications should use a more modern algorithm such as PBKDF2 as defined in PKCS # 5v2 .1 and provided by pkcs5_pbkdf2_hmac_APIName, pkcs5_pbkdf2_hmac_sha1_APIName
After all BIO_new_CMS_APIParam_2 has been written through the chain, BIO_flush_APIName must be called to finalise the structure
that is The OpenSSL ASN1 functions can not retry after a partial read or write
SSL_SESSION_free_APIName must not be called on other SSL_SESSION objects , as this would cause incorrect reference counts and program failures
It is the caller  responsibility to ensure that EVP_EncodeFinal_APIParam_2 is sufficiently large to accommodate the output data which will never be more than 65 bytes plus an additional NUL terminator
In a setup where attackers can measure the time of RSA decryption or signature operations , blinding must be used to protect the RSA operation from that attack
A client application must provide a callback function which is called when the client is sending the ClientKeyExchange message to the server
It could be argued that BIO_gets_APIName and BIO_puts_APIName should be passed to the next BIO in the BIO_puts_APIParam2_2 and digest the data passed through and that digests should be retrieved using a separate BIO_ctrl_APIName call
An application will normally wait until the necessary condition is satisfied
The functions X509_NAME_oneline_APIName and X509_NAME_print_APIName are legacy functions which produce a non standard X509_NAME_print_ex_APIParam_1
MD2_APIName , MD4_APIName , and MD5_APIName are recommended only for compatibility with existing applications
EVP_CIPHER_CTX_cleanup_APIName should be called after all operations using a EVP_EncryptInit_ex_APIParam2_2 are complete so sensitive information does not remain in memory
Note that SSL_shutdown_APIName must not be called
Thus , SSL_get_error_APIName must be used in the same thread that call BN_mod_mul_reciprocal_APIName , and no other SSL_get_error_APIParam_1 calls should appear in between
An application must not rely on the error value of SSL_operation_APIName but must assure that the call DES_enc_write_APIName is always flushed first
An application must not rely on the error value of SSL_operation_APIName but must assure that the call DES_enc_write_APIName is always flushed first
BN_CTX_end_APIName must be called before the BN_CTX_new_APIParam_0 may be freed by BN_CTX_free_APIName
However , the meaningfulness of this result is dependent on whether the ENGINE API is being used , so DSA_get_default_method_APIName is no longer recommended
Finally, BN_CTX_end_APIName must be called before returning from the function
the call BIO_should_retry_APIName should be used for non blocking call BIO_new_buffer_ssl_connect_APIName to determine if the call should be retried
Note that OpenSSL is not completely thread-safe , and unfortunately not all global resources have the necessary locks
it is necessary to use the ENGINE_cleanup_APIName function to correspondingly cleanup before program exit
The calling process must repeat the call after taking appropriate action to satisfy the needs of SSL_accept
The calling process must repeat the call after taking appropriate action to satisfy the needs of SSL_connect
The calling process must repeat the call after taking appropriate action to satisfy the needs of SSL_read
The calling process must repeat the call after taking appropriate action to satisfy the needs of SSL_write_APIName
The calling process must repeat the call after taking appropriate action to satisfy the needs of SSL_do_handshake_APIName
The calling process must repeat the call after taking appropriate action to satisfy the needs of SSL_shutdown
As the size of an SSL/TLS record may exceed the maximum packet size of the underlying transport , it may be necessary to read several packets from the transport layer before the record is complete and SSL_read_APIName can succeed
EVP_PKEY_set1_engine_APIName must be called after the key algorithm and components are set up
The DSA_PUBKEY functions should be used in preference to the DSAPublicKey functions
RSA_set_default_method_APIName is no longer recommended
DSA_set_default_method_APIName is no longer recommended
DH_set_default_method_APIName is no longer recommended
RAND_set_default_method_APIName is no longer recommended
This is rarely used in practice and is not supported by SMIME_write_CMS
Applications are strongly advised to use this interface in preference to explicitly calling X509_check_host , hostname checks are out of scope with the DANE-EE certificate usage , and
Applications which use the configuration functions directly will need to call OPENSSL_load_builtin_modules themselves before any other configuration code
An application should not free the SSL_CTX_add_extra_chain_cert_APIParam_2 object
it is not strictly necessary to call DH_generate_key_APIName during each handshake but it is also recommended
An application MUST NOT free the data pointer with OPENSSL_free_APIName
an explicit call to PKCS7_SIGNER_INFO_sign is needed to finalize this case
X509_add1_trust_object_APIParam_1 and X509_add1_trust_object_APIParam_2 should be freed up
Do not mix the verification callback described in this function with the verify_callback function called
an explicit call to CMS_SignerInfo_sign is needed to finalize it
the necessary amount of space should be obtained by first calling i2d_SSL_SESSION with pp setting to NULL , and obtain the size needed , allocate the memory and call i2d_SSL_SESSION again
The CMS_ContentInfo structure should be obtained from an initial call to CMS_encrypt with the flag CMS_PARTIAL set
The value returned is an internal pointer which must not be freed up after the call
New applications should write private keys using the PEM_write_bio_PKCS8PrivateKey or PEM_write_PKCS8PrivateKey routines
After this function is called, the encryption operation is finished and no further calls to EVP_EncryptUpdate should be made
The above functions should be used instead of directly referencing the fields in the X509_VERIFY_CTX structure
This list must explicitly be set using SSL_CTX_set_client_CA_list_APIName for SSL_CTX_add_client_CA_APIParam_1 and SSL_set_client_CA_list_APIName for the specific SSL_add_client_CA_APIParam_1
To do so, the client should call the SSL_set_tlsext_status_type function prior to the start of the handshake
These functions should never be called directly
The certificates and CRLs in a store are used internally and should not be freed up until after the associated X509_STORE_CTX_set0_param_APIParam_1 X509_STORE_CTX_get0_param_APIParam_1 X509_STORE_CTX_free_APIParam_1 X509_STORE_CTX_set_default_APIParam_1 X509_STORE_CTX_cleanup_APIParam_1 X509_STORE_CTX_set_cert_APIParam_1 X509_STORE_CTX_init_APIParam_1 is freed
This function should only be used
The certificates and CRLs in a context are used internally and should not be freed up until after the associated X509_STORE_CTX_set0_param_APIParam_1 X509_STORE_CTX_get0_param_APIParam_1 X509_STORE_CTX_free_APIParam_1 X509_STORE_CTX_set_default_APIParam_1 X509_STORE_CTX_cleanup_APIParam_1 X509_STORE_CTX_set_cert_APIParam_1 X509_STORE_CTX_init_APIParam_1 is freed
CMS_final_APIName must be called to finalize the structure
the callback must call SSL_has_matching_session_id_APIName and generate another id
Modern servers that do not support export ciphersuites are advised to either use SSL_CTX_set_tmp_dh or alternatively , use the callback but ignore keylength and is_export and simply supply at least 2048-bit parameters in the callback
it must be freed up after the call
it must be freed up after the call
SSL_get0_alpn_selected_APIParam_2 must not be freed
It must be called before each call to X509_verify_cert_APIName
The returned pointer is an internal pointer which must not be freed
it must be freed at some point after the operation
it must be freed at some point after the operation
the data must be read twice
DES_enc_write and DES_enc_read can not handle non-blocking sockets
CMS_set1_eContentType copies the supplied OID and it should be freed up after use
Instead select should be combined with non blocking I/O so successive reads will request a retry instead of blocking
Those containing a SSL_CTX_select_current_cert_APIParam_2 SSL_CTX_add0_chain_cert_APIParam_2 SSL_add0_chain_cert_APIParam_2 SSL_CTX_add1_chain_cert_APIParam_2 SSL_select_current_cert_APIParam_2 SSL_add1_chain_cert_APIParam_2 do not increment reference counts and the supplied certificate or chain MUST NOT be freed after the operation
As the 0 implies CMS_get0_type, CMS_get0_eContentType and CMS_get0_content return internal pointers which should not be freed up
These functions should not be used to examine or modify ASN1_INTEGER or ASN1_ENUMERATED types
DES_enc_read uses an internal state and thus can not be used on multiple files
To use the serverinfo extension for multiple certificates , SSL_CTX_use_serverinfo needs to be called multiple times , once after each time a certificate is loaded
CMS_get0_signers_APIName it must be called after a successful CMS_verify operation
Do not explicitly free these indirectly freed up items before or after calling SSL_free , as trying to free things twice may lead to program failure
this function is only suggested for use
The hash value is normally truncated to a power of 2, so make sure that your hash function returns well mixed low order bits
OPENSSL_config_APIName is deprecated and its use should be avoided
In server mode , , the server must send the list of CAs of which it will accept client certificates
Applications should use the higher level functions EVP_EncryptInit_APIName instead of calling the RC4_set_key_APIName and RC4_APIName directly
This call should be made before the cipher is actually  used
The values written to revtime , OCSP_check_validity_APIParam_1 and nextupd by OCSP_resp_find_status and OCSP_single_get0_status are internal pointers which MUST NOT be freed up by the calling application
low level algorithm specific functions use is discouraged
This function should not be called on untrusted input
This function should be called after the base cipher type is set but before the call SSL_CTX_set_tmp_rsa_callback_APIName
Applications which need finer control over their configuration functionality should use the configuration functions such as CONF_modules_load directly
The OpenSSL ASN1 functions can not gracefully deal with non blocking I/O
RSA_generate_key is deprecated
A method of call d2i_RSA_PUBKEY_APIName using opaque RSA API functions might need to be considered
For applications that can catch Windows events , seeding the PRNG by calling RAND_event_APIName is a significantly better source of randomness
However , the meaningfulness of this result is dependent on whether the ENGINE API is being used , so this function is no longer recommended
Using the compression API in the current state is not recommended
As a result applications may wish to use multiple keys and avoid using long term keys stored in files
This is no longer necessary and the use of clone digest is now discouraged
This is no longer necessary and the use of clone digest is now discouraged
An application may either directly specify the key or can supply the key via a callback function
HMAC_cleanup_APIName is an alias for HMAC_CTX_cleanup_APIName included for back compatibility with 0.9.6 b , HMAC_cleanup_APIName is deprecated
It is currently not recommended to integrate SSL_COMP_add_compression_method_APIParam_2 into applications
Hence , these two functions are no longer the recommended way to control defaults
An application may need to securely establish the context within which this keying material will be used
The functions EC_GROUP_get_basis_type_APIName , EC_GROUP_get_trinomial_basis_APIName and EC_GROUP_get_pentanomial_basis_APIName should only be called for curves defined over an F2^m field
Applications should use the higher level functions EVP_DigestInit_APIName etc
A server application must also call the SSL_CTX_set_tlsext_status_cb_APIName function
However , new applications should not typically use this
It only makes sense for a new connection with the exact same peer that shares these settings, and may fail
The functions EVP_DigestInit_APIName , EVP_DigestFinal_APIName and EVP_MD_CTX_copy_APIName are obsolete but are retained to maintain compatibility with existing code
These functions will typically be called after a failed BIO_read_APIName or BIO_write_APIName call
It is the responsibility of this function to create or retrieve the cryptographic parameters and to maintain their state
Do not call this function
Most applications should use these method , and avoid the version specific methods described below
It is expected that this function is called from the application callback cb
The above functions should be used to manipulate X509_VERIFY_PARAM_get_depth_APIParam2_1 instead of legacy functions which work in specific structures such as X509_STORE_CTX_set_flags_APIName
Do not ask for a client certificate again in case of a renegotiation
So do not use these functions
consider using lh _ <type> _ doall to deallocate any remaining entries in the hash table
ERR_remove_state is deprecated and has been replaced by ERR_remove_thread_state
Memory BIOs support BIO_gets_APIName and BIO_puts_APIName
However , on all other systems , the application is responsible for seeding the PRNG by calling RAND_add , RAND_egd or RAND_load_file
the user should explicitly unset the callback by calling SSL_CTX_sess_set_remove_cb prior to calling SSL_CTX_free_APIName
However be sure to also compare the library number
the ENGINE API is the recommended way to control default implementations for use in DH and other cryptographic algorithms
ASN1_OBJECT_new_APIName is almost never used in applications
You should instead call SSL_get_error_APIName to find out
You should instead call SSL_get_error_APIName to find out
An application wishing to support multiple certificate chains may call this function on each chain in turn
the list of available compression methods can not be set for specific SSL_CTX or SSL objects
BIO_gets_APIName and BIO_puts_APIName are supported on file BIOs
the ENGINE API is the recommended way to control default implementations for use in DSA and other cryptographic algorithms
Attributes currently can not be stored in the private key PKCS12_parse_APIParam_3 structure
The BIO_get_mem_data_APIParam_2 should not occur after every small read of a large BIO to improve efficiency
The BIO_should_retry_APIName call should be used and appropriate action taken is the call fails
The lack of single pass processing and the need to hold all data in memory as mentioned in CMS_verify_APIName also applies to CMS_decrypt_APIName
The lack of single pass processing and the need to hold all data in memory as mentioned in CMS_verify_APIName also applies to CMS_decompress_APIName
The lack of single pass processing and need to hold all data in memory as mentioned in PKCS7_sign_APIName also applies to PKCS7_verify_APIName
The lack of single pass processing and need to hold all data in memory as mentioned in PKCS7_sign_APIName also applies to PKCS7_verify_APIName
This can only be accomplished by either call SSL_CTX_add_client_CA_APIName into the trusted certificate store for the SSL_CTX object , or by adding the chain certificates using the SSL_CTX_add_extra_chain_cert_APIName function , which is only available for the SSL_CTX object as a whole and that probably can only apply for one client certificate , making the concept of the callback function questionable
Normally an application is only interested in whether a signature verification operation is successful in those cases the EVP_verify_APIName function should be used
CRYPTO_destroy_dynlockid_APIParam_1 is needed to perform locking off dynamic CRYPTO_set_dynlock_create_callback_APIParam_1 numbered
dyn_lock_function is needed to perform locking off dynamic lock numbered n
the relevant INTEGER or ENUMERATED utility functions should be used instead
DES_3cbc_encrypt_APIName is flawed and must not be used in applications
Applications should instead call CONF_modules_load
Applications are encouraged to use X509_VERIFY_PARAM_set1_host_APIName rather than explicitly calling X509_check_host_APIName
BF_encrypt_APIName and BF_decrypt_APIName should not be used
SSL_get_certificate_APIName returned internal pointers that must not be freed by the application program
The callback function should determine whether the returned OCSP response is acceptable or not
ASN1_STRING_new_APIName type is undefined
An error occurred , check the error stack for a detailed error message
Multi-threaded CRYPTO_lock_APIParam_2 might crash at random
Multi-threaded CRYPTO_lock_APIParam_2 might crash at random
A server application must provide a callback function which is called when the server receives the ClientKeyExchange message from the client
OBJ_obj2txt_APIName is awkward and messy to use
OBJ_obj2txt_APIName is awkward and messy to use
Multi-threaded CRYPTO_lock_APIParam_2 will crash at random
Collisions can also occur
call SSL_CTX_set_tmp_rsa_APIName key exchange for other purposes violates the standard and can break interoperability with clients
Using different compression methods with the same SSL_COMP_add_compression_method_APIParam_1 will lead to connection failure
the library crashes
Attempting to use this function in SSL_export_keying_material_APIParam_1 will result in an error
SSL_set_rfd_APIName and SSL_set_wfd_APIName perform the respective action , but only for the read channel or the write channel , which can be set independently
It is possible to have RSA_set_method_APIParam2_2 that only work with certain RSA_set_method_APIParam2_2 , and attempting to change the RSA_METHOD for the key can have unexpected results
Also note that , as for the SHA1_APIName function above , the SHA224_APIName , SHA256_APIName , SHA384_APIName and SHA512_APIName functions are not thread safe
BIO_free_APIName will only free one BIO resulting in a memory leak
several functions will misbehave and complain several functions can not find algorithms
currently CRYPTO_get_ex_data() can only fail
using the same dsa - > kinv and dsa - > r pair twice under the same private key on different plaintexts will result in permanently exposing the DSA private key
It is possible to have DSA keys that only work with certain DSA_METHOD implementations , and attempting to change the DSA_METHOD for the key can have unexpected results
SSL_CTX_sess_set_cache_size_APIParam_2 is a hint and not an absolute
The following flags are currently recognized
Currently only AES based key wrapping algorithms are supported for CMS_add0_recipient_key_APIParam_2 , specifically
Any or all of these parameters can be NULL , see NOTES below
The following flags can be passed in the flags parameter
Any of the following flags can be passed in the flags parameter
The reason for this is that the variable i2d_X509_bio_APIParam_2 i2d_re_X509_tbs_APIParam_1 i2d_X509_fp_APIParam_2 i2d_X509_AUX_APIParam_1 i2d_X509_APIParam_1 d2i_X509_fp_APIParam_2 d2i_X509_bio_APIParam_2 is uninitialized and an attempt will be made to interpret its value as an d2i_X509_APIParam_1 structure , typically causing a segmentation violation
The OCSP_resp_find_status_APIParam_3 value will be one of V_OCSP_CERTSTATUS_GOOD , V_OCSP_CERTSTATUS_REVOKED or V_OCSP_CERTSTATUS_UNKNOWN
Any of the following CMS_add1_signer_APIParam_5 can be passed in the CMS_add1_signer_APIParam_5 parameter
The following CMS_decrypt_APIParam_6 can be passed in the CMS_decrypt_APIParam_6 parameter
Any of the following PKCS7_sign_add_signer_APIParam_5 can be passed in the PKCS7_sign_add_signer_APIParam_5 parameter
The following PKCS7_decrypt_APIParam_5 can be passed in the PKCS7_decrypt_APIParam_5 parameter
The following SMIME_write_CMS_APIParam_4 can be passed in the SMIME_write_CMS_APIParam_4 parameter
The following SMIME_write_PKCS7_APIParam_4 can be passed in the SMIME_write_PKCS7_APIParam_4 parameter
The following CMS_uncompress_APIParam_4 can be passed in the CMS_uncompress_APIParam_4 parameter
There are data in the SSL buffer that must be written to the call BIO_ssl_shutdown_APIName
RSA_sign_APIParam_1 RSA_verify_APIParam_1 usually is one of NID_sha1 , NID_ripemd160 and NID_md5
The buffer ASN1_STRING_to_UTF8_APIParam_1 should be free using OPENSSL_free_APIName
Flags can be: BIO_CLOSE , BIO_NOCLOSE BIO_FP_TEXT
The complete set of the flags supported by X509_NAME_print_ex_APIName is listed below
OBJ_txt2nid_APIParam_1 can be a long name , a short name or the numerical respresentation of an OBJ_obj2nid_APIParam2_1
As automatic lookup only applies for SSL/TLS servers , the flag SSL_SESS_CACHE_NO_INTERNAL_LOOKUP has no effect on clients
sessions should be removed from the cache to save resources
It should equal half of the targeted security level in BN_generate_prime_ex_APIParam_2
A key must have been associated with the structure first
This option must be used to prevent small subgroup attacks
After such trimming the length of the data in EVP_DecodeBlock_APIParam_2 must be divisbile by 4
the call SSL_CTX_sess_set_remove_cb_APIName SSL_SESSION_free_APIName
the call BIO_new_socket_APIName must be made available for further incoming connections
RSA_blinding_on_APIParam_2 RSA_blinding_on_APIParam_2 is NULL or a pre-allocated and initialized RSA_blinding_on_APIParam_2 RSA_blinding_on_APIParam_2
ek is an array of buffers where the public key encrypted secret key will be written , each buffer must contain enough room for the corresponding encrypted key
The SSL_has_matching_session_id_APIParam_2 is not security critical but must be unique for the server
Generation of custom DH parameters should still be preferred to stop an attacker from specializing on a commonly used group
The SSL_select_next_proto_APIParam_1 value will point into either server or client , so it should be copied immediately
Similar care should be take to ensure that the data is in the correct format
BN_bn2mpi_APIName and BN_mpi2bn_APIName convert BN_bn2mpi_APIParam_1 BN_mpi2bn_APIParam_3s from and to a format that consists of the BN_print_APIParam2_2  length in bytes represented as a 4-byte big-endian BN_print_APIParam2_2 , and the BN_print_APIParam2_2 itself in big-endian format , where the most significant BN_bn2mpi_APIParam2_2 a negative BN_print_APIParam2_2
BIO_set_mem_buf_APIName sets the internal BIO_new_mem_buf_APIParam_1 to BIO_set_mem_buf_APIParam_2 and call BIO_set_close_APIName to BIO_set_mem_buf_APIParam_3 , that is BIO_set_mem_buf_APIParam_3 should be either BIO_CLOSE or BIO_NOCLOSE
Where OCSP_resp_get0_APIParam_2 runs from 0 to OCSP_resp_get0_id_APIParam2_1 - 1
Note that this will advance the value contained in i2d_SSL_SESSION_APIParam_2 i2d_SSL_SESSION_APIParam_2 i2d_SSL_SESSION_APIParam_2 so it is necessary to save a copy of the original allocation
Only CMS_encrypt_APIParam_1 carrying RSA , Diffie-Hellman or EC keys are supported by CMS_encrypt_APIName
The extensions must be in PEM format
Each extension must consist of a 2-byte Extension Type , a 2-byte length , and length bytes of extension_data
Each extension must consist of a 2-byte Extension Type , a 2-byte length , and length bytes of extension_data
Each PEM extension name must begin with the phrase  BEGIN SERVERINFO FOR
For the transparent negotiation to succeed , the SSL_write_APIParam_1 must have been initialized to client or server mode
For the transparent negotiation to succeed , the SSL_read_APIParam_1 must have been initialized to client or server mode
DH_generate_parameters_ex_APIParam_3 is a small number more than 1, typically 2 or 5
EVP_SignInit_ex_APIParam_1 must be initialized with EVP_MD_CTX_init_APIName before calling EVP_DigestSignInit_APIName
RSA_public_decrypt_APIParam_3 must point to RSA_size_APIName RSA_private_decrypt_APIParam_4 bytes of memory
RSA_private_decrypt_APIParam_3 must point to RSA_size_APIName RSA_private_decrypt_APIParam_4 bytes of memory
Memory call SSL_CONF_CTX_new_APIName should be freed up using the OPENSSL_free_APIName function
Ciphers with DSA keys always use ephemeral DH keys as well
The certificates must be in PEM format and must be sorted
SSL_CTX_set_quiet_shutdown_APIParam_2 may be 0 or 1
SSL_set_quiet_shutdown_APIParam_2 SSL_set_quiet_shutdown_APIParam_2 may be 0 or 1
DES_fcrypt_APIParam_1 needs to be at least 14 bytes long
It is strongly recommended to not use ephemeral RSA key exchange and use DHE key exchange instead
the content must be supplied in the SMIME_write_PKCS7_APIParam_3 argument
the content must be supplied in the SMIME_write_CMS_APIParam_3 argument
Both halves of a BIO pair should be freed
Both halves of a BIO pair should be freed
The password callback, which must be provided by the application, hands back the password to be used
BIO_set_accept_name_APIParam_1 is represented as a string of the form "host:port", where "host" is the interface to use and "port" is the port
the call SSL_CTX_set_session_id_context_APIName by the server
BIO_ctrl_APIParam_3 must be at least 512 bytes
Both EC_POINT_dup_APIParam_1 EC_POINT_copy_APIParam_2 and EC_POINT_copy_APIParam_1 must use the same EC_METHOD
Both EC_GROUP_dup_APIParam_1 EC_GROUP_copy_APIParam_2 and EC_GROUP_copy_APIParam_1 must use the same EC_METHOD
EVP_MD_CTX_copy_ex_APIParam_1 must be initialized before calling EVP_DigestInit_ex_APIName
The call SSL_CTX_set_tmp_dh_callback_APIName to NULL
The call SSL_CTX_set_tmp_dh_callback_APIName to NULL
The buffer SHA512_Final_APIParam_1 SHA384_Final_APIParam_1 SHA256_Final_APIParam_1 SHA1_Final_APIParam_1 SHA224_Final_APIParam_1 must have space for the output from the SHA variant being used
The context value is left to the application but must be the same on both sides of the SSL_export_keying_material_APIParam_2
The EC_POINT_copy_APIParam2_2 must be supplied with a buffer long enough to call BN_hex2bn_APIName
ADH ciphers do not need a certificate , but DH-parameters must have been set
the recovered key length must match the fixed cipher length
Chain verification should arguably be performed using the signing time rather than the current time
Chain verification should arguably be performed using the signing time rather than the current time
The SSL_CTX_new_APIParam2_1 offers little to no security and should not be used
applications should generally avoid using DH_set_default_method_APIParam2_1 directly and instead use API functions to query or modify DH_compute_key_APIParam_1
The only currently supported CMS_compress_APIParam_1 is zlib
A call SSL_CTX_set_tlsext_status_cb_APIName
The parameter EC_get_builtin_curves_APIParam_1 should be an array of EC_get_builtin_curves_APIParam_1 of size EC_get_builtin_curves_APIParam_2
According to the SSLv3 spec, one should use 32 bytes for the challenge, but as mentioned above, this breaks this server so 16 bytes is the way to go
There are two types of BN_is_prime_ex_APIParam_4 BN_GENCB_call_APIParam_1 structure that are supported: "new" style and "old" style
CMS_final_APIParam_3 is only used with detached data and will usually be set to NULL
BIO_set_cipher_APIParam2_2 do not support BIO_gets_APIName or BIO_puts_APIName
ECB mode is not suitable for most applications
to reach the 128 BN_generate_prime_ex_APIParam_2 , BN_is_prime_ex_APIParam_2 BN_is_prime_fasttest_ex_APIParam_2 should be set to 64
RSA_public_encrypt_APIParam_1 must be less than RSA_size
This format call RAND_pseudo_bytes_APIName and should be avoided
The only currently supported CMS_compress_APIParam_1 is zlib using the NID NID_zlib_compression
The X509_VERIFY_PARAM_set1_ip_asc_APIParam_2 argument is a NULL-terminal ASCII string: dotted decimal quad for IPv4 and colon-separated hexadecimal for IPv6
The timeout value SSL_CTX_set_timeout_APIParam_2 must be given in seconds
Private keys encoded without parameters can not be loaded using d2i_ECPrivateKey_APIName
SSL_SESSION_free_APIName must only be called for SSL_SESSION objects
The length is either 4 or 16
ERR_error_string_APIParam_2 ERR_error_string_n_APIParam_2 ERR_error_string_APIParam_2 ERR_error_string_n_APIParam_2 must be at least 120 bytes long
X509_NAME_get_index_by_NID_APIParam_3 X509_NAME_get_index_by_OBJ_APIParam_3 should initially be set to -1
One or both of SSL_CONF_FLAG_CLIENT, SSL_CONF_FLAG_SERVER must be set
For a longer chain , the client must send the complete chain
The PRNG must be seeded prior to using this function
Instead OBJ_obj2txt_APIParam_1 must point to a valid buffer and OBJ_obj2txt_APIParam_2 should be set to a positive value
Instead OBJ_obj2txt_APIParam_1 must point to a valid buffer and OBJ_obj2txt_APIParam_2 should be set to a positive value
A buffer length of 80 should be more than enough to handle any OID encountered in practice
A buffer length of 80 should be more than enough to handle any OID encountered in practice
Each string is limited to 255 bytes
The formatting SSL_CTX_use_certificate_file_APIParam_3 SSL_use_certificate_file_APIParam_3 of the certificate must be specified from the known SSL_CTX_check_private_key_APIParam2_1 , SSL_FILETYPE_ASN1
The formatting SSL_CTX_use_certificate_file_APIParam_3 of the certificate must be specified from the known types SSL_FILETYPE_PEM , SSL_FILETYPE_ASN1
A byte-string length of 0 is invalid
This mode is recommended for all new applications
the client must send the same information about acceptable SSL/TLS protocol levels as during the first hello
The value of BN_rand_APIParam_2 must be zero or greater
PKCS7_decrypt_APIName must be passed the correct recipient key and PKCS7_decrypt_APIParam_3
BN_rand_APIParam_3 can not also be 1
error queue data structures must be freed
both CMS_decrypt_APIParam_3 and CMS_decrypt_APIParam_2 should be set to NULL
BN_bn2bin_APIParam_2 must point to BN_num_bytes bytes of memory
DH_compute_key_APIParam_1 must point to DH_size bytes of memory
RSA_public_encrypt_APIParam_3 must point to RSA_size bytes of memory
RSA_sign_ASN1_OCTET_STRING_APIParam_4 must point to RSA_size bytes of memory
ECDSA_sign_ex_APIParam_2 must point to ECDSA_size bytes of memory
A cryptographic PRNG must be seeded with unpredictable data such as mouse movements or keys pressed at random by the RAND_bytes_APIParam2_1
For BN_div_word_APIName and BN_mod_word_APIName , BN_div_word_APIParam_2 BN_mod_word_APIParam_2 must not be 0
For F2 ^ EC_METHOD_get_field_type_APIParam2_1 there is only one EC_METHOD_get_field_type_APIParam_1 , ie EC_METHOD_get_field_type_APIParam_1
BN_init_APIParam_1 should be considered opaque and fields should not be modified or accessed directly
It is not permissible to perform multiple encryptions using the same key stream
Make sure to not have expired certificates mixed with valid ones
The public key must be RSA
X509_NAME_add_entry_APIParam_2 must be freed up after the call
the DSA_generate_parameters_ex_APIParam_1 allows a maximum of 1024 bits
so the BIO_NOCLOSE flag should be set
the input data must not have been a multiple of 4 and an error has occurred
the underlying stream should not normally be closed
EC_KEY_set_asn1_flag_APIParam_1 EC_KEY_set_conv_form_APIParam_1 must have an EC_GROUP object associated with it before calling EC_KEY_generate_key_APIName
SMIME_read_CMS_APIParam_2 should be initialized to NULL
Acceptable values for X509_NAME_get_entry_APIParam_2 run from 0 to - 1
The same certificate or CRL must not be added to the same cms structure more than once
SHA-1 and SHA should be used only
The PRNG must be seeded before DSA_sign_APIName is called
The flags currently supported are UI_INPUT_FLAG_ECHO , which is relevant for UI_add_input_string_APIName and will have the users response be echoed
The second password is stored in des_read_pw_APIParam_2 des_read_pw_APIParam_2 , which must also be at least des_read_pw_APIParam_3 des_read_pw_APIParam_3 bytes
A DSA cipher can only be chosen
After this call X509_STORE_CTX_free_APIParam_1 is no longer valid
CMS_RecipientInfo_set0_key_APIName associates the symmetric key CMS_RecipientInfo_set0_key_APIParam_2 of length CMS_RecipientInfo_set0_key_APIParam_3 with the CMS_RecipientInfo structure CMS_RecipientInfo_set0_key_APIParam_1 , which must be of type CMS_RECIPINFO_KEK
X509_check_host_APIName checks if the certificate Subject Alternative Name or Subject CommonName matches the call X509_VERIFY_PARAM_set1_host_APIName , which must be encoded in the preferred name syntax described in section 3.5 of RFC 1034
BF_ofb64_encrypt_APIName uses the same parameters as BF_cfb64_encrypt_APIName , which must be initialized the same way
For some key types and parameters the random number generator must be seeded
Large numbers of small writes through the chain should be avoided
BN_bn2mpi_APIName stores the representation of BN_bn2mpi_APIParam_1 at BN_bn2mpi_APIParam_2 , where BN_bn2mpi_APIParam_2 must be large enough to hold the result
In either case for the curve to be valid the discriminant must be non zero
Integers used for point multiplications will be between 0 and n-1 where n is the EC_GROUP_set_generator_APIParam_3 EC_GROUP_get_order_APIParam_2
the SSLv3 protocol is recommended that applications should set this option
For RC5 the number of rounds can currently only be set to 8 , 12 or 16
The SSL_CTX_set_default_passwd_cb_APIParam_2 must write the SSL_CTX_set_default_passwd_cb_APIParam_2 into the provided buffer pem_passwd_cb_APIParam_1 which is of size pem_passwd_cb_APIParam_2
SHA1_Final_APIName places the message digest in SHA1_Final_APIParam_1 , which must have space for 20 bytes of output , and erases the SHA1_Final_APIParam_2
MD2_Final_APIName places the message digest in MD2_Final_APIParam_1 , which must have space for 16 bytes of output , and erases the MD2_Final_APIParam_2
MDC2_Final_APIName places the message digest in MDC2_Final_APIParam_1 , which must have space for MDC2_DIGEST_LENGTH == 16 bytes of output , and erases the MDC2_Final_APIParam_2
CMS_RecipientInfo_set0_pkey_APIName associates the private key CMS_RecipientInfo_set0_pkey_APIParam_2 with the CMS_RecipientInfo structure CMS_RecipientInfo_set0_pkey_APIParam_1 , which must be of type CMS_RECIPINFO_TRANS
The SSL_SESSION object is built from several malloc_APINameed parts , The SSL_SESSION object can not be moved , copied or stored directly
The d2i_RSAPrivateKey_APIParam_1 i2d_RSAPrivateKey_APIParam_2 structure passed to the private key encoding functions should have all the PKCS # 1 private key components present
Under normal conditions it should never be necessary to set a value smaller than the default , as the buffer is handled dynamically and only uses the memory actually required by the data sent by the peer
The elements of Fp are the integers 0 to p-1 , where EC_GROUP_get_curve_GFp_APIParam2_1 is a prime EC_GROUP_new_curve_GF2m_APIParam2_3
The chain of BIOs must not be freed after this call
The current thread  error queue must be empty before the SSL_get_error_APIParam_1 is attempted , or SSL_get_error_APIName will not work reliably
you should be aware that BF_encrypt_APIName and BF_decrypt_APIName take each 32-bit chunk in host-byte order , which is little-endian on little-endian platforms and big-endian on big-endian ones
As call DH_generate_parameters_ex_APIName is extremely time consuming , an application should not generate the parameters on the fly but supply the parameters
Due to the link between EVP_SignFinal_APIParam_2 and public key algorithms the correct digest algorithm must be used with the correct public key type
Due to the link between EVP_SignFinal_APIParam_2 and public key algorithms the correct digest algorithm must be used with the correct public key type
RSA export ciphers with a keylength of 512 EVP_PKEY_CTX_set_rsa_rsa_keygen_bits_APIParam_2 for the RSA EVP_PKEY_CTX_set_rsa_rsa_keygen_bits_APIParam_1 call EVP_PKEY_CTX_set_rsa_rsa_keygen_bits_APIName , as typically the supplied EVP_PKEY_CTX_set_rsa_rsa_keygen_bits_APIParam_1 has a length of 1024 bit
It is important that the correct implementation type for the form of curve selected is used
call BIO_seek_APIName should not be used for socket I/O
currently EVP_PKEY_CTX_set_rsa_keygen_pubexp_APIParam_2 should be an odd integer
X509_cmp_time_APIParam_1 must satisfy the ASN1_TIME format mandated by RFC 5280 , ie , X509_cmp_time_APIParam_1 format must be either YYMMDDHHMMSSZ or YYYYMMDDHHMMSSZ
This function performs integrity checks on all the RSA key material , so the RSA key structure must contain all the private key data too
Some advanced attributes such as counter signatures are not supported
the EVP_SignInit_ex_APIParam2_2 must be cleaned up after use by calling EVP_MD_CTX_cleanup_APIName or a memory leak will occur
the EVP_SignInit_ex_APIParam2_2 must be cleaned up after use by calling EVP_MD_CTX_cleanup_APIName or a memory leak will occur
the EVP_SignInit_ex_APIParam2_2 must be cleaned up after use by calling EVP_MD_CTX_cleanup_APIName or a memory leak will occur
the EVP_SignInit_ex_APIParam2_2 must be cleaned up after use by calling EVP_MD_CTX_cleanup_APIName or a memory leak will occur
Accept BIOs support BIO_puts_APIName but not support BIO_gets_APIName
The protocol-lists must be in wire-format , which is defined as a vector of non-empty , 8-bit length-prefixed , byte strings
Exactly one of the SSL_CTX_set_verify_APIParam_2 SSL_set_verify_APIParam_2 flags SSL_VERIFY_NONE and SSL_VERIFY_PEER must be call X509_VERIFY_PARAM_set_time_APIName
The string is returned in des_read_pw_APIParam_1 des_read_pw_APIParam_1, which must call RAND_pseudo_bytes_APIName for at least des_read_pw_APIParam_3 des_read_pw_APIParam_3 bytes
Only RSA keys are supported in PKCS # 7 and envelopedData so the recipient certificates supplied to this function must all contain RSA public keys
After the digest has been retrieved from a call BIO_set_md_APIName, the digest must be reinitialized by calling BIO_reset_APIName , or BIO_set_md_APIName before any more data is passed through it
After this call no further call BIO_write_APIName are allowed
num must point at an integer which must be initially zero
To avoid ambiguity with a normal positive return value, BIO_set_mem_eof_return_APIParam_2 should be set to a negative value, typically -1
BF_cfb64_encrypt_APIParam5 must point at an 8 byte long initialization vector
Once SSL_write_APIName returns with r, r bytes have been successfully written and the next call to SSL_write_APIName must only send the SSL_write_APIParam2_2 left, imitating the behaviour of write_APIName
The CMS_ContentInfo structure CMS_add0_crl_APIParam_1 CMS_add1_crl_APIParam_1 CMS_add0_cert_APIParam_1 CMS_add1_cert_APIParam_1 must be of type signed data or enveloped data or an error will be returned
The call BIO_set_mem_eof_return_APIName to a read only state and as a result can not be written to
The vector pointed at by BF_ecb_encrypt_APIParam_1 and BF_ecb_encrypt_APIParam_2 must be 64 bits in length , no less
This integer must be initialized to zero
The use of string types such as MBSTRING_ASC or MBSTRING_UTF8 is strongly recommended for the X509_NAME_add_entry_by_OBJ_APIParam_3 X509_NAME_add_entry_by_txt_APIParam_3 X509_NAME_add_entry_by_NID_APIParam_3 parameter
sigret must point to DSA_size bytes of memory
so the supplied area of memory must be unchanged until the BIO is freed
the BIO_new_mem_buf_APIParam_1 is assumed to be nul terminated
The purpose of the latter two is to simulate stream ciphers , and , they need the parameter num , which is a pointer to an integer where the current offset in ivec is stored between calls
Contexts MUST NOT be shared between threads
Normally the reference count is not incremented and the session must not be explicitly freed with SSL_SESSION_free
EVP_DigestSignInit_APIParam_1 must be initialized with EVP_MD_CTX_init before calling this function
EVP_DigestVerifyInit_APIParam_1 must be initialized with EVP_MD_CTX_init before calling this function
In the unlikely even an application explicitly wants to set no prefix it must be explicitly set to
RAND_event() should be called with the RAND_event_APIParam_1 , RAND_event_APIParam_2 and RAND_event_APIParam_3 arguments of all messages sent to the window procedure
The precomputed values from DSA_sign_setup_APIName MUST NOT be used for more than one signature
it should point to an 8 byte buffer or NULL
SSL_OP_SINGLE_DH_USE should be enabled
The implementation of this callback should not fill in CRYPTO_THREADID_set_numeric_APIParam_1 CRYPTO_THREADID_set_pointer_APIParam_1 directly
The parameters PKCS12_parse_APIParam_3 and PKCS12_parse_APIParam_4 can not be NULL
The d2i_PrivateKey_APIParam_1 parameter should be a public key algorithm constant such as EVP_PKEY_RSA
they should be set to NULL
The X509_VERIFY_PARAM_set1_ip_APIParam_2 is in binary format , in network byte-order and iplen must be set to 4 for IPv4 and 16 for IPv6
The communication channel must already have been set and assigned to the SSL_connect_APIParam_1 by setting an call BIO_ssl_shutdown_APIName
The communication channel must already have been set and assigned to the SSL_accept_APIParam_1 by setting an call BIO_ssl_shutdown_APIName
The EVP_SealInit_APIParam_5 must contain enough room for the corresponding cipher  IV , as determined by EVP_CIPHER_iv_length
ek[i] must have room for EVP_PKEY_size(pubk[i]) bytes
RSA_public_encrypt_APIParam_3  must point to a memory section large enough to hold the message digest
As a minimum, the flag CERT_PKEY_VALID must be set for a chain to be usable
The initialization vector iv should be a random value
The first call should have npubk set to 0 and it should be called again with EVP_SealInit_APIParam_2 set to NULL
CMS_RecipientInfo_kekri_get0_id retrieves the key information from the CMS_RecipientInfo structure CMS_RecipientInfo_kekri_get0_id_APIParam_1 which must be of type CMS_RECIPINFO_KEK
Otherwise it can be recommended to pass zero-padded f, so that fl equals to rsa_len, RSA_padding_check_PKCS1_type_2_APIParam_2 being set to the expected length
CMS_RecipientInfo_ktri_get0_signer_id retrieves the certificate recipient identifier associated with a specific CMS_RecipientInfo structure CMS_RecipientInfo_ktri_get0_signer_id_APIParam_1 , which must be of type CMS_RECIPINFO_TRANS
Note that BN_lshift_APIParam_3 must be non-negative
Note that BN_rshift_APIParam_3 must be non-negative
BIO_set_cipher_APIParam_5 should be set to 1 for encryption and zero for decryption
the verification result must be set in any case using the error member of x509_store_ctx
This flag should only be set
The cipher context ctx should use the initialisation vector iv
DH_bits_APIParam_1 must not be NULL
CMS_RecipientInfo_kekri_id_cmp compares the ID in the CMS_RecipientInfo_kekri_id_cmp_APIParam_2 and CMS_RecipientInfo_kekri_id_cmp_APIParam_3 parameters against the keyIdentifier CMS_RecipientInfo structure CMS_RecipientInfo_kekri_id_cmp_APIParam_1 , which must be of type CMS_RECIPINFO_KEK
More data must be read from the call SSL_set_bio_APIName
The hctx needs to be set using HMAC_Init_ex
HMAC_Init_ex_APIParam_1 HMAC_Init_APIParam_1 HMAC_Init_ex_APIParam_1 must have been created with HMAC_CTX_new before the first use of an HMAC_Init_ex_APIParam_1 HMAC_Init_APIParam_1 HMAC_Init_ex_APIParam_1 in this function
EVP_EncryptInit_ex_APIParam_1 must be initialized before calling this function
EVP_DigestInit_ex_APIParam_1 must be initialized before calling this function
Those containing a SSL_CTX_set0_verify_cert_store_APIParam_2 SSL_set0_chain_cert_store_APIParam_2 SSL_CTX_set1_chain_cert_store_APIParam_2 SSL_set1_verify_cert_store_APIParam_2 SSL_set1_chain_cert_store_APIParam_2 SSL_set0_verify_cert_store_APIParam_2 SSL_CTX_set0_chain_cert_store_APIParam_2 SSL_CTX_set1_verify_cert_store_APIParam_2 do not increment reference counts and the supplied store MUST NOT be freed after the operation
The key type used must match EVP_PKEY_CTX_ctrl_APIParam_2
The PKCS7 structure should be obtained from an initial call to PKCS7_sign with the flag PKCS7_PARTIAL set or in the case or re-signing a valid PKCS7 signed data structure
The algorithm call EVP_CIPHER_param_to_asn1_APIName must support ASN1 encoding of its parameters
EVP_CipherInit_ex_APIParam_6 should be set to 1 for encryption , 0 for decryption and -1 to leave the value unchanged
EVP_EncryptUpdate_APIParam_2 should contain sufficient room
the total amount of data encrypted or decrypted must be a multiple of the block size or an error will occur
Files dh1024.pem and dh512.pem contain old parameters that must not be used by applications
This value should be passed in the SSL_set_tlsext_status_type_APIParam_2 argument
The encrypted final call BIO_flush_APIName to EVP_EncryptFinal_ex_APIParam_2 EVP_EncryptUpdate_APIParam_2 which should have sufficient space for one cipher block
session ids must be unique
the EVP_PKEY_encrypt_APIParam_3 should contain the length of the out buffer
The CMS_ContentInfo structure should be obtained from an initial call to CMS_sign_APIName with the flag CMS_PARTIAL set or in the case or re-signing a valid CMS_ContentInfo SignedData structure
It is not recommended to change the id_len for SSLv2 sessions
The first call should have EVP_OpenInit_APIParam_6 set to NULL and it should be called again with EVP_OpenInit_APIParam_2 set to NULL
bn_mul_recursive_APIParam_4 bn_sqr_recursive_APIParam_3 must be a power of 2
it is recommended to use the maximum id_len and fill in the bytes not used to code special information with random data to avoid collisions
The SSL_CTX_set_alpn_protos_APIParam_2 SSL_set_alpn_protos_APIParam_2 must be in protocol-list format , described below
The client should additionally provide a callback function to decide what to do with the returned OCSP response by calling SSL_CTX_set_tlsext_status_cb
This also means that OPENSSL_instrument_bus2_APIParam_1 and OPENSSL_instrument_bus_APIParam_1 should be zeroed upon invocation
A mul_add_APIParam_1 sqr_APIParam_1 mul_APIParam_1 bn_div_words_APIParam_1 bn_mul_words_APIParam_4 can be either 16 , 32 or 64 bits in size , depending on the ` number of bits ' specified in openssl/bn
the callback must never increase id_len or write to the location SSL_has_matching_session_id_APIParam_2 exceeding the given limit
The ALPN select callback SSL_CTX_set_alpn_select_cb_APIParam_2, must return one of SSL_TLSEXT_ERR_OK, SSL_TLSEXT_ERR_ALERT_FATAL or SSL_TLSEXT_ERR_NOACK
Otherwise it should be any other value
This flag must be used together with SSL_VERIFY_PEER
The value of the SSL_select_next_proto_APIParam_1 , SSL_select_next_proto_APIParam_2 vector should be set to the value of a single protocol selected from the SSL_select_next_proto_APIParam_0 SSL_CTX_set_alpn_protos_APIParam_0 SSL_set_alpn_protos_APIParam_0 , inlen vector
it should not be freed or modified in any way
The application specific context should be supplied in the location pointed to by context and should be contextlen bytes long
An application specific label should be provided in the location pointed to by label and should be llen bytes long
The CMS_STREAM flag must be included in the corresponding flags parameter of the BIO_new_CMS_APIParam_2 creation function
The function EC_GROUP_get_trinomial_basis_APIName must only be called where f is of the trinomial form, and returns the value of EC_GROUP_get_trinomial_basis_APIParam_2
rsa - > n must not be NULL
Before a DES key can be used , a DES key must be converted into the architecture dependent DES_key_schedule via the DES_set_key_checked or DES_set_key_unchecked function
the ivec variable is changed and the new changed value needs to be passed to the next call to this function
For  new  style callbacks a BN_GENCB structure should be initialised with a call to BN_GENCB_set , where gencb is a BN_is_prime_ex_APIParam_4 BN_GENCB_call_APIParam_1 , callback is of type int and cb_arg is a void
Similary the function EC_GROUP_get_pentanomial_basis_APIName must only be called where f is of the pentanomial form, and returns the values of EC_GROUP_get_pentanomial_basis_APIParam_2, k2 and k3 respectively
a certificate/private key combination must be set using the x509 and pkey arguments and "1" must be returned
dsa - > q must not be NULL
any FILE pointers or BIOs should be opened in binary mode
each application must set its own session id context SSL_CTX_set_session_id_context_APIParam_2 SSL_set_session_id_context_APIParam_2 which is used to distinguish the contexts and is stored in exported sessions
Applications should use this flag with extreme caution especially in automated gateways as it can leave them open to attack
Normally the current time should be between these two values
The actual X509 structure passed to i2d_X509 must be a valid populated i2d_X509_APIParam_1 structure
For lh _ <type> _ doall and lh _ <type> _ doall_arg , function pointer casting should be avoided in the callbacks - instead use the declare/implement macros to create type-checked wrappers that cast variables prior to calling your type-specific callbacks
The actual X509 structure can not simply be fed with an empty structure such as that returned by X509_new
EVP_SignFinal_APIParam_2 must be at least EVP_SignInit_ex_APIParam2_2 in size
Applications should typically use SSL_CTX_set_options in combination with the SSL_OP_NO_SSLv3 flag to disable negotiation of SSLv3 via the above version-flexible SSL/TLS methods
Base64 BIOs do not support BIO_gets_APIName or BIO_puts_APIName
The control string SSL_CTX_set_cipher_list_APIParam_2 SSL_set_cipher_list_APIParam_2 should be universally usable and not depend on details of the library configuration
OBJ_txt2nid_APIParam_1 can be a long name , a short name or the numerical representation of an OBJ_length_APIParam2_1
HMAC_Final_APIName places the HMAC_Final_APIParam_2 in HMAC_Final_APIParam_2 , which must have space for the hash function output
The following EVP_PKEY_meth_new_APIParam_2 are supported
The following strings can occur for SSL_alert_type_string_APIName or SSL_alert_type_string_long_APIName
The cipher IV must be set
Not all BIOs support these calls
It can not be shared between threads
SSL_CTX_new_APIParam_1 can be of the following types
Using 16 bytes is ok but it should be ok to use 32
The following SSLeay_version_APIParam_1 values are supported
The parameters generated by DH_generate_parameters_ex_APIName and DH_generate_parameters_APIName are not to be used in signature schemes
Following bits are significant
The i2d_DSAPublicKey_APIParam_1 d2i_DSA_PUBKEY_APIParam_1 d2i_DSAPublicKey_APIParam_1 d2i_DSA_SIG_APIParam_1 i2d_DSA_SIG_APIParam_1 i2d_DSA_PUBKEY_APIParam_1 i2d_DSAparams_APIParam_1 d2i_DSAparams_APIParam_1 i2d_DSAPrivateKey_APIParam_1 d2i_DSAPrivateKey_APIParam_1 structure passed to the private key encoding functions should have all the private key components present
The protocol data in server , server_len and client , client_len must be in the protocol-list format described below
As such , this function can not be used with any arbitrary RSA key object
The error strings will have the following format
EC_GROUP_get_degree_APIParam2_1 is an enum defined as follows
CRYPTO_lock_APIParam_1 can be combined from 1,2,4,8
Only a single delta can be used and constructed CRLs are not maintained
The maximum IV length is EVP_MAX_IV_LENGTH bytes defined in evp.h
MIME headers for type text/plain are added to the content , this only makes sense
MIME headers for type text/plain are added to the content , this only makes sense if CMS_DETACHED is also set
Currently the only supported type is TLSEXT_NAMETYPE_host_name
Currently the only supported type is TLSEXT_STATUSTYPE_ocsp
Ensure the output buffer contains 65 bytes of storage for each block , plus an additional byte for a NUL terminator
The output is always an integral multiple of eight bytes
setting SHA256_Final_APIParam_1 SHA512_Final_APIParam_1 SHA384_Final_APIParam_1 SHA224_Final_APIParam_1 SHA1_Final_APIParam_1 to NULL is not thread safe
It is possible to call EVP_CIPHER_asn1_to_param_APIName to NULL except EVP_EncryptInit_ex_APIParam_2 in an initial call and supply the remaining parameters in subsequent calls , all of which have EVP_EncryptInit_ex_APIParam_2 set to NULL
Two special values are supported
the error number is stored in verify_callback_APIParam_2 and verify_callback is called with verify_callback_APIParam_1 = 0
For finer control of the output format the certs , signcert and pkey parameters can all be NULL and the CMS_PARTIAL flag set
the bn_dump_APIParam_1 bn_div_words_APIParam_3 field can be NULL and top == 0
A RSA cipher can only be chosen
the peer certificate must be obtained separately using SSL_get_peer_certificate_APIName
The maximum length of the SSL_CTX_set_session_id_context_APIParam_2 SSL_set_session_id_context_APIParam_2 is limited to SSL_MAX_SSL_SESSION_ID_LENGTH
This list is not influenced by the contents of SSL_CTX_load_verify_locations_APIParam_2 or CApath and must explicitly be set using the SSL_CTX_set_client_CA_list family of functions
RSA_private_decrypt_APIParam_3 must point to a memory section large enough to hold the decrypted data
The SSL_SESSION object must be transformed into a binary i2d_SSL_SESSION_APIParam_1
Adds a padding extension to ensure the ClientHello size is never between 256 and 511 bytes in length
SSL_want_write_APIParam2_1 are not handled and must be treated using SSL_get_error_APIName
only the numerical form is acceptable
only the numerical form is acceptable
At least one of these flags must be set
the pointer must not be used any longer
Applications can access , modify or create the embedded content in a CMS_get0_type_APIParam_1 CMS_set1_eContentType_APIParam_1 CMS_get0_content_APIParam_1 CMS_get0_eContentType_APIParam_1 structure using this function
The algorithm to use is specified in the PEM_write_bio_PKCS8PrivateKey_nid_APIParam_3 PEM_write_PKCS8PrivateKey_nid_APIParam_3 parameter and should be the NID of the corresponding OBJECT IDENTIFIER
The rate is 2 ^ -80 starting at 308 bits , 2 ^ -112 at 852 bits , 2 ^ -128 at 1080 bits , 2 ^ -192 at 3747 bits and 2 ^ -256 at 6394 bits
RSA_private_decrypt_APIParam_5 RSA_public_encrypt_APIParam_5 denotes one of the following modes
A pointer to the response data should be provided in the SSL_set_tlsext_status_ocsp_resp_APIParam_2 argument , and the SSL_set_tlsext_status_ocsp_resp_APIParam_3 of that data should be in the SSL_set_tlsext_status_ocsp_resp_APIParam_3 argument
BIO_get_fd_APIParam_2 should be of type
In previous releases they also cleaned up the EVP_EncryptFinal_APIParam_1 EVP_DecryptFinal_APIParam_1 EVP_CipherFinal_APIParam_1 EVP_EncryptFinal_ex_APIParam_1 EVP_DecryptFinal_ex_APIParam_1 EVP_CipherFinal_ex_APIParam_1 , but this is no longer done and EVP_CIPHER_CTX_clean_APIName must be called to call EVP_PKEY_CTX_free_APIName
The EVP_MD_CTX_init_APIParam_1 EVP_MD_size_APIParam_1 EVP_DigestInit_APIParam_1 EVP_MD_block_size_APIParam_1 EVP_MD_CTX_md_APIParam_1 EVP_MD_CTX_destroy_APIParam_1 EVP_MD_pkey_type_APIParam_1 EVP_MD_CTX_copy_APIParam_1 EVP_MD_CTX_cleanup_APIParam_1 EVP_MD_type_APIParam_1 EVP_DigestFinal_ex_APIParam_1 EVP_DigestInit_ex_APIParam_1 EVP_DigestUpdate_APIParam_1 EVP_MD_CTX_copy_ex_APIParam_1 EVP_DigestFinal_APIParam_1 interface to message digests should almost always be used in preference to the low level interfaces
CMS_RecipientInfo_ktri_cert_cmp_APIName compares the certificate CMS_RecipientInfo_ktri_cert_cmp_APIParam_2 against the CMS_RecipientInfo structure CMS_RecipientInfo_ktri_cert_cmp_APIParam_1 , which must be of type CMS_RECIPINFO_TRANS
The EC_KEY_insert_key_method_data_APIParam_2 to be stored by EC_KEY_get0_private_key_APIParam2_1 is provided in the EC_KEY_insert_key_method_data_APIParam_2 parameter , which must have associated functions for duplicating , freeing and  clear_freeing  the EC_KEY_insert_key_method_data_APIParam_2 item
BIO_set_close_APIParam_2 can take the value BIO_CLOSE or BIO_NOCLOSE
ASN1_TIME_set_string_APIName sets ASN1_TIME structure ASN1_TIME_set_string_APIParam_1 to the ASN1_TIME_check_APIParam2_1 represented by string ASN1_TIME_set_string_APIParam_2 which must be in appropriate ASN .1 ASN1_TIME_check_APIParam2_1 format
this is only of use for multiline format
The default RAND_set_rand_method_APIParam_1, as set by RAND_set_rand_method_APIName and returned by RAND_get_rand_method_APIName, is only used
The call SSL_CTX_sess_cb_hits_APIName and SSL_CTX_set_session_cache_mode_APIParam_2 are available
The following bug workaround options are available
The EVP_PKEY_CTX_set_rsa_keygen_pubexp_APIParam_2 pointer is used internally by this function so EVP_PKEY_CTX_set_rsa_keygen_pubexp_APIParam_2 should not be modified or free after the call
Legacy applications might implicitly use an X509_STORE_CTX_set0_param_APIParam_1 X509_STORE_CTX_get0_param_APIParam_1 X509_STORE_CTX_free_APIParam_1 X509_STORE_CTX_set_default_APIParam_1 X509_STORE_CTX_cleanup_APIParam_1 X509_STORE_CTX_set_cert_APIParam_1 X509_STORE_CTX_init_APIParam_1 like this
The EVP_PKEY_CTX_set_rsa_pss_saltlen macro call EVP_PKEY_CTX_set_rsa_rsa_keygen_bits_APIName to EVP_PKEY_CTX_set_rsa_pss_saltlen_APIParam_2 as its name implies it is only supported for PSS padding
The following mode changes are available
At the most basic level , each ENGINE pointer is inherently a structural reference - a structural reference is required to use the pointer value at all , as this kind of reference is a guarantee that the structure can not be deallocated until the reference is released
Currently the following SSL_CONF_CTX_clear_flags_APIParam_2 SSL_CONF_CTX_set_flags_APIParam_2 values are recognised
The following modifying options are available
A truncated byte-string is invalid
DSA_generate_parameters_APIParam_2 > 20 are not supported
ENGINE_CTRL_GET_FLAGS returns a ENGINE_set_STORE_APIParam2_2 of the following possible values
As the CMS_add0_cert_APIParam_2 CMS_add1_cert_APIParam_2 implies , CMS_add0_cert_APIName adds CMS_add0_cert_APIParam_2 CMS_add1_cert_APIParam_2 internally to CMS_add0_cert_APIParam_1 CMS_add1_cert_APIParam_1 , and CMS_add0_cert_APIParam_1 CMS_add1_cert_APIParam_1 must not be freed up after the call as opposed to CMS_add1_cert_APIName where CMS_add0_cert_APIParam_2 CMS_add1_cert_APIParam_2 must be freed up
It is the caller  responsibility to ensure that the buffer at EVP_DecodeUpdate_APIParam_2 EVP_DecodeUpdate_APIParam_2 is sufficiently large to accommodate the output data
It is the caller  responsibility to ensure that the buffer at EVP_EncodeUpdate_APIParam_2 EVP_EncodeUpdate_APIParam_2 EVP_EncodeFinal_APIParam_2 EVP_EncodeUpdate_APIParam_2 EVP_EncodeUpdate_APIParam_2 is sufficiently large to accommodate the output data
For special applications it can be necessary to call SSL_set_max_cert_list_APIName allowed to be sent by the peer , see eg the work on  Internet X. 509 Public Key Infrastructure Proxy Certificate Profile  and  TLS Delegation Protocol  at http
padding denotes one of the following modes
This may lead to unexpected results
The following functions may be used
The following functions may be used
The following functions may be used
The following functions may be used
The following functions may be used
the BN_CTX_get_APIParam_0 pointers obtained from BN_CTX_get_APIName become invalid
The length of the session id is between 1 and 32 bytes
Misconfigured applications sending incorrect certificate chains often cause problems with peers
The risk in reusing DH parameters is that an attacker may specialize on a very often used DH group
a SSL_has_matching_session_id_APIParam2_2 can occur in that another thread generates the same SSL_has_matching_session_id_APIParam_2
The setting stays valid until SSL_set_quiet_shutdown_APIParam_1 SSL_set_quiet_shutdown_APIParam_1 is removed with SSL_free_APIName or SSL_set_quiet_shutdown_APIName is called again
The buffer is no longer valid after the callback function has returned
Key sizes with num < 1024 should be considered insecure
passing a NULL value for HMAC_Final_APIParam_2 to use the static array is not thread safe
The constant EVP_MAX_IV_LENGTH is the maximum IV length for all ciphers
For ERR_error_string_n_APIName , ERR_error_string_APIParam_2 ERR_error_string_n_APIParam_2 ERR_error_string_APIParam_2 ERR_error_string_n_APIParam_2 may not be NULL
the session may be removed completely, and the pointer obtained will become invalid
The constant EVP_MAX_IV_LENGTH is also the maximum block length for all ciphers
one or both of ASN1_TIME_diff_APIParam_1 and ASN1_TIME_diff_APIParam_2 will be positive
one or both of ASN1_TIME_diff_APIParam_1 and ASN1_TIME_diff_APIParam_2 will be negative
ASN1_TIME_diff_APIParam_1 and ASN1_TIME_diff_APIParam_2 will both be zero
SSL_get0_alpn_selected_APIParam_2 is set to NULL and len is set to 0
The X509_check_ip_asc_APIParam_3 argument is usually 0
this function has no effect
As of OpenSSL 1.0.2 g , EXPORT ciphers and 56-bit DES are no longer available with SSL_CTX_new_APIParam2_1
The length of ASN1_STRING_to_UTF8_APIParam_1 is returned or a negative error code
Passing a NULL EC_get_builtin_curves_APIParam_1, or setting EC_get_builtin_curves_APIParam_2 to 0 will do nothing other than return the total EC_GROUP_new_curve_GF2m_APIParam2_3 of curves available
RSA_set_ex_data is used to set application specific data , the data is supplied in the RSA_set_ex_data_APIParam_3 parameter and its precise meaning is up to the application
CRYPTO_set_ex_data is used to set application specific data , the data is supplied in the CRYPTO_set_ex_data_APIParam_3 parameter and its precise meaning is up to the application
At this point it is important to mention an important API function
Allow SSL_write to return r with 0 < r < n
The return values of BIO_pending_APIName and BIO_wpending_APIName may not reliably determine the amount of pending data in all cases
Supported representations are octet strings , BIGNUMs and hexadecimal
EC_GROUP_set_generator call SSL_CTX_set1_curves_APIName that must be agreed by all participants using the curve
EC_POINT_copy_APIParam2_2 returns the EC_METHOD associated with the supplied EC_POINT
An application supporting multiple chains with different CA signature algorithms may also wish to check CERT_PKEY_CA_SIGNATURE too
BIO_new_accept_APIParam_1 call RAND_pseudo_bytes_APIName as the BIO_new_accept_APIParam_1 specified in BIO_set_conn_port_APIName for connect BIOs , that is it can be a numerical BIO_new_accept_APIParam_1 string or a string to lookup using getservbyname_APIName and a BIO_set_nbio_accept_APIParam_2
It is not NUL-terminated
The string will have the following format
Any or all of these call SSL_CTX_set_tmp_dh_callback_APIName to NULL
ASN1_generate_v3_APIParam_2 or ASN1_generate_nconf_APIParam_2 can be set to NULL
The following encoding methods are implemented
, SSL_accept will only return once the handshake has been finished or an error occurred
If the underlying BIO is blocking, SSL_do_handshake will only return once the handshake has been finished or an error occurred
If the underlying BIO is blocking, SSL_connect will only return once the handshake has been finished or an error occurred
The SSL_get_error_APIParam_2 returned by SSL_want_APIName should always be consistent with the SSL_get_error_APIParam_2 of SSL_get_error_APIName
These functions can not return OBJ_obj2txt_APIParam_3 OBJ_sn2nid_APIParam_1 OBJ_create_APIParam_1 OBJ_ln2nid_APIParam_1 OBJ_cmp_APIParam_1
The policies parameter can be NULL to clear an existing policy set
CMS_add1_signer_APIName returns an internal pointer to the CMS_SignerInfo structure just added
PKCS7_sign_add_signers_APIName returns an internal pointer to the PKCS7_SIGNER_INFO structure just added
In public keys , priv_key is NULL
A return value of 0 or 1 indicates successful processing of the data
Use the c_rehash utility to create the necessary links
the key genration operation is aborted and an error occurs
Typically BIO_CLOSE is used in a source/sink BIO to indicate that the underlying I/O stream should be closed when the BIO is freed
Any or all of the X509_STORE_CTX_init_APIParam_2 X509_STORE_CTX_init_APIParam_2 , STACK_OF_APIParam_0 and chain parameters can be NULL
An application may either directly specify the DH parameters or can supply the DH parameters via a callback function
The length of the SSL_has_matching_session_id_APIParam_2 is 16 bytes for SSL_has_matching_session_id_APIParam2_1 and between 1 and 32 bytes for SSL_has_matching_session_id_APIParam2_1
The exponent is an odd number , typically 3 , 17 or 65537
These CRLs will only be used
It might also call SSL_certs_clear to delete any certificates call EVP_PKEY_meth_new_APIName
The certificate callback functionality is always called even is a certificate is already set so the callback can modify or delete the existing certificate
RAND_priv_bytes_APIName call RAND_pseudo_bytes_APIName as RAND_bytes_APIName
This option is not needed for clients
This is often not desirable
The following call DES_quad_cksum_APIName in C
Netscape-Commerce/1 .12 , , accepts a 32 byte challenge but appears to only use 16 bytes when call DES_random_key_APIName
instead of calling the hash functions directly
Alternatively , the EGD-interface compatible daemon PRNGD can be used
Others might not even call the callback
Some applications will want to allow the user to specify exactly which ENGINE they want used
On Windows BIO_new_files reserves for the filename argument to be UTF-8 encoded
do not prefer ECDHE-ECDSA ciphers
The following descriptions apply in the case of the built-in procedure
the state information however can be of significant interest
You can find out
Why is this useful you ask
The reference count for the newly created EC_KEY is initially set to 1
This function is thread safe , unlike the normal crypt
BIO_set_accept_port_APIName uses the string BIO_set_accept_port_APIParam_2 to set the accept port
It will typically be called in the certificate callback
an application has been configured by its user or admin to want to use the ACME ENGINE
the SSL_CTX_set_default_passwd_cb_APIParam_2 dialog may ask for the same SSL_CTX_set_default_passwd_cb_APIParam_2 twice for comparison
CRYPTO_get_new_dynlockid_APIName will call CRYPTO_destroy_dynlockid_APIParam_1 for the actual creation
2 is used
65537 is used
The seed values can not be recovered from the PRNG output
call BIO_set_accept_bios_APIName for each key type supported by a server
SSL_set_bio_APIName can not fail
either TLSCiphertext was not an even multiple of the block length or TLSCiphertext  padding values were not correct
CRYPTO_destroy_dynlockid_APIName will call dyn_destroy_function for the actual destruction
The use of a read only memory BIO avoids this problem
In public keys , the private exponent and the related secret values are NULL
Not all members of the X509_STORE are used
Applications can use the CONF_modules_load_APIName function
Applications for non-public use may agree on certain compression methods
These functions are not normally called directly , various macros are used instead
For a EC_KEY_copy_APIParam_1 of EC_KEY_set_conv_form_APIParam_2 please refer to EC_POINT_new_APIName
Similarly for command lines "--ssl-no_tls1_2" is recognised instead of "-no_tls1_2" instead of "-no_tls1_2
The X509_STORE_CTX_set_default_APIParam2_2 can be reused with an new call to X509_STORE_CTX_init_APIName
this can be used
this can be used
the automatic flushing may be disabled and SSL_CTX_flush_sessions_APIName can be called explicitly by the application
The ASN1_TIME_check_APIParam2_1 is represented as an ASN1_STRING internally and can be freed up using ASN1_STRING_free_APIName
EVP_MAX_KEY_LENGTH and EVP_MAX_IV_LENGTH only refer to the internal EVP_EncryptInit_ex_APIParam2_2 with default key lengths
BN_bn2bin_APIName converts the absolute value of BN_bn2bin_APIParam_1 into big-endian form and stores BN_bn2bin_APIParam_1 at BN_bn2bin_APIParam_2
DH_generate_parameters_ex_APIName and DH_generate_parameters_APIName may run for several hours before finding a suitable prime
only the first one will be examined
In OpenSSL , the type X509 is used to express such a certificate , and the type X509_CRL is used to express a CRL
These are the version-specific SSL_CTX_new_APIParam_1 for DTLSv1
A  negative zero  is converted to zero
The following are DES-based transformations
This size can be modified using the SSL_CTX_sess_set_cache_size_APIName call
Several certificates can be added one after another
For almost all applications X509_NAME_add_entry_by_txt_APIParam_6 X509_NAME_add_entry_by_NID_APIParam_6 X509_NAME_delete_entry_APIParam_2 X509_NAME_add_entry_APIParam_3 X509_NAME_add_entry_by_OBJ_APIParam_6 can be set to -1 and X509_NAME_add_entry_by_txt_APIParam_7 X509_NAME_add_entry_by_NID_APIParam_7 X509_NAME_add_entry_APIParam_4 X509_NAME_add_entry_by_OBJ_APIParam_7 to 0
there is no need to use these pseudo-digests in OpenSSL 1.0.0 and later , they are however retained for compatibility
Applications will typically call OCSP_resp_find_status_APIName using the certificate ID of interest and check its validity using OCSP_check_validity_APIName
it is the applications responsibility to set the inner content type of any outer CMS_ContentInfo structures
other sockets can bind to the same port
OBJ_length_APIParam_1 do not need to be in the internal tables to be processed , the functions OBJ_txt2obj_APIName and OBJ_obj2txt_APIName can process the numerical form of an OID
OBJ_length_APIParam_1 do not need to be in the internal tables to be processed , the functions OBJ_txt2obj_APIName and OBJ_obj2txt_APIName can process the numerical form of an OID
the EGD-interface compatible daemon PRNGD is available from http
instead of calling the RC4 functions directly
as a result a statically linked executable can be quite large
The SSL_CONF_CTX_set_ssl_ctx_APIParam_2 need not be set or The call SSL_CTX_set_session_id_context_APIName to NULL in which case only syntax checking of commands is performed , where possible
The value EC_POINT_mul_APIParam_3 EC_POINTs_mul_APIParam_3 may be NULL in which case the result is just EC_POINT_mul_APIParam_4 EC_POINT_mul_APIParam_5 EC_POINTs_mul_APIParam_6
Others may prefer to load all support and have OpenSSL automatically use at run-time any ENGINE that is able to successfully initialise - ie to assume that this corresponds to ENGINE_set_name_APIParam2_2 attached to the machine or some such thing
The meaning of the BIO_get_retry_BIO_APIParam_2 and the action that should be taken depends on the type of BIO that resulted in this condition
This can be used to set either defaults or values which can not be overridden
Under previous export restrictions , ciphers with RSA keys shorter than the usual key length of 1024 bits were created
A shutdown alert was received form the peer , either a normal  close notify  or a fatal error
no 8 byte padding
The error message produced will be that of an incomplete certificate chain and not X509_V_ERR_CERT_CHAIN_TOO_LONG as may be expected
the results for earlier versions of TLS and DTLS may not be very useful
From the X509_STORE the X509_STORE_CTX used is created
The functions are as follows
The functions SSL_CTX_build_cert_chain_APIName and SSL_build_cert_chain_APIName can be used to check application configuration and to ensure any necessary subordinate CAs are sent in the correct order
Slated for possible release in 0.9.8 is support for transparent ENGINE_get_ex_new_index_APIParam_1 of  dynamic  ENGINE_get_load_privkey_function_APIParam2_1
For each supported abstraction , the ENGINE_get_load_privkey_function_APIParam2_1 maintains an internal table of state to control which implementations are available for a given abstraction and which should be used by ENGINE_set_cmd_defns_APIParam2_2
This would allow ENGINE_get_load_privkey_function_APIParam2_1 to be provided independently of OpenSSL libraries and/or OpenSSL-based applications , and would also remove any requirement for applications to explicitly use the  dynamic  ENGINE to bind to shared-library implementations
The rest of the certificates needed to form the complete call SSL_CTX_build_cert_chain_APIName the SSL_CTX_add_extra_chain_cert_APIName function
bn_expand_APIName ensures that bn_mul_normal_APIParam_4 bn_mul_comba4_APIParam_3 bn_mul_low_recursive_APIParam_3 bn_mul_high_APIParam_3 bn_mul_low_normal_APIParam_3 bn_cmp_words_APIParam_2 bn_mul_comba8_APIParam_3 bn_mul_recursive_APIParam_3 bn_mul_part_recursive_APIParam_3 has enough space for a bn_expand_APIParam_2 bit number
bn_wexpand_APIName ensures that bn_mul_normal_APIParam_4 bn_mul_comba4_APIParam_3 bn_mul_low_recursive_APIParam_3 bn_mul_high_APIParam_3 bn_mul_low_normal_APIParam_3 bn_cmp_words_APIParam_2 bn_mul_comba8_APIParam_3 bn_mul_recursive_APIParam_3 bn_mul_part_recursive_APIParam_3 has enough space for an bn_wexpand_APIParam_2 bn_expand2_APIParam_2 word number
X509_NAME_ENTRY_create_by_txt_APIName , X509_NAME_ENTRY_create_by_OBJ_APIName , X509_NAME_ENTRY_create_by_NID_APIName and X509_NAME_ENTRY_set_data_APIName are seldom used in practice are typically used to create and add new entries in a single operation
EC_METHOD_get_field_type_APIParam_1 offers an implementation optimised for use with NIST recommended curves
CRYPTO_lock_APIParam_1 is a bitfield describing what should be done with the lock
This is currently used to support EVP_PKEY_base_id_APIParam2_1 , which use an identical encoding to ECDSA
The parameter SSL_flush_sessions_APIParam_2 SSL_CTX_flush_sessions_APIParam_2 specifies the time which should be used for the expiration test , in most cases the actual time given by time_APIName will be used
BN_is_prime_ex_APIParam_4 BN_GENCB_call_APIParam_1 is used as follows
The way this SSL_CTX_set_default_passwd_cb_APIParam_2 can be supplied may depend on the application
The output will be padded with 0 bits to ensure that the output is always 3 bytes for every 4 input bytes
It is possible to have DH_set_method_APIParam2_2 that only work with certain DH_set_method_APIParam2_2 , and attempting to change the DH_METHOD for the key can have unexpected results
Otherwise a deadlock may occur as the peer might be waiting for the data before being able to continue
Otherwise a deadlock may occur as the peer might be waiting for the data before being able to continue
OBJ_obj2txt_APIName does not follow the OBJ_length_APIParam2_1 of other OpenSSL functions where the buffer can be set to NULL to determine the amount of data that should be written
OBJ_obj2txt_APIName does not follow the OBJ_length_APIParam2_1 of other OpenSSL functions where the buffer can be set to NULL to determine the amount of data that should be written
SSL_get_shared_ciphers_APIParam_2 is the SSL_get_shared_ciphers_APIParam_2 that should be populated with the list of names and SSL_get_shared_ciphers_APIParam_3 is the SSL_get_shared_ciphers_APIParam_3 of that SSL_get_shared_ciphers_APIParam_2
So the first consideration is whether any/all available ENGINE implementations should be made visible to OpenSSL - this is controlled by calling the various  load  functions , eg
Session resumption shortcuts the TLS so that the client certificate negiotation do not occur
However , as callers are themselves providing these pointers , they can choose whether they too should be treating all such parameters as constant
CMS_decrypt_APIName can be called with a NULL key to decrypt the enveloped content
Items that are not recognized , or , are simply ignored
attempt is first made to use BIO_BIN_NORMAL
 the amount of space needed in X509_NAME_get_text_by_NID_APIParam_3 X509_NAME_get_text_by_OBJ_APIParam_3  is returned
The return value can be compared to the macro to make sure that the correct SSLeay_version_APIParam_1 of the library has been loaded, especially when using DLLs on SSLeay_version_APIParam_1
Further , the thread-safety does not extend to things like multiple threads call SSL_want_APIName at the same time
Some have tried using BN_num_bits on individual numbers in RSA keys , DH keys and DSA keys , and found that they do not always come up with the number of bits they expected
, EVP_BytesToKey returns the number of bytes needed to store the derived key
The parameter indent indicated how far the printout should be indented
The values of offset_day or offset_sec can be negative to call X509_VERIFY_PARAM_set_time_APIName before ASN1_TIME_adj_APIParam_2
SSL_CTX_set_read_ahead and SSL_set_read_ahead set whether we should read as many input bytes as possible or not
All functionalities needed are made available via other functions or macros
the returned CMS_ContentInfo structure is not complete and outputting its contents via a function that does call CMS_add1_recipient_cert_APIName will give unpredictable results
verify_callback is called with verify_callback_APIParam_1 = 1 before advancing to the next level
The shutdown can also occur
The tmp_rsa_callback is called with the keylength needed and the is_export information
The encrypted data follows , padded with random data out to a multiple of 8 bytes
Currently SSL_CTX_set_current_cert_APIParam_2 can be SSL_CERT_SET_FIRST to use the first valid certificate or SSL_CERT_SET_NEXT to set the next valid certificate after the current certificate
Any TLS/SSL I/O function can lead to either of SSL_ERROR_WANT_READ and SSL_ERROR_WANT_WRITE
Note that BIO_get_read_request_APIName never returns an amount larger than that returned by BIO_get_write_guarantee_APIName
Note that SSL_ERROR_ZERO_RETURN does not necessarily indicate that the underlying transport has been closed
The  re  in i2d_re_X509_tbs stands for  re-encode  , and ensures that a fresh encoding is generated in case the object has been modified after creation
This can be used to determine how much call BIO_flush_APIName to the BIO so the next read will succeed
The EC_get_builtin_curves_APIParam_1 is defined as follows
These functions are typically called after X509_verify_cert_APIName has indicated an error or in a verification callback to determine the nature of an error
Only explicitly marked addresses in the certificates are considered
Right now RSA_check_key_APIName simply uses the RSA structure elements directly , bypassing the RSA_METHOD table altogether
a password might be supplied to call X509_check_private_key_APIName
DES_cbc_cksum_APIName produces an 8 byte checksum based on the input stream
Otherwise , the encoding of the TBSCertificate portion of the i2d_re_X509_tbs_APIParam_1 can be manually renewed by calling i2d_re_X509_tbs_APIName
Both are NULL-terminated
Its state can be saved in a seed file to avoid having to go through the seeding process
BN_bn2hex_APIName and BN_bn2dec_APIName return a null-terminated string
X509_getm_notBefore_APIName and X509_getm_notAfter_APIName are similar to X509_get0_notBefore_APIName and X509_get0_notAfter_APIName except X509_getm_notBefore_APIName and X509_getm_notAfter_APIName return non-constant mutable references to the associated date field of the certificate
i2d_SSL_SESSION_APIName returns the size of the i2d_SSL_SESSION_APIParam_1 in bytes
For an unknown SSLeay_version_APIParam_1, the text "not available" is returned
The structure returned by EVP_PKEY_new_APIName is empty
CRYPTO_get_new_dynlockid_APIName returns the index to the newly created lock
a return value of -2 indicates the operation is not supported by the public key algorithm
a return value of -2 indicates the operation is not supported by the public key algorithm
a return value of -2 indicates the operation is not supported by the public key algorithm
a return value of -2 indicates the operation is not supported by the public key algorithm
a return value of -2 indicates the operation is not supported by the public key algorithm
a return value of -2 indicates the operation is not supported by the public key algorithm
a return value of -2 indicates the operation is not supported by the public key algorithm
a return value of -2 indicates the operation is not supported by the public key algorithm
a return value of -2 indicates the operation is not supported by the public key algorithm
a return value of -2 indicates the operation is not supported by the public key algorithm
a return value of -2 indicates the operation is not supported by the public key algorithm
a return value of -2 indicates the operation is not supported by the public key algorithm
If the return value is -2 the operation is not implemented in the specific BIO type
ASN1_TIME_set_APIName and ASN1_TIME_adj_APIName return a pointer to an ASN1_TIME_check_APIParam2_1 or NULL if an error occurred
an application might call SSL_CTX_cmd_APIName and if SSL_CTX_cmd_APIName returns -2  continue with processing of application specific commands
BN_get_word_APIName returns the value BN_get_word_APIParam_1, or all-bits-set if BN_get_word_APIParam_1 cannot be represented as a BN_get_word_APIParam_0
If des_read_pw_APIParam_5 des_read_pw_APIParam_5 is set, the user is asked for the password twice and 
SSL_CTX_sess_set_cache_size_APIName returns the previously valid size
BN_num_bits_APIName returns the BN_num_bytes_APIParam2_1 of significant bits in a BN_num_bits_APIParam_1, following the same principle as BN_num_bits_word_APIName
the return type may be replaced with a RSA_PKCS1_SSLeay_APIParam_1 RSA_get_default_method_APIParam_1 RSA_null_method_APIParam_1 declaration in a future release
This returns a EC_GROUP_set_generator_APIParam2_2 to a memory block containing the EC_GROUP_method_of_APIParam_0 that was used
More complex PKCS#12 files with multiple private keys will only return the first match
a required argument is missing and an error is indicated
If the BIO_set_mem_eof_return_APIParam_2 is zero an empty memory BIO will return EOF
Calling the function with a NULL buffer will not perform the EC_POINT_copy_APIParam2_2 but will still return the required buffer length
The length of the output string written is returned excluding the terminating null
EVP_PKEY_get1_RSA_APIName, EVP_PKEY_get1_DSA_APIName, EVP_PKEY_get1_DH_APIName and EVP_PKEY_get1_EC_KEY_APIName return the referenced key in EVP_PKEY_get1_RSA_APIParam_1 EVP_PKEY_get1_DSA_APIParam_1 EVP_PKEY_get1_DH_APIParam_1 EVP_PKEY_get1_EC_KEY_APIParam_1 or NULL if the key is not of the correct EVP_PKEY_type_APIParam_1
EVP_PKEY_get1_RSA_APIName, EVP_PKEY_get1_DSA_APIName, EVP_PKEY_get1_DH_APIName and EVP_PKEY_get1_EC_KEY_APIName return the referenced key in EVP_PKEY_get1_RSA_APIParam_1 EVP_PKEY_get1_DSA_APIParam_1 EVP_PKEY_get1_DH_APIParam_1 EVP_PKEY_get1_EC_KEY_APIParam_1 or NULL if the key is not of the correct EVP_PKEY_type_APIParam_1
X509_STORE_CTX_get_error_depth_APIName returns a non-negative error depth
The d2i_SSL_SESSION_APIParam_3 of the resulting i2d_SSL_SESSION_APIParam_1 is returned
The return string is allocated by the library and is no longer valid once the associated X509_VERIFY_PARAM_get0_peername_APIParam_1 argument is freed
SSL_get_default_timeout_APIName return this hardcoded value, which is 300 SSL_get_default_timeout_APIParam2_1 for all currently supported protocols
If the read and the write channel are different, SSL_get_fd_APIName will return the file descriptor of the read channel
In case of failure the i2d_SSL_SESSION_APIParam_1 is returned and the error message can be retrieved from the error stack
CMS_get1_crls_APIName returns any CRLs in CMS_add0_crl_APIParam_1 CMS_add1_crl_APIParam_1
EC_METHOD_get_field_type_APIParam_1 returns an integer that identifies the type of field the EC_METHOD_get_field_type_APIParam_1 supports
In the last case, the SSL_CTX_set_default_passwd_cb_APIParam_2 could be stored into the pem_passwd_cb_APIParam_4 pem_passwd_cb_APIParam_4 storage and the pem_passwd_cb_APIName only returns the SSL_CTX_set_default_passwd_cb_APIParam_2 already stored
EVP_PKEY_meth_find_APIName returns a pointer to the found EVP_PKEY_meth_find_APIParam_0 object or returns NULL if not found
The client_cert_cb_APIName cannot return a complete certificate chain, it can only return one client certificate
EVP_PKEY_meth_new_APIName returns a pointer to a new EVP_PKEY_meth_new_APIParam_0 object or returns NULL on error
That a certificate is returned does not indicate information about the verification state, use SSL_get_verify_result_APIName to check the verification state
Any function which encodes an X509 structure such as i2d_X509_APIName, i2d_X509_fp_APIName or i2d_X509_bio_APIName may return a stale encoding if the i2d_X509_APIParam_1 i2d_X509_fp_APIParam_2 i2d_X509_bio_APIParam_2 structure has been modified after deserialization or previous serialization
EC_GROUP_get_degree_APIParam2_1 returns the EC_GROUP_set_seed_APIParam_3 of the EC_GROUP_method_of_APIParam_0 that has been set
This function returns the Diffie-Hellman size in bytes
This RSA_set_method_APIParam2_2 may or may not be supplied by an ENGINE implementation, but if it is, the return value can only be guaranteed to be valid as long as the RSA_set_method_APIParam2_2 itself is valid and does not have its implementation changed by RSA_set_method_APIName
EC_KEY_get0_private_key_APIParam2_1 returns the private EC_KEY_get0_private_key_APIParam2_1 associated with the EC_KEY
This function can be called repeatedly until there are no more error codes to return
EC_KEY_get0_private_key_APIParam2_1 returns the EC_GROUP associated with the EC_KEY
Data written to the null sink is discarded, reads return EOF
BN_bn2mpi_APIName returns the length of the representation
Basically, except for a zero, it returns floor+1
A negative return value from X509_verify_cert_APIName can occur if X509_verify_cert_APIName is invoked incorrectly, such as with no certificate set in X509_verify_cert_APIParam_1, or when X509_verify_cert_APIName is called twice in succession without reinitialising X509_verify_cert_APIParam_1 for the second call
0 may also be valid application data but
It is run as egd RAND_egd_APIParam_1 RAND_egd_APIParam_1 , where RAND_egd_APIParam_1 RAND_egd_APIParam_1 is an absolute path designating a socket
The remove_session_cb is called
The new_session_cb is called
The get_session_cb is always called
DSA_sign_setup_APIParam_2 DSA_sign_setup_APIParam_2 is a pre-allocated DSA_sign_setup_APIParam_2 DSA_sign_setup_APIParam_2 or NULL
OpenSSL makes sure that the PRNG state is unique for each thread
BN_BLINDING_create_param creates new BN_BLINDING_create_param_APIParam_1 parameters using the exponent BN_BLINDING_set_flags_APIParam_2 BN_BLINDING_set_thread_id_APIParam_2 and the modulus m. bn_mod_exp and m_ctx can be used to pass special functions for exponentiation and BN_MONT_CTX
OpenSSL can generally be used safely in multi-threaded applications provided that at least call SSL_CTX_set_psk_client_callback_APIName , the locking_function and threadid_func
The digest type may be NULL
A detailed description for the _ get_ex_new_index functionality can be found in RSA_get_ex_new_index
X509_VERIFY_PARAM_set1_host sets the expected DNS hostname to name clearing any call X509_VERIFY_PARAM_set1_host_APIName or names
As for EC_POINT_mul the value EC_POINTs_mul_APIParam_3 EC_POINT_mul_APIParam_3 may be NULL
It is usually safe to use SSL_OP_ALL to enable the bug workaround options
p , q , dmp1 , dmq1 and iqmp may be NULL in private keys , but
It call DES_random_key_APIName and stores it in a - > pub_key and a - > priv_key
XN_FLAG_RFC2253 sets options which produce an output compatible with RFC2253 it is equivalent to
Only friendlyName and localKeyID attributes are currently stored in certificates
The EVP_PKEY_FLAG_SIGCTX_CUSTOM is used to indicate
RSA_padding_add_PKCS1_OAEP and RSA_padding_check_PKCS1_OAEP may be used in an application combined with RSA_NO_PADDING
p may be NULL
the iv parameter is ignored and can be NULL
the server implementation only applies to TLS and there is no SSLv3 implementation
Any of the remaining parameters can be NULL
An ENGINE implementation can override the way key data is stored and handled , and can even provide support for HSM keys - in which case the RSA structure may contain no key data at all
SSL_CTX_set_msg_callback_arg and SSL_set_msg_callback_arg can be used to set argument SSL_CTX_set_msg_callback_arg_APIParam_2 SSL_set_msg_callback_arg_APIParam_2 to the callback function , which is available for arbitrary application use
the function arguments have the following meaning
The returned PKCS7 structure will be valid and finalized
no error occurred
Some applications add offset times directly to a time_t value and pass the results to ASN1_TIME_set
The returned CMS_ContentInfo structure will be valid and finalized
On success the length of psk in bytes is returned
If the underlying BIO is blocking, SSL_read will only return, once the read operation has been finished or an error occurred, except when a renegotiation take place, in which case a SSL_ERROR_WANT_READ may occur
If the underlying BIO is blocking, SSL_write will only return, once the write operation has been finished or an error occurred, except when a renegotiation take place, in which case a SSL_ERROR_WANT_READ may occur
X509_STORE_CTX_get1_chain returns a complete validate chain if a previous call to X509_verify_cert is successful
This is a non-negative integer representing where in the certificate chain the error occurred
The DER call i2d_ECDSA_SIG_APIName is stored in ECDSA_sign_ex_APIParam_2 and it is length is returned in sig_len
Either of BN_div_APIParam_1 and BN_div_APIParam_2 may be NULL, in which case the respective value is not returned
The callback is only allowed to generate a shorter id and reduce id_len
In the event of an error EVP_EncodeUpdate will set EVP_EncodeUpdate_APIParam_3 EVP_EncodeUpdate_APIParam_3 EVP_EncodeFinal_APIParam_3 EVP_EncodeUpdate_APIParam_3 EVP_EncodeUpdate_APIParam_3 to 0
The flags begin with BN_FLG _
the NULL pointer can be used for verify_callback
cert_cb is the application defined callback
client_cert_cb is the application defined callback
BN_is_prime_fasttest_ex_APIParam_3 BN_is_prime_ex_APIParam_3 is a pre-allocated BN_is_prime_fasttest_ex_APIParam_3 BN_is_prime_ex_APIParam_3 , or NULL
The length of SSL_CTX_set_alpn_protos_APIParam_2 SSL_set_alpn_protos_APIParam_2 is specified in protos_len
It is an error to return a value greater than max_psk_len
If the underlying BIO is blocking, SSL_shutdown will only return once the handshake step has been finished or an error occurred
an application can add any set of certificates using SSL_CTX_use_certificate_chain_file call SSL_CTX_build_cert_chain with the option SSL_BUILD_CHAIN_FLAG_CHECK to check and reorder them
the accept can be freed using BIO_free
It returns a 4 byte checksum from the input bytes
These provide per-variable casts before calling the type-specific callbacks written by the application author
The length sid_ctx_len of the session id context SSL_CTX_set_session_id_context_APIParam_2 SSL_set_session_id_context_APIParam_2 exceeded the maximum allowed length of SSL_MAX_SSL_SESSION_ID_LENGTH
Multiple calls have no effect
SSL_read or SSL_peek may want to call BIO_flush_APIName and SSL_write may want to read data
This emulates the normal non-thread safe semantics of crypt_APIName
additional certificates can be supplied in extra_certs