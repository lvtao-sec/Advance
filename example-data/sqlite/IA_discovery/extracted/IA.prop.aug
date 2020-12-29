The sqlite3_table_column_metadata_APIName interface returns SQLITE_ERROR_API_constant if the specified column does not exist
The sqlite3_stmt_busy_APIName interface returns false
sqlite3_collation_needed_APIParam_2 and sqlite3_collation_needed16_APIParam_2 are one of SQLITE_UTF8_API_constant, SQLITE_UTF16_API_constantBE or SQLITE_UTF16_API_constantLE, indicating the most ideal form of the required collation sequence function
Type conversion and pointer failure may occur in the following situations
SQLITE_RANGE_API_constant is returned by sqlite3_bind_text_APIName
The sqlite3_mprintf_APIName and sqlite3_vmprintf_APIName routines return NULL pointers
The string returned by sqlite3_expanded_sql_APIName must be released by the application by passing it to sqlite3_free_APIName
Call of pointer to sqlite3_keyword_name_APIName causes undefined behavior
The safest strategy is to call these routines in one of the following ways
These APIs are only available
This method is disabled on MacOS X 10.7 and iOS version 5.0 and will always return SQLITE_MISUSE_API_constant
The sqlite3_uri_boolean_APIName routine returns false
The application should complete all prepared statements, close all BLOB handles, and complete all sqlite3_backup objects associated with the sqlite3 object before attempting to close the object.
The sqlite3_expanded_sql_APIName interface returns NULL
sqlite3_complete_APIName and sqlite3_complete16_APIName return 0
Transaction control statements such as BEGIN, COMMIT, ROLLBACK, SAVEPOINT, and RELEASE make sqlite3_stmt_readonly_APIName return true
File names containing international characters must be converted to UTF-8 before being passed to sqlite3_open_APIName or sqlite3_open_v2_APIName
This attribute can only be used in SQLITE_UPDATE_API_constant and SQLITE_DELETE_API_constant pre-update callbacks
sqlite3_db_filename_APIName will return NULL pointer or empty string
But for maximum security, mutex locks should be enabled
sqlite3_strlike_APIName interface returns zero
The sqlite3_update_hook_APIName function returns the P parameter from the last call to D on the same database connection, or NULL to the first call to D.
sqlite3_open16_APIName returns an error to the caller
The strings returned by sqlite3_column_text_APIName and sqlite3_column_text16_APIName, even if they are empty strings, always end with zero
Call sqlite3_close_APIName and sqlite3_close_v2_APIName return SQLITE_OK_API_constant
The application does not need to worry about the release result
The interrupted SQL operation will return SQLITE_INTERRUPT_API_constant
For maximum portability, it is recommended that applications always always call sqlite3_initialize_APIName directly before using any other SQLite interface.
For the INSERT operation on the rowid table or any operation on the WITHOUT ROWID table, the value of the sixth parameter is undefined
SQLITE_BUSY_API_constant is returned by sqlite3_wal_checkpoint_v2_APIName
SQLITE_ERROR_API_constant is returned by sqlite3_snapshot_open_APIName
sqlite3_msize_APIName returns zero
The sqlite3_free_table_APIParam_1 table should be released using sqlite3_free_table_APIName
Applications using SQLite mutexes should only use the dynamic mutexes returned by SQLITE_MUTEX_FAST_API_constant or SQLITE_MUTEX_RECURSIVE_API_constant
sqlite3_value_type_APIParam_0 is one of SQLITE_INTEGER_API_constant, SQLITE_FLOAT_API_constant, SQLITE_TEXT_API_constant, SQLITE_BLOB_API_constant or SQLITE_NULL_API_constant
The result may be an infinite loop
The SQLite query planner can perform other optimizations on deterministic functions, so it is recommended to use the SQLITE_DETERMINISTIC_API_constant flag whenever possible
These routines should return true
Incremental Blob I/O routines can only read or overwrite existing Blob content
This interface sqlite3_snapshot_recover_APIName is only available
The callback function should normally return SQLITE_OK_API_constant
You must call sqlite3_reset_APIName or sqlite3_finalize_APIName
sqlite3_test_control_APIName does not apply to applications
The values ​​returned by sqlite3_column_bytes_APIName and sqlite3_column_bytes16_APIName do not contain a zero terminator at the end of the string
sqlite3_initialize_APIName returns error codes other than SQLITE_OK_API_constant
sqlite3_compileoption_get_APIName returns a NULL pointer
sqlite3_uri_parameter_APIName returns NULL, and sqlite3_uri_boolean_APIName returns B
sqlite3_blob_reopen_APIName returns a SQLite error code, and the blob handle is considered aborted
These routines must be called from the same thread running the SQL function
Passing any other pointers to this routine will result in undefined behavior and may be bad behavior
sqlite3_data_count_APIName returns 0
sqlite3_realloc_APIName returns NULL
Only external mutex implementation is needed to provide these routines
sqlite3_bind_parameter_name_APIParam_0 always uses UTF-8 encoding
It is recommended that you add a path name (such as "./") before sqlite3_open_v2_APIParam_1 to avoid ambiguity.
The operation is still attempted on all remaining additional databases, and SQLite_BUSY_API_constant is finally returned by sqlite3_wal_checkpoint_v2_APIName
sqlite3_column_decltype16_APIParam_0 is always UTF-8 encoded
Please note that the name length limit is in UTF-8 bytes, not characters or UTF-16 bytes
SQLITE_NOMEM_API_constant is returned by sqlite3_complete16_APIName
These routines sqlite3_column_database_name_APIName sqlite3_column_database_name16_APIName sqlite3_column_table_name_APIName sqlite3_column_table_name16_APIName sqlite3_column_origin_name_APIName sqlite3_column_origin_name16_APIName may also return
To avoid memory leaks, the object returned by sqlite3_str_new_APIName must be released by subsequent calls to sqlite3_str_finish_APIName.
Otherwise, sqlite3_open_APIName returns an error code
sqlite3_config_APIName returns SQLITE_OK_API_constant
This attribute can only be used in SQLITE_INSERT_API_constant and SQLITE_UPDATE_API_constant pre-update callbacks
For sqlite3_snapshot_get_APIName to succeed, the following conditions must be met
This is considered the wrong form
On these systems, the shared cache mode for each database connection should be enabled via sqlite3_open_v2_APIName with SQLITE_OPEN_SHAREDCACHE_API_constant
The application must always be prepared to encounter a NULL pointer in any of the third to sixth parameters of the authorization callback
These routines sqlite3_trace_APIName and sqlite3_profile_APIName are deprecated
Subsequent calls to sqlite3_value_type_APIName may return SQLITE_TEXT_API_constant
These routines only apply to protected sqlite3_value objects
sqlite3_close_v2_APIName returns SQLITE_OK_API_constant, and the release of resources is postponed until all prepared statements, BLOB handles, and sqlite3_backup objects are also destroyed
sqlite3_stmt_busy_APIName interface returns true
Any attempt to create a function with a longer name will result in SQLITE_MISUSE_API_constant being returned
The collation function must always return the same answer given the same input
However, it is not safe to call this routine in a database connection that is closed or may be closed before sqlite3_interrupt_APIName returns
In the old interface, the return value will be SQLITE_BUSY_API_constant, SQLITE_DONE_API_constant, SQLITE_ROW_API_constant, SQLITE_ERROR_API_constant or SQLITE_MISUSE_API_constant
But sometimes they are impossible, in this case, the previous pointer will be invalid
Call sqlite3_serialize_APIName may return NULL
The sqlite3_str_errcode_APIName method will return the appropriate error code
 This parameter must be a byte offset that assumes that the string appears with a NUL terminator.
When using sqlite3_prepare_v2_APIName, sqlite3_prepare_v3_APIName, sqlite3_prepare16_v2_APIName or sqlite3_prepare16_v3_APIName or any one of the traditional interfaces sqlite3_prepare_APIName or sqlite3_prepare_step or must be called once, you must use preliteestep_step or must be evaluated long
However, such a call cannot close the database connection, nor can it finalize or reset the prepared statement in which the function runs.
In the "v2" interface, more specific error codes are returned directly by sqlite3_step_APIName
Therefore, sqlite3_set_auxdata_APIName should be called at the end of the function implementation, and after calling sqlite3_set_auxdata_APIName, the function implementation should not use P
Functions with non-negative nArg parameters achieve better matching than functions with negative nArg
For "X LIKE P" without ESCAPE clause, set the sqlite3_strlike_APIParam_3 parameter of sqlite3_strlike_APIName to 0
After success, sqlite3_blob_open_APIName returns SQLITE_OK_API_constant, and the new BLOB handle is stored in ppBlob
The resource associated with the database connection handle should be released by passing it to sqlite3_close_APIName
The application must provide a custom mutex implementation using the SQLITE_CONFIG_MUTEX_API_constant option of the sqlite3_config_APIName function before calling sqlite3_initialize_APIName or any other public sqlite3_function calling sqlite3_initialize_APIName.
To avoid memory leaks, the application should call sqlite3_free_APIName on the error message string returned by the fifth parameter of sqlite3_exec_APIName after the error message string is no longer needed.
Currently, there is only one option that can be configured using sqlite3_vtab_config_APIName
The collation function must follow the following attributes for all strings A, B and C
Only need to use this interface
Behavior is uncertain and may be undesirable
Older interfaces are retained for backward compatibility, but they are not recommended
Developers may also want to use the sqlite3_set_authorizer_APIName interface to further control untrusted SQL
The sqlite3_stmt_isexplain_APIName interface returns 1
Only one authorizer can be connected to the database at a time
Assuming that after registering an unlock notification callback, the database waits for the callback to be issued before performing any further operations, using this API may cause the application to deadlock
sqlite3_blob_write_APIName returns SQLITE_READ_API_constantONLY
May cause memory corruption, segmentation faults or other serious errors
Parameter name must be given in UTF-8
sqlite3_close_APIName will keep the database connection open and return SQLITE_BUSY_API_constant
sqlite3_wal_checkpoint_v2_APIName returns SQLITE_ERROR_API_constant to the caller
Database connection must not be closed
The parameter of sqlite3_mutex_alloc_APIName must be one of these integer constants
To avoid resource leakage, you should eventually release each open BLOB handle by calling sqlite3_blob_close_APIName.
On these systems, sqlite3_mutex_try_APIName will always return SQLITE_BUSY_API_constant
The returned value is unpredictable and meaningless
The UTF-8 interface is preferred because SQLite currently uses UTF-8 for all parsing
The application should only call sqlite3_initialize_APIName and sqlite3_shutdown_APIName
In the xUpdate method of the virtual table, the sqlite3_value_nochange_APIName interface will return true if and only if the column corresponding to sqlite3_value_nochange_APIParam_1 corresponding to the call sqUpdate3_value_nochange_APIParam_1 has not changed and the xUpdate method is called to call the UPDATE operation to be implemented and the value has not been changed. Extract the value of the returned column without setting the result
These routines must be called from the same thread as the SQL function that provides the sqlite3_value parameter
The pointer parameters of sqlite3_free_APIName and sqlite3_realloc_APIName must be NULL, otherwise the pointer obtained from the sqlite3_malloc_APIName or sqlite3_realloc_APIName call previously called has not been released
The sqlite3_prepare_APIName interface is an old interface and should be avoided
Tests show that most applications do not need to use SQLITE_ENABLE_MEMORY_MANAGEMENT to achieve sufficient soft heap limit implementation
 The result is uncertain
It is recommended to use the SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION_API_constant method instead of this interface to disable extension loading, so the load_extension_APIName SQL function remains disabled
The authorizer callback should return SQLITE_OK_API_constant to allow operations, SQLITE_IGNORE_API_constant to prohibit specific operations but allow to continue compiling SQL statements, or SQLITE_DENY_API_constant to cause the entire SQL statement to be wrongly rejected.
SQLite3_aggregate_context_APIName must be called from the same thread running the aggregate SQL function
sqlite3_sql_APIName will return the original string "SELECT $ abc,: xyz", but sqlite3_expanded_sql_APIName will return" SELECT 2345, NULL".
In the old interface, after any errors other than SQLITE_BUSY_API_constant and SQLITE_MISUSE_API_constant, the sqlite3_step_APIName API always returns the common error code SQLITE_ERROR_API_constant.
The sqlite3_shutdown_APIName interface can only be called from a single thread
Otherwise, sqlite3_db_cacheflush_APIName returns SQLITE_OK_API_constant
It will continue to execute and return SQLITE_BUSY_API_constant to the application instead of calling the busy handler
The sqlite3_win32_set_directory_APIParam_2 parameter should be NULL to release the previous value through sqlite3_free
You should roll back the transaction before continuing
SQLITE_LOCKED_API_constant is returned by sqlite3_unlock_notify_APIName
The value returned by sqlite3_status_APIName is undefined
Therefore, the application should ensure that the correct authorizer callback is retained during sqlite3_step_APIName.
The sqlite3_stmt_isexplain_APIName interface returns 0
The sqlite3_column_name_APIParam_0 pointer is valid until the prepared statement is destroyed with sqlite3_finalize_APIName or until the first call to sqlite3_step_APIName for a specific run automatically prepares the statement, or until the next call to sqlite3_column_name_APIName or sqlite3_column_name16_APIName on the same object
After the application uses the result of sqlite3_get_table_APIName, it must pass the result table pointer to sqlite3_free_table_APIName
The calling application should pass sqlite3_str_finish_APIParam_0 to sqlite3_free_APIName to avoid memory leaks
The sqlite3_compileoption_used_APIName function returns 0 or 1, indicating whether the specified option was defined at compile time
The sqlite3_str_finish_APIName interface will also return a NULL pointer
The result is uncertain and may be harmful
Only sqlite3_free_table_APIName can correctly and safely release memory
The result of an expression involving a string with embedded NUL is undefined
Attempt to write expired BLOB handle failed with error code SQLITE_ABORT_API_constant
In this case, for the same column in the xUpdate method, sqlite3_value_nochange_APIName will return true
SQLITE_OK_API_constant is returned by sqlite3_wal_checkpoint_v2_APIName
``iScanStatusOp'' must be one of the scanstatus options, otherwise the behavior of this interface is undefined
In a multi-threaded environment, unprotected sqlite3_value objects can only be used safely with sqlite3_bind_value_APIName and sqlite3_result_value_APIName
SQLITE_ERROR_API_constant_SNAPSHOT is returned by sqlite3_snapshot_open_APIName
Upon success, sqlite3_blob_read_APIName returns SQLITE_OK_API_constant
sqlite3_stmt_scanstatus_APIName is only available
No mutex lock, it is not safe to use SQLite from multiple threads at the same time
SQLITE_OMIT_TRACE compile time option makes sqlite3_expanded_sql_APIName always return NULL
If sqlite3_uri_parameter_APIName exists, the value of sqlite3_uri_parameter_APIParam_2 is returned; if sqlite3_uri_parameter_APIParam_2 does not appear as a query parameter of sqlite3_uri_parameter_APIParam_1, a NULL pointer is returned.
However, after opening the BLOB handle, you cannot change the column, table, or database of the BLOB handle
The result is uncertain
The sqlite3_libversion_number_APIName function returns an integer equal to SQLITE_VERSION_API_constant_NUMBER
The result is undefined behavior
 sqlite3_value_pointer_APIName will return the pointer P. Otherwise, sqlite3_value_pointer_APIName will return NULL
Sqlite3_step_APIName should not be called again on the VM
The sqlite3_commit_hook_APIName and sqlite3_rollback_hook_APIName functions return P parameters from previous calls to the same function on the same database connection D, and return NULL for the first call of each function on D.
The length of the name is limited to 255 bytes in UTF-8 representation, excluding zero terminator
The sqlite3_snapshot_free_APIName interface is only available
sqlite3_uri_boolean_APIName is returned (B! = 0).
Only valid calls to sqlite3_shutdown_APIName can perform any de-initialization
sqlite3_log_APIParam_2 string cannot be NULL
This routine is only applicable to the BLOB handle, which was created by a previous successful call to sqlite3_blob_open_APIName and has not been closed by sqlite3_blob_close_APIName
The zero-length BLOB return value of sqlite3_column_blob_APIName is a NULL pointer
sqlite3_column_bytes_APIName returns zero
The sqlite3_errcode_APIName interface returns the numeric result code or extended result code of the API call
Failure to reset prepared statements using sqlite3_reset_APIName will result in SQLITE_MISUSE_API_constant being returned from sqlite3_step_APIName
The only exception is if SQLite cannot allocate memory to hold the sqlite3 object, then write a NULL to *ppDb instead of a pointer to the sqlite3 object.
sqlite3_preupdate_depth_APIName interface returns 1
The sqlite3_table_column_metadata_APIName interface returns SQLITE_OK_API_constant and fills the appropriate value in the non-NULL pointer in the last five parameters (if the specified column exists)
sqlite3_column_type_APIParam_0 is one of SQLITE_INTEGER_API_constant, SQLITE_FLOAT_API_constant, SQLITE_TEXT_API_constant, SQLITE_BLOB_API_constant or SQLITE_NULL_API_constant
The sqlite3_status_APIName and sqlite3_status64_APIName routines return SQLITE_OK_API_constant on success and non-zero error codes on failure
Calling sqlite3_blob_bytes_APIName on an abnormally terminated Blob handle always returns zero
The sqlite3_release_memory_APIName routine is no operation and returns zero
Only one busy handler can be defined per database connection
Applications that need to use untrusted sources to process SQL can use SQLite3_limit_APIName to reduce resource limits and max_page_count PRAGMA to limit the database size in addition to the authorizer.
The calling function must not attempt to call sqlite3_free_APIName directly
The sqlite3_win32_set_directory8 and sqlite3_win32_set_directory16 interfaces behave exactly the same as the sqlite3_win32_set_directory interface, except that the string parameters must be UTF-8 or UTF-16, respectively.
The sqlite3_config_APIName interface is not thread safe
Calling sqlite3_snapshot_open_APIName will fail
After encountering a lock, sqlite3_busy_handler_APIName immediately returns SQLITE_BUSY_API_constant
Can only change rows
Calling sqlite3_blob_close_APIName with parameters that are not NULL pointers or open Blob handles will cause undefined behavior
Then the behavior is uncertain.
SQLite behavior is undefined
This routine returns a non-zero error code
The behavior of sqlite3_msize_APIName is undefined and may be harmful
This interface is not recommended
The sqlite3_data_count_APIName routine also returns 0
When a NULL pointer is given, the sqlite3_mutex_notheld_APIName interface should also return 1
sqlite3_reset_APIName returns the appropriate error code
The sqlite3_load_extension_APIName interface returns SQLITE_OK_API_constant successfully, or SQLITE_ERROR_API_constant if there is a problem
The callback implementation must not do anything that would modify the database connection that called the callback
Processing was abandoned, sqlite3_wal_checkpoint_v2_APIName immediately returned the error code to the caller
This routine only checks if the table exists and returns SQLITE_OK_API_constant
The sqlite3_mutex_alloc_APIName routine returns NULL
Using any prepared statement after the end may lead to undefined bad behavior, such as segfaults and heap damage
The API sqlite3_unlock_notify_APIName is only available
sqlite3_keyword_check_APIName returns zero
The callback implementation should return zero to ensure future compatibility
The update hook implementation must not do anything that would modify the database connection that called the update hook
The sqlite3_trace_v2_APIName interface is designed to replace the old interfaces sqlite3_trace_APIName and sqlite3_profile_APIName are deprecated
One way to solve this problem is to check the extended error code returned by the sqlite3_step_APIName call
SQLITE_ERROR_API_constant was returned by sqlite3_blob_write_APIName, and no data was written
Attempting to deallocate static mutex will cause undefined behavior
The sqlite3_get_autocommit_APIName interface returns non-zero or zero
The third to sixth parameters of the callback are NULL pointers or zero-terminated strings, which contain additional details about the operation to be authorized
Any attempt to use these routines on unprotected sqlite3_value is not thread safe
The M parameter should be zero or more bitwise OR combinations of SQLITE_TRACE_API_constant constants
The sqlite3_snapshot_get_APIName interface is only available
The sqlite3_data_count_APIName routine returns 0
Some systems do not support operations implemented by sqlite3_mutex_try_APIName
sqlite3_table_column_metadata_APIName returned an error
The implementation of new functions always causes an exception to be thrown
If sqlite3_keyword_name_APIParam_1 is in range, the sqlite3_keyword_name_APIName routine returns SQLITE_OK_API_constant, otherwise it returns SQLITE_ERROR_API_constant
The database handle must have no active statements
After successful input, the sqlite3_mutex_try_APIName interface returns SQLITE_OK_API_constant
 The return value is arbitrary and meaningless
 No other attempt to access the database, sqlite3_busy_handler_APIName returns SQLITE_BUSY_API_constant to the application
sqlite3_blob_close_APIName returns an error code and the transaction is rolled back
Call the sqlite3_next_stmt_APIName database connection pointer sqlite3_next_stmt_APIParam_1 must refer to the open database connection, and cannot be a NULL pointer
All operations that modify the database connection must be delayed until the sqlite3_step_APIName call that triggers the update hook is completed
At any given moment, there can only be one busy handler for a particular database connection
After release, it should not read or write to memory
The sqlite3_cancel_auto_extension_APIName routine returns 1
Aggregate SQL functions require the implementation of xStep and xFinal, and must pass a NULL pointer for xFunc
sqlite3_value_frombind_APIName returns zero
Any such action will result in undefined behavior
The sqlite3_stmt_readonly_APIName interface returns true for BEGIN, but the BEGIN IMMEDIATE and BEGIN EXCLUSIVE commands do touch the database, so sqlite3_stmt_readonly_APIName returns false for these commands
After at least "ms" milliseconds of sleep, the handler returns 0, which causes sqlite3_step_APIName to return SQLITE_BUSY_API_constant
Calls to sqlite3_blob_read_APIName and sqlite3_blob_write_APIName on the expired BLOB handle failed with return code SQLITE_ABORT_API_constant
The input of sqlite3_complete_APIName must be a zero-terminated UTF-8 string
sqlite3_prepare_v3_APIName differs from sqlite3_prepare_v2_APIName only in that it has an additional sqlite3_prepare_v3_APIParam_4, which is a bit array consisting of zero or more SQLITE_PREPARE_PERSISTENT, SQLITE_PREPARE_NORMALIZE and SQLITE_PREPARE_NO_VT
The result is uncertain
The sqlite3_result_text64_APIName interface sets the return value of the application-defined function to the text string in the encoding specified by the fifth parameter, which must be SQLITE_UTF8_API_constant, SQLITE_UTF16_API_constant, SQLITE_UTF16_API_constantBE or SQLITE_UTF16_API_constantLE
The sqlite3_initialize_APIName interface is thread safe, but sqlite3_shutdown_APIName is not
It is recommended that when the database sqlite3_open_v2_APIParam_1 actually starts with the ":" character, a path name (eg "./") should be added in front of sqlite3_open_v2_APIParam_1 to avoid ambiguity.
Use the sqlite3_trace_v2_APIName interface instead of the routine described here
The third and fourth parameters of sqlite3_table_column_metadata_APIName are the table name and column name of the required column, respectively
sqlite3_unlock_notify_APIName always returns SQLITE_OK_API_constant
Before calling sqlite3_shutdown_APIName, all open database connections must be closed, and all other SQLite resources must be released.
The sqlite3_win32_set_directory interface returns SQLITE_OK_API_constant to indicate success, if sqlite3_win32_set_directory_APIParam_1 does not support SQLITE_ERROR_API_constant, if it cannot allocate memory it returns SQLITE_NOMEM_API_constant
sqlite3_mutex_enter_APIName will be blocked, and sqlite3_mutex_try_APIName will return SQLITE_BUSY_API_constant
The application must provide suitable implementations for sqlite3_os_init_APIName and sqlite3_os_end_APIName
sqlite3_blob_write_APIName returns SQLITE_OK_API_constant
sqlite3_malloc_APIName returns a NULL pointer
sqlite3_bind_parameter_name_APIName returns NULL
You should first call sqlite3_column_text_APIName, sqlite3_column_blob_APIName or sqlite3_column_text16_APIName to force the result to the required format, call sqlite3_column_bytes_APIName or sqlite3_column_bytes16_APIName to find the size of the result
If sqlite3_value_dup_APIParam_1 is NULL or memory allocation fails, the sqlite3_value_dup_APIName interface returns NULL.
You can call the sqlite3_finalize_APIName routine at any time during the prepared statement S: before evaluating the statement sqlite3_finalize_APIParam_1, after making one or more calls to sqlite3_reset_APIName, or after making any calls to sqlite3_step_APIName, regardless of whether the statement has been executed .
The returned pointer is valid until type conversion occurs as described above, or until sqlite3_step_APIName or sqlite3_reset_APIName or sqlite3_finalize_APIName is called
sqlite3_vtab_nochange_APIName returns true, during which the column value will remain unchanged
Unlock notification notification callback is not reentrant
However, the application must call sqlite3_initialize_APIName directly before using any other SQLite interface.
sqlite3_blob_open_APIName failed with SQLITE_ERROR_API_constant
NULL pointer must be passed as sqlite3_create_function_APIParam_7 and sqlite3_create_function_APIParam_8
Soft heap limits are for reference only
sqlite3_finalize_APIName returns SQLITE_OK_API_constant
The busy handler must not close the database connection or prepared statement that called the busy handler
The new row must meet the same conditions as sqlite3_blob_open_APIName-the new row must exist and the blob or text value must be stored in the nominated column
sqlite3_column_bytes16_APIName returns zero
Only the following subset of interfaces will have out of memory errors
It is recommended to use SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION_API_constant method to enable this interface only
sqlite3_wal_checkpoint_v2_APIName cannot obtain the lock and returns SQLITE_BUSY_API_constant
sqlite3_snapshot_get_APIName may also return SQLITE_NOMEM_API_constant
sqlite3_next_stmt_APIName returns NULL
Therefore, applications usually do not need to call sqlite3_initialize_APIName directly
Applications that care about shared cache settings should set it explicitly
The sqlite3_preupdate_depth_APIName interface returns 0
After running an INSERT, UPDATE or DELETE statement on the view, the value returned by sqlite3_changes_APIName is always zero
Passing sqlite3_prepare16_v2_APIParam_3 parameter has a small performance advantage, the parameter is the number of bytes including nul-terminator in the input string
sqlite3_create_collation_APIParam_3 sqlite3_create_collation_v2_APIParam_3 sqlite3_create_collation16_APIParam_3 must be one of SQLITE_UTF8, SQLITE_UTF16LE, SQLITE_UTF16BE, SQLITE_UTF16, SQLITE_UTF16_ALIGNED.
If sqlite3_uri_parameter_APIParam_2 is a query parameter of sqlite3_uri_parameter_APIParam_1 without an explicit value, then sqlite3_uri_parameter_APIName returns a pointer to an empty string
The sqlite3_strglob_APIName interface returns zero
It will return SQLITE_MISUSE_API_constant
The application must ensure that other threads will not call other SQLite interfaces
The value returned by sqlite3_snapshot_cmp_APIName is undefined
sqlite3_finalize_APIName returns the appropriate error code or extended error code
The second callback parameter is one of SQLITE_INSERT_API_constant, SQLITE_DELETE_API_constant or SQLITE_UPDATE_API_constant, depending on the operation that caused the callback to be called
sqlite3_preupdate_depth_APIName interface returns 2
Then call sqlite3_get_auxdata_APIName to return NULL
To execute an SQL statement, it must first be compiled into a bytecode program using one of the following routines
The SQLite core will never use these routines unless inside the assert_APIName, and it is recommended that the application follow the core
As long as the input parameters are correct, these routines will only fail
The flags parameter of sqlite3_open_v2_APIName can take one of the following three values ​​and can be combined with SQLITE_OPEN_NOMUTEX_API_constant, SQLITE_OPEN_FULLMUTEX_API_constant, SQLITE_OPEN_SHAREDCACHE_API_constant, SQLITE_OPEN_PRIVATECACHE_API_constant and/or SQLITE_OPEN_URI
sqlite3_column_database_name_APIName sqlite3_column_database_name16_APIName sqlite3_column_table_name_APIName sqlite3_column_table_name16_APIName sqlite3_column_origin_name_APIName sqlite3_column_origin_name16_APIName returns NULL
sqlite3_vfs_find_APIName returns a NULL pointer
For all new programs, it is recommended to use sqlite3_prepare_v2_APIName, sqlite3_prepare_v3_APIName, sqlite3_prepare16_v2_APIName and sqlite3_prepare16_v3_APIName interfaces
sqlite3_column_decltype_APIName and sqlite3_column_decltype16_APIName will return the string "VARIANT" for the second result column and a NULL pointer for the first result column
The callback function should use the sqlite3_create_collation_APIName, sqlite3_create_collation16_APIName or sqlite3_create_collation_v2_APIName to register the required collation
If the value of the query parameter sqlite3_uri_boolean_APIParam_2 is in any case one of "yes", "true" or "on", or if the value starts with a non-zero, the sqlite3_uri_boolean_APIName routine returns true.
xBestInde_APIParam_0 must be a sqlite3_index_info object, which is the first parameter of the xBestIndex_APIName method
sqlite3_create_function_APIParam_7 and sqlite3_create_function_APIParam_8 must both be non-NULL
It must be an empty string or the string ``localhost''
This interface is only available
You should not call sqlite3_step_APIName on this virtual machine again before calling sqlite3_reset_APIName to reset the virtual machine back to its initial state
The value returned by sqlite3_column_type_APIName is only meaningful
If malloc_APIName fails, sqlite3_bind_value_APIName returns SQLITE_NOMEM_API_constant
May cause crashes or deadlocks
SQLITE_ERROR_API_constant is returned by sqlite3_snapshot_get_APIName
It is not safe to pass the sqlite3_free_table_APIParam_1 table directly to sqlite3_free_APIName
Call sqlite3_db_config_APIName returns SQLITE_OK_API_constant
The sqlite3_str_errcode_APIName method returns SQLITE_NOMEM_API_constant after any out-of-memory errors; if the size of the dynamic string exceeds SQLITE_MAX_LENGTH, then SQLITE_TOOBIG_API_constant; if there are no errors, SQLITE_OK_API_constant
sqlite3_column_name_APIName returns a NULL pointer
The index of the first host parameter is 1, not 0
sqlite3_db_mutex_APIName returns a NULL pointer
If sqlite3_aggregate_context_APIParam_2 is less than or equal to zero, or a memory allocation error occurs, the sqlite3_aggregate_context_APIName routine will return a NULL pointer on the first call.
sqlite3_bind_parameter_index_APIName returns zero
Busy handler is not reentrant
The name of the database or table or column can be returned as a UTF-8 or UTF-16 string
sqlite3_bind_pointer_APIParam_5 is a NULL pointer or a pointer to the destructor of sqlite3_bind_pointer_APIParam_3
The sqlite3_bind_ routine returns SQLITE_OK_API_constant on success, and returns an error code if any errors occur
The routine returns SQLITE_OK_API_constant
According to the calling method of the SQL CONFIGICT mode of the ON CONFLICT mode of the virtual table call method that triggered the SQL table update, the values ​​returned by sqlite3_vtab_on_conflict_APIName are SQLITE_ROLLBACK_API_constant, SQLITE_IGNORE_API_constant, SQLITE_FAIL_API_constant, one of SQLITE_ABORT_API_constant or SQLITE_REPL.
Do not mix calls to sqlite3_column_text_APIName or sqlite3_column_blob_APIName with calls to sqlite3_column_bytes16_APIName, and do not mix calls to sqlite3_column_text16_APIName with calls to sqlite3_column_bytes_APIName
The resulting string will contain embedded NUL, and the result of the expression that operates on the string with embedded NUL is undefined
After making any subsequent method calls on the same object, the application must not use the pointer returned by sqlite3_str_value_APIName
This interface sqlite3_deserialize_APIName is only available
The behavior of this routine is undefined and may be undesirable
Therefore, the sqlite3_column_value_APIName interface is usually only useful in the implementation of application-defined SQL functions or virtual tables, but not in top-level application code
The application tries to use the prepared statement after completion, which is a serious error
The input of sqlite3_complete16_APIName must be a zero-terminated UTF-16 string in local byte order
sqlite3_column_decltype16_APIName returns a NULL pointer
The only way to find out if SQLite automatically rolls back a transaction after an error is to use sqlite3_get_autocommit_APIName
The sqlite3_exec_APIName routine returns SQLITE_ABORT_API_constant without calling the callback again or running any subsequent SQL statements
The calling function should free this memory by calling sqlite3_free_APIName
NNN value must be between 1 and sqlite3_limit_APIName parameter SQLITE_LIMIT_VARIABLE_NUMBER_API_constant
Whenever the caller is ready to process a new data row, it will return SQLITE_ROW_API_constant
Processing was abandoned, sqlite3_db_cacheflush_APIName immediately returned the SQLite error code to the caller
The sqlite3_db_status_APIName routine returns SQLITE_OK_API_constant on success and non-zero error code on failure
The caller is responsible for releasing sqlite3_serialize_APIParam_0 to avoid memory leak
The sqlite3_realloc64_APIName interface is the same as sqlite3_realloc_APIName, except that sqlite3_realloc_APIParam_2 is a 64-bit unsigned integer, not a 32-bit signed integer
SQLITE_OK_API_constant is returned by sqlite3_open_APIName
These routines return 1
sqlite3_str_append_APIParam_2 must contain at least non-zero bytes of sqlite3_str_append_APIParam_3
The default encoding for databases created with sqlite3_open16_APIName is UTF-16 (native byte order)
The sqlite3_get_auxdata_APIName interface returns a NULL pointer
The second parameter must be the index of the aConstraint array, which belongs to the sqlite3_index_info structure passed to xBestIndex
Database connection must not be in auto-commit mode
Moving an existing BLOB handle to a new line is faster than closing the existing handle and opening the new handle.
For security reasons, it is recommended to use the SQLITE_DIRECTONLY_API_constant flag for any application-defined SQL function with side effects
sqlite3_reset_APIName returns SQLITE_OK_API_constant
This routine only checks if the table exists and returns SQLITE_ERROR_API_constant
Only use the built-in memory allocator
Even reading previously freed memory may cause segmentation faults or other serious errors
All subsequent calls to sqlite3_blob_read_APIName, sqlite3_blob_write_APIName or sqlite3_blob_reopen_APIName on the interrupted Blob handle will immediately return SQLITE_ABORT_API_constant
Applications that call sqlite3_create_collation_v2_APIName with non-NULL xDestroy parameters should check the return code and handle the application data pointers themselves, instead of expecting SQLite to handle them for them
The progress handler callback must not do anything that would modify the database connection that called the progress handler
Before another thread can enter, the mutex must exit the same number of times
However, the best practice is to avoid using keywords as identifiers
Collation is no longer available
After releasing an application using sqlite3_free_APIName or sqlite3_realloc_APIName, the application must not read or write to any part of the memory block
All operations that modify the database connection must be delayed until after the sqlite3_step_APIName call that first triggers the commit or rollback hook is completed
The sqlite3_snapshot_open_APIName interface returns SQLITE_OK_API_constant when successful, and returns an appropriate error code if it fails
For all SQLite versions 3.6.23.1 and below, before sqlite3_step_APIName is subsequently called, after sqlite3_step_APIName returns a value other than SQLITE_ROW_API_constant, sqlite3_reset_APIName needs to be called.
The implementation of sqlite3_os_init_APIName or sqlite3_os_end_APIName provided by the application must return SQLITE_OK_API_constant when successful, and some other error codes should be returned when it fails
The value returned by sqlite3_last_insert_rowid_APIName is unpredictable and may not be equal to the old or new last inserted row ID
Busy callbacks should not take any measures to modify the database connection that calls the busy handler
sqlite3_stmt_readonly_APIName interface returns true
SQLITE_LOCKED_API_constant is returned by sqlite3_unlock_notify_APIName, and no unlock notification callback is registered
The application must complete all prepared statements
The first parameter must be a copy of the SQL function context, the copy is the first parameter of the xStep or xFinal callback routine that implements the aggregate function
SQLITE_ERROR_API_constant is returned by sqlite3_blob_read_APIName, and no data is read
The result of the comparison is uncertain
The underlying xFileControl method may also return SQLITE_ERROR_API_constant
If the string ends with NULL, it must be the byte offset in the string where the NULL terminator appears
Static mutex is for internal use of SQLite only
If the database sqlite3_db_readonly_APIParam_2 connected to sqlite3_db_readonly_APIParam_1 is read-only, the sqlite3_db_readonly_APIName interface returns 1, if it is readable/writeable, it returns 0, if sqlite3_db_readonly_APIParam_2 is not the name of the database connected to sqlite3_db_readonly_APIParam_2, it returns -1.
The module name must be registered before using the module to create a new virtual table and before using the module's existing virtual table
There is no memory allocation, and the sqlite3_serialize_APIName function will return a pointer to the continuous memory representation of the database that SQLite is currently using for the database; if there is no continuous memory representation of the database, NULL is returned
The sqlite3_enable_load_extension_APIName interface should be avoided
The return value is uncertain
The authorizer callback must not do anything that would modify the database connection that called the authorizer callback
Then the call will return SQLITE_MISUSE_API_constant.
Otherwise, sqlite3_blob_read_APIName returns an error code or extended error code
Otherwise, sqlite3_blob_open_APIName returns an error code
The SQL functions defined by the application must be added to each database connection separately
sqlite3_column_origin_name_APIParam_0 remains in effect until the prepared statement is destroyed using sqlite3_finalize_APIName, or until the first call to sqlite3_step_APIName for a specific run and the statement is automatically prepared again, or until the same information is requested again with a different encoding
The sqlite3_snapshot_open_APIName interface is only available
To delete an existing SQL function or aggregate, pass a NULL pointer for all three function callbacks
Otherwise, if the snapshot referenced by P1 is earlier than P2, this API returns a negative value; if two handles refer to the same database snapshot, this API returns zero; if P1 is a higher snapshot than P2, the API returns a positive value .
The sqlite3_cancel_auto_extension_APIName routine returns 0
The temporary directory must be set before calling sqlite3_open_APIName or sqlite3_open_v2_APIName
These interfaces are only available
It returns a NULL pointer
The sqlite3_open_APIName and sqlite3_open_v2_APIName sqlite3_open_APIParam_1 parameters must use UTF-8 instead of any code page currently defined
The pointer returned by the previous call to sqlite3_column_blob_APIName, sqlite3_column_text_APIName and/or sqlite3_column_text16_APIName may be invalid
Otherwise, sqlite3_blob_write_APIName returns an error code or extended error code
Do not pass pointers returned from sqlite3_column_blob_APIName, sqlite3_column_text_APIName, etc.
These interfaces are only available on Windows
The strings returned by these two routines should be released by sqlite3_free_APIName
Then SQLlite_ERROR_API_constant is returned by sqlite3_file_control_APIName
You can distinguish valid SQL NULL returns from out-of-memory errors by calling sqlite3_errcode_APIName immediately after obtaining the suspicious return value and before calling any other SQLite interface on the same database connection
No longer provide this feature
sqlite3_last_insert_rowid_APIName returns zero
The sqlite3_initialize_APIName routine returns SQLITE_OK_API_constant on success
If any errors are encountered during the construction of the string, the sqlite3_str_finish_APIName interface may return a NULL pointer
This routine must be called from the same thread running the application-defined function sqlite3_user_data_APIName
The routine should return 1
The collation function must return a negative, zero or positive integer
SQLITE_OK_API_constant is returned by sqlite3_wal_checkpoint_v2_APIName, and both pnLog and pnCkpt are set to -1
The memory containing the error message string is managed internally, and the application must not release the memory
The third parameter of the preupdate callback is one of the constants SQLITE_INSERT_API_constant, SQLITE_DELETE_API_constant or SQLITE_UPDATE_API_constant, which is used to identify the type of update operation that is about to occur
sqlite3_str_append_APIParam_3 must be non-negative
Both sqlite3_create_window_function_APIParam_8 and sqlite3_create_window_function_APIParam_9 can be NULL (in this case, create a regular aggregate function), or both must be non-NULL, in which case, the new function can be used as an aggregate or aggregate window function
Behavior is uncertain
If the value sqlite3_value_frombind_APIParam_1 originates from one of the sqlite3_bind_APIName interfaces, the sqlite3_value_frombind_APIName interface returns non-zero.
However, sqlite3_stmt_readonly_APIName will still return true
The N parameter must be between 0 and 1 less than the number of columns, otherwise the behavior will be undefined
Please note that when sqlite3_strglob_APIName matches, it returns zero, non-zero, the same as sqlite3_stricmp_APIName and sqlite3_strnicmp_APIName
The value of the sqlite3_get_auxdata_APIParam_2 parameter of these interfaces should be non-negative
The sqlite3_uri_boolean_APIName routine assumes that sqlite3_uri_boolean_APIParam_2 is a boolean parameter and returns true or false based on the value of sqlite3_uri_boolean_APIParam_2.
The sqlite3_malloc64_APIName routine is the same as sqlite3_malloc_APIName, except that sqlite3_malloc_APIParam_1 is an unsigned 64-bit integer, not a signed 32-bit integer
sqlite3_bind_text64_APIParam_6 must be one of SQLITE_UTF8_API_constant, SQLITE_UTF16_API_constant, SQLITE_UTF16_API_constantBE or SQLITE_UTF16_API_constantLE to specify the encoding of the text in the third parameter
This API sqlite3_stmt_scanstatus_reset_APIName is only available
The memory pointed to by the character pointer returned for the declaration type and collation sequence remains valid until the next call to any SQLite API function
Applications should never call sqlite3_os_init_APIName or sqlite3_os_end_APIName directly
The sqlite3_close_v2_APIParam_1 parameter of sqlite3_close_APIName and sqlite3_close_v2_APIName must be a NULL pointer or a sqlite3 object pointer obtained from sqlite3_open_APIName, sqlite3_open16_APIName or sqlite3_open_v2_APIName, and has not been closed before
sqlite3_uri_int64_APIName returns zero
The sqlite3_snapshot object returned by a successful call to sqlite3_snapshot_get_APIName must be released using sqlite3_snapshot_free_APIName to avoid memory leaks
