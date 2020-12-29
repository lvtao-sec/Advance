The application must ensure that the 1_APIConstant parameter to sqlite3_exec_APIName is a valid and open sqlite3_exec_APIParam_2
resources associated with the sqlite3_open_v2_APIParam_2 should be released by passing sqlite3_open_v2_APIParam_2 to sqlite3_close_APIName
resources associated with the sqlite3_open_APIParam_2 should be released by passing sqlite3_open_APIParam_2 to sqlite3_close_APIName
Any such actions result in undefined behavior
But for maximum safety , mutexes should be enabled
The incremental sqlite3_blob_bytes_APIParam_1 can only read or overwriting call sqlite3_blob_reopen_APIName
The safest policy is to invoke these routines in one of the following ways
Only the row can be changed
The only way to find out whether SQLite automatically rolled back the transaction after an error is to use sqlite3_get_autocommit_APIName
Only built-in memory allocators can be used
The following must be true for sqlite3_snapshot_get_APIName to succeed
Applications that need to process SQL from untrusted sources might also consider lowering resource limits using sqlite3_limit_APIName and limiting database size using the max_page_count PRAGMA in addition to using an authorizer
the sqlite3_snapshot_open_APIParam_1 must not be in autocommit mode
Only an effective call to sqlite3_shutdown_APIName does any deinitialization
the database handle must have no active statements
the result is undefined and probably harmful
There can only be a single busy handler for a particular database connection at any given moment
the application must supply a suitable implementation for sqlite3_os_init_APIName and sqlite3_os_end_APIName
As long as the input parameter is correct , these routines can only fail
The unlock-notify callback is not reentrant
The callback function should normally return SQLITE_OK_API_constant
Callback implementations should return zero to ensure future compatibility
Applications must always be prepared to encounter a NULL pointer in any of the third through the sixth parameters of the authorization callback
The authorizer callback should return SQLITE_OK_API_constant to allow the action, SQLITE_IGNORE_API_constant to disallow the specific action but allow the SQL statement to continue to be compiled, or SQLITE_DENY_API_constant to cause the entire SQL statement to be rejected with an error
Applications must not used the pointer returned by sqlite3_str_value_APIName after any subsequent method call on the same object
Applications that invoke sqlite3_create_collation_v2_APIName with a non-NULL xDestroy argument should check the return code and dispose of the application data pointer themselves rather than expecting SQLite to deal with it for them
sqlite3_uri_parameter_APIName returns NULL and sqlite3_uri_boolean_APIName returns B
The sqlite3_uri_boolean_APIName routine returns true if the value of query parameter sqlite3_uri_boolean_APIParam_2 is one of "yes", "true", or "on" in any case or if the value begins with a non-zero number
the value returned is unpredictable and not meaningful
the value returned is unpredictable and not meaningful
The collating function must return an integer that is negative, zero, or positive
zero is returned by sqlite3_uri_int64_APIName
SQLITE_NOMEM_API_constant is returned by sqlite3_bind_value_APIName if malloc_APIName fails
SQLITE_RANGE_API_constant is returned by sqlite3_bind_text_APIName
SQLITE_ERROR_API_constant is returned by sqlite3_snapshot_open_APIName
A zero is returned by sqlite3_bind_parameter_index_APIName
SQLITE_ERROR_API_constant is returned by sqlite3_snapshot_get_APIName
SQLITE_LOCKED_API_constant is returned by sqlite3_unlock_notify_APIName
SQLITE_BUSY_API_constant is returned by sqlite3_wal_checkpoint_v2_APIName
SQLITE_OK_API_constant is returned by sqlite3_wal_checkpoint_v2_APIName
SQLITE_NOMEM_API_constant is returned by sqlite3_complete16_APIName
SQLITE_OK_API_constant is returned by sqlite3_open_APIName
then SQLITE_ERROR_API_constant is returned by sqlite3_file_control_APIName
The sqlite3_mutex_notheld_APIName interface should also return 1 when given a NULL pointer
These routines should return true
the routine should return 1
The sqlite3_value_dup_APIName interface returns NULL if sqlite3_value_dup_APIParam_1 is NULL or if a memory allocation fails
sqlite3_next_stmt_APIName returns NULL
sqlite3_column_database_name_APIName sqlite3_column_database_name16_APIName sqlite3_column_table_name_APIName sqlite3_column_table_name16_APIName sqlite3_column_origin_name_APIName sqlite3_column_origin_name16_APIName return NULL
sqlite3_realloc_APIName returns NULL
The sqlite3_expanded_sql_APIName interface returns NULL
The sqlite3_mutex_alloc_APIName routine returns NULL
sqlite3_uri_boolean_APIName returns (B!=0
sqlite3_value_frombind_APIName returns zero
sqlite3_column_bytes_APIName returns zero
sqlite3_column_bytes16_APIName returns zero
sqlite3_finalize_APIName returns SQLITE_OK_API_constant
The sqlite3_strglob_APIName interface returns zero
The sqlite3_stmt_readonly_APIName interface returns true
The sqlite3_strlike_APIName interface returns zero
sqlite3_blob_write_APIName returns SQLITE_OK_API_constant
sqlite3_config_APIName returns SQLITE_OK_API_constant
The sqlite3_data_count_APIName routine also returns 0
The sqlite3_data_count_APIName routine returns 0
The sqlite3_cancel_auto_extension_APIName routine returns 0
The sqlite3_cancel_auto_extension_APIName routine returns 1
sqlite3_data_count_APIName returns 0
This routine returns SQLITE_OK_API_constant
The sqlite3_db_readonly_APIName interface returns 1 if the sqlite3_db_readonly_APIParam_1 sqlite3_db_readonly_APIParam_2 of connection sqlite3_db_readonly_APIParam_1 is read-only, 0 if it is read/write, or -1 if sqlite3_db_readonly_APIParam_2 is not the name of a sqlite3_db_readonly_APIParam_1 on connection sqlite3_db_readonly_APIParam_1
sqlite3_last_insert_rowid_APIName returns zero
The sqlite3_stmt_busy_APIName interface returns false
The sqlite3_stmt_isexplain_APIName interface returns 0
The sqlite3_stmt_busy_APIName interface returns true
The sqlite3_stmt_isexplain_APIName interface returns 1
The sqlite3_table_column_metadata_APIName interface returns SQLITE_ERROR_API_constant and if the specified sqlite3_table_column_metadata_APIParam_4 does not exist
sqlite3_complete_APIName and sqlite3_complete16_APIName return 0
These routines return 1
sqlite3_msize_APIName returns zero
The sqlite3_keyword_name_APIName routine returns SQLITE_OK_API_constant if sqlite3_keyword_name_APIParam_1 is within bounds and SQLITE_ERROR_API_constant if not
The sqlite3_keyword_check_APIName returning zero
The sqlite3_preupdate_depth_APIName interface returns 0
The sqlite3_preupdate_depth_APIName interface returns 1
The sqlite3_preupdate_depth_APIName interface returns 2
The sqlite3_uri_boolean_APIName routines returns false
sqlite3_reset_APIName returns SQLITE_OK_API_constant
a NULL pointer is returned by sqlite3_vfs_find_APIName
a NULL pointer is returned by sqlite3_column_name_APIName
a NULL pointer is returned by sqlite3_column_decltype16_APIName
subsequent calls to sqlite3_value_type_APIName might return SQLITE_TEXT_API_constant
The sqlite3_str_errcode_APIName method returns SQLITE_NOMEM_API_constant following any out-of-memory error, or SQLITE_TOOBIG_API_constant if the size of the dynamic sqlite3_str_errcode_APIParam_1 exceeds SQLITE_MAX_LENGTH, or SQLITE_OK_API_constant if there have been no errors
 sqlite3_value_pointer_APIName will return the pointer P. Otherwise, sqlite3_value_pointer_APIName returns a NULL
The sqlite3_win32_set_directory interface returns SQLITE_OK_API_constant to indicate success, SQLITE_ERROR_API_constant if the sqlite3_win32_set_directory_APIParam_1 is unsupported, or SQLITE_NOMEM_API_constant if memory could not be allocated
The sqlite3_bind_ routines return SQLITE_OK_API_constant on success or an error code if anything goes wrong
then the call will return SQLITE_MISUSE_API_constant
 no additional attempts are made to access the database and SQLITE_BUSY_API_constant is returned by sqlite3_busy_handler_APIName to the application
The return value from sqlite3_column_blob_APIName for a zero-length BLOB is a NULL pointer
The underlying sqlite3_file_control_APIParam_2 might also return SQLITE_ERROR_API_constant
the value returned by sqlite3_snapshot_cmp_APIName is undefined
the values returned by sqlite3_status_APIName are undefined
sqlite3_db_filename_APIName will return either a NULL pointer or an empty string
In the legacy interface, the return value will be either SQLITE_BUSY_API_constant, SQLITE_DONE_API_constant, SQLITE_ROW_API_constant, SQLITE_ERROR_API_constant, or SQLITE_MISUSE_API_constant
the lock cannot be obtained and SQLITE_BUSY_API_constant is returned by sqlite3_wal_checkpoint_v2_APIName
sqlite3_vtab_nochange_APIName returns true, during which the column value will not change
The only exception is that if SQLite is unable to allocate memory to call sqlite3_str_new_APIName, a NULL will be written into *ppDb instead of a pointer to the sqlite3 object
The value returned by sqlite3_column_type_APIName is only meaningful
NULL is returned by sqlite3_bind_parameter_name_APIName
On success, sqlite3_blob_read_APIName returns SQLITE_OK_API_constant
On success, SQLITE_OK_API_constant is returned by sqlite3_blob_open_APIName and the new BLOB handle is stored in ppBlob
The sqlite3_aggregate_context_APIName routine returns a NULL pointer when first called if sqlite3_aggregate_context_APIParam_2 is less than or equal to zero or if a memory allocate error occurs
Otherwise, an error code or an extended error code is returned by sqlite3_blob_read_APIName
Otherwise, an error code or an extended error code is returned by sqlite3_blob_write_APIName
Within the xUpdate method of a virtual table, the sqlite3_value_nochange_APIName interface returns true if and only if the column corresponding to sqlite3_value_nochange_APIParam_1 is unchanged by the UPDATE operation that the call sqlite3_vtab_on_conflict_APIName to implement and if and the prior xColumn method call that was invoked to extracted the value for that column returned without setting a result
SQLITE_ERROR_API_constant is returned by sqlite3_blob_read_APIName and no data is read
Calls to sqlite3_blob_read_APIName and sqlite3_blob_write_APIName for an expired BLOB handle fail with a return code of SQLITE_ABORT_API_constant
All subsequent calls to sqlite3_blob_read_APIName, sqlite3_blob_write_APIName or sqlite3_blob_reopen_APIName on an aborted sqlite3_blob_reopen_APIParam_1 handle immediately return SQLITE_ABORT_API_constant
an SQLite error code is returned by sqlite3_blob_reopen_APIName and the call sqlite3_blob_close_APIName aborted
Calling sqlite3_blob_bytes_APIName on an aborted sqlite3_blob_reopen_APIParam_1 handle always returns zero
sqlite3_blob_write_APIName returns SQLITE_READ_API_constantONLY
it will return SQLITE_MISUSE_API_constant
After at least "ms" sqlite3_busy_timeout_APIParam_2 of sleeping, the handler returns 0 which causes sqlite3_step_APIName to return SQLITE_BUSY_API_constant
SQLITE_ERROR_API_constant is returned by sqlite3_blob_write_APIName and no data is written
The value returned by sqlite3_changes_APIName immediately after an INSERT, UPDATE or DELETE statement run on a view is always zero
this routine returns a non-zero error code
Otherwise, sqlite3_db_cacheflush_APIName returns SQLITE_OK_API_constant
sqlite3_db_mutex_APIName returns a NULL pointer
The sqlite3_str_finish_APIName interface will also return a NULL pointer
sqlite3_compileoption_get_APIName returns a NULL pointer
sqlite3_malloc_APIName returns a NULL pointer
the sqlite3_get_auxdata_APIName interface returns a NULL pointer
The sqlite3_mprintf_APIName and sqlite3_vmprintf_APIName routines return a NULL pointer
The sqlite3_db_status_APIName routine returns SQLITE_OK_API_constant on success and a non-zero error code on failure
The sqlite3_status_APIName and sqlite3_status64_APIName routines return SQLITE_OK_API_constant on success and a non-zero error code on failure
sqlite3_finalize_APIName returns the appropriate error code or extended error code
An sqlite3_interrupt_APIParam_1 that is interrupted will return SQLITE_INTERRUPT_API_constant
the sqlite3_exec_APIName routine returns SQLITE_ABORT_API_constant without invoking the callback again and without running any subsequent SQL statements
A call to sqlite3_serialize_APIName might return NULL
The sqlite3_load_extension_APIName interface returns SQLITE_OK_API_constant on success and SQLITE_ERROR_API_constant if something goes wrong
sqlite3_reset_APIName returns an appropriate error code
the sqlite3_str_errcode_APIName method will return an appropriate error code
The sqlite3_release_memory_APIName routine is a no-op returning zero
sqlite3_snapshot_get_APIName may also return SQLITE_NOMEM_API_constant
Otherwise, this API returns a negative value if P1 refers to an older sqlite3_snapshot_cmp_APIParam_2 than P2, zero if the two handles refer to the same database snapshot, and a positive value if P1 is a newer sqlite3_snapshot_cmp_APIParam_2 than P2
no memory allocations are made, and the sqlite3_serialize_APIName function will return a sqlite3_serialize_APIParam_3 to the contiguous memory representation of the sqlite3_serialize_APIParam_1 that SQLite is currently using for that database, or NULL if the no such contiguous memory representation of the sqlite3_serialize_APIParam_1 exists
Failure to reset the prepared sqlite3_step_APIParam_1 using sqlite3_reset_APIName would result in an SQLITE_MISUSE_API_constant return from sqlite3_step_APIName
In the "v2" interface, the more specific error code is returned directly by sqlite3_step_APIName
The sqlite3_snapshot_open_APIName interface returns SQLITE_OK_API_constant on success or an appropriate error code if it fails
But , sqlite3_stmt_readonly_APIName would still return true
In the legacy interface, the sqlite3_step_APIName API always returns a generic error code, SQLITE_ERROR_API_constant, following any error other than SQLITE_BUSY_API_constant and SQLITE_MISUSE_API_constant
The sqlite3_stmt_readonly_APIName interface returns true for BEGIN , but the BEGIN IMMEDIATE and BEGIN EXCLUSIVE commands do touch the database and so sqlite3_stmt_readonly_APIName returns false for those commands
sqlite3_stmt_readonly_APIParam_1 such as BEGIN , COMMIT , ROLLBACK , SAVEPOINT , and RELEASE cause sqlite3_stmt_readonly_APIName to return true
The sqlite3_str_finish_APIName interface may return a NULL pointer if any errors were encountered during sqlite3_str_finish_APIParam_1 of the sqlite3_str_finish_APIParam_0
Note that sqlite3_strglob_APIName returns zero on a match and non-zero, the same as sqlite3_stricmp_APIName and sqlite3_strnicmp_APIName
sqlite3_table_column_metadata_APIName returns an error
sqlite3_unlock_notify_APIName always returns SQLITE_OK_API_constant
In that case, sqlite3_value_nochange_APIName will return true for the same column in the xUpdate method
SQLITE_ERROR_API_constant is returned by sqlite3_wal_checkpoint_v2_APIName to the caller
The sqlite3_update_hook_APIName function returns the P argument from the previous call on the same database connection D, or NULL for the first call on D
These routine sqlite3_column_database_name_APIName sqlite3_column_database_name16_APIName sqlite3_column_table_name_APIName sqlite3_column_table_name16_APIName sqlite3_column_origin_name_APIName sqlite3_column_origin_name16_APIName might also return NULL
SQLITE_OK_API_constant is returned by sqlite3_wal_checkpoint_v2_APIName and both pnLog and pnCkpt set to -1
Calls to sqlite3_close_APIName and sqlite3_close_v2_APIName return SQLITE_OK_API_constant
Calls to sqlite3_db_config_APIName return SQLITE_OK_API_constant
sqlite3_close_APIName will leave the database connection open and return SQLITE_BUSY_API_constant
The sqlite3_compileoption_used_APIName function returns 0 or 1 indicating whether the specified option was defined at compile time
sqlite3_close_v2_APIName returns SQLITE_OK_API_constant and the deallocation of resources is deferred until all prepared statements, BLOB handles, and sqlite3_backup objects are also destroyed
it returns a NULL pointer
The sqlite3_expanded_sql_APIParam_1 causes sqlite3_expanded_sql_APIName to always return NULL
The sqlite3_commit_hook_APIName and sqlite3_rollback_hook_APIName functions return the P argument from the previous call of the same function on the same database connection D, or NULL for the first call for each function on D
The sqlite3_initialize_APIName routine returns SQLITE_OK_API_constant on success
sqlite3_initialize_APIName returns an error code other than SQLITE_OK_API_constant
sqlite3_sql_APIName will return the original string, "SELECT $abc,:xyz" but sqlite3_expanded_sql_APIName will return "SELECT 2345,NULL
Subsequent calls to sqlite3_get_auxdata_APIName return NULL
On those systems, sqlite3_mutex_try_APIName will always return SQLITE_BUSY_API_constant
The sqlite3_mutex_try_APIName interface returns SQLITE_OK_API_constant upon successful entry
sqlite3_mutex_enter_APIName will block and sqlite3_mutex_try_APIName will return SQLITE_BUSY_API_constant
an error is returned by sqlite3_open16_APIName to the caller
 the return value is arbitrary and meaningless
sqlite3_value_type_APIParam_0 is one of SQLITE_INTEGER_API_constant, SQLITE_FLOAT_API_constant, SQLITE_TEXT_API_constant, SQLITE_BLOB_API_constant, or SQLITE_NULL_API_constant
sqlite3_column_type_APIParam_0 is one of SQLITE_INTEGER_API_constant , SQLITE_FLOAT_API_constant , SQLITE_TEXT_API_constant , SQLITE_BLOB_API_constant , or SQLITE_NULL_API_constant
Valid SQL NULL returns can be distinguished from out-of-memory errors by invoking the sqlite3_errcode_APIName immediately after the suspect return value is obtained and before any other sqlite3_value_text16le_APIParam_1 is called on the same sqlite3_errcode_APIParam_1
Valid SQL NULL returns can be distinguished from out-of-memory errors by invoking the sqlite3_errcode_APIName immediately after the suspect return value is obtained and before any other sqlite3_value_text16le_APIParam_1 is called on the same sqlite3_errcode_APIParam_1
Any attempt to create a function with a longer name will result in SQLITE_MISUSE_API_constant being returned
The sqlite3_get_autocommit_APIName interface returns non-zero or zero
the return value is undefined
Strings returned by sqlite3_column_text_APIName and sqlite3_column_text16_APIName, even empty strings, are always zero-terminated
pointers returned by prior calls to sqlite3_column_blob_APIName, sqlite3_column_text_APIName, and/or sqlite3_column_text16_APIName may be invalidated
The pointers returned are valid until a type conversion occurs as described above, or until sqlite3_step_APIName or sqlite3_reset_APIName or sqlite3_finalize_APIName is called
An application-supplied implementation of sqlite3_os_init_APIName or sqlite3_os_end_APIName must return SQLITE_OK_API_constant on success and some other error code upon failure
this routine simply checks for the existence of the sqlite3_table_column_metadata_APIParam_3 and returns SQLITE_OK_API_constant
this routine simply checks for the existence of the table and returns SQLITE_ERROR_API_constant
it will go ahead and return SQLITE_BUSY_API_constant to the application instead of invoking the busy handler
The application should only invoke sqlite3_initialize_APIName and sqlite3_shutdown_APIName
sqlite3_aggregate_context_APIName must be called from the same thread in which the aggregate SQL function is running
These routines must be called from the same thread in which the sqlite3_get_auxdata_APIParam_1 is running
A collating function must always return the same answer given the same inputs
To avoid a resource leak , every open BLOB handle should eventually be released by a call to sqlite3_blob_close_APIName
This routine only works on a BLOB handle which has been created by a prior successful call to sqlite3_blob_open_APIName and which has not been closed by sqlite3_blob_close_APIName
This routine only works on a BLOB handle which has been created by a prior successful call to sqlite3_blob_open_APIName and which has not been closed by sqlite3_blob_close_APIName
This routine only works on a BLOB handle which has been created by a prior successful call to sqlite3_blob_open_APIName and which has not been closed by sqlite3_blob_close_APIName
The collating function must obey the following properties for all strings A , B , and C
The application must call sqlite3_finalize_APIName
The sqlite3_config_APIName interface may only be invoked prior to library initialization using sqlite3_initialize_APIName or after shutdown by sqlite3_shutdown_APIName
Applications that care about shared cache setting should set it explicitly
The use of the sqlite3_enable_load_extension_APIName interface should be avoided
It is recommended that the SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION_API_constant method be used to enable only this interface
The progress handler callback must not do anything that will modify the database connection that invoked the progress handler
This interface sqlite3_deserialize_APIName is only available
The sqlite3_snapshot_free_APIName interface is only available
The sqlite3_snapshot_get_APIName interface is only available
The sqlite3_snapshot_open_APIName interface is only available
This interface sqlite3_snapshot_recover_APIName is only available
This API sqlite3_stmt_scanstatus_reset_APIName is only available
sqlite3_stmt_scanstatus_APIName is only available
This API sqlite3_unlock_notify_APIName is only available
These interfaces are only available
This interface is only available
This interface is only available
This interface is only available
This interface is only available
sqlite3_step_APIName should not be called again on the VM
You must call sqlite3_reset_APIName or sqlite3_finalize_APIName
sqlite3_step_APIName should not be called again on this virtual machine without first calling sqlite3_reset_APIName to reset the virtual machine back to its initial state
you should rollback the transaction before continuing
The use of this interface is only necessary
After a prepared sqlite3_step_APIParam_1 has been prepared using any of sqlite3_prepare_v2_APIName , sqlite3_prepare_v3_APIName , sqlite3_prepare16_v2_APIName , or sqlite3_prepare16_v3_APIName or one of the legacy interfaces sqlite3_prepare_APIName or sqlite3_prepare16_APIName , sqlite3_step_APIName must be called one or more times to evaluate the sqlite3_step_APIParam_1
This routine sqlite3_user_data_APIName must be called from the same thread in which the application-defined function is running
The update hook implementation must not do anything that will modify the database connection that invoked the update hook
Any actions to modify the database connection must be deferred until after the completion of the sqlite3_step_APIName call that triggered the update hook
The callback function should register the desired collation using sqlite3_create_collation_APIName , sqlite3_create_collation16_APIName , or sqlite3_create_collation_v2_APIName
These APIs are only available
The callback implementation must not do anything that will modify the database connection that invoked the callback
Any actions to modify the database connection must be deferred until after the completion of the sqlite3_step_APIName call that triggered the commit or rollback hook in the first place
Applications should finalize all prepared statements , close all BLOB handles , and finish all sqlite3_backup objects associated with the sqlite3_close_APIParam_1 prior to attempting to call sqlite3_close_APIName
The application does not need to worry about freeing the result
Module names must be registered before call sqlite3_declare_vtab_APIName using the module and before using a preexisting virtual table for the module
After being freed , memory should neither be read nor written
Memory to hold the error message string is managed internally and must not be freed by the application
The string returned by sqlite3_expanded_sql_APIName must be free by the application by passing it to sqlite3_free_APIName
A sqlite3_free_table_APIParam_1 table should be deallocated using sqlite3_free_table_APIName
The sqlite3_shutdown_APIName interface must only be called from a single thread
The application should never invoke either sqlite3_os_init_APIName or sqlite3_os_end_APIName directly
the calling function must not try to call sqlite3_free_APIName directly
After the application has finished with the sqlite3_get_table_APIParam_3 from sqlite3_get_table_APIName , it must pass the sqlite3_get_table_APIParam_3 to sqlite3_free_table_APIName
All open database connections must be closed and all other SQLite resources must be deallocated prior to invoking sqlite3_shutdown_APIName
so that an application usually does not need to invoke sqlite3_initialize_APIName directly
The strings returned by these two routines should be released by sqlite3_free_APIName
Hence sqlite3_set_auxdata_APIName should be called near the end of the function implementation and the function implementation should not make any use of P after sqlite3_set_auxdata_APIName has been called
However , and the application must call sqlite3_initialize_APIName directly prior to using any other SQLite interface
Static mutexes are for internal use by SQLite only
Applications that use SQLite mutexes should use only the dynamic mutexes returned by SQLITE_MUTEX_FAST_API_constant or SQLITE_MUTEX_RECURSIVE_API_constant
Some systems do not support the operation implemented by sqlite3_mutex_try_APIName
The sqlite3_mutex_held_APIParam_1 never uses these routines except inside an assert_APIName and applications are advised to follow the lead of the core
the sqlite3_mutex_enter_APIParam_1 must be exited an equal number of times before another thread can enter
External sqlite3_mutex_held_APIParam_1 are only required to provide these routines
The temporary directory must be set prior to calling sqlite3_open_APIName or sqlite3_open_v2_APIName
This must only be used within SQLITE_UPDATE_API_constant and SQLITE_DELETE_API_constant preupdate callbacks
This must only be used within SQLITE_INSERT_API_constant and SQLITE_UPDATE_API_constant preupdate callbacks
the application must supply a sqlite3_mutex_enter_APIParam_1 using the SQLITE_CONFIG_MUTEX_API_constant option of the sqlite3_config_APIName function before calling sqlite3_initialize_APIName or any other public sqlite3_mutex_enter_APIParam_1 that calls sqlite3_initialize_APIName
These routines must be called from the same thread as the sqlite3_value_blob_APIParam_1 that supplied the sqlite3_value parameters
The sqlite3_prepare_APIName interface is legacy and should be avoided
The sqlite3_prepare16_APIParam_1 must not have been closed
application-defined SQL functions must be added to each database connection separately
To execute an sqlite3_prepare_APIParam_4 , it must first be compiled into a sqlite3_prepare_APIParam_3 using one of these routines
However , such calls must not close the database connection nor finalize or call sqlite3_clear_bindings_APIName in which the function is running
There can only be a single busy handler defined for each database connection
The authorizer callback must not do anything that will modify the database connection that invoked the authorizer callback
A busy handler must not close the database connection or prepared statement that invoked the busy handler
The application must ensure that no other SQLite interfaces are invoked by other threads
The busy callback should not take any actions which modify the database connection that invoked the busy handler
you should call sqlite3_column_text_APIName , sqlite3_column_blob_APIName , or sqlite3_column_text16_APIName first to force the result into the desired format , invoke sqlite3_column_bytes_APIName or sqlite3_column_bytes16_APIName to find the size of the result
Any use of a prepared sqlite3_finalize_APIParam_1 after it has been finalized can result in undefined and undesirable behavior such as segfaults and heap corruption
This method is disabled on MacOS X 10.7 and iOS version 5.0 and will always return SQLITE_MISUSE_API_constant
It is recommended that extension loading be disabled using the SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION_API_constant method rather than this interface , so the load_extension_APIName SQL function remains disabled
But it is not safe to call this routine with a database connection that is closed or might close before sqlite3_interrupt_APIName returns
It is a grievous error for the application to try to use a prepared sqlite3_finalize_APIParam_1 after it has been finalized
For all versions of SQLite up to and including 3.6.23.1, a call to sqlite3_reset_APIName was required after sqlite3_step_APIName returned anything other than SQLITE_ROW_API_constant before any subsequent invocation of sqlite3_step_APIName
The caller is responsible for freeing sqlite3_serialize_APIParam_0 to call sqlite3_release_memory_APIName
sqlite3_test_control_APIName is not for use by applications
Without the mutexes , it is not safe to use SQLite concurrently from more than one thread
Only sqlite3_free_table_APIName is able to release the memory properly and safely
For maximum portability , it is recommended that applications always invoke sqlite3_initialize_APIName directly prior to using any other SQLite interface
These routines sqlite3_trace_APIName and sqlite3_profile_APIName are deprecated
The older interfaces are retained for backwards compatibility , but their use is discouraged
The sqlite3_prepare_v2_APIName , sqlite3_prepare_v3_APIName , sqlite3_prepare16_v2_APIName , and sqlite3_prepare16_v3_APIName interfaces are recommended for all new programs
The calling function should call sqlite3_release_memory_APIName by calling sqlite3_free_APIName
Only the following subset of interfaces are subject to out-of-memory errors
Only the following subset of interfaces are subject to out-of-memory errors
The sqlite3_snapshot_get_APIParam_3 returned from a successful call to sqlite3_snapshot_get_APIName must be freed using sqlite3_snapshot_free_APIName to call sqlite3_release_memory_APIName
Calling sqlite3_blob_close_APIName with an argument that is not a NULL pointer or an open sqlite3_blob_close_APIParam_1 handle results in undefined behaviour
a crash or deadlock may be the result
the behavior is undefined
the behavior is undefined
the behavior is undefined
the behavior is undefined
the behavior is undefined
the behavior is undefined
the behavior is undefined
the behavior is undefined
the behavior is undefined
the behavior is undefined
the behavior of SQLite is undefined
then the behavior is undefined
the results are undefined
the results are undefined
the results are undefined
the results are undefined
the results are undefined
the results are undefined
the results are undefined
the results are undefined
the results are undefined
the results are undefined
the result is undefined
 the results are undefined
that collation is no longer usable
That capability is no longer provided
Use of this interface is not recommended
It is not safe to pass a sqlite3_free_table_APIParam_1 table directly to sqlite3_free_APIName
the behavior of sqlite3_msize_APIName is undefined and possibly harmful
pointers calls to sqlite3_keyword_name_APIName result in undefined behavior
Memory corruption , a segmentation fault , or other severe error might result
Attempting to deallocate a static sqlite3_mutex_free_APIParam_1 results in undefined behavior
The parameter name must be given in UTF-8
The sqlite3_log_APIParam_2 string must not be NULL
The new sqlite3_blob_open_APIParam_5 must meet the same criteria as for sqlite3_blob_open_APIName - it must exist and there must be either a sqlite3_blob_reopen_APIParam_1 or text value stored in the nominated sqlite3_blob_open_APIParam_4
The  sqlite3_stmt_scanstatus_APIParam_3  must be one of the sqlite3_stmt_scanstatus_APIParam_3 or the behavior of this interface is undefined
The first parameter must be a copy of the SQL function context that is first parameter to the xStep or xFinal callback routine that call sqlite3_result_null_APIName
To call sqlite3_release_memory_APIName, the application should invoke sqlite3_free_APIName on error message strings returned through the 5_APIConstant parameter of sqlite3_exec_APIName after the error message string is no longer needed
The sqlite3_next_stmt_APIParam_1 pointer sqlite3_next_stmt_APIParam_1 in a call to sqlite3_next_stmt_APIName must refer to an open sqlite3_next_stmt_APIParam_1 and must not be a NULL pointer
The calling application should pass sqlite3_str_finish_APIParam_0 to sqlite3_free_APIName to call sqlite3_release_memory_APIName
xBestInde_APIParam_0 must be the sqlite3_index_info object that is the first parameter to the xBestIndex_APIName method
The M argument should be the bitwise OR-ed combination of zero or more SQLITE_TRACE_API_constant constants
To call sqlite3_release_memory_APIName, the object returned by sqlite3_str_new_APIName must be freed by a subsequent call to sqlite3_str_finish_APIName
The second argument must be an index into the aConstraint array belonging to the sqlite3_index_info structure passed to xBestIndex
The sqlite3_close_v2_APIParam_1 parameter to sqlite3_close_APIName and sqlite3_close_v2_APIName must be either a NULL pointer or an sqlite3_close_APIParam_1 obtained from sqlite3_open_APIName , sqlite3_open16_APIName , or sqlite3_open_v2_APIName , and not previously closed
The sqlite3_create_collation_APIParam_3 sqlite3_create_collation_v2_APIParam_3 sqlite3_create_collation16_APIParam_3 must be one of SQLITE_UTF8, SQLITE_UTF16LE, SQLITE_UTF16BE, SQLITE_UTF16, SQLITE_UTF16_ALIGNED
The input to sqlite3_complete_APIName must be a zero-terminated UTF-8 string
The input to sqlite3_complete16_APIName must be a zero-terminated UTF-16 string in native byte order
The application must not read or write any part of a block of memory after it has been released using sqlite3_free_APIName or sqlite3_realloc_APIName
The value of the sqlite3_get_auxdata_APIParam_2 parameter to these interfaces should be non-negative
The pointer arguments to sqlite3_free_APIName and sqlite3_realloc_APIName must be either NULL or else pointers obtained from a prior invocation of sqlite3_malloc_APIName or sqlite3_realloc_APIName that have not yet been released
The argument to sqlite3_mutex_alloc_APIName must be one of these integer constants
The encoding used for the sqlite3_open_APIParam_1 argument of sqlite3_open_APIName and sqlite3_open_v2_APIName must be UTF-8 , not whatever codepage is currently defined
Filenames containing international sqlite3_open_APIParam_1 must be converted to UTF-8 prior to passing them into sqlite3_open_APIName or sqlite3_open_v2_APIName
it must be either an empty sqlite3_open_APIParam_1 or the sqlite3_open_APIParam_1  localhost
It is recommended that when a database sqlite3_open_v2_APIParam_1 actually does begin with a ":" character you should prefix the sqlite3_open_v2_APIParam_1 with a pathname such as "./" to avoid ambiguity
The N parameter must be between 0 and one less than the number of columns or the behavior will be undefined
The N parameter must be between 0 and one less than the number of columns or the behavior will be undefined
it must be the byte offset into the string where the NULL terminator would appear if the string where NULL terminated
sqlite3_str_append_APIParam_2 must contain at least sqlite3_str_append_APIParam_3 non-zero bytes of content
The NNN value must be between 1 and the sqlite3_limit_APIName parameter SQLITE_LIMIT_VARIABLE_NUMBER_API_constant
The sqlite3_win32_set_directory_APIParam_2 parameter should be NULL to cause the previous value to be freed via sqlite3_free
The sqlite3_result_text64_APIName interface sets the return value of an application-defined function to be a text string in an encoding specified by the fifth parameter, which must be one of SQLITE_UTF8_API_constant, SQLITE_UTF16_API_constant, SQLITE_UTF16_API_constantBE, or SQLITE_UTF16_API_constantLE
sqlite3_str_append_APIParam_3 must be non-negative
sqlite3_create_function_APIParam_7 and sqlite3_create_function_APIParam_8 must both be non-NULL
The sqlite3_bind_text64_APIParam_6 must be one of SQLITE_UTF8_API_constant , SQLITE_UTF16_API_constant , SQLITE_UTF16_API_constantBE , or SQLITE_UTF16_API_constantLE to specify the encoding of the text in the third parameter
An aggregate SQL function requires an implementation of xStep and xFinal and NULL pointer must be passed for xFunc
The sqlite3_win32_set_directory8 and sqlite3_win32_set_directory16 interfaces behave exactly the same as the sqlite3_win32_set_directory interface except the string parameter must be UTF-8 or UTF-16 , respectively
NULL pointers must be passed as sqlite3_create_function_APIParam_7 and sqlite3_create_function_APIParam_8
sqlite3_bind_pointer_APIParam_5 is either a NULL pointer or a pointer to a destructor function for sqlite3_bind_pointer_APIParam_3
Hence, the application should ensure that the correct authorizer callback remains in place during the sqlite3_step_APIName
sqlite3_prepare_v3_APIName differs from sqlite3_prepare_v2_APIName only in having the extra sqlite3_prepare_v3_APIParam_4 , which is a bit array consisting of zero or more of the SQLITE_PREPARE_PERSISTENT, SQLITE_PREPARE_NORMALIZE and SQLITE_PREPARE_NO_VTAB
In a multithreaded environment , an unprotected sqlite3_value object may only be used safely with sqlite3_bind_value_APIName and sqlite3_result_value_APIName
The first host parameter has an index of 1 , not 0
However , the sqlite3_blob_open_APIParam_4 , sqlite3_blob_open_APIParam_3 , or sqlite3_blob_open_APIParam_3 of a BLOB handle can not be changed after the BLOB handle is opened
sqlite3_create_window_function_APIParam_8 and sqlite3_create_window_function_APIParam_9 may either both be NULL , in which case a regular aggregate function is created , or must both be non-NULL , in which case the new function may be used as either an aggregate or aggregate window function
Testing suggests that , most applications will call sqlite3_soft_heap_limit64_APIName without the use of SQLITE_ENABLE_MEMORY_MANAGEMENT
It is recommended that you should prefix the sqlite3_open_v2_APIParam_1 with a pathname such as "./" to avoid ambiguity
To delete an existing SQL function or aggregate , pass NULL pointers for all three function callbacks
The length of the name is limited to 255 bytes in a UTF-8 representation , exclusive of the zero-terminator
 that parameter must be the byte offset where the NUL terminator would occur assuming the string were NUL terminated
For security reasons , the SQLITE_DIRECTONLY_API_constant flag is recommended for any application-defined SQL function that has side-effects
At present , there is only one sqlite3_vtab_config_APIParam_2 that may be configured using sqlite3_vtab_config_APIName
The SQLite query planner is able to perform additional optimizations on deterministic functions , so use of the SQLITE_DETERMINISTIC_API_constant flag is recommended where possible
A call to sqlite3_snapshot_open_APIName will fail
the behavior is undefined and probably undesirable
the result is undefined behavior
the busy handler is not reentrant
Type conversions and pointer invalidations might occur in the following cases
On those systems , shared call sqlite3_enable_shared_cache_APIName per-database connection via sqlite3_open_v2_APIName with SQLITE_OPEN_SHAREDCACHE_API_constant
Developers might also want to use the sqlite3_set_authorizer_APIName interface to further control untrusted SQL
The sqlite3_finalize_APIName routine can be called at any point after any call to sqlite3_step_APIName regardless of
the result of the comparison is undefined
Passing any other pointer into this routine results in undefined and probably undesirable behavior
Even reading call sqlite3_release_memory_APIName might result in a segmentation fault or other severe error
The calling procedure is responsible for deleting the compiled sqlite3_prepare_v2_APIParam_4 using sqlite3_finalize_APIName after it has finished with it
the resulting string will contain embedded NULs and the result of expressions operating on strings with embedded NULs is undefined
The result of expressions involving strings with embedded NULs is undefined
the behavior of this routine is undefined and probably undesirable
sqlite3_blob_open_APIName fails with SQLITE_ERROR_API_constant
Do not mix calls to sqlite3_column_text_APIName or sqlite3_column_blob_APIName with calls to sqlite3_column_bytes16_APIName , and do not mix calls to sqlite3_column_text16_APIName with calls to sqlite3_column_bytes_APIName
sqlite3_blob_open_APIParam_7 is set to NULL
sqlite3_prepare_v2_APIParam_4 is set to NULL
sqlite3_blob_write_APIName may only modify the sqlite3_blob_write_APIParam_2 of the BLOB
Perhaps it was called on a prepared sqlite3_step_APIParam_1 that has already been finalized or on one that had previously returned SQLITE_ERROR_API_constant or SQLITE_DONE_API_constant
Workstation applications using SQLite normally do not need to invoke either of these routines
SQLite will only request a recursive sqlite3_mutex_alloc_APIParam_0 in cases where it really needs one
The sqlite3_uri_int64_APIName routine sqlite3_uri_int64_APIParam_2 the value of sqlite3_uri_int64_APIParam_2 into a 64-bit signed integer and returns that integer, or sqlite3_uri_int64_APIParam_3 if sqlite3_uri_int64_APIParam_2 does not exist
 the sqlite3_prepare_v2_APIName or equivalent call that triggered the authorizer will fail with an error message explaining that access is denied
the more specific error codes are returned directly by sqlite3_step_APIName
The return value from sqlite3_soft_heap_limit64_APIName is the size of the soft heap limit prior to the call, or negative in the case of an error
SQLITE_TOOBIG_API_constant might be returned
The default configuration is recommended for most applications and so this routine is usually not necessary
sqlite3_vtab_collation_APIName may only be called from within a call to the sqlite3_vtab_collation_APIParam_1 of a virtual table
A call to sqlite3_initialize_APIName is an "effective" call
sqlite3_vtab_on_conflict_APIName may only be called from within a call to the xUpdate method of a virtual table implementation for an INSERT or UPDATE operation
These routines may only be called when the most recent call to sqlite3_step_APIName has returned SQLITE_ROW_API_constant and neither sqlite3_reset_APIName nor sqlite3_finalize_APIName have been called subsequently
The SQLITE_IGNORE_API_constant return can be used to deny an untrusted user access to individual columns of a table
This error code is not remembered and will not be recalled by sqlite3_errcode_APIName or sqlite3_errmsg_APIName
the maximum length of the string call sqlite3_str_finish_APIName will be the value set for sqlite3_limit_APIName instead of SQLITE_MAX_LENGTH
It is permitted to register multiple implementations of the same functions with the same name but with either differing numbers of arguments or differing preferred text encodings
the length of sqlite3_bind_text_APIParam_4 and sqlite3_bind_text16_APIParam_4 is the number of bytes up to the first zero terminator
Attempt to return the underlying operating system error code or error number that caused the most recent I/O error or failure to open a file
Returns the size in bytes of the BLOB accessible via the call sqlite3_blob_close_APIName handle in its only argument
The following interfaces are provided
The problem has been fixed with the  v2  interface
The SQLITE_FCNTL_DATA_VERSION_API_constant returns the data version counter from the pager
 VACUUM  is not a keyword
It is provided to support rare applications with unusual needs
SQLITE_BUSY_API_constant means that the database engine was unable to acquire the database locks it needs to do its job
This interface used to be the only way to cause a checkpoint to occur
it is invoked and the writer lock retried until either the busy-handler returns 0 or the lock is successfully obtained
This interface is retained for backwards compatibility and as a sqlite3_wal_checkpoint_APIParam_2 for applications that need to manually start a callback but which do not need the full power of sqlite3_wal_checkpoint_v2_APIName
The sqlite3_mutex_try_APIParam_1 only ever uses sqlite3_mutex_try_APIName as an optimization so this is acceptable behavior
The mutex implementation does not need to make a distinction between SQLITE_MUTEX_RECURSIVE_API_constant and SQLITE_MUTEX_FAST_API_constant
These routines only compile the first sqlite3_prepare16_APIParam_4 in sqlite3_prepare16_APIParam_2 , so sqlite3_prepare16_APIParam_5 is left pointing to what remains uncompiled
A protected sqlite3_value object may always be used where an unprotected call sqlite3_value_nochange_APIName , so either kind of sqlite3_value object can be used with this interface
The sqlite3_bind_pointer_APIName routine causes the I-th parameter in prepared statement S to have an SQL value of NULL , but to also be associated with the pointer P of type T
But the application does not want the user to be able to make arbitrary changes to the database
The return value of sqlite3_column_type_APIName can be used to decide which of the first six interface should be used to extract the column value
SQLite will invoke sqlite3_free_APIName on pzErrMsg after xEntryPoint_APIName returns
SQLite ensures that pzErrMsg is NULL before calling the xEntryPoint_APIName
the sqlite3_open_APIName, sqlite3_open16_APIName, or sqlite3_open_v2_APIName call that provoked the xEntryPoint_APIName will fail
Calling this routine with a null pointer is a harmless no-op
Parameters of the form "?" without a following integer have no name and are referred to as  nameless  or  anonymous parameters
they can not change the size of a sqlite3_blob_bytes_APIParam_1
This means that, provided the API is not misused, it is always safe to call sqlite3_blob_close_APIName on ppBlob after sqlite3_blob_open_APIName it returns
that means the prepared statement returns no data
Executing any other type of sqlite3_changes_APIParam_1 does not modify the value returned by sqlite3_changes_APIName
Use this routine to reset all host parameters to NULL
Calling this routine with an argument less than or equal to zero turns off all busy handlers
A sqlite3_column_count_APIParam_1 will always have a positive sqlite3_column_count_APIName but depending on the WHERE clause constraints and the table content, it might return no rows
This means that if the changes_APIName SQL function is used by the first INSERT, UPDATE or DELETE statement within a trigger, it returns the value as set when the calling statement began executing
The sqlite3_db_status_APIParam_5 of sqlite3_db_status_APIParam_2 is likely to grow in future releases of SQLite
the filename will be an absolute pathname
The sqlite3_extended_result_codes_APIName routine enables or call sqlite3_extended_result_codes_APIName of SQLite
sqlite3_exec_APIName sets the pointer in its 5th parameter to NULL before returning
A call to sqlite3_interrupt_APIName that occurs when there are no running sqlite3_interrupt_APIParam_1 is a no-op and has no effect on sqlite3_interrupt_APIParam_1 that are started after the sqlite3_interrupt_APIName call returns
subsequent calls to sqlite3_last_insert_rowid_APIName return the rowid associated with these internal INSERT operations, which leads to unintuitive results
this routine will return the rowid of the inserted row as long as the trigger is running
The sqlite3_last_insert_rowid_APIName interface usually returns the rowid of the most recent successful INSERT into a rowid table or virtual table on database connection D
it does not fail
sqlite3_limit_APIParam_3 may be added in future releases
The sqlite3_exec_APIName interface is a convenience wrapper around sqlite3_prepare_v2_APIName , sqlite3_step_APIName , and sqlite3_finalize_APIName , that allows an application to run multiple statements of SQL without having to use a lot of C code
The rowid is always available as an undeclared column named ROWID , OID , or _ ROWID _ as long as those names are not also used by call sqlite3_column_origin_name_APIName
it might not have an opportunity to be interrupted and might continue to completion
before statement sqlite3_finalize_APIParam_1 is ever evaluated , after one or more calls to sqlite3_reset_APIName , or after any call to sqlite3_step_APIName regardless of whether or not the statement has completed execution
Any new SQL statements that are started after the sqlite3_interrupt_APIName call and before the running statements reaches zero are interrupted as if they had been running prior to the sqlite3_interrupt_APIName call
So as not to open security holes in older applications that are unprepared to deal with extension loading , and as a means of call sqlite3_enable_load_extension_APIName , the following API is provided to turn the sqlite3_load_extension_APIName mechanism on and off
Setting parameter X to NULL disables the progress handler
To avoid deadlocks and other threading problems , the sqlite3_log_APIName routine will not use dynamically allocated memory
This interface allows applications to access the same PRNG for other purposes
This feature can be used to implement a  Cancel  button on a GUI progress dialog box
This API makes sure a global version of a sqlite3_overload_function_APIParam_2 with a particular name and number of parameters exists
The final value of P is undefined
The sqlite3_snapshot_get_APIName interface attempts to make a new sqlite3_snapshot_get_APIParam_3 that records the current state of schema sqlite3_snapshot_get_APIParam_2 in database connection D. On success, the sqlite3_snapshot_get_APIName interface writes a pointer to the newly created sqlite3_snapshot_get_APIParam_3 into P and returns SQLITE_OK_API_constant
SQLITE_DONE_API_constant means that the sqlite3_step_APIParam_1 has finished executing successfully
The values may be accessed using the column access functions
With the "v2" interface, any of the other result codes or extended result codes might be returned as well
SQLITE_MISUSE_API_constant means that the this routine was called inappropriately
But after version 3.6.23.1,sqlite3_step_APIName began calling sqlite3_reset_APIName automatically in this circumstance rather than returning SQLITE_MISUSE_API_constant
sqlite3_stmt_scanstatus_APIParam_3 are numbered starting from zero
sqlite3_stmt_scanstatus_APIParam_3 might not be available for all sqlite3_stmt_scanstatus_APIParam_3 in all sqlite3_stmt_scanstatus_APIParam_1
you can retry the sqlite3_step_APIParam_1
The sqlite3_str_new_APIParam_1 parameter to sqlite3_str_new_APIName may be NULL
SQLite can be compiled with or without mutexes
Executing any other type of sqlite3_total_changes_APIParam_1 does not affect the value returned by sqlite3_total_changes_APIName
So , it makes sense to disable the mutexes
This interface can be used by an application to make sure that the version of SQLite that it is linking against was compiled with the desired setting of the SQLITE_THREADSAFE macro
then mutexes are enabled by default but can be fully or partially disabled using a call to sqlite3_config_APIName with the verbs SQLITE_CONFIG_SINGLETHREAD_API_constant, SQLITE_CONFIG_MULTITHREAD_API_constant, or SQLITE_CONFIG_SERIALIZED_API_constant
on unix systems, after sqlite3_open_v2_APIName returns SQLITE_CANTOPEN_API_constant, this interface could be called to get back the underlying "errno" that caused the problem, such as ENOSPC, EAUTH, EISDIR, and so forth
SQLite checks if there are any currently executing SELECT statements that belong to the same connection
the values written to sqlite3_wal_checkpoint_v2_APIParam_4 and sqlite3_wal_checkpoint_v2_APIParam_5 are undefined
Note that upon successful completion of an SQLITE_CHECKPOINT_TRUNCATE_API_constant , the sqlite3_wal_checkpoint_v2_APIParam_4 will have been truncated to zero bytes and so both sqlite3_wal_checkpoint_v2_APIParam_4 and sqlite3_wal_checkpoint_v2_APIParam_5 will be set to zero
Calling sqlite3_close_APIName or sqlite3_close_v2_APIName with a NULL pointer argument is a harmless no-op
the following sqlite3_column_decltype_APIParam_1 to be compiled
SQLite is strongly typed , but the typing is dynamic not static
The commit and rollback hook callbacks are not reentrant
These routines do not parse the sqlite3_complete_APIParam_1 thus will not detect syntactically incorrect SQL
The inconsistency is unfortunate but can not be changed without breaking backwards compatibility
The sqlite3_create_module_APIName interface is equivalent to sqlite3_create_module_v2_APIName with a NULL destructor
Passing a NULL pointer to sqlite3_free_APIName is harmless
The sqlite3_extended_errcode_APIName interface is the same except that it always returns the extended result code even when extended result codes are disabled
In that case , the error code and message may or may not be set
The sqlite3_normalized_sql_APIName interface returns a pointer to a UTF-8 string containing the normalized sqlite3_normalized_sql_APIParam_1 of prepared statement P. The semantics used to normalize a sqlite3_normalized_sql_APIParam_1 are unspecified and subject to change
Calling sqlite3_free_APIName with a pointer previously returned by sqlite3_malloc_APIName or sqlite3_realloc_APIName releases that memory so that it might be reused
Memory allocation errors were detected , but they were reported back as SQLITE_CANTOPEN_API_constant or SQLITE_IOERR_API_constant rather than SQLITE_NOMEM_API_constant
The memory returned by sqlite3_malloc_APIName, sqlite3_realloc_APIName, sqlite3_malloc64_APIName, and sqlite3_realloc64_APIName is always aligned to at least an 8 byte boundary, or to a 4 byte boundary
Only an effective call of sqlite3_initialize_APIName does any initialization
The destructor X in sqlite3_set_auxdata_APIName might be called immediately, before the sqlite3_set_auxdata_APIName interface even returns
Subsequent calls to sqlite3_get_auxdata_APIName return sqlite3_set_auxdata_APIParam_3 from the most recent sqlite3_set_auxdata_APIName call
Also , new keywords may be added to future releases of SQLite
as long as the pattern string remains the same , the compiled regular expression can be reused on multiple invocations of the same function
As a sqlite3_get_table_APIParam_2 , sqlite3_get_table_APIParam_6 that occur in the wrapper layer outside of the internal sqlite3_exec_APIName call are not reflected in subsequent calls to sqlite3_errcode_APIName or sqlite3_errmsg_APIName
The sqlite3_libversion_APIName function returns a pointer to the to the sqlite3_version[] string constant
Cautious programmers might include assert_APIName statements in their application to verify that values returned by these interfaces match the macros in the header, and thus ensure that the application is compiled with matching library and header files
Applications can uses these routines to determine whether or not a specific identifier needs to be escaped so as not to confuse the parser
This is an historical accident that can not be fixed without breaking backwards compatibility
The following implementations are available in the sqlite3_mutex_try_APIParam_1
After each call to sqlite3_set_auxdata_APIName where X is not NULL , SQLite will invoke the destructor function X with parameter P exactly once
The SQLite source code contains multiple implementations of these mutex routines
the behavior exhibited might become the default behavior in some future release of SQLite
The other allowed parameters to sqlite3_mutex_alloc_APIName each return a pointer to a static preexisting mutex
The first two constants cause sqlite3_mutex_alloc_APIName to create a new mutex
The sqlite3_mutex_enter_APIName and sqlite3_mutex_try_APIName routines attempt to enter a mutex
code that links against SQLite is permitted to use any of these routines
Note that sqlite3_mutex_alloc_APIName returns a different mutex on every call
sqlite3_mutex_enter_APIParam_1 created using SQLITE_MUTEX_RECURSIVE_API_constant can be entered multiple times by the same thread
the sqlite3_mutex_alloc_APIParam_0 subsystem might return such a sqlite3_mutex_alloc_APIParam_0 in response to SQLITE_MUTEX_FAST_API_constant
The sqlite3_mutex_leave_APIName routine exits a sqlite3_mutex_leave_APIParam_1 that was previously entered by the same thread
The implementation is not required to provide versions of these routines that actually work
sqlite3_open_APIParam_1 handle is usually returned in sqlite3_open_APIParam_2
The sqlite3_errmsg_APIName or sqlite3_errmsg16_APIName routines can be used to obtain an English language description of the error following a failure of any of the sqlite3_open_APIName routines
Additional sqlite3_trace_APIName callbacks might occur as each triggered subprogram is entered
Hence, the calling function can deallocate or modify the sqlite3_result_error_APIParam_1 after they return without sqlite3_result_error_APIParam_2
The sqlite3_result_null_APIName interface sets the return value of the application-defined function to be NULL
The sqlite3_result_error_code_APIName function changes the error code returned by SQLite as a result of an error in a function
The sqlite3_result_error_nomem_APIName interface causes SQLite to throw an error indicating that a memory allocation failed
These methods do not return a result code
The sqlite3_result_error_toobig_APIName interface causes SQLite to throw an error indicating that a string or BLOB is too long to represent
Invoking any of these routines from outside of a preupdate callback or with a database connection pointer that is different from the one supplied to the preupdate callback results in undefined and probably undesirable behavior
Otherwise no conversion occurs
SQLite assumes that the text or BLOB result is in constant space and does not copy the content of the parameter nor call a destructor on the content when it has finished using that result
Please pay particular attention to the fact that the pointer returned from sqlite3_value_blob_APIName, sqlite3_value_text_APIName, or sqlite3_value_text16_APIName can be invalidated by a subsequent call to sqlite3_value_bytes_APIName, sqlite3_value_bytes16_APIName, sqlite3_value_text_APIName, or sqlite3_value_text16_APIName
Whether or not a persistent internal datatype conversion occurs is undefined and may change from one release of SQLite to the next
sqlite3_prepare_APIParam_4 is left pointing to a compiled prepared sqlite3_prepare_APIParam_4 that can be executed using sqlite3_step_APIName
The implementation of the function can gain access to this pointer using sqlite3_user_data_APIName
an application may allow a user to enter arbitrary SQL queries for evaluation by a database
Future versions of SQLite may change the behavior of sqlite3_column_type_APIName following a type conversion
The first process can not proceed and the second process can not proceed
An authorizer is used , to ensure that the SQL statements do not try to access data they are not allowed to see , or that they do not try to execute malicious statements that damage the database
There is no way to distinguish between an incorrect sqlite3_file_control_APIParam_2 and an SQLITE_ERROR_API_constant return from the underlying sqlite3_file_control_APIParam_2
Future releases of SQLite may require this