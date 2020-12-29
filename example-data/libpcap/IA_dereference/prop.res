pcap_create_APIName and pcap_activate_APIName were not available in versions of libpcap prior to 1.0
you should use a non-zero pcap_open_live_APIParam_4
If there is an error, or if pcap_init_APIName has been called, NULL is returned by pcap_lookupdev_APIName and pcap_lookupdev_APIParam_1 is filled in with an appropriate pcap_lookupdev_APIParam_1
A call to pcap_dispatch_APIName or pcap_next_ex_APIName will return 0  but will not block
A call to pcap_dispatch_APIName or pcap_next_ex_APIName will return 0  but will not block
A call to pcap_dispatch_APIName or pcap_next_ex_APIName will return 0  but will not block
A call to pcap_dispatch_APIName or pcap_next_ex_APIName will return 0  but will not block
If pcap_get_required_select_timeout_APIName returns NULL, it is not possible to wait for packets to arrive on the device in an event loop
pcap_setfilter_APIName returns 0 on success and PCAP_ERROR on failure
pcap_setdirection_APIName returns 0 on success and PCAP_ERROR on failure
pcap_sendpacket_APIName returns 0 on success and PCAP_ERROR on failure
pcap_lookupnet_APIName returns 0 on success and PCAP_ERROR on failure
pcap_dump_flush_APIName returns 0 on success and PCAP_ERROR on failure
pcap_findalldevs_APIName returns 0 on success and PCAP_ERROR on failure
pcap_set_datalink_APIName returns 0 on success and PCAP_ERROR on failure
pcap_compile_APIName returns 0 on success and PCAP_ERROR on failure
Some pcap_open_live_APIParam_1 opened with pcap_create_APIName and pcap_activate_APIName, or with pcap_open_live_APIName, do not support those calls , so PCAP_ERROR be returned by pcap_get_selectable_fd_APIName for those pcap_open_live_APIParam_1
Mac OS X prior to Mac OS X 10.7
otherwise, PCAP_ERROR be returned by pcap_get_selectable_fd_APIName
otherwise, 0 be returned by pcap_setnonblock_APIName
pcap_setdirection_APIParam_2 is one of the pcap_setdirection_APIParam_2 , PCAP_D_OUT or PCAP_D_INOUT
pcap_set_buffer_size_APIName returns 0 on success or PCAP_ERROR_ACTIVATED if pcap_set_buffer_size_APIName is called on a pcap_set_buffer_size_APIParam_1 handle that has been activated
pcap_set_protocol_linux_APIName returns 0 on success or PCAP_ERROR_ACTIVATED if pcap_set_protocol_linux_APIName is called on a pcap_set_protocol_linux_APIParam_1 handle that has been activated
pcap_set_timeout_APIName returns 0 on success or PCAP_ERROR_ACTIVATED if pcap_set_timeout_APIName is called on a pcap_set_timeout_APIParam_1 handle that has been activated
pcap_set_immediate_mode_APIName returns 0 on success or PCAP_ERROR_ACTIVATED if pcap_set_immediate_mode_APIName is called on a pcap_set_immediate_mode_APIParam_1 handle that has been activated
pcap_set_promisc_APIName returns 0 on success or PCAP_ERROR_ACTIVATED if pcap_set_promisc_APIName is called on a pcap_set_promisc_APIParam_1 handle that has been activated
pcap_set_snaplen_APIName returns 0 on success or PCAP_ERROR_ACTIVATED if pcap_set_snaplen_APIName is called on a pcap_set_snaplen_APIParam_1 handle that has been activated
pcap_set_rfmon_APIName returns 0 on success or PCAP_ERROR_ACTIVATED if pcap_set_rfmon_APIName is called on a pcap_set_rfmon_APIParam_1 handle that has been activated
This operation is not supported
pcap_offline_filter_APIParam_1 is a pcap_offline_filter_APIParam_3 to a pcap_offline_filter_APIParam_1 , usually the result of a call to pcap_compile_APIName
PCAP_ERROR be returned by pcap_dump_ftell_APIName on error
PCAP_ERROR be returned by pcap_dump_ftell_APIName on error
PCAP_ERROR be returned by pcap_dump_ftell_APIName on error
PCAP_ERROR be returned by pcap_dump_ftell_APIName on error
pcap_setdirection_APIName is not necessarily fully supported on all platforms
some platforms might return an error for all values, and some other platforms might not support PCAP_D_OUT
This will be zero
It is typically used
pcap_datalink_name_to_val_APIName returns the type value on success and PCAP_ERROR if the pcap_datalink_name_to_val_APIParam_1 is not a known type name
using libpcap for compiling BPF code
One can use pcap_set_tstamp_precision_APIParam_2 and PCAP_TSTAMP_PRECISION_NANO to request call pcap_set_tstamp_precision_APIName with precision
NULL be returned by pcap_tstamp_type_val_to_name_APIName on failure
NULL be returned by pcap_tstamp_type_val_to_description_APIName on failure
NULL be returned by pcap_dump_open_APIName on failure
It must be called on a pcap_activate_APIParam_1 created by pcap_create_APIName that has not yet been activated by pcap_activate_APIName
It must be called on a pcap_activate_APIParam_1 created by pcap_create_APIName that has not yet been activated by pcap_activate_APIName
It must be called on a pcap_activate_APIParam_1 created by pcap_create_APIName that has not yet been activated by pcap_activate_APIName
It must be called on a pcap_activate_APIParam_1 created by pcap_create_APIName that has not yet been activated by pcap_activate_APIName
this can happen on 32-bit UNIX-like systems with large file support and on Windows
pcap_set_tstamp_precision_APIName became available in pcap_set_tstamp_precision_APIParam_1 1.5.1
pcap_set_protocol_linux_APIName became available in pcap_set_protocol_linux_APIParam_1 1.9.0
pcap_get_tstamp_precision_APIName became available in pcap_get_tstamp_precision_APIParam_1 1.5.1
pcap_open_offline_with_tstamp_precision_APIName and pcap_fopen_offline_with_tstamp_precision_APIName became available in libpcap release 1.5.1
pcap_set_immediate_mode_APIName became available in pcap_set_immediate_mode_APIParam_1 1.5.0
pcap_tstamp_type_name_to_val_APIName became available in libpcap release 1.2.1
pcap_set_tstamp_type_APIName became available in pcap_set_tstamp_type_APIParam_1 1.2.1
pcap_get_required_select_timeout_APIName became available in pcap_get_required_select_timeout_APIParam_1 1.9.0
it can also be used
These functions became available in libpcap release 1.2.1
These functions became available in libpcap release 1.2.1
These functions became available in libpcap release 1.2.1
These functions became available in libpcap release 1.2.1
Applications should be prepared for this to happen , but must not rely on it happening
pcap_loop_APIName returns 0 if pcap_loop_APIParam_2 is exhausted or if, when reading from a savefile, no more packets are available
pcap_loop_APIName returns PCAP_ERROR if an error occurs or PCAP_ERROR_BREAK if the loop terminated due to a call to pcap_breakloop_APIName before any packets were processed
pcap_dispatch_APIName returns PCAP_ERROR if an error occurs or PCAP_ERROR_BREAK if the loop terminated due to a call to pcap_breakloop_APIName before any packets were processed
pcap_can_set_rfmon_APIName returns 0 if monitor mode could not be set, 1 if monitor mode could be set, and a negative value on error
pcap_is_swapped_APIName returns true  if pcap_is_swapped_APIParam_1 refers to a savefile that uses a different byte order than the current system
pcap_next_ex_APIName returns 1 if the pcap_next_ex_APIParam_3 was read without problems, 0 if pcap_next_ex_APIParam_3 are being read from a live pcap_next_ex_APIParam_2 and the pcap_next_ex_APIParam_3 buffer timeout expired, PCAP_ERROR if an error occurred while reading the packet, and PCAP_ERROR_BREAK if pcap_next_ex_APIParam_3 are being read from a savefile and there are no more pcap_next_ex_APIParam_3 to read from the savefile
Do NOT assume that the packets for a given pcap_next_APIParam_2 or savefile will have any given link-layer header type , such as DLT_EN10MB for Ethernet
Do NOT assume that the packets for a given pcap_next_APIParam_2 or savefile will have any given link-layer header type , such as DLT_EN10MB for Ethernet
Do NOT assume that the packets for a given pcap_next_APIParam_2 or savefile will have any given link-layer header type , such as DLT_EN10MB for Ethernet
Do NOT assume that the packets for a given pcap_next_APIParam_2 or savefile will have any given link-layer header type , such as DLT_EN10MB for Ethernet
Do NOT assume that the packets for a given pcap_next_APIParam_2 or savefile will have any given link-layer header type , such as DLT_EN10MB for Ethernet
Do NOT assume that the packets for a given pcap_next_APIParam_2 or savefile will have any given link-layer header type , such as DLT_EN10MB for Ethernet
Do NOT assume that the packets for a given pcap_next_APIParam_2 or savefile will have any given link-layer header type , such as DLT_EN10MB for Ethernet
Do NOT assume that the packets for a given pcap_next_APIParam_2 or savefile will have any given link-layer header type , such as DLT_EN10MB for Ethernet
Do NOT assume that the packets for a given pcap_next_APIParam_2 or savefile will have any given link-layer header type , such as DLT_EN10MB for Ethernet
If your application uses pcap_breakloop_APIName, make sure that you explicitly check for PCAP_ERROR and PCAP_ERROR_BREAK, rather than just checking for a return value < 0
pcap_dispatch_APIName returns the number of packets processed on success
it will have no effect
It has no effect on savefiles
In that case , those calls must be given a timeout less than or equal to the timeout returned by pcap_get_required_select_timeout_APIName for the device  , the device must be put in non-blocking mode with a call to pcap_setnonblock_APIName , and an attempt must always be made to read packets from the device when the call returns
pcap_setfilter_APIParam_2 is a pointer to a pcap_setfilter_APIParam_2 , usually the result of a call to pcap_setfilter_APIParam_1 -LRB- 3PCAP
The value pcap_loop_APIName returns will be valid for all packets received 
The value pcap_next_ex_APIName returns will be valid for all pcap_next_ex_APIParam_3 received 
this can be 0 or
The pcap_loop_APIParam_1 and the packet data are not to be freed by the pcap_loop_APIParam_3 routine, and are not guaranteed to be valid after the pcap_loop_APIParam_3 routine returns
-LRB- In older versions of libpcap , the behavior was undefined
It should not be used in portable code
pcap_set_tstamp_precision_APIName returns 0 on success if the specified pcap_set_tstamp_precision_APIParam_2 is expected to be supported by the pcap_set_tstamp_precision_APIParam_1 device, PCAP_ERROR_TSTAMP_PRECISION_NOTSUP if the pcap_set_tstamp_precision_APIParam_1 does not support the requested time stamp precision, PCAP_ERROR_ACTIVATED if pcap_set_tstamp_precision_APIName is called on a pcap_set_tstamp_precision_APIParam_1 handle that has been activated
it must make a copy of them
it must make a copy of them
it must make a copy of it
it must make a copy of them
it must make a copy of them
instead , a filter should be specified with pcap_set_protocol_linux_APIParam_1 -LRB- 3PCAP
PCAP_TSTAMP_PRECISION_MICRO should be specified
and PCAP_TSTAMP_PRECISION_NANO should be specified if the packets to be written call pcap_tstamp_type_name_to_val_APIName with time stamps in pcap_tstamp_type_name_to_val_APIParam_1 and pcap_tstamp_type_name_to_val_APIParam_1
different platforms and devices behaved differently , so code that must work with older versions of libpcap should use -1 , not 0 , as the value of pcap_dispatch_APIParam_2
Note that the pcap_file_APIParam_1 is usually built with large pcap_file_APIParam_0 support , so the standard I/O stream of the pcap_file_APIParam_0 might refer to a pcap_file_APIParam_0 larger than 2 gigabytes
applications that use pcap_file_APIName should, if possible, use calls that support large pcap_file_APIParam_0 on the return value of pcap_file_APIName or the value returned by fileno_APIName when passed the return value of pcap_file
pcap_dispatch_APIName processes packets from a live pcap_dispatch_APIParam_3 or savefile until pcap_dispatch_APIParam_2 packets are processed , , the end of the savefile is reached when reading from a savefile , pcap_breakloop_APIName is called , or an error occurs
Note also that some devices might not support sending packets
Note also that poll_APIName and kevent_APIName does not work on character special files, including BPF devices, in Mac OS X 10.4 and 10.5, so, while select_APIName can be used on the descriptor returned by pcap_get_selectable_fd_APIName, poll_APIName and kevent_APIName cannot be used on it those versions of Mac OS X. poll_APIName, but not kevent_APIName, works on that descriptor in Mac OS X releases prior to 10.4
pcap_sendpacket_APIName is like pcap_inject_APIName, but pcap_inject_APIName returns 0 on success, rather than returning the number of bytes written
To work around this , code that uses those calls to wait for packets to arrive must put the pcap_get_selectable_fd_APIParam_1 in non-blocking mode , and must arrange that the call have a timeout less than or equal to the packet buffer timeout , and must try to read packets after that timeout expires , regardless of
pcap_inject_APIName returns the number of bytes written on success and PCAP_ERROR on failure
The pcap_dump_open_append_APIName function became available in pcap_dump_open_APIParam_1 1.7.2
Note that on Windows , that stream should be opened in binary mode
Note that on Windows , that stream should be opened in binary mode
Note that on Windows , that stream should be opened in binary mode
Note that on Windows , that stream should be opened in binary mode
In previous releases , there is no support for appending packets to an call pcap_file_APIName with
If NULL be returned by pcap_dump_open_APIName, pcap_geterr_APIName can be used to call pcap_geterr_APIName with error text
if pcap_dump_APIName is called directly, the pcap_dump_APIParam_1 parameter is of type pcap_dumper_t_APIConstant_1 as returned by pcap_dump_open_APIName
pcap_get_tstamp_precision_APIName returns PCAP_TSTAMP_PRECISION_MICRO or PCAP_TSTAMP_PRECISION_NANO, which indicates that pcap_get_tstamp_precision_APIParam_1 captures contains time stamps in microseconds or nanoseconds respectively
RETURN VALUES A pcap_dump_APIParam_3 to a pcap_dump_open_APIParam_1 to use in subsequent pcap_dump_APIName and pcap_dump_close_APIName calls be returned by pcap_dump_open_APIName on success
pcap_list_datalinks_APIName returns the number of link-layer header types in the array on success, PCAP_ERROR_NOT_ACTIVATED if pcap_list_datalinks_APIName is called on a pcap_list_datalinks_APIParam_1 handle that has been created but not activated, and PCAP_ERROR on other errors
pcap_list_tstamp_types_APIName returns the number of pcap_list_tstamp_types_APIParam_2 in the array on success and PCAP_ERROR on failure
A return value of zero means that the only pcap_list_tstamp_types_APIParam_2 supported is PCAP_TSTAMP_HOST, which is the pcap_list_tstamp_types_APIParam_1
pcap_open_live_APIName returns a pcap_t pcap_open_live_APIParam_5 on success and NULL on failure
pcap_open_offline_APIName, pcap_open_offline_with_tstamp_precision_APIName, pcap_fopen_offline_APIName, and pcap_fopen_offline_with_tstamp_precision_APIName return a pcap_t pcap_open_offline_APIParam_2 on success and NULL on pcap_fopen_offline_APIParam_1
pcap_create_APIName returns a pcap_t pcap_create_APIParam_2 on success and NULL on failure
In previous releases , the call pcap_set_tstamp_type_APIName with pcap_set_tstamp_type_APIParam_2
In previous releases , the call pcap_set_tstamp_type_APIName with pcap_set_tstamp_type_APIParam_2
In previous releases , the call pcap_set_tstamp_type_APIName with pcap_set_tstamp_type_APIParam_2
In previous releases , the call pcap_set_tstamp_type_APIName with pcap_set_tstamp_type_APIParam_2
pcap_open_live_APIParam_5 is assumed to be able to hold at least PCAP_ERRBUF_SIZE chars
pcap_lookupnet_APIParam_4 is assumed to be able to hold at least PCAP_ERRBUF_SIZE chars
pcap_open_offline_APIParam_2 is assumed to be able to hold at least PCAP_ERRBUF_SIZE chars
pcap_create_APIParam_2 is assumed to be able to hold at least PCAP_ERRBUF_SIZE chars
pcap_findalldevs_APIParam_2 is assumed to be able to hold at least PCAP_ERRBUF_SIZE chars
pcap_lookupdev_APIParam_1 is assumed to be able to hold at least PCAP_ERRBUF_SIZE chars
Even worse , some drivers on some platforms might change the link-layer type field to whatever value , even on platforms that do nominally support sending completely raw and unchanged packets
If NULL be returned by pcap_open_live_APIName, pcap_open_live_APIParam_5 is filled in with an appropriate pcap_open_live_APIParam_5
If NULL be returned by pcap_open_offline_APIName, pcap_open_offline_APIParam_2 is filled in with an appropriate pcap_open_offline_APIParam_2
If NULL be returned by pcap_create_APIName, pcap_create_APIParam_2 is filled in with an appropriate pcap_create_APIParam_2
A pcap_stats_APIParam_2 has the following members
NULL be returned by pcap_datalink_val_to_name_APIName if the type value does not correspond to a known DLT_ value
NULL be returned by pcap_datalink_val_to_description_APIName if the type value does not correspond to a known DLT_ value
pcap_stats_APIParam_2 might , or might not , be implemented
on pcap_open_live_APIParam_4 with 2.2 or later kernels , a pcap_open_live_APIParam_1 argument of  any  or NULL can be used to capture packets from all interfaces
on Linux systems with 2.2 or later kernels , a pcap_create_APIParam_1 argument of  any  or NULL can be used to capture packets from all interfaces
If a positive number be returned by pcap_breakloop_APIName, the flag is not cleared, so a subsequent call will return PCAP_ERROR_BREAK and clear the flag
number of pcap_stats_APIParam_2 dropped because
pcap_stats_APIParam_2 is not available on all pcap_stats_APIParam_2
it is zero on pcap_stats_APIParam_2 where it is not available
It also might , or might not , pcap_stats_APIParam_2 dropped because
pcap_stats_APIName is supported only on live pcap_stats_APIParam_2 , not on savefiles
pcap_breakloop_APIName should be used to terminate packet processing
you might not have permission to send packets on it
Note that , , or it might not support sending packets
pcap_stats_APIName returns 0 on success and returns PCAP_ERROR if there is an error or if pcap_stats_APIParam_1 does not support pcap_stats_APIParam_2
It must not be called on a pcap_activate_APIParam_1 created by pcap_create_APIName that has not yet been call pcap_activate_APIName with pcap_is_swapped_APIParam_1 -LRB- 3PCAP
It must not be called on a pcap_activate_APIParam_1 created by pcap_create_APIName that has not yet been call pcap_activate_APIName with pcap_is_swapped_APIParam_1 -LRB- 3PCAP
It must not be called on a pcap_activate_APIParam_1 created by pcap_create_APIName that has not yet been call pcap_activate_APIName with pcap_is_swapped_APIParam_1 -LRB- 3PCAP
It must not be called on a pcap_activate_APIParam_1 created by pcap_create_APIName that has not yet been call pcap_activate_APIName with pcap_is_swapped_APIParam_1 -LRB- 3PCAP
It must not be called on a pcap_activate_APIParam_1 created by pcap_create_APIName that has not yet been call pcap_activate_APIName with pcap_is_swapped_APIParam_1 -LRB- 3PCAP
It must not be called on a pcap_activate_APIParam_1 created by pcap_create_APIName that has not yet been call pcap_activate_APIName with pcap_is_swapped_APIParam_1 -LRB- 3PCAP
It must not be called on a pcap_activate_APIParam_1 created by pcap_create_APIName that has not yet been call pcap_activate_APIName with pcap_is_swapped_APIParam_1 -LRB- 3PCAP
It must not be called on a pcap_activate_APIParam_1 created by pcap_create_APIName that has not yet been call pcap_activate_APIName with pcap_is_swapped_APIParam_1 -LRB- 3PCAP
It must not be called on a pcap_activate_APIParam_1 created by pcap_create_APIName that has not yet been call pcap_activate_APIName with pcap_is_swapped_APIParam_1 -LRB- 3PCAP
It must not be called on a pcap_activate_APIParam_1 created by pcap_create_APIName that has not yet been call pcap_activate_APIName with pcap_is_swapped_APIParam_1 -LRB- 3PCAP
It must not be called on a pcap_activate_APIParam_1 created by pcap_create_APIName that has not yet been call pcap_activate_APIName with pcap_is_swapped_APIParam_1 -LRB- 3PCAP
It must not be called on a pcap_activate_APIParam_1 created by pcap_create_APIName that has not yet been call pcap_activate_APIName with pcap_is_swapped_APIParam_1 -LRB- 3PCAP
It must not be called on a pcap_activate_APIParam_1 created by pcap_create_APIName that has not yet been call pcap_activate_APIName with pcap_is_swapped_APIParam_1 -LRB- 3PCAP
It must not be called on a pcap_activate_APIParam_1 created by pcap_create_APIName that has not yet been call pcap_activate_APIName with pcap_is_swapped_APIParam_1 -LRB- 3PCAP
It must not be called on a pcap_activate_APIParam_1 created by pcap_create_APIName that has not yet been call pcap_activate_APIName with pcap_is_swapped_APIParam_1 -LRB- 3PCAP
It must not be called on a pcap_activate_APIParam_1 created by pcap_create_APIName that has not yet been call pcap_activate_APIName with pcap_is_swapped_APIParam_1 -LRB- 3PCAP
you must specify , when catching those signals , that system calls
Note that should NOT be restarted by that signal
Both pcap_stats_APIParam_2 and pcap_stats_APIParam_2 might , or might not , pcap_stats_APIParam_2 not yet read from the pcap_stats_APIParam_2 and thus not yet seen by the application
to detect this case the caller should store a pcap_open_live_APIParam_2 in pcap_open_live_APIParam_5 before calling pcap_open_live_APIName and display the warning to the user
You will need to use whatever mechanism the OS provides for breaking a thread out of blocking calls in order to unblock the thread , such as thread cancellation or thread signalling in systems that support POSIX threads , or SetEvent_APIName on the result of pcap_getevent_APIName on a pcap_breakloop_APIParam_1 on which the thread is blocked on Windows
pcap_datalink_APIName returns the link-layer header type on success and PCAP_ERROR_NOT_ACTIVATED if pcap_datalink_APIName is called on a pcap_datalink_APIParam_1 handle that has been created but not activated
We recommend always setting the pcap_set_timeout_APIParam_2 to a non-zero value 
Another error occurred
Another error occurred
Another error occurred
Another error occurred
The pcap_activate_APIParam_1 specified does not exist
The pcap_activate_APIParam_1 specified does not exist
The pcap_activate_APIParam_1 specified does not exist
The pcap_activate_APIParam_1 specified does not exist
For a live capture, it always returns false (0
a program should check for 0, 1, and negative, return codes, and treat all negative return codes as errors
they will be scaled up or down as necessary before being supplied
The behavior , , is undefined , as is the behavior if the pcap_set_timeout_APIParam_2 is set to zero or to a negative value
pcap_next_ex_APIName reads the next pcap_next_ex_APIParam_3 and returns a success/failure indication
pcap_is_swapped_APIName returns true  or false  on success and PCAP_ERROR_NOT_ACTIVATED if pcap_is_swapped_APIName is called on a pcap_is_swapped_APIParam_1 handle that has been created but not activated
pcap_strerror_APIName is provided in case strerror_APIName is not available
Unfortunately , there is no way to determine whether an error occurred or not
The returned handle must be activated with pcap_activate_APIName before packets can be captured with it
pcap_snapshot_APIName returns the snapshot length on success and PCAP_ERROR_NOT_ACTIVATED if pcap_snapshot_APIName is called on a pcap_snapshot_APIParam_1 handle that has been created but not activated
the pointer pcap_geterr_APIName returns will no longer point to a valid error message string after the pcap_geterr_APIParam_1 passed to it is closed
pcap_geterr_APIName returns the error text pertaining to the last pcap library error
on FreeBSD, NetBSD, OpenBSD, DragonFly BSD, macOS, and Solaris 11, immediate pcap_set_immediate_mode_APIParam_2 must be turned on with a BIOCIMMEDIATE ioctl_APIName, as documented in bpf_APIName, on the descriptor returned by pcap_fileno_APIName, after pcap_activate_APIName is called
you must use or copy the pcap_geterr_APIParam_0 before call pcap_close_APIName with pcap_geterr_APIParam_1
pcap_next_APIName returns a pointer to the packet data on success, and returns NULL if an error occurred, or if no packets were read from a live pcap_next_APIParam_2 , or if no more packets are available in a savefile
on Solaris 10 and earlier versions of Solaris , immediate pcap_set_immediate_mode_APIParam_2 must be turned on by
On Linux , with previous releases of libpcap , pcap_set_immediate_mode_APIParam_1 are always in immediate pcap_set_immediate_mode_APIParam_2
on Digital UNIX/Tru64 UNIX, immediate pcap_set_immediate_mode_APIParam_2 must be turned on by doing a BIOCMBIC ioctl, as documented in packetfilter_APIName, to clear the ENBATCH flag on the descriptor returned by pcap_fileno_APIName, after pcap_activate_APIName is called
The pcap_next_ex_APIParam_3 is not to be freed by the caller , and is not guaranteed to be valid after the next call to pcap_next_ex_APIName , pcap_next_APIName , pcap_loop_APIName , or pcap_dispatch_APIName
on Windows , immediate pcap_set_immediate_mode_APIParam_2 must be turned on by calling pcap_setmintocopy_APIName with a size of 0
pcap_tstamp_type_name_to_val_APIName returns time stamp type value on success and PCAP_ERROR on failure
pcap_getnonblock_APIParam_2 is assumed to be able to hold at least PCAP_ERRBUF_SIZE chars
it always returns 0 on savefiles
The pcap_next_ex_APIParam_2 and the pcap_next_ex_APIParam_3 are not to be freed by the caller , and are not guaranteed to be valid after the next call to pcap_next_ex_APIName , pcap_next_APIName , pcap_loop_APIName , or pcap_dispatch_APIName
If there is an error, PCAP_ERROR be returned by pcap_getnonblock_APIName and pcap_getnonblock_APIParam_2 is filled in with an appropriate pcap_getnonblock_APIParam_2
If there is an error, PCAP_ERROR be returned by pcap_setnonblock_APIName and pcap_setnonblock_APIParam_3 is filled in with an appropriate pcap_setnonblock_APIParam_3
however , in 1.5.0 and , it should be used
The timeout that should be used in those calls must be no larger than the smallest of all timeouts returned by pcap_get_required_select_timeout_APIName for devices from which packets will be captured
otherwise NULL be returned by pcap_get_required_select_timeout_APIName
pcap_get_required_select_timeout_APIName returns, on UNIX, a pointer to a pcap_get_required_select_timeout_APIParam_0 timeval containing a value that must be used as the minimum timeout in select_APIName, poll_APIName, epoll_wait_APIName, and kevent_APIName calls if pcap_get_selectable_fd_APIName returns PCAP_ERROR
Each element of the list is of pcap_findalldevs_APIParam_1 , and has the following members
In previous releases, select_APIName, poll_APIName, epoll_wait_APIName, and kevent_APIName cannot be used on any pcap_get_required_select_timeout_APIParam_1 for which pcap_get_selectable_fd_APIName returns -1
The device  must be put in non-blocking mode with pcap_setnonblock_APIName , and an attempt must always be made to read packets from the device when the select_APIName , poll_APIName , epoll_wait_APIName , or kevent_APIName call returns
NULL for the last element of the list name
the pcap_findalldevs_APIParam_2 pointed to by pcap_findalldevs_APIParam_1 is set to point to the first element of the list , or to NULL if no pcap_findalldevs_APIParam_1 were found
Each element of the list of addresses is of pcap_freealldevs_APIParam_1 , and has the following members
NULL for the last element of the list addr
The list of pcap_findalldevs_APIParam_1 must be freed with pcap_freealldevs_APIName , which call pcap_freealldevs_APIName with list pointed to by alldevs
The PCAP_IF_UP and pcap_freealldevs_APIParam_1 became available in pcap_freealldevs_APIParam_1 1.6.1
The PCAP_IF_WIRELESS , PCAP_IF_CONNECTION_STATUS , PCAP_IF_CONNECTION_STATUS_UNKNOWN , PCAP_IF_CONNECTION_STATUS_CONNECTED , PCAP_IF_CONNECTION_STATUS_DISCONNECTED , and pcap_freealldevs_APIParam_1 became available in pcap_freealldevs_APIParam_1 1.9.0
The PCAP_NETMASK_UNKNOWN constant became available in pcap_compile_APIParam_1 1.1.0
as indicated, finding no pcap_findalldevs_APIParam_1 is considered success, rather than failure, so 0 will be returned in that case
A non-zero return value indicates what warning or error condition occurred
may be null dstaddr
pcap_activate_APIName returns 0 on success without warnings, a non-zero positive value on success with warnings, and a negative value on error
Promiscuous mode was requested , but the pcap_activate_APIParam_1 does not support promiscuous mode
may be null a pcap_freealldevs_APIParam_1
The pcap_set_tstamp_type_APIParam_2 specified in a previous pcap_set_tstamp_type_APIName call is not supported by the pcap_activate_APIParam_1 , PCAP_WARNING
Another warning condition occurred
call pcap_can_set_rfmon_APIName with Monitor mode but the pcap_activate_APIParam_1 does not support monitor mode
for IPv6 addresses , it can be interpreted
pcap_lookupdev_APIName is obsoleted by pcap_findalldevs_APIName
the pcap_activate_APIParam_1 is not closed and freed
the pcap_activate_APIParam_1 should be closed using pcap_activate_APIParam_1
In WinPcap, pcap_lookupdev_APIName may return a UTF-16 string rather than an ASCII or UTF-8 string
If there is an error, NULL be returned by pcap_lookupdev_APIName and pcap_lookupdev_APIParam_1 is filled in with an appropriate pcap_lookupdev_APIParam_1
a program should check for positive, negative, and zero return codes, and treat all positive return codes as warnings and all negative return codes as errors
in libpcap 1.8.0 and later , pcap_compile_APIName can be used in multiple threads within a single pcap_compile_APIParam_2
do not assume that the addresses are all IPv4 addresses , or even all IPv4 or IPv6 addresses
Note that the addresses in the list of addresses might be IPv4 addresses , IPv6 addresses , or some other type of addresses , so you must check the sa_family member of the struct sockaddr before interpreting the contents of the address
a value of PCAP_NETMASK_UNKNOWN can be supplied
pcap_set_tstamp_type_APIName returns 0 on success if the specified pcap_set_tstamp_type_APIParam_2 is expected to be supported by the pcap_set_tstamp_type_APIParam_1 device, PCAP_WARNING_TSTAMP_TYPE_NOTSUP if the specified pcap_set_tstamp_type_APIParam_2 is not supported by the pcap_set_tstamp_type_APIParam_1 device, PCAP_ERROR_ACTIVATED if pcap_set_tstamp_type_APIName is called on a pcap_set_tstamp_type_APIParam_1 handle that has been activated, and PCAP_ERROR_CANTSET_TSTAMP_TYPE if the pcap_set_tstamp_type_APIParam_1 device does not support setting the pcap_set_tstamp_type_APIParam_2 (only older versions of libpcap will return that
However , in earlier versions of libpcap , it is not safe to use pcap_compile_APIName in multiple threads in a single pcap_compile_APIParam_2 without some pcap_compile_APIParam_2 of mutual exclusion allowing only one thread to call it at any given pcap_compile_APIParam_4
If pcap_fileno_APIParam_1 refers to a pcap_fopen_offline_APIParam_1 that was opened using functions such as pcap_open_offline_APIName or pcap_fopen_offline_APIName, a dead pcap_fileno_APIParam_1 opened using pcap_open_dead_APIName, or a pcap_fileno_APIParam_1 that was created with pcap_create_APIName but that has not yet been activated with pcap_activate_APIName, pcap_fileno_APIName returns PCAP_ERROR
