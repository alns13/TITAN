# Dataset Feature Descriptions

## Core Traffic Features
- **duration** – Length of the connection in seconds
- **src_bytes** – Bytes sent from source to destination
- **dst_bytes** – Bytes sent from destination to source
- **land** – 1 if source and destination IP/port are the same, 0 otherwise
- **wrong_fragment** – Number of wrong fragments in the connection
- **urgent** – Number of urgent packets

## Content Features
- **hot** – Number of "hot" indicators (e.g. access to system dirs, creating programs)
- **num_failed_logins** – Number of failed login attempts
- **logged_in** – 1 if successfully logged in, 0 otherwise
- **num_compromised** – Number of compromised conditions triggered
- **root_shell** – 1 if root shell was obtained, 0 otherwise
- **su_attempted** – 1 if `su root` command was attempted, 0 otherwise
- **num_root** – Number of root accesses
- **num_file_creations** – Number of file creation operations
- **num_shells** – Number of shell prompts
- **num_access_files** – Number of accesses to access control files
- **num_outbound_cmds** – Number of outbound commands in an FTP session
- **is_host_login** – 1 if login belongs to the host list, 0 otherwise
- **is_guest_login** – 1 if login is a guest login, 0 otherwise

## Time-Based Traffic Features (2-second window)
- **count** – Connections to the same destination host in the past 2 seconds
- **srv_count** – Connections to the same service in the past 2 seconds
- **serror_rate** – % of connections with SYN errors (by host)
- **srv_serror_rate** – % of connections with SYN errors (by service)
- **rerror_rate** – % of connections with REJ errors (by host)
- **srv_rerror_rate** – % of connections with REJ errors (by service)
- **same_srv_rate** – % of connections to the same service (by host)
- **diff_srv_rate** – % of connections to different services (by host)
- **srv_diff_host_rate** – % of connections to different destination hosts (by service)

## Host-Based Traffic Features (100-connection window)
- **dst_host_count** – Connections to the same destination host over the last 100 connections
- **dst_host_srv_count** – Connections to the same service on the destination host
- **dst_host_same_srv_rate** – % of connections to the same service on the destination host
- **dst_host_diff_srv_rate** – % of connections to different services on the destination host
- **dst_host_same_src_port_rate** – % of connections from the same source port
- **dst_host_srv_diff_host_rate** – % of connections to different destination hosts for the same service
- **dst_host_serror_rate** – % of connections with SYN errors (destination host level)
- **dst_host_srv_serror_rate** – % of connections with SYN errors (destination host + service level)
- **dst_host_rerror_rate** – % of connections with REJ errors (destination host level)
- **dst_host_srv_rerror_rate** – % of connections with REJ errors (destination host + service level)

## Target
- **target** – Attack label (e.g. normal, neptune, smurf, etc.)

## One-Hot Encoded Features
The following were expanded from categorical columns via one-hot encoding.
Each is a binary flag (1 = true for this connection, 0 = false).

### protocol_type — Network protocol used
`protocol_type_icmp`, `protocol_type_tcp`, `protocol_type_udp`

### service — Network service on the destination
`service_IRC`, `service_X11`, `service_Z39_50`, `service_aol`, `service_auth`,
`service_bgp`, `service_courier`, `service_csnet_ns`, `service_ctf`, `service_daytime`,
`service_discard`, `service_domain`, `service_domain_u`, `service_echo`, `service_eco_i`,
`service_ecr_i`, `service_efs`, `service_exec`, `service_finger`, `service_ftp`,
`service_ftp_data`, `service_gopher`, `service_harvest`, `service_hostnames`, `service_http`,
`service_http_2784`, `service_http_443`, `service_http_8001`, `service_imap4`, `service_iso_tsap`,
`service_klogin`, `service_kshell`, `service_ldap`, `service_link`, `service_login`,
`service_mtp`, `service_name`, `service_netbios_dgm`, `service_netbios_ns`, `service_netbios_ssn`,
`service_netstat`, `service_nnsp`, `service_nntp`, `service_ntp_u`, `service_other`,
`service_pm_dump`, `service_pop_2`, `service_pop_3`, `service_printer`, `service_private`,
`service_red_i`, `service_remote_job`, `service_rje`, `service_shell`, `service_smtp`,
`service_sql_net`, `service_ssh`, `service_sunrpc`, `service_supdup`, `service_systat`,
`service_telnet`, `service_tftp_u`, `service_tim_i`, `service_time`, `service_urh_i`,
`service_urp_i`, `service_uucp`, `service_uucp_path`, `service_vmnet`, `service_whois`

### flag — Status of the connection
- **flag_OTH** – Other/unknown state
- **flag_REJ** – Connection rejected
- **flag_RSTO** – Connection reset by originator
- **flag_RSTOS0** – Originator sent SYN then RST, no reply
- **flag_RSTR** – Connection reset by responder
- **flag_S0** – Connection attempt seen, no reply
- **flag_S1** – Connection established, not terminated
- **flag_S2** – Connection established, originator sent FIN, no reply
- **flag_S3** – Connection established, responder sent FIN, no reply
- **flag_SF** – Normal SYN/FIN completion (clean connection)
- **flag_SH** – Originator sent SYN then FIN (no responder SYN)