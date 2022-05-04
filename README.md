# pg_intercept_server_logs
A PostgreSQL external module providing a way to intercept server logs of specific level via the emit_log_hook implementation. The server logs can either be intercepted to a log file under a specified directory or to standard error console i.e. stderr. Use this module to filter out server logs at a particular level (say report all of the FATAL errors or server PANICs into a different log file for better understand the server behaviour in production and analysis of issues). The intercepted logs can be routed to a different disk (a cheaper HDD or netowork mounted drive). This module provides no SQL-accessible functions.

Custom GUCs or Configuration Parameters
=======================================
- pg_intercept_server_logs.log_level - log level to intercept. Ensure that the server is set to emit logs at this level via log_min_messages parameter setting.
- pg_intercept_server_logs.log_directory - destination directory to store intercepted server log messages into a file of the form log_level.log.

All the above parameters can be set by anyone any time.

Compatibility with PostgreSQL
=============================
Version 15 and above.

Installation
============
Easiest way to use the module is to copy it as contrib/pg_intercept_server_logs in PostgreSQL source code and run "make install" to compile.

Usage
=====
Add pg_intercept_server_logs to PostgreSQL's shared_preload_libraries either via postgresql.conf file or ALTER SYTEM SET command and restart the PostgreSQL database cluster i.e. restart the postmaster. This module can also be loaded into an individual session by LOAD command.

Dependencies
============
No dependencies.

Future Scope
============
Right now, it requires server's log_min_messages to be set to emit logs at pg_intercept_server_logs.log_level. What this means is that, say a production server is emitting logs at LOG level (because DEBUGX level really generates huge amouts of logs and might fill up the disk) and developers want to analyse a particular issue with just intercepting logs at DEBUG2 level, it requires developers to server's LOG level to DEBUGX to be able to use this module. But there's no way to avoid it immediately without changing the PostgreSQL source code, see [1].

All the TODO items are listed in the code comments under "XXX" tag in pg_intercept_server_logs.c.

Related Discussion
==================
[1] https://www.postgresql.org/message-id/CALj2ACVg4mtRc5sBYLi7aXR46ZzgUrn6quoK%2BcPxqZ%3DaCzpFCQ%40mail.gmail.com

LICENSE
=======
pg_intercept_server_logs is free software distributed under the PostgreSQL Licence.

Copyright (c) 1996-2022, PostgreSQL Global Development Group

Developer
=========
This extension is developed and being maintained by Bharath Rupireddy.

- Twitter: https://twitter.com/BRupireddy
- LinkedIn: www.linkedin.com/in/bharath-rupireddy

Bug Report: https://github.com/BRupireddy/pg_intercept_server_logs or <bharath.rupireddyforpostgres@gmail.com>
