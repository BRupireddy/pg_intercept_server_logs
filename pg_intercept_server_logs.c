/* -------------------------------------------------------------------------
 *
 * pg_intercept_server_logs.c
 *
 * Copyright (c) 2010-2022, PostgreSQL Global Development Group
 *
 * IDENTIFICATION
 *		contrib/pg_intercept_server_logs/pg_intercept_server_logs.c
 *
 * -------------------------------------------------------------------------
 */
#include "postgres.h"

#include <limits.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#include "common/file_perm.h"
#include "lib/stringinfo.h"
#include "miscadmin.h"
#include "pgtime.h"
#include "tcop/tcopprot.h"
#include "utils/guc.h"

PG_MODULE_MAGIC;

void		_PG_init(void);
void		_PG_fini(void);

#define LOG_LEVEL_NONE 255
#define FORMATTED_TS_LEN 128

/* GUC Variables */
static int log_level = LOG_LEVEL_NONE;
static char *log_directory = NULL;

/* Original Hook */
static emit_log_hook_type original_emit_log_hook = NULL;

/* Function declarations */
static bool check_intercept_log_directory(char **newval, void **extra,
										  GucSource source);
static inline bool is_log_level_output(int elevel, int log_min_level);
static bool check_intercept_log_level(int *newval, void **extra,
									  GucSource source);
static void intercept_log(ErrorData *edata);
static const char *intercept_log_severity(int elevel);
static void write_console(const char *line, int len);
static void write_file(const char *line, int len, int elevel);
static void append_with_tabs(StringInfo buf, const char *str);
static void add_prefix(StringInfo buf, ErrorData *edata);
static void prepare_and_emit_intercept_log_message(ErrorData *edata);

/*
 * This structure is similar to server_message_level_options in guc.c, except
 * LOG_LEVEL_NONE.
 */
static const struct config_enum_entry log_level_options[] = {
	{"debug5", DEBUG5, false},
	{"debug4", DEBUG4, false},
	{"debug3", DEBUG3, false},
	{"debug2", DEBUG2, false},
	{"debug1", DEBUG1, false},
	{"debug", DEBUG2, true},
	{"info", INFO, false},
	{"notice", NOTICE, false},
	{"warning", WARNING, false},
	{"error", ERROR, false},
	{"log", LOG, false},
	{"fatal", FATAL, false},
	{"panic", PANIC, false},
	{"none", LOG_LEVEL_NONE, false},
	{NULL, 0, false}
};

/*
 * Module Load Callback
 */
void
_PG_init(void)
{
	/* Define custom GUC variables */
	DefineCustomEnumVariable("pg_intercept_server_logs.log_level",
							 gettext_noop("Log level to intercept."),
							 gettext_noop("Ensure that the server is set to emit logs at \"pg_intercept_server_logs.log_level\" via \"log_min_messages\" parameter setting."),
							 &log_level,
							 LOG_LEVEL_NONE,
							 log_level_options,
							 PGC_USERSET,
							 0,
							 check_intercept_log_level,
							 NULL,
							 NULL);

	DefineCustomStringVariable("pg_intercept_server_logs.log_directory",
							   gettext_noop("Destination directory to store intercepted server log messages into a file."),
							   gettext_noop("Log file name will be of the form \"log_level.log\"."),
							   &log_directory,
							   "",
							   PGC_USERSET,
							   0,
							   check_intercept_log_directory,
							   NULL,
							   NULL);

	/*
	 * XXX: An option (list of comma separated strings) to specify more than
	 * one interested log levels, say, log_levels = 'debug1, error, panic';
	 * Use SplitGUCList to parse the list.
	 */

	/*
	 * XXX: An option to specify substring to intercept the logs that matches
	 * it, helps capturing logs at more granular level.
	 */

	/*
	 * XXX: An option clean the old logs in the log_directory before generating
	 * new logs.
	 */

	/*
	 * XXX: Add ability to write the intercepted logs to remote storage or
	 * data lake or any other analytical databases or data stores.
	 */

	/*
	 * XXX: Add ability to write the intercepted logs to console stdout or
	 * stderr.
	 */

	/*
	 * XXX: Change log file name to be of the form log_level_timestamp.log,
	 * where timestamp is the time at which log_level was set to a new value.
	 */

	/*
	 * XXX: Add ability to generate intercepted logs in JSON or CSV format.
	 */

	MarkGUCPrefixReserved("pg_intercept_server_logs");

	/* Install Hooks */
	original_emit_log_hook = emit_log_hook;
	emit_log_hook = intercept_log;
}

/*
 * Module unload callback
 */
void
_PG_fini(void)
{
	/* Uninstall hook */
	emit_log_hook = original_emit_log_hook;
}

/*
 * Checks that the provided destination intercept log directory exists.
 */
static bool
check_intercept_log_directory(char **newval, void **extra, GucSource source)
{
	struct stat st;

	/*
	 * The default value is an empty string, so we have to accept that value.
	 * Our check_configured callback also checks for this and prevents archiving
	 * from proceeding if it is still empty.
	 */
	if (*newval == NULL || *newval[0] == '\0')
		return true;

	/*
	 * Make sure the file paths won't be too long.  The docs indicate that the
	 * file names to be archived can be up to 64 characters long.
	 */
	if (strlen(*newval) + 64 + 2 >= MAXPGPATH)
	{
		GUC_check_errdetail("intercept log directory too long");
		return false;
	}

	/*
	 * Do a basic sanity check that the specified archive directory exists.  It
	 * could be removed at some point in the future, so we still need to be
	 * prepared for it not to exist in the actual archiving logic.
	 */
	if (stat(*newval, &st) != 0 || !S_ISDIR(st.st_mode))
	{
		GUC_check_errdetail("specified intercept log directory does not exist");
		return false;
	}

	return true;
}

/*
 * is_log_level_output -- is elevel logically >= log_min_level?
 *
 * We use this for tests that should consider LOG to sort out-of-order,
 * between ERROR and FATAL.  Generally this is the right thing for testing
 * whether a message should go to the postmaster log, whereas a simple >=
 * test is correct for testing whether the message should go to the client.
 *
 * This function is similar to is_log_level_output function in elog.c.
 */
static inline bool
is_log_level_output(int elevel, int log_min_level)
{
	if (elevel == LOG || elevel == LOG_SERVER_ONLY)
	{
		if (log_min_level == LOG || log_min_level <= ERROR)
			return true;
	}
	else if (elevel == WARNING_CLIENT_ONLY)
	{
		/* never sent to log, regardless of log_min_level */
		return false;
	}
	else if (log_min_level == LOG)
	{
		/* elevel != LOG */
		if (elevel >= FATAL)
			return true;
	}
	/* Neither is LOG */
	else if (elevel >= log_min_level)
		return true;

	return false;
}

/*
 * Checks that the provided log level.
 */
static bool
check_intercept_log_level(int *newval, void **extra, GucSource source)
{
	/* Accept 'none'. */
	if (*newval == LOG_LEVEL_NONE)
		return true;

	if (!is_log_level_output(*newval, log_min_messages))
	{
		GUC_check_errcode(ERRCODE_INVALID_PARAMETER_VALUE);
		GUC_check_errmsg("cannot set \"pg_intercept_server_logs.log_level\" to more than the level at which server emits logs");
		GUC_check_errhint("You can increase server's log level by setting \"log_min_messages\" parameter to at least \"pg_intercept_server_logs.log_level\".");

		return false;
	}

	return true;
}

/*
 * Implements emit_log_hook for this module.
 */
static void
intercept_log(ErrorData *edata)
{
	static bool in_intercept_log_hook = false;

	/* Any other plugins which use emit_log_hook. */
	if (original_emit_log_hook)
		original_emit_log_hook(edata);

	/* Let's not recursively call the intercept_log hook. */
	if (in_intercept_log_hook)
		return;

	/* Nothing to do if no log_level is provided. */
	if (log_level == LOG_LEVEL_NONE ||
		edata->elevel != log_level)
		return;

	in_intercept_log_hook = true;

	prepare_and_emit_intercept_log_message(edata);

	in_intercept_log_hook = false;
}

/*
 * Gets string representing elevel.
 *
 * This function is similar to error_severity function in elog.c except that
 * it gives separate DEBUGX as prefix as opposed to error_severity giving prefix
 * DEBUG for all DEBUGX levels.
 */
static const char *
intercept_log_severity(int elevel)
{
	const char *prefix;

	switch (elevel)
	{
		case DEBUG1:
			prefix = gettext_noop("DEBUG1");
			break;
		case DEBUG2:
			prefix = gettext_noop("DEBUG2");
			break;
		case DEBUG3:
			prefix = gettext_noop("DEBUG3");
			break;
		case DEBUG4:
			prefix = gettext_noop("DEBUG4");
			break;
		case DEBUG5:
			prefix = gettext_noop("DEBUG5");
			break;
		case LOG:
		case LOG_SERVER_ONLY:
			prefix = gettext_noop("LOG");
			break;
		case INFO:
			prefix = gettext_noop("INFO");
			break;
		case NOTICE:
			prefix = gettext_noop("NOTICE");
			break;
		case WARNING:
		case WARNING_CLIENT_ONLY:
			prefix = gettext_noop("WARNING");
			break;
		case ERROR:
			prefix = gettext_noop("ERROR");
			break;
		case FATAL:
			prefix = gettext_noop("FATAL");
			break;
		case PANIC:
			prefix = gettext_noop("PANIC");
			break;
		default:
			prefix = "???";
			break;
	}

	return prefix;
}

/*
 * Computes the log timestamp.
 */
static void
get_formatted_intercept_log_time(char *formatted_log_time)
{
	pg_time_t	stamp_time;
	char		msbuf[13];
	struct timeval saved_timeval;

	gettimeofday(&saved_timeval, NULL);

	stamp_time = (pg_time_t) saved_timeval.tv_sec;

	/*
	 * Note: we expect that guc.c will ensure that log_timezone is set up (at
	 * least with a minimal GMT value).
	 */
	pg_strftime(formatted_log_time, FORMATTED_TS_LEN,
	/* leave room for milliseconds... */
				"%Y-%m-%d %H:%M:%S     %Z",
				pg_localtime(&stamp_time, log_timezone));

	/* 'paste' milliseconds into place... */
	sprintf(msbuf, ".%03d", (int) (saved_timeval.tv_usec / 1000));
	memcpy(formatted_log_time + 19, msbuf, 4);
}

/*
 *	Appends the string to the StringInfo buffer, inserting a tab after any
 *	newline.
 */
static void
append_with_tabs(StringInfo buf, const char *str)
{
	char		ch;

	while ((ch = *str++) != '\0')
	{
		appendStringInfoCharMacro(buf, ch);
		if (ch == '\n')
			appendStringInfoCharMacro(buf, '\t');
	}
}

/*
 * Adds a fixed prefix of the form "formatted_timestamp [PID]".
 */
static void
add_prefix(StringInfo buf, ErrorData *edata)
{
	char formatted_log_time[FORMATTED_TS_LEN];

	MemSet(formatted_log_time, '\0', sizeof(formatted_log_time));

	get_formatted_intercept_log_time(formatted_log_time);

	appendStringInfoString(buf, formatted_log_time);

	appendStringInfo(buf, " [%d] ", MyProcPid);
}

/*
 * Writes the provided line to stderr.
 */
static void
write_console(const char *line, int len)
{
	int			rc;

	/*
	 * We ignore any error from write() here.  We have no useful way to report
	 * it ... certainly whining on stderr isn't likely to be productive.
	 */
	rc = write(fileno(stderr), line, len);
	(void) rc;
}

/*
 * Writes the provided line to intercept log file.
 */
static void
write_file(const char *line, int len, int elevel)
{
	int		fd;
	char	fullpath[MAXPGPATH * 2];

	snprintf(fullpath, sizeof(fullpath), "%s/%s.log", log_directory,
			_(intercept_log_severity(elevel)));

	fd = open(fullpath, O_WRONLY | O_CREAT | O_APPEND,
			  pg_file_create_mode);

	if (fd < 0)
		ereport(ERROR,
				(errcode_for_file_access(),
					errmsg("could not open intercept log file \"%s\": %m",
						   fullpath)));

	if (write(fd, line, len) != len)
	{
		/* if write didn't set errno, assume problem is no disk space */
		if (errno == 0)
			errno = ENOSPC;

		ereport(ERROR,
				(errcode_for_file_access(),
					errmsg("could not write intercept log file \"%s\": %m",
						   fullpath)));
	}
}

/*
 * Prepares the log message and intercepts to file or console.
 */
static void
prepare_and_emit_intercept_log_message(ErrorData *edata)
{
	StringInfoData buf;

	initStringInfo(&buf);

	add_prefix(&buf, edata);
	appendStringInfo(&buf, "%s:  ", _(intercept_log_severity(edata->elevel)));

	if (edata->sqlerrcode != 0)
		appendStringInfo(&buf, "%s:  ", unpack_sql_state(edata->sqlerrcode));

	if (edata->message)
		append_with_tabs(&buf, edata->message);
	else
		append_with_tabs(&buf, _("missing error text"));

	if (edata->cursorpos > 0)
		appendStringInfo(&buf, _(" at character %d"),
						 edata->cursorpos);
	else if (edata->internalpos > 0)
		appendStringInfo(&buf, _(" at character %d"),
						 edata->internalpos);

	appendStringInfoChar(&buf, '\n');

	if (edata->detail_log)
	{
		add_prefix(&buf, edata);
		appendStringInfoString(&buf, _("DETAIL:  "));
		append_with_tabs(&buf, edata->detail_log);
		appendStringInfoChar(&buf, '\n');
	}
	else if (edata->detail)
	{
		add_prefix(&buf, edata);
		appendStringInfoString(&buf, _("DETAIL:  "));
		append_with_tabs(&buf, edata->detail);
		appendStringInfoChar(&buf, '\n');
	}

	if (edata->hint)
	{
		add_prefix(&buf, edata);
		appendStringInfoString(&buf, _("HINT:  "));
		append_with_tabs(&buf, edata->hint);
		appendStringInfoChar(&buf, '\n');
	}

	if (edata->internalquery)
	{
		add_prefix(&buf, edata);
		appendStringInfoString(&buf, _("QUERY:  "));
		append_with_tabs(&buf, edata->internalquery);
		appendStringInfoChar(&buf, '\n');
	}

	if (edata->context && !edata->hide_ctx)
	{
		add_prefix(&buf, edata);
		appendStringInfoString(&buf, _("CONTEXT:  "));
		append_with_tabs(&buf, edata->context);
		appendStringInfoChar(&buf, '\n');
	}

	/* assume no newlines in funcname or filename... */
	if (edata->funcname && edata->filename)
	{
		add_prefix(&buf, edata);
		appendStringInfo(&buf, _("LOCATION:  %s, %s:%d\n"),
						 edata->funcname, edata->filename,
						 edata->lineno);
	}
	else if (edata->filename)
	{
		add_prefix(&buf, edata);
		appendStringInfo(&buf, _("LOCATION:  %s:%d\n"),
						 edata->filename, edata->lineno);
	}

	if (edata->backtrace)
	{
		add_prefix(&buf, edata);
		appendStringInfoString(&buf, _("BACKTRACE:  "));
		append_with_tabs(&buf, edata->backtrace);
		appendStringInfoChar(&buf, '\n');
	}

	/*
	 * Log the query, if exists, irrespective of whether user wants it or
	 * hide_stmt is true unlike regular server logging facility which uses
	 * check_log_of_query().
	 */
	if (debug_query_string != NULL)
	{
		add_prefix(&buf, edata);
		appendStringInfoString(&buf, _("STATEMENT:  "));
		append_with_tabs(&buf, debug_query_string);
		appendStringInfoChar(&buf, '\n');
	}

	/*
	 * Check if the log_directory exists, if yes, just write the logs
	 * to output file, otherwise write to console i.e. stderr.
	 */
	if (strcmp(log_directory, "") == 0)
		write_console(buf.data, buf.len);
	else
		write_file(buf.data, buf.len, edata->elevel);

	pfree(buf.data);
}
