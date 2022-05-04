# contrib/pg_intercept_server_logs/Makefile

MODULES = pg_intercept_server_logs
PGFILEDESC = "pg_intercept_server_logs - intercept server log messages of specified type to console or a separate file"

ifdef USE_PGXS
PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
else
subdir = contrib/pg_intercept_server_logs
top_builddir = ../..
include $(top_builddir)/src/Makefile.global
include $(top_srcdir)/contrib/contrib-global.mk
endif
