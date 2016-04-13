EXTRA_DIST = combined_server.c daytime_server.c discard_server.c echo_server.c echo_tool.c \
            terminal.c parser.c script1 script2 sctptest.h test_tool.c testengine.c main.c mini-ulp.c mini-ulp.h \
            sctp_wrapper.h sctp_wrapper.c monitor.c chat.c echo_monitor.c localcom.c chargen_server.c Makefile.nmake

AM_CPPFLAGS = -I$(srcdir)/../sctp

noinst_PROGRAMS = combined_server daytime_server discard_server echo_server echo_tool terminal test_tool localcom chargen_server testsctp

combined_server_SOURCES = combined_server.c sctp_wrapper.c
combined_server_LDADD =  ../sctp/libsctplib.la

daytime_server_SOURCES = daytime_server.c sctp_wrapper.c
daytime_server_LDADD =  ../sctp/libsctplib.la

discard_server_SOURCES = discard_server.c sctp_wrapper.c
discard_server_LDADD = ../sctp/libsctplib.la

chargen_server_SOURCES = chargen_server.c sctp_wrapper.c
chargen_server_LDADD = ../sctp/libsctplib.la

echo_server_SOURCES = echo_server.c sctp_wrapper.c
echo_server_LDADD =  ../sctp/libsctplib.la

echo_tool_SOURCES = echo_tool.c sctp_wrapper.c
echo_tool_LDADD =  ../sctp/libsctplib.la

terminal_SOURCES = terminal.c sctp_wrapper.c
terminal_LDADD =  ../sctp/libsctplib.la

test_tool_SOURCES = parser.c test_tool.c testengine.c sctp_wrapper.c
test_tool_LDADD =  ../sctp/libsctplib.la

testsctp_SOURCES = testsctp.c sctp_wrapper.c
testsctp_LDADD =  ../sctp/libsctplib.la

localcom_SOURCES = localcom.c sctp_wrapper.c
localcom_LDADD =  ../sctp/libsctplib.la
