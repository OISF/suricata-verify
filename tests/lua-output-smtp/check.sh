#! /bin/sh

exec grep -q 'FROM <gurpartap@patriots.in> TO {<raj_deol2002in@yahoo.co.in>}' \
     output/smtp_lua.log
