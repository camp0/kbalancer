#! /bin/sh

autoheader \
&& automake --add-missing \
&& autoconf 
