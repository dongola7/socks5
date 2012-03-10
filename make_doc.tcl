#!/bin/sh
# This line continues for Tcl, but is a single line for 'sh' \
exec tclsh "$0" ${1+"$@"}

# make_doc.tcl --
#
#   Converts doctools formatted markup to the specified output format.
#   Usage: ./make_doc.tcl html < socks5.man > socks5.html
#
# Copyright (c) 2012 Blair Kitchen
#
# See the file "license.terms" for information on usage and redistribution of
# this file, and for a DISCLAIMER OF ALL WARRANTIES.
#

package require Tcl 8.5
package require doctools 1.4

if {$argc != 1} {
    puts stderr "Usage: [info script] <format>"
    exit -1
}

set doc_format [lindex $argv 0]

set raw [read stdin]

::doctools::new generator -format $doc_format
puts [generator format $raw]
