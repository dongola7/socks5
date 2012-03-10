#!/bin/sh
# This line continues for Tcl, but is a single line for 'sh' \
exec tclsh "$0" ${1+"$@"}

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
