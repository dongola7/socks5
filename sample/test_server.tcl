#!/bin/sh
# This line continues for Tcl, but is a single line for 'sh' \
exec tclsh "$0" ${1+"$@"}

# socks5.tcl --
#
#   Implements a simple TCP server for use with test_client.tcl
#
# Copyright (c) 2011 Blair Kitchen
#
# See the file "license.terms" for information on usage and
# redistribution of this file, and for a DISCLAIMER OF ALL WARRANTIES.
#

set listenPort "30000"

set root [file join [file dirname [info script]] ..]
source [file join $root socks5.tcl]

set cntrl ""

proc handleConnect {cntrl addr port} {
    puts "CNTRL connection from $addr:$port"
    set host [gets $cntrl]
    set port [gets $cntrl]

    puts "Attempting DATA connection to $host:$port"
    set data [socket $host $port]
    puts "DATA connection established"

    fconfigure $cntrl -blocking 0 -translation binary -encoding binary
    fconfigure $data -blocking 0 -translation binary -encoding binary
    fileevent $cntrl readable [list handleRead $cntrl $data]
    fileevent $data readable [list handleRead $data $cntrl]
}

proc handleRead {src dst} {
    if {[eof $src]} {
        close $src
        close $dst
        puts "Client disconnected"
        return
    }

    puts "Echoing data"
    set data [read $src]
    puts -nonewline $dst $data
    flush $dst
}

set server_sock [socket -server handleConnect $listenPort]
puts "Listening for CNTRL connections on port $listenPort"
vwait forever
