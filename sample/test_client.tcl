#!/bin/sh
# This line continues for Tcl, but is a single line for 'sh' \
exec tclsh "$0" ${1+"$@"}

# test_client.tcl --
#
#   Implements a simple TCP client program utilizing the SOCKS 5 library
#
# Copyright (c) 2011 Blair Kitchen
#
# See the file "license.terms" for information on usage and
# redistribution of this file, and for a DISCLAIMER OF ALL WARRANTIES.
#

set proxyIP "localhost"
set proxyPort "1080"
set serverHost "localhost"
set serverIP "127.0.0.1"
set serverPort "30000"

set root [file join [file dirname [info script]] ..]
source [file join $root socks5.tcl]

set data ""
proc handleConnect {result arg} {
    if {$result != "ok"} {
        puts "SOCKS error accepting incoming connection: $arg"
        return
    }

    set ::data $arg
}

::socks5::configure -proxy $proxyIP -proxyport $proxyPort -username foo -password bar

foreach server [list $serverHost $serverIP] {
    puts "Attempting CNTRL connection to $server:$serverPort using proxy $proxyIP:$proxyPort"
    set cntrl [::socks5::connect $server $serverPort]
    puts "CNTRL connection established"

    puts "Attempting to create SOCKS5 binding for DATA connection"
    set bindInfo [::socks5::bind $server $serverPort handleConnect]
    lassign $bindInfo host port
    puts "SOCKS server listening for DATA connection on $host:$port"

    puts "Sending details via CNTRL connection"
    puts $cntrl $host
    puts $cntrl $port
    flush $cntrl

    puts "Waiting for DATA connection"
    vwait data
    puts "DATA connection established"

    puts $cntrl "Hello World (via CNTRL)"
    flush $cntrl
    puts [gets $data]

    puts $data "Hello World (via DATA)"
    flush $data
    puts [gets $cntrl]

    close $data
    close $cntrl

    puts "---------------"
}
