#!/bin/sh
# This line continues for Tcl, but is a single line for 'sh' \
exec tclsh "$0" ${1+"$@"}

# test_tor.tcl --
#
#   Implements a simple script that connects to the Internet through a
#   Tor proxy.  Assumes you have a tor proxy running on localhost:9050.
#
# Copyright (c) 2012 Blair Kitchen
#
# See the file "license.terms" for information on usage and
# redistribution of this file, and for a DISCLAIMER OF ALL WARRANTIES.
#

package require Tcl 8.5
package require tls 1.6
package require http 2.7

set root [file join [file dirname [info script]] ..]
source [file join $root socks5.tcl]

proc httpsConnect {host port} {
    set sock [::socks5::connect $host $port]
    ::tls::import $sock
    return $sock
}

::http::register http 80 ::socks5::connect
::http::register https 443 ::httpsConnect

::socks5::configure -proxy localhost -proxyport 9050

set token [::http::geturl "https://check.torproject.org" -channel stdout]
::http::cleanup $token
