# socks5.tcl --
#
#   Tcl implementation of a SOCKS 5 client
#
# Copyright (c) 2011 Blair Kitchen
#
# See the file "license.terms" for information on usage and
# redistribution of this file, and for a DISCLAIMER OF ALL WARRANTIES.
#

package require Tcl 8.5
package require cmdline 1.3

package provide socks5 1.0

namespace eval ::socks5 { 
    namespace export configure bind connect

    array set Config {
        proxy {} 
        proxyport 1080 
        bindtimeout 2000 
        username {} 
        password {}
    }

    array set ResponseCodes {
        0 "succeeded"
        1 "general SOCKS server failure"
        2 "connection not allowed by ruleset"
        3 "network unreachable"
        4 "host unreachable"
        5 "connection refused"
        6 "TTL expired"
        7 "command not supported"
        8 "address type not supported"
    }

    array set MethodCodes {
        0 "no authentication required"
        1 "gssapi"
        2 "username/password"
        255 "no acceptable methods"
    }
}

# ::socks5::configure
#
#   Configures the SOCKS 5 client library
#
# Arguments:
#   args    List of parameters to configure (see ::socks5::Config for list)
#
# Results:
#   None
#
proc ::socks5::configure {args} {
    variable Config

    set options [list proxy.arg \
        proxyport.arg \
        bindtimeout.arg \
        username.arg \
        password.arg]

    while {[::cmdline::getopt args $options option value] == 1} {
        switch -- $option {
            proxyport {
                if {($value <= 0) || ($value >= 65565)} {
                    return -code error "proxyport requires a value between 1 and 65565"
                }
            }
            bindtimeout {
                if {($value < 0)} {
                    return -code error "bindtimeout requires a value greater than 1"
                }
            }
        }

        set Config($option) $value
    }

    if {[llength $args] > 0} {
        return -code error "unknown option '[lindex $args 0]'"
    }
}

# ::socks5::bind
#
#   Requests the SOCKS 5 server open a port for listening and await a
#   connection from the specified host and port.
#
# Arguments:
#   options List of options to pass to the socket call
#           ?-myaddr addr? ?-myport port?
#   host    The hostname or IP from which a connection will be established
#   port    The port number from which a connection will be established
#   command Command that will be executed when the connection is established
#
# Results:
#   List consisting of IP and port on the proxy server opened and listening
#   for an incoming connection
#
#   command is executed when the connection is established and two arguments
#   appended.  The first is the success indication and is one of: ok, timeout,
#   or error.  The second is an argument related to the success indicator.  For
#   ok, it is the channel handle on which communication may take place.  For
#   error and timeout, it is an error message.
#
proc ::socks5::bind {args} {
    variable Config

    set errorCode [catch {ProxyConnect args} sock]
    if {$errorCode == -1} {
        return -code error $sock
    } elseif {$errorCode != 0} {
        return -code $errorCode -errorinfo $::errorInfo $sock
    }

    if {[llength $args] != 3} {
        return -code "wrong # args: should be \"bind ?-myaddr addr? ?-myport myport? host port command"
    }

    lassign $args host port command

    set cmd [binary format ccc 5 2 0]
    append cmd [FormatAddress $host $port]

    puts -nonewline $sock $cmd
    flush $sock

    set errorCode [catch {ReadResponse $sock} result]
    if {$errorCode != 0} {
        chan close $sock
        if {$errorCode == -1} {
            return -code error $result
        } else {
            return -code $errorCode -errorinfo $::errorInfo $result
        }
    }

    set timeout_id [after $Config(bindtimeout) \
        [list ::socks5::BindCallback timeout {} $sock $command]]
    chan event $sock readable \
        [list ::socks5::BindCallback readable $timeout_id $sock $command]

    return $result
}

# ::socks5::connect
#
#   Requests the SOCKS 5 server establish an outgoing connection to
#   the named host on the named port.
#
# Arguments:
#   options List of options to pass to the socket call
#           ?-myaddr addr? ?-myport port?
#   host    The hostname or IP to which a connection should be established
#   port    The port number to which a connection should be established
#
# Results:
#   Returns a channel handle to the socket used for communication.
#   The channel is ready for normal use when returned.
#
proc ::socks5::connect {args} {
    set errorCode [catch {ProxyConnect args} sock]
    if {$errorCode == -1} {
        return -code error $sock
    } elseif {$errorCode != 0} {
        return -code $errorCode -errorinfo $::errorInfo $sock
    }

    if {[llength $args] != 2} {
        return -code "wrong # args: should be \"connect ?-myaddr addr? ?-myport myport? host port command"
    }

    lassign $args host port

    set cmd [binary format ccc 5 1 0]
    append cmd [FormatAddress $host $port]

    puts -nonewline $sock $cmd
    flush $sock


    set errorCode [catch {ReadResponse $sock} msg]
    if {$errorCode != 0} {
        chan close $sock
        if {$errorCode == -1} {
            return -code error $msg
        } else {
            return -code $errorCode -errorinfo $::errorInfo
        }
    }

    return $sock
}

# ::sock5::BindCallback
#
#   Callback procedure registered by ::socks5::bind on the
#   SOCKS 5 client socket for the readable event.
#
# Arguments:
#   reason  The reason the callback is firing (timeout or else)
#   timeout_id  after callback identifier for cancelling the timeout event
#   sock    Channel handle to the open socket
#   command User command for callback (passed to ::socks5::bind)
#
# Results:
#   Calls "command" in the global namespace to provide information
#   to the user logic.
#
proc ::socks5::BindCallback {reason timeout_id sock command} {
    after cancel $timeout_id

    if {$reason eq "timeout"} {
        chan close $sock
        uplevel #0 [list $command timeout "timeout occurred while waiting for connection"]
    } else {
        if {[catch {ReadResponse $sock} result]} {
            chan close $sock
            uplevel #0 [list $command error $result]
        } else {
            uplevel #0 [list $command ok $sock]
        }
    }
}

# ::socks5::FormatAddress
#
#   Formats a hostname and port into the format defined by the SOCKS 5
#   specification.
#
# Arguments:
#   host    The hostname or IP address
#   port    The port number
#
# Results:
#   Returns the hostname/IP and port number formatted as a binary message
#   for transmission to the SOCKS 5 server.
#
proc ::socks5::FormatAddress {host port} {
    if {[regexp -- {^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$} $host]} {
        set parts [split $host .]
        set result [binary format cccccS 1 {*}$parts $port]
    } else {
        if {[string length $host] > 255} {
            return -code -1 "host must be 255 characters or less"
        }

        set result [binary format cca*S 3 [string length $host] $host $port]
    }

    return $result
}

# ::socks5::ReadResponse
#
#   Reads a SOCKS 5 server response message from the given channel handle.
#
# Arguments:
#   sock    The channel handle from which to read
#
# Results:
#   Returns an error if there is a problem reading the response.  Otherwise
#   returns a two element list consisting of the hostname/IP and port number
#   from the response.
#
proc ::socks5::ReadResponse {sock} {
    variable ResponseCodes

    set rsp [read $sock 3]
    if {[string length $rsp] != 3} {
        return -code -1 "unable to read response from proxy"
    }

    binary scan $rsp ccx version reply
    if {$reply != 0} {
        if {[info exists ResponseCodes($reply)]} {
            return -code -1 "error from proxy: $ResponseCodes($reply) ($reply)"
        }

        return -code -1 "error from proxy: $reply"
    }

    set rsp [read $sock 1]
    binary scan $rsp c addr_type

    if {$addr_type == 1} {
        set rsp [read $sock 6]
        binary scan $rsp "cucucucuSu" ip1 ip2 ip3 ip4 port
        set result [list "$ip1.$ip2.$ip3.$ip4" $port]
    } elseif {$addr_type == 3} {
        set len [read $sock 1]
        set len [binary scan $len c]
        
        set host [read $sock $len]
        set port [binary scan S [read $sock 2]]
        set result [list $host $port]
    } else {
        return -code -1 "invalid address type from proxy: $addr_type"
    }

    return $result
}

#
# ::socks5::ProxyConnect
#
#   Helper procedure to connect and perform handshaking with a SOCKS 5 proxy 
#   server.  The proxy server address and port are taken from the global
#   configuration and may be specified via a call to ::socks5::configure.
#
# Arguments:
#   args    List of arguments to pass to the socket call 
#           ?-myaddr addr? ?-myport port?
#
# Results:
#   Returns a channel handle to the open connection on success.  Returns an
#   error otherwise.  The channel is authenticated and ready for use in SOCKS 5
#   client requests on return.
#
proc ::socks5::ProxyConnect { argsVar } {
    variable Config
    variable MethodCodes

    if {$Config(proxy) eq {} || $Config(proxyport) eq {}} { 
        return -code -1 "no proxy or proxy port specified"
    }

    # Parse the command line options for socket related options.  Leave the
    # remaining arguments for the parent
    upvar $argsVar args
    set socketOptions [list]
    while {[set result [cmdline::getopt args {myaddr.arg myport.arg} option value]] == 1} {
        lappend socketOptions "-$option" $value
    }

    if {$result == -1} {
        return -code -1 "unknown option '[lindex $args 0]'"
    }

    set errorCode [catch {socket {*}$socketOptions $Config(proxy) $Config(proxyport)} sock]
    if {$errorCode != 0} {
        return -code -1 "unable to connect to proxy: $sock"
    }
    fconfigure $sock -translation binary -encoding binary -blocking 1

    set numMethods 1
    set methods [list 0]

    if {$Config(username) != {} || $Config(password) != {}} {
        incr numMethods
        lappend methods 5
    }

    puts -nonewline $sock [binary format ccc* 5 $numMethods $methods]
    flush $sock

    set rsp [read $sock 2]
    if {[string length $rsp] != 2} {
        chan close $sock
        return -code -1 "unable to read handshake response from proxy"
    }

    binary scan $rsp cc version method
    if {$version != 5} {
        chan close $sock
        return -code -1 "unsupported version: $version"
    } elseif {$method == 255} {
        chan close $sock
        return -code -1 "unsupported method from proxy: $MethodCodes($method) ($method)"
    } elseif {$method == 5} {
        PerformUserPassAuth $sock
    }

    return $sock
}

# ::socks5::PerformUserPassAuth
#
#   Performs username/password authentication on the given channel.  The
#   username and password are taken from the global configuration and may
#   be specified via a call to ::socks5::configure.
#
# Arguments:
#   sock    The socket on which to perform authentication
#
# Results:
#   Returns an error on authentication failure.
#
proc ::socks5::PerformUserPassAuth {sock} {
    variable Config

    if {[string length $Config(username)] > 255]} {
        chan close $sock
        return -code -1 "username must be 255 characters or less"
    }

    if {[string length $Config(password)] > 255]} {
        chan close $sock
        return -code -1 "password must be 255 characters or less"
    }

    puts -nonewline $sock [binary scan cca*ca* 1 \
        [string length $Config(username)] $Config(username) \
        [string length $Config(password)] $Config(password)]
    flush $sock

    set rsp [read $sock 2]
    if {[string length $rsp] != 2} {
        chan close $sock
        return -code -1 "unable to read auth response from proxy"
    }

    binary scan cc $rsp version reply
    if {$version != 1} {
        chan close $sock
        return -code -1 "unsupported username/password auth version ($version)"
    } elseif {$reply != 0} {
        chan close $sock
        return -code -1 "proxy denied presented auth tokens"
    }

    return
}
