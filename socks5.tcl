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

package provide socks5 0.1

namespace eval ::socks5 { 
    namespace export configure bind connect

    array set Config {
        proxy {} 
        proxyport 1080 
        bindtimeout 2000 
        username {} 
        password {}
    }

    set Options [list]
    foreach key [array names Config] { 
        lappend Options "-$key" 
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

proc ::socks5::configure {args} {
    variable Config
    variable Options

    foreach {option value} $args {
        set normalized_option [string range [lsearch -regexp -inline $Options $option] 1 end]
        if {$normalized_option eq ""} {
            return -code error "invalid option $option"
        }

        set Config($normalized_option) $value
    }
}

proc ::socks5::bind {host port command} {
    variable Config

    set cmd [binary format ccc 5 2 0]
    append cmd [FormatAddress $host $port]

    set errorCode [catch {ProxyConnect} sock]
    if {$errorCode == -1} {
        return -code error $sock
    } elseif {$errorCode != 0} {
        return -code $errorCode -errorinfo $::errorInfo $sock
    }

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

proc ::socks5::connect {host port} {
    set cmd [binary format ccc 5 1 0]
    append cmd [FormatAddress $host $port]

    set errorCode [catch {ProxyConnect} sock]
    if {$errorCode == -1} {
        return -code error $sock
    } elseif {$errorCode != 0} {
        return -code $errorCode -errorinfo $::errorInfo $sock
    }

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

proc ::socks5::ProxyConnect { } {
    variable Config
    variable MethodCodes

    if {$Config(proxy) eq {} || $Config(proxyport) eq {}} { 
        return -code -1 "no proxy or proxy port specified"
    }

    set errorCode [catch {socket $Config(proxy) $Config(proxyport)} sock]
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
