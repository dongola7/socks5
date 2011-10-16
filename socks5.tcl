package require Tcl 8.5

package provide socks5 0.1

namespace eval ::socks5 { 
   namespace export configure bind connect

   array set config {proxy {} proxyport 1080 bindtimeout 2000}
   set options [list -proxy -proxyport -bindtimeout]

   array set response_codes {
      00 "succeeded"
      01 "general SOCKS server failure"
      02 "connection not allowed by ruleset"
      03 "network unreachable"
      04 "host unreachable"
      05 "connection refused"
      06 "TTL expired"
      07 "command not supported"
      08 "address type not supported"
   }

   array set method_codes {
      00 "no authentication required"
      01 "gssapi"
      02 "username/password"
      ff "no acceptable methods"
   }
}

proc ::socks5::configure {args} {
   variable config
   variable options

   foreach {option value} $args {
      set normalized_option [string range [lsearch -regexp -inline $options $option] 1 end]
      if {$normalized_option eq ""} {
         return -code error "invalid option $option"
      }

      set config($normalized_option) $value
   }
}

proc ::socks5::bind {host port callback} {
   variable config

   set cmd [binary format H2H2H2 05 02 00]
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

   set timeout_id [after $config(bindtimeout) \
      [list ::socks5::BindCallback timeout {} $sock $callback]]
   chan event $sock readable \
      [list ::socks5::BindCallback readable $timeout_id $sock $callback]

   return $result
}

proc ::socks5::connect {host port} {
   set cmd [binary format H2H2H2 05 01 00]
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

proc ::socks5::BindCallback {reason timeout_id sock callback} {
   after cancel $timeout_id

   if {$reason eq "timeout"} {
      chan close $sock
      uplevel #0 [list $callback timeout "timeout occurred while waiting for connection"]
   } else {
      if {[catch {ReadResponse $sock} result]} {
         chan close $sock
         uplevel #0 [list $callback error $result]
      } else {
         uplevel #0 [list $callback ok $sock]
      }
   }
}

proc ::socks5::FormatAddress {host port} {
   if {[regexp -- {^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$} $host]} {
      set parts [split $host .]
      set result [binary format H2ccccS 01 {*}$parts $port]
   } else {
      if {[string length $host] > 255} {
         return -code -1 "host must be 255 characters or less"
      }

      set result [binary format H2ca*S 03 [string length $host] $host $port]
   }

   return $result
}

proc ::socks5::ReadResponse {sock} {
   variable response_codes

   set rsp [read $sock 3]
   if {[string length $rsp] != 3} {
      return -code -1 "unable to read response from proxy"
   }

   binary scan $rsp H2H2x version reply
   set reply [string tolower $reply]
   if {$reply != "00"} {
      if {[info exists response_codes($reply)]} {
         return -code -1 "error from proxy: $response_codes($reply) ($reply)"
      }

      return -code -1 "error from proxy: $reply"
   }

   set rsp [read $sock 1]
   binary scan $rsp H2 addr_type
   set addr_type [string tolower $addr_type]

   if {$addr_type == "01"} {
      set rsp [read $sock 6]
      binary scan $rsp "cucucucuSu" ip1 ip2 ip3 ip4 port
      set result [list "$ip1.$ip2.$ip3.$ip4" $port]
   } elseif {$addr_type == "03"} {
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
   variable config
   variable method_codes

   if {$config(proxy) eq {} || $config(proxyport) eq {}} { 
      return -code -1 "no proxy or proxy port specified"
   }

   set errorCode [catch {socket $config(proxy) $config(proxyport)} sock]
   if {$errorCode != 0} {
      return -code -1 "unable to connect to proxy: $sock"
   }
   fconfigure $sock -translation binary -encoding binary -blocking 1

   puts -nonewline $sock [binary format H2H2H2 05 01 00]
   flush $sock

   set rsp [read $sock 2]
   if {[string length $rsp] != 2} {
      chan close $sock
      return -code -1 "unable to read handshake response from proxy"
   }

   binary scan $rsp H2H2 version method
   set method [string tolower $method]
   if {$version != "05"} {
      chan close $sock
      return -code -1 "unsupported version: $version"
   } elseif {$method != "00"} {
      chan close $sock

      if {[info exists method_codes($method)]} {
         return -code -1 "unsupported method from proxy: $method_codes($method) ($method)"
      }

      return -code -1 "unsupported method from proxy: $method"
   }

   return $sock
}
