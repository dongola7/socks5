package require Tcl 8.5

namespace eval ::socks5 { 
   array set config {proxy {} proxyport 1080}
   set options [list -proxy -proxyport]

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
   if {[catch {ProxyConnect} sock]} {
      return -code error $sock
   }

   set cmd [binary format H2H2H2 05 02 00]
   append cmd [FormatAddress $host $port]

   puts -nonewline $sock $cmd
   flush $sock

   if {[catch {ReadResponse $sock} result]} {
      chan close $sock
      return -code error $result
   }

   chan event $sock readable [list ::socks5::BindCallback $sock $callback]

   return $result
}

proc ::socks5::connect {host port} {

   if {[catch {ProxyConnect} sock]} {
      return -code error $sock
   }

   set cmd [binary format H2H2H2 05 01 00]
   append cmd [FormatAddress $host $port]

   puts -nonewline $sock $cmd
   flush $sock

   if {[catch {ReadResponse $sock} msg]} {
      chan close $sock
      return -code error $msg
   }

   return $sock
}

proc ::socks5::BindCallback {sock callback} {
   if {[catch {ReadResponse $sock} result]} {
      chan close $sock
      eval $callback error $result
   } else {
      eval $callback ok $sock
   }
}

proc ::socks5::FormatAddress {host port} {
   if {[regexp -- {^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$} $host]} {
      set parts [split $host .]
      set result [eval binary format H2ccccS 01 $parts $port]
   } else {
      set result [binary format H2c 03 [string bytelength $host]]
      append result $host
      append result [binary format S $port]
   }

   return $result
}

proc ::socks5::ReadResponse {sock} {
   variable response_codes

   set rsp [read $sock 4]
   binary scan $rsp H2H2xH2 version reply addr_type
   if {$reply != "00"} {
      if {[info exists response_codes($reply)]} {
         return -code error "error from proxy server: $response_codes($reply) ($reply)"
      }

      return -code error "error from proxy server: $reply"
   }


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
      return -code error "invalid address type from proxy server: $addr_type"
   }

   return $result
}

proc ::socks5::ProxyConnect { } {
   variable config

   if {$config(proxy) eq {} || $config(proxyport) eq {}} { 
      return -code error "no proxy or proxy port specified"
   }

   set sock [socket $config(proxy) $config(proxyport)]
   fconfigure $sock -translation binary -encoding binary -blocking 1

   puts -nonewline $sock [binary format H2H2H2 05 01 00]
   flush $sock

   set rsp [read $sock 2]
   binary scan $rsp H2H2 version method
   if {$version != "05"} {
      chan close $sock
      return -code error "unsupported version: $version"
   } elseif {$method != "00"} {
      chan close $sock
      return -code error "unsupported method: $method"
   }

   return $sock
}
   
package provide socks5 0.1
