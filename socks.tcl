package require Tcl 8.5

namespace eval ::socks5 { }

proc ::socks5::bind {proxy proxyport host port callback} {
   if {[catch {ProxyConnect $proxy $proxyport} sock]} {
      return -code error $sock
   }

   puts -nonewline $sock [binary format H2H2H2H2c 05 02 00 03 [string bytelength $host]]
   puts -nonewline $sock $host
   puts -nonewline $sock [binary format S $port]
   flush $sock

   if {[catch {ReadResponse $sock} result]} {
      chan close $sock
      return -code error $result
   }

   chan event $sock readable [list ::socks5::BindCallback $sock $callback]

   return $result
}

proc ::socks5::BindCallback {sock callback} {
   if {[catch {ReadResponse $sock} result]} {
      chan close $sock
      eval $callback error $result
   } else {
      eval $callback ok $sock
   }
}

proc ::socks5::connect {proxy proxyport host port} {

   if {[catch {ProxyConnect $proxy $proxyport} sock]} {
      return -code error $sock
   }

   puts -nonewline $sock [binary format H2H2H2H2c 05 01 00 03 [string bytelength $host]]
   puts -nonewline $sock $host
   puts -nonewline $sock [binary format S $port]
   flush $sock

   if {[catch {ReadResponse $sock} msg]} {
      chan close $sock
      return -code error $msg
   }

   return $sock
}

proc ::socks5::ReadResponse {sock} {

   set rsp [read $sock 4]
   binary scan $rsp H2H2xH2 version reply addr_type
   if {$reply != "00"} {
      return -code error "invalid reply: $reply"
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
      return -code error "invalid address type: $addr_type"
   }

   return $result
}

proc ::socks5::ProxyConnect {proxy proxyport} {
   set sock [socket $proxy $proxyport]
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
