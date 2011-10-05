package require Tcl 8.5

namespace eval ::socks5 { }

proc ::socks5::connect {proxy proxyport host port} {

   set sock [socket $proxy $proxyport]
   fconfigure $sock -translation binary -encoding binary -blocking 1

   set cmd [binary format H2H2H2 05 01 00]

   puts -nonewline $sock [binary format H2H2H2 05 01 00]
   flush $sock

   set rsp [read $sock 2]
   binary scan $rsp H2H2 version method
   if {$version != "05"} {
      close $sock
      return -code error "unsupported version: $version"
   } elseif {$method != "00"} {
      close $sock
      return -code error "unsupported method: $method"
   }

   puts -nonewline $sock [binary format H2H2H2H2c 05 01 00 03 [string bytelength $host]]
   puts -nonewline $sock $host
   puts -nonewline $sock [binary format S $port]
   flush $sock

   set rsp [read $sock 4]
   binary scan $rsp H2H2xH2 version reply addr_type
   if {$reply != "00"} {
      close $sock
      return -code error "invalid reply: $reply"
   }

   if {$addr_type == "01"} {
      read $sock 6
   } elseif {$addr_type == "03"} {
      set len [read $sock 1]
      set len [binary scan $len c]
      read $sock [expr {$len+2}]
   } else {
      close $sock
      return -code error "invalid address type: $addr_type"
   }

   return $sock
}

package provide socks5 0.1
