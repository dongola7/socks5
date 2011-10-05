package require Tcl 8.5

namespace eval ::socks5 { 
   array set instances { }
}

proc ::socks5::socket {proxy proxyport host port} {
   variable instances

   set sock [::socket $proxy $proxyport]
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

   set channelId [chan create [list read write] ::socks5::Connect]
   dict set instances($channelId) socket $sock

   return $channelId
}

proc ::socks5::GetSocket {channelId} {
   variable instances
   return [dict get $instances($channelId) socket]
}

proc ::socks5::Connect {subcommand args} {
   return [eval Connect_$subcommand $args]
}

proc ::socks5::Connect_initialize {channelId mode} {
   variable instances
   set instances($channelId) [dict create]

   return [list initialize finalize watch read write blocking]
}

proc ::socks5::Connect_finalize {channelId} {
   variable instances
   close [GetSocket $channelId]
   unset instances($channelId)
}

proc ::socks5::Connect_watch {channelId eventSpec} {
   variable instances
   set sock [GetSocket $channelId]
   
   if {[llength $eventSpec] == 0} {
      chan event $sock readable {}
      chan event $sock writable {}
      return
   }

   if {[lindex $eventSpec read] != -1} {
      chan event $sock readable [list ::socks5::Connect_event $channelId read]
   } else {
      chan event $sock readable {}
   }

   if {[lindex $eventSpec write] != -1} {
      chan event $sock writable [list ::socks5::Connect_event $channelId write]
   } else {
      chan event $sock writable {}
   }
}

proc ::socks5::Connect_event {channelId eventSpec} {
   chan postevent $channelId $eventSpec
}

proc ::socks5::Connect_read {channelId count} {
   variable instances
   set sock [GetSocket $channelId]

   if {[eof $sock]} {
      return ""
   }

   set data [chan read $sock $count]
   if {$data eq {}} {
      return -code error EAGAIN
   }

   return $data
}

proc ::socks5::Connect_write {channelId data} {
   variable instances
   set sock [GetSocket $channelId]

   chan puts -nonewline $sock $data
   flush $sock
   return [string bytelength $data]
}

proc ::socks5::Connect_blocking {channelId mode} {
   variable instances
   set sock [GetSocket $channelId]

   chan configure $sock -blocking $mode
}

package provide socks5 0.1
