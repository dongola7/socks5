set listen_port "30000"

set cntrl ""

proc HandleConnect {cntrl addr port} {
   puts "CNTRL connection from $addr:$port"
   set host [gets $cntrl]
   set port [gets $cntrl]

   puts "Attempting DATA connection to $host:$port"
   set data [socket $host $port]
   puts "DATA connection established"

   fconfigure $cntrl -blocking 0 -translation binary -encoding binary
   fconfigure $data -blocking 0 -translation binary -encoding binary
   fileevent $cntrl readable [list HandleRead $cntrl $data]
   fileevent $data readable [list HandleRead $data $cntrl]
}

proc HandleRead {src dst} {
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

set server_sock [socket -server HandleConnect $listen_port]
puts "Listening for CNTRL connections on port $listen_port"
vwait forever
