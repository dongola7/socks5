source socks.tcl

set proxy_ip "localhost"
set proxy_port "1080"
set server_ip "localhost"
set server_port "30000"

set data ""
proc HandleConnect {result arg} {
   if {$result != "ok"} {
      puts "SOCKS error accepting incoming connection: $arg"
      return
   }

   set ::data $arg
}

puts "Attempting CNTRL connection to $server_ip:$server_port using proxy $proxy_ip:$proxy_port"
set cntrl [::socks5::connect $proxy_ip $proxy_port $server_ip $server_port]
puts "CNTRL connection established"

puts "Attempting to create SOCKS5 binding for DATA connection"
set bind_info [::socks5::bind $proxy_ip $proxy_port $server_ip $server_port HandleConnect]
foreach {host port} $bind_info break
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
