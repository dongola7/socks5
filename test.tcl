source socks.tcl

set sock [socks5::socket localhost 1080 www.google.com 80]
puts $sock "GET index.html"
flush $sock
fconfigure $sock -blocking true -translation auto
puts [read $sock]
close $sock
