 fn open(message, asn, addr) {
     message.emit()
 }

 fn update(message, asn, addr) {
     if asn == 64502 {
         message.prefix_filter(|prefix|
			prefix.within("192.168.12.0/24")
		);
     }
     if asn == 64500 || asn == 64501 {
         message.prefix_filter(|prefix|
			prefix.within("198.51.100.0/24")
		);
     }
     message.emit()
 }
