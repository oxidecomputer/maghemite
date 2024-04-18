fn open(message, asn, addr) {
    message.emit()
}

fn update(message, asn, addr) {
    if asn == 65402 {
        // Apply a filter on both NLRI elements and withdraw elements
        message.prefix_filter(|prefix| prefix.within("10.128.0.0/16"));
    }
    message.emit()
}
