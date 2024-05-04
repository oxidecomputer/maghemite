fn open(message, asn, addr) {
    if asn == 100 {
        message.add_four_octet_as(74);
    }
    message.emit()
}

fn update(message, asn, addr) {
    if asn == 100 {
        message.add_community(1701);
    }
    message.emit()
}
