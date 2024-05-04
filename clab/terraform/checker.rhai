fn open(message, asn, addr) {
    if !message.has_capability(CapabilityCode::FourOctetAs) {
        return CheckerResult::Drop;
    }
    CheckerResult::Accept
}

fn update(message, asn, addr) {
    // drop no-export community
    if message.has_community(0xFFFFFF01) {
        return CheckerResult::Drop;
    }
    CheckerResult::Accept
}
