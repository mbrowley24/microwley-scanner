use bitflags::bitflags;

bitflags! {
    pub struct Flags: u16 {
        const FIN  = 0x01; //Finish
        const SYN  = 0x02; // Sync
        const RST  = 0x04; //reset
        const PSH  = 0x08; // push
        const ACK  = 0x10; // acknowledge
        const URG  = 0x20; //urgent
        const ECE  = 0x40; //Explicit congestions Notification
        const CWR  = 0x80; // congestion window Reduced
        const NS   = 0x100; //nonce sum
    }
}