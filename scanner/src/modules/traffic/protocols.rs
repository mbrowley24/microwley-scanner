pub enum Protocol{
    ICMP              = 1,
    IGMP              = 2,
    TCP               = 6,
    UDP               = 17,
    IPv6Encapsulation = 41,
    GRE               = 47,
    ESP               = 50,
    AH                = 51,
    ICMPv6            = 58,
    OSPF              = 89,
    SCTP              = 132,
    Unknown(u8),
}

impl Protocol {

    pub fn from(num: u8) -> Self {

        match num {
            1 => Protocol::ICMP,
            2 => Protocol::IGMP,
            6 => Protocol::TCP,
            17 => Protocol::UDP,
            41 => Protocol::IPv6Encapsulation,
            47 => Protocol::GRE,
            50 => Protocol::ESP,
            51 => Protocol::AH,
            58 => Protocol::ICMPv6,
            89 => Protocol::OSPF,
            132 => Protocol::SCTP,
            _ => Protocol::Unknown(num),
        }
    }

    pub fn as_number(&self) -> u8 {

        match self {
            Protocol::ICMP              => 1,
            Protocol::IGMP              => 2,
            Protocol::TCP               => 6,
            Protocol::UDP               => 17,
            Protocol::IPv6Encapsulation => 41,
            Protocol::GRE               => 47,
            Protocol::ESP               => 50,
            Protocol::AH                => 51,
            Protocol::ICMPv6            => 58,
            Protocol::OSPF              => 89,
            Protocol::SCTP              => 132,
            Protocol::Unknown(num) => *num,
        }
    }

    pub fn to_string(&self) -> String {
        match self {
            Protocol::ICMP              => "ICMP",
            Protocol::IGMP              => "IGMP",
            Protocol::TCP               => "TCP",
            Protocol::UDP               => "UDP",
            Protocol::IPv6Encapsulation => "IPv6Encapsulation",
            Protocol::GRE               => "GRE",
            Protocol::ESP               => "ESP",
            Protocol::AH                => "AH",
            Protocol::ICMPv6            => "ICMPv6",
            Protocol::OSPF              => "OSPF",
            Protocol::SCTP              => "SCTP",
            Protocol::Unknown(_)        => "Unknown",
        }
    }
}