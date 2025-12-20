export const ruleList = [
  {
    sid: 2024219,
    rev: 3,
    msg: "SQL Injection Attempt",
    category: "web-application-attack",
    proto: "tcp",
    src: "$EXTERNAL_NET",
    src_port: "any",
    direction: "->",
    dst: "$HTTP_SERVERS",
    dst_port: "80",
    priority: "High",
    status: "Enabled",
    source: "snort",

    mitre: {
      tactic: "Execution",
      technique: "T1190 – Exploit Public-Facing Application",
    },

    hits24h: 34,

    raw: `alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS 80 (
        msg:"SQL Injection Attempt"; 
        flow:to_server,established; 
        content:"union select"; nocase; 
        classtype:web-application-attack; 
        sid:2024219; rev:3;
    )`,
  },

  {
    sid: 1003921,
    rev: 1,
    msg: "Suspicious DNS Query",
    category: "dns-anomaly",
    proto: "udp",
    src: "$HOME_NET",
    src_port: "any",
    direction: "->",
    dst: "$DNS_SERVERS",
    dst_port: "53",
    priority: "Medium",
    status: "Disabled",
    source: "ti",

    mitre: {
      tactic: "Command and Control",
      technique: "T1071.004 – DNS Tunnel",
    },

    hits24h: 0,

    raw: `alert udp $HOME_NET any -> $DNS_SERVERS 53 (
        msg:"Suspicious DNS Query"; 
        content:"|00 00 29|"; depth:3;
        classtype:dns-anomaly; 
        sid:1003921; rev:1;
    )`,
  },
];
