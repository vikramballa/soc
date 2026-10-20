# Lab packet captures

Put **pcap files you captured yourself in an authorized lab** here (`*.pcap`). With
`docker compose --profile sensors up -d`, Suricata and Zeek replay them offline and SentinelX ingests the
resulting `eve.json` and Zeek JSON logs automatically.

Never use captures containing third-party or personal data you are not authorized to process.
