# Description

Test HTTP file to server.

# PCAP

The pcap comes from running server
`docker run --name mattermost-preview -d --publish 8065:8065 mattermost/mattermost-preview -m=4G`

And client from mm.go (you need to setup credentials and channel Id)
