Prerequisites:

Create an account on abuseipdb and retrieve an API key.

Enter the API key in the apiKey variable.



This powershell script will do the following:
- Retrieve IOC's from the urlhaus TI feed
- Strips the prefix and URI from the IP or domain
- Cross references these IP's and domains to the abuseipdb database
- If the abuse confidence is greater than 50% (can be modified), add the IP / domain to a separate txt file
- These txt files can be used to implement in your SIEM / added as a blocklist on the firewall / proxy.



You can run this as a scheduled task




##PCAP analyzer
Sample usage: 
- python pcap.py pcap.pcap --src-ip 208.50.77.134 --dst-ip 192.168.3.131
- python pcap.py smallflows.pcap --flows
- - python pcap.py smallflows.pcap --ip
