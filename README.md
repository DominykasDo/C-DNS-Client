# C-DNS-Client
A DNS client made in C.

# How to use
Compile with `gcc dnsClient.c -o dnsClient`. Works on Linux only.

# What it does
Looks up IP addresses (IPv4 or IPv6) to a user given domain name. Additionally, it caches the address. Use `-v` as a command line flag to ping a cached address to check if it is outdated (the program then automatically does a DNS lookup if it is outdated and replaces the outdated address).
