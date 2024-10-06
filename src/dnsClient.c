//gcc dnsClient.c -o dnsClient
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>

int ipRespondsMultiple(char *ips);
int ipResponds(char *ip);
void deleteLineInCache(int n);
char *getIpFromHosts(const char *domain, char *protocol);

int main(int argc, char *argv[])
{
	int verbose = 0;

	for(int i = 1; i < argc; i++)
		if(strcmp(argv[i], "-v") == 0)
		{
			printf("Verbose mode.\n");
			verbose = 1;
			break;
		}
	
	// DNS address scanf
	char dnsAddress[16] = {0};
	printf("Enter DNS host (default is 1.1.1.1): ");
	scanf("%15[^\n]", dnsAddress);
	if(dnsAddress[0] == 0)
		strcpy(dnsAddress, "1.1.1.1");
	while(getchar() != '\n' && !feof(stdin)); // Flush stdin
	printf("Using %s\n", dnsAddress);
	
	// Protocol scanf
	int queryType;
	printf("Enter 4 for IPv4 or 6 for IPv6 (default is IPv4): ");
	char queryTypeInput[2] = {0};
	scanf("%1[^\n]", queryTypeInput);
	if(strcmp(queryTypeInput, "6") == 0)
	{
		queryType = 28; // AAAA record
		queryTypeInput[0] = '6';
	}
	else
	{
		queryType = 1; // A record
		queryTypeInput[0] = '4';
	}
	while(getchar() != '\n' && !feof(stdin)); // Flush stdin
	printf("Using IPv%s\n", queryTypeInput);
	
	// Domain scanf
	char domain[256] = {0};
	printf("Enter a domain name: ");
	scanf("%255[^\n]", domain);
	domain[strcspn(domain, "\n")] = 0;
	while(getchar() != '\n' && !feof(stdin)); // Flush stdin
	
	if(domain[0] == 0)
	{
		printf("Hostname cannot be empty.\n");
		return 3;
	}
	printf("Domain %s, finding address...\n", domain);
	
	// Check hosts file
	char *hostsAddress;
	if((hostsAddress = getIpFromHosts(domain, queryTypeInput)) != NULL)
	{
		printf("Address from hosts:\n%s\n", hostsAddress);
		return 0;
	}
	
	// Check the cache before sending the query
	FILE *cacheFileRead = fopen("dns_cache.txt", "r");
	if(cacheFileRead != NULL)
	{
		int found = 0;
		char line[512];
		int lineCount = 0;
		while(fscanf(cacheFileRead, "%511[^\n]\n", line) > 0)
		{
			char domainCache[256] = {0};
			char protocolCache[2] = {0};
			sscanf(line, "%255[^ ] %1[^ ]", domainCache, protocolCache);
			if(strcmp(domain, domainCache) == 0 && strcmp(queryTypeInput, protocolCache) == 0)
			{
				found = 1;
				char address[256] = {0};
				sscanf(line, "%*[^ ] %*[^ ] %255[^\n]", address);
				if(verbose)
				{
					printf("Checking for outdated addresses in cache...\n");
					char addressCopy[256];
					memcpy(addressCopy, address, 256);
					if(!ipRespondsMultiple(addressCopy))
					{
						printf("Found outdated addresses, deleting cache entry...\n");
						fclose(cacheFileRead);
						deleteLineInCache(lineCount);
						break;
					}
				}
				printf("Cached results:\n");
				char *oneAddress;
				char *addressesPointer = address;
				while(oneAddress = strtok_r(addressesPointer, " ", &addressesPointer))
				{
					printf("%s: %s\n", strcmp(queryTypeInput, "4") == 0 ? "IPv4" : "IPv6", oneAddress);
				}
				fclose(cacheFileRead);
				return 0;
			}
			++lineCount;
		}
		if(!found)
			fclose(cacheFileRead);
	}
	printf("Unable to cache, proceeding to DNS query...\n");

	// Create a DNS query packet
	char dnsQuery[512];
	memset(dnsQuery, 0, 512);
	uint16_t id = htons(0x1234); // Random ID
	memcpy(dnsQuery, &id, 2);
	uint16_t flags = htons(0x0100); // Standard query, recursion desired
	memcpy(dnsQuery + 2, &flags, 2);
	uint16_t qdCount = htons(1); // One question
	memcpy(dnsQuery + 4, &qdCount, 2);

	// Add the question section
	int offsetQuery = 12;
	char *domainPointer = domain;
	char *queryPointer = dnsQuery + offsetQuery;
	int labelLength;
	while(*domainPointer)
	{
		labelLength = strcspn(domainPointer, ".");
		*queryPointer++ = labelLength;
		memcpy(queryPointer, domainPointer, labelLength);
		queryPointer += labelLength;
		domainPointer += labelLength + 1;
	}
	*queryPointer = 0;
	++queryPointer;
	offsetQuery = queryPointer - dnsQuery;

	uint16_t qType = htons(queryType); // A or AAAA record
	memcpy(dnsQuery + offsetQuery, &qType, 2);
	offsetQuery += 2;
	uint16_t qClass = htons(1); // IN class
	memcpy(dnsQuery + offsetQuery, &qClass, 2);
	offsetQuery += 2;

	// UDP socket
	int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if(sock == 0)
	{
		printf("socket failed.\n");
		return 4;
	}

	struct sockaddr_in serverAddressDNS;
	serverAddressDNS.sin_family = AF_INET;
	serverAddressDNS.sin_port = htons(53); // DNS port
	inet_pton(AF_INET, dnsAddress, &serverAddressDNS.sin_addr);

	// Send
	int bytesSent = sendto(sock, dnsQuery, offsetQuery, 0, (struct sockaddr *)&serverAddressDNS, sizeof(serverAddressDNS));
	if(bytesSent <= 0)
	{
		printf("sendto failed.\n");
		close(sock);
		return 5;
	}

	// Receive
	char dnsResponse[512];
	socklen_t serverAddressLength = sizeof(serverAddressDNS);
	int bytesReceived = recvfrom(sock, dnsResponse, 512, 0, (struct sockaddr *)&serverAddressDNS, &serverAddressLength);
	if(bytesReceived <= 0)
	{
		printf("recvfrom failed.\n");
		close(sock);
		return 6;
	}
	
	// Parse
	uint16_t responseAnCount;
	memcpy(&responseAnCount, dnsResponse + 6, 2);
	
	int offsetResponse = 12; // Skip header
	while(dnsResponse[offsetResponse] != 0) offsetResponse++; // Skip domain
	offsetResponse += 5;  // Skip null byte, QTYPE and QCLASS
	
	if(ntohs(responseAnCount) > 0)
	{
		// Cache
		FILE *cacheFileAppend = fopen("dns_cache.txt", "a");
		fprintf(cacheFileAppend, "%s %s", domain, queryTypeInput);

		// Print addresses
		for(int i = 0; i < ntohs(responseAnCount); i++)
		{
			offsetResponse += 2;
			uint16_t protocol;
			memcpy(&protocol, dnsResponse + offsetResponse, 2);
			offsetResponse += 8;
			uint16_t rdLength;
			memcpy(&rdLength, dnsResponse + offsetResponse, 2);
			offsetResponse += 2;
			if(ntohs(protocol) == 1 && ntohs(rdLength) == 4) // IPv4 address
			{
				struct in_addr ipAddr;
				memcpy(&ipAddr, dnsResponse + offsetResponse, 4);
				char *ip = inet_ntoa(ipAddr);
				printf("IPv4: %s\n", ip);
				fprintf(cacheFileAppend, " %s", ip); // Cache address
			}
			else if(ntohs(protocol) == 28 && ntohs(rdLength) == 16) // IPv6 address
			{
				struct in6_addr ip6Addr;
				memcpy(&ip6Addr, dnsResponse + offsetResponse, 16);
				char ip[INET6_ADDRSTRLEN];
				inet_ntop(AF_INET6, &ip6Addr, ip, INET6_ADDRSTRLEN);
				printf("IPv6: %s\n", ip);
				fprintf(cacheFileAppend, " %s", ip); // Cache address
			}
			offsetResponse += ntohs(rdLength);
		}
		
		fprintf(cacheFileAppend, "\n");
		fclose(cacheFileAppend);
	}
	else
	{
		printf("No IPv%s addresses found for %s\n", queryTypeInput, domain);
	}

	close(sock);
	return 0;
}

int ipRespondsMultiple(char *ips)
{
	char *ip = strtok(ips, " ");
	while(ip != NULL)
	{
		if(ipResponds(ip) == 0)
			return 0;
		ip = strtok(NULL, " ");
	}
	return 1;
}

int ipResponds(char *ip)
{
	char cmd[256];
	sprintf(cmd, "ping -c 1 -W 1 %s", ip);
	FILE *fp = popen(cmd, "r");
	if(fp == NULL)
		return 0;

	char response[256];
	while(fgets(response, sizeof(response), fp) != NULL)
		if(strstr(response, "bytes from") != NULL)
		{
			pclose(fp);
			return 1;
		}

	pclose(fp);
	return 0;
}

void deleteLineInCache(int n)
{
	FILE *dnsFile = fopen("dns_cache.txt", "r");
	FILE *tempFile = fopen("dns_temp.txt", "w");

	char buffer[512];
	int count = 0;

	while(fgets(buffer, sizeof(buffer), dnsFile) != NULL)
	{
		if(n != count)
			fputs(buffer, tempFile);

		count++;
	}

	fclose(dnsFile);
	fclose(tempFile);

	if(remove("dns_cache.txt") != 0)
		perror("Error deleting file");
	else if(rename("dns_temp.txt", "dns_cache.txt") != 0)
		perror("Error renaming file");
}

char *getIpFromHosts(const char *domain, char *protocol)
{
	FILE *fp;
	char line[512];
	char ip[INET6_ADDRSTRLEN];
	char *token;
	int family;

	if(strcmp(protocol, "6") == 0)
		family = AF_INET6;
	else
		family = AF_INET;

	fp = fopen("/etc/hosts", "r");
	if(fp == NULL)
	{
		printf("Failed to open /etc/hosts\n");
		return NULL;
	}

	while(fgets(line, 512, fp))
	{
		line[strcspn(line, "\n")] = 0;
		token = strtok(line, " \t");
		if(token != NULL)
		{
			if(inet_pton(family, token, ip) == 1)
			{
				token = strtok(NULL, " \t");
				while (token != NULL)
				{
					if(strcmp(token, domain) == 0)
					{
						fclose(fp);
						return strdup(line);
					}
					token = strtok(NULL, " \t");
				}
			}
		}
	}

	fclose(fp);
	return NULL;
}
