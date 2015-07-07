#include "stdafx.h"
#include "PortScan.h"

#include <sys\stat.h>
#include <string.h>
#include <iostream>
#include <winsock2.h>
#include <ws2def.h>
#include <Ws2tcpip.h>
#include <windows.h>
#include <vector>
#pragma comment(lib, "Ws2_32.lib")


PortScan::PortScan()
{
	std::vector<int> ports = parseRangePort(0, 255);	// List of ports
	std::vector<int> open_ports;						// List of open ports

	WSADATA my_first_sock;
	SOCKET sockett;
	SOCKADDR_IN sa;

	sa.sin_family = AF_INET;
	WSAStartup(MAKEWORD(2, 0), &my_first_sock);

	// Define socket host
	sa.sin_addr.S_un.S_addr = inet_addr("localhost");

	//need a while loop to check open ports every x time

	for (int port : ports)
	{
		sockett = socket(AF_INET, SOCK_STREAM, 0);

		if (sockett < 0)
		{
			exit(EXIT_FAILURE); //ERROR
			std::cout << "socket error on port " << port << "\n";
		}			

		sa.sin_port = htons(port);

		// Connect socket
		int err = connect(sockett, (struct sockaddr *)&sa, sizeof sa);

		if (err == SOCKET_ERROR)
		{
			fflush(stdout);
			std::cout << "error to connect socket on port " << port << "\n";
		}			
		else
		{
			std::cout << "Connect to " << port << "\n";

			// Add open port to the list
			open_ports.push_back(port);
		}
		std::cout << "Closing socket \n";
		// Close the socket
		closesocket(sockett);
	}
	
	for (int por : open_ports)
	{
		sa.sin_port = por;
		connect(sockett, (struct sockaddr *)&sa, sizeof sa);
		send(sockett, "lolilol", 7, 0);							// This is a test, send lolilol to each port in the list
		closesocket(sockett);
	}

	/*sf::TcpSocket socket;
	for (int por : open_ports)
	{
		socket.connect("localhost", por);
		socket.send();
	}*/
}


PortScan::~PortScan()
{
}

bool isPortOpen(const std::string& add, int port)
{
	/*SOCKET sock;
	
	bool is_open = (sock.connect(sf::IpAddress(add), port) == SOCKET_ERROR);
	sock.disconnect();
	return is_open;	*/
	return false;
}


static std::vector<int> parseRangePort(int min, int max)
{
	// Fill the list with each number port
	std::vector<int> ports;
	for (; min <= max; ++min)
		ports.push_back(min);
	return ports;
}

void sendFile(std::vector<int> open_ports, std::string filename)
{
	SOCKET sock;                  /* socket */
	int desc;                  /* file descriptor for socket */
	int fd;                    /* file descriptor for file to send */
	struct stat stat_buf;      /* argument to fstat */
	struct sockaddr_in addr;   /* socket parameters for bind */
	struct sockaddr_in addr1;  /* socket parameters for accept */

	/* create socket */
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock == -1) {
		fprintf(stderr, "unable to create socket: %s\n", strerror(errno));
		exit(1);
	}

	/* fill in socket structure */
	for (int port : open_ports)
	{
		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = INADDR_ANY;
		addr.sin_port = htons(port);

		/* bind socket to the port */
		int rc = bind(sock, (struct sockaddr *)&addr, sizeof(addr));
		if (rc == -1) {
			fprintf(stderr, "unable to bind to socket: %s\n", strerror(errno));
			exit(1);
		}

		/* listen for clients on the socket */
		rc = listen(sock, 1);
		if (rc == -1) {
			fprintf(stderr, "listen failed: %s\n", strerror(errno));
			exit(1);
		}

		/* open the file to be sent */
		FILE *f = fopen(filename.c_str(), "rb");
		fseek(f, 0, SEEK_END);
		long fsize = ftell(f);
		fseek(f, 0, SEEK_SET);

		char *buff = new char[fsize + 1];
		fread(buff, fsize, 1, f);
		fclose(f);

		buff[fsize] = 0;

		/*fd = open(filename, O_RDONLY);
		if (fd == -1) {
			fprintf(stderr, "unable to open '%s': %s\n", filename, strerror(errno));
			exit(1);
		}*/

		/* get the size of the file to be sent */
		//fstat(fd, &stat_buf);

		/* copy file using sendfile */
		//int offset = 0;

		// send the file via socket

		rc = send(sock, buff, fsize + 1, 0);

		//rc = sendfile(desc, fd, &offset, stat_buf.st_size);

		if (rc == SOCKET_ERROR)
		{
			fprintf(stderr, "error from send: %s\n", strerror(errno));
			exit(1);
		}
		/*if (rc != stat_buf.st_size) 
		{
			fprintf(stderr, "incomplete transfer from sendfile: %d of %d bytes\n",
				rc,
				(int)stat_buf.st_size);
			exit(1);
		}*/

		/* close descriptor for file that was sent */
		//close(fd);

		/* close socket descriptor */
		//close(desc);

		/* close socket */
		closesocket(sock);
	}
}