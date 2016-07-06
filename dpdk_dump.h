#pragma once
#include <sys/time.h>
#include <unistd.h>
#include <csignal>

#include "dynamic.h"
#include "activity.h"
#include "dpdkpp.h"



//! Begin parse console arguments
#define __BeginParseConsoleArguments__( printHelpFunction ) \
	if( argc < 2 || (argc == 2 &&  (!strcmp( argv[ 1 ], "--help" ) || !strcmp( argv[ 1 ], "/?" ) || !strcmp( argv[ 1 ], "/h" ) )) ){ \
		printHelpFunction(); \
		return 1; \
	} \
	try{ \
		for (int ArgID = 1; ArgID < argc; ArgID++) { \
			std::string Arg = argv[ ArgID ];

#define __OnArgument(Name) if(Arg == Name)
#define __ArgValue argv[++ArgID]

#define __EndParseConsoleArguments__ \
			else throw std::invalid_argument("Unknown argument"); \
		} \
	} catch (const std::invalid_argument& e){ \
		printf( "> ERROR: %s\n", e.what() ); \
		return 1; \
	} catch (...){ \
		printf("> ERROR: Invalid arguments\n"); \
		return 1; \
	}

#define TCPDUMP_MAGIC     0xa1b2c3d4
#define LINKTYPE_ETHERNET 1

#pragma pack(push,1)
//! PCAP File Header
struct PCAPFileHeader {
  std::uint32_t magic;
  std::uint16_t version_major;
  std::uint16_t version_minor;
  std::int32_t  thiszone;       /* gmt to local correction */
  std::uint32_t sigfigs;        /* accuracy of timestamps */
  std::uint32_t snaplen;        /* max length saved portion of each pkt */
  std::uint32_t linktype;       /* data link type (LINKTYPE_*) */
};

//! PCAP Packet Header
struct PCAPPacketHeader {
  std::uint32_t   ts_sec;
  std::uint32_t   ts_usec;
  std::uint32_t   caplen;
  std::uint32_t   len;
};
#pragma pack(pop)
