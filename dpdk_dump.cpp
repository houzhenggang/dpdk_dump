#include "dpdk_dump.h"

void printHelp() {
  printf(
    "\n\t\tDPDK Dump v16.06.29-1\n"
    "\n"
    "    Usage: dpdk_dump [Arguments]\n"
    "\n"
    "    Arguments:\n"
    "        -p [Number]    - DPDK port number           (Default: 0)\n"
    "        -a [Args]      - DPDK extra arguments       (Default: none)\n"
    "        -mc [Count]    - DPDK memory pool capacity  (Default: 16383)\n"
    "        -ms [Size]     - DPDK memory pool item size (Default: auto from MTU)\n"
    "        -mtu [Size]    - MTU size                   (Default: 1500)\n"
    "        -rc [Count]    - Receive buffer capacity    (Default: 2048)\n"
    "        -f [Path]      - Output file path\n"
    "\n"
    "    Examples:\n"
    "\n"
    "        1) Run standalone on: device = 0000:01:00.1, core id = 1, memory = 1024M\n"
    "            dpdk_dump -f dump.pcap -a \"--file-prefix dpdk_dump -m 1024 -c 0x01 -w 0000:01:00.1\"\n"
    "\n"
  );
}

//! Application config
struct AppConfig {
  //! DPDK Port configuration
  dpdkpp::PortConfig  port_config;

  //! Output file path
  std::string         out_file_path;

  //! Memory pool items
  std::size_t         mempool_items_count;

  //! Memory item size
  std::uint32_t       mempool_item_size;

  //! DPDK extra arguments
  std::string         dpdk_args;
};



//! DPDK Port implementation
class DPDKPort : public dpdkpp::Port {
public:

  //! Constructor
  DPDKPort(AppConfig& config)
  : config_(config)
  , file_(nullptr)
  , stats_activity_(this, &DPDKPort::__statsActivity__)
  {}

  //! Open output file
  bool openDump() {
    // - Open file
    file_ = fopen(config_.out_file_path.c_str(), "w");
    if (!file_) return false;

    // - Write PCAP header
    PCAPFileHeader header;
    header.magic          = TCPDUMP_MAGIC;
    header.sigfigs        = 0;
    header.version_major  = 2;
    header.version_minor  = 4;
    header.snaplen        = USHRT_MAX;
    header.thiszone       = 0;
    header.linktype       = LINKTYPE_ETHERNET;
    fwrite(&header, sizeof(header), 1, file_);
    fflush(file_);
    return true;
  }

  //! Close dump file
  void closeDump() {
    if (file_) {
      fclose(file_);
      file_ = nullptr;
    }
  }
  //! On packets received
  void onReceive(std::uint8_t port_id, uint16_t queue_id, rte_mbuf *packets[], std::uint16_t packets_count, uint16_t max_packets) override {
    if (file_) {
      // - Get current time
      timeval ts;
      gettimeofday(&ts, NULL);

      // - Write each packet
      for (std::uint16_t i = 0; i < packets_count; i++) {
        // - Fill header
        PCAPPacketHeader header;
        header.len        = rte_pktmbuf_pkt_len(packets[i]);
        header.caplen     = rte_pktmbuf_data_len(packets[i]);
        header.ts_sec  = ts.tv_sec;
        header.ts_usec = ts.tv_usec;

        // - Write packet
        fwrite(&header, sizeof(header), 1, file_);
        fwrite(rte_pktmbuf_mtod(packets[i],char*), header.len, 1, file_);
        fflush(file_);
      }
    }
    // - Release packets
    releasePacketsBulk(packets, packets_count);
  }

  //! Start stats
  void startStats() {
    stats_activity_.start();
  }

  //! Stop stats
  void stopStats() {
    stats_activity_.stop();
  }

  //! Stats activity
  void __statsActivity__() {
    while (stats_activity_.running()) {
      stats_activity_.__cancel_point__();

      // - Meansure time in seconds
      timespec current_timestamp;
      clock_gettime(CLOCK_REALTIME, &current_timestamp);
      double time_elapsed =
        (current_timestamp.tv_sec - stats_bytes_received_last_meansure_time_.tv_sec)
        +
        (current_timestamp.tv_nsec - stats_bytes_received_last_meansure_time_.tv_nsec) / 1000000000.
      ;

      // - Store receiving speed
      const rte_eth_stats& nic_stats = getStats();
      if (time_elapsed) {
        // - Get RX rate (bits/sec)
        long double rx_rate = static_cast<double>((nic_stats.ibytes - stats_bytes_received_last_meansure_) / time_elapsed) * 8;

        // - Scale RX rate
        std::string   rx_rate_name;
        std::uint64_t rx_rate_divider = 1;
        if (rx_rate < 1024) {
          rx_rate_name = "bit";
        } else if (rx_rate < 1024 * 1024) {
          rx_rate_name    = "Kbit";
          rx_rate_divider = 1024;
        } else if (rx_rate < 1024 * 1024 * 1024) {
          rx_rate_name    = "Mbit";
          rx_rate_divider = 1024 * 1024;
        } else {
          rx_rate_name    = "Gbit";
          rx_rate_divider = 1024 * 1024 * 1024;
        }
        rx_rate = rx_rate / rx_rate_divider;

        printf( "> Link: %s | Speed: %.2Lf %s/sec | Packets: %ld | Bytes: %ld | Errors: %ld\n",
          getLinkStatus() ? "YES" : "NO ", rx_rate, rx_rate_name.c_str(), nic_stats.ipackets, nic_stats.ibytes, nic_stats.ierrors
        );
      }

      // - Store current values
      stats_bytes_received_last_meansure_       = nic_stats.ibytes;
      stats_bytes_received_last_meansure_time_  = current_timestamp;

      // - Wait for next stats
      sleep(1);
    }
  }

private:
  //! Application config
  AppConfig&          config_;

  //! Output file
  FILE*               file_;

  //! Stats activity
  activity<DPDKPort>  stats_activity_;

  //! Last stats received bytes
  std::uint64_t       stats_bytes_received_last_meansure_;

  //! Last meansure timestam
  timespec            stats_bytes_received_last_meansure_time_;
};

//! Application running flag
bool is_app_running = true;

//! Signal handler :: INT
void onSigINT(int signal) {
  printf("> Stopping\n");
  is_app_running = false;
}


//! Entry point
int main(int argc, char **argv) {
  AppConfig config;
  // --- Set default configuration
  config.mempool_items_count          = 16383;
  config.mempool_item_size            = 0;
  config.port_config.max_payload_size = 1500;
  config.port_config.rx.buffer_size   = 2048;

  // --- Parse console arguments
  __BeginParseConsoleArguments__(printHelp)
    __OnArgument("-p") {
      // - Implicit cast to uint8_t will return string charter, so use explicit cast to <int>
      config.port_config.port_id = dynamic(__ArgValue).cast<int>();
      continue;
    }
    __OnArgument("-o") {
      config.out_file_path = __ArgValue;
      continue;
    }
    __OnArgument("-mc") {
      config.mempool_items_count = dynamic(__ArgValue);
      continue;
    }
    __OnArgument("-ms") {
      config.mempool_item_size = dynamic(__ArgValue);
      continue;
    }
    __OnArgument("-mtu") {
      config.port_config.max_payload_size = dynamic(__ArgValue);
      continue;
    }
    __OnArgument("-a") {
      config.dpdk_args = __ArgValue;
      continue;
    }
    __OnArgument("-rc") {
      config.port_config.rx.buffer_size = dynamic(__ArgValue);
      continue;
    }
    __OnArgument("-f") {
      config.out_file_path = __ArgValue;
      continue;
    }
  __EndParseConsoleArguments__

  // - Check pool item size
  if (!config.mempool_item_size) {
    config.mempool_item_size = config.port_config.max_payload_size;
    if (config.mempool_item_size < RTE_MBUF_DEFAULT_DATAROOM) config.mempool_item_size = RTE_MBUF_DEFAULT_DATAROOM;
  }
  else if (config.mempool_item_size < config.port_config.max_payload_size) throw std::invalid_argument("Memory pool item size cannot be less than MTU");

  // - Init DPDK
  if (!dpdkpp::init(config.dpdk_args)) {
    printf("> ERROR: Unable initialize DPDK\n");
    exit(1);
  }

  // - Create memory pool
  config.port_config.memory_pool = std::make_shared<dpdkpp::MemoryPool>(
    "DPDK_DUMP_POOL", config.mempool_items_count, config.mempool_item_size
  );
  if (!config.port_config.memory_pool) {
    printf("> ERROR: Unable to allocate memory pool\n");
    exit(1);
  }

  // - Init port
  DPDKPort port(config);
  port.init(&config.port_config);

  // - Open dump file
  port.openDump();

  // - Start port
  port.start();

  // - Check output file
  if (config.out_file_path.empty()) {
    printf("> WARNING: Output file not set. Will display stats only.\n");
  }

  // - Install signal handler
  std::signal(SIGINT, onSigINT);


  printf("> Capture started\n");

  // - Start stats monitor
  port.startStats();

  // - Receive data
  while (is_app_running) {
    // - Receive data
    port.receive(0);
  }
  printf("> Capture stopped\n");

  // - Stop stats monitor
  port.stopStats();

  // - Stop port
  port.stop();

  // - Close dump file
  port.closeDump();

  // - Shutdown port
  port.shutdown();
	return 0;
}
