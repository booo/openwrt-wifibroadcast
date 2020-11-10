#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <time.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netpacket/packet.h>

#define IEEE80211_RADIOTAP_MCS_HAVE_BW    0x01
#define IEEE80211_RADIOTAP_MCS_HAVE_MCS   0x02
#define IEEE80211_RADIOTAP_MCS_HAVE_GI    0x04
#define IEEE80211_RADIOTAP_MCS_HAVE_FMT   0x08

#define IEEE80211_RADIOTAP_MCS_BW_20    0
#define IEEE80211_RADIOTAP_MCS_BW_40    1
#define IEEE80211_RADIOTAP_MCS_BW_20L   2
#define IEEE80211_RADIOTAP_MCS_BW_20U   3
#define IEEE80211_RADIOTAP_MCS_SGI      0x04
#define IEEE80211_RADIOTAP_MCS_FMT_GF   0x08

#define IEEE80211_RADIOTAP_MCS_HAVE_FEC   0x10
#define IEEE80211_RADIOTAP_MCS_HAVE_STBC  0x20
#define IEEE80211_RADIOTAP_MCS_FEC_LDPC   0x10
#define IEEE80211_RADIOTAP_MCS_STBC_MASK  0x60
#define IEEE80211_RADIOTAP_MCS_STBC_1  1
#define IEEE80211_RADIOTAP_MCS_STBC_2  2
#define IEEE80211_RADIOTAP_MCS_STBC_3  3
#define IEEE80211_RADIOTAP_MCS_STBC_SHIFT 5

#define MCS_KNOWN (IEEE80211_RADIOTAP_MCS_HAVE_MCS | IEEE80211_RADIOTAP_MCS_HAVE_BW | IEEE80211_RADIOTAP_MCS_HAVE_GI | IEEE80211_RADIOTAP_MCS_HAVE_STBC | IEEE80211_RADIOTAP_MCS_HAVE_FEC)

// offset of MCS_FLAGS and MCS index
#define MCS_FLAGS_OFF 11
#define MCS_IDX_OFF 12

static volatile sig_atomic_t is_aborted = 0;

static void sig_handler(int sig) {
  switch (sig) {
  case SIGINT:
  case SIGTERM:
    is_aborted = 1;
    break;
  default:
    break;
  }
}

struct dump_if {
	char *dev;
	int32_t raw_sock;
	struct sockaddr_ll addr;
	int32_t hw_type;
};

static struct dump_if *create_dump_interface(char *iface) {
  struct dump_if *dump_if;
  struct ifreq req;
  int res;

  dump_if = malloc(sizeof(struct dump_if));
  if (!dump_if)
    return NULL;

  memset(dump_if, 0, sizeof(struct dump_if));

  dump_if->dev = iface;
  if (strlen(dump_if->dev) > IFNAMSIZ - 1) {
    fprintf(stderr, "Error - interface name too long: %s\n", dump_if->dev);
    goto free_dumpif;
  }

  dump_if->raw_sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (dump_if->raw_sock < 0) {
    perror("Error - can't create raw socket");
    goto free_dumpif;
  }

  memset(&req, 0, sizeof (struct ifreq));
  strncpy(req.ifr_name, dump_if->dev, IFNAMSIZ);
  req.ifr_name[sizeof(req.ifr_name) - 1] = '\0';

  res = ioctl(dump_if->raw_sock, SIOCGIFHWADDR, &req);
  if (res < 0) {
    perror("Error - can't create raw socket (SIOCGIFHWADDR)");
    goto close_socket;
  }

  dump_if->hw_type = req.ifr_hwaddr.sa_family;

  switch (dump_if->hw_type) {
  case ARPHRD_ETHER:
  case ARPHRD_IEEE80211_PRISM:
  case ARPHRD_IEEE80211_RADIOTAP:
    break;
  default:
    fprintf(stderr, "Error - interface '%s' is of unknown type: %i\n", dump_if->dev, dump_if->hw_type);
    goto close_socket;
  }

  memset(&req, 0, sizeof (struct ifreq));
  strncpy(req.ifr_name, dump_if->dev, IFNAMSIZ);
  req.ifr_name[sizeof(req.ifr_name) - 1] = '\0';

  res = ioctl(dump_if->raw_sock, SIOCGIFINDEX, &req);
  if (res < 0) {
    perror("Error - can't create raw socket (SIOCGIFINDEX)");
    goto close_socket;
  }

  dump_if->addr.sll_family   = AF_PACKET;
  dump_if->addr.sll_protocol = htons(ETH_P_ALL);
  dump_if->addr.sll_ifindex  = req.ifr_ifindex;

  res = bind(dump_if->raw_sock, (struct sockaddr *)&dump_if->addr, sizeof(struct sockaddr_ll));
  if (res < 0) {
    perror("Error - can't bind raw socket");
    goto close_socket;
  }

  return dump_if;

close_socket:
  close(dump_if->raw_sock);
free_dumpif:
  free(dump_if);

  return NULL;
}

struct ieee80211_radiotap_header {
  u_int8_t        it_version;     /* set to 0 */
  u_int8_t        it_pad;
  u_int16_t       it_len;         /* entire length */
  u_int32_t       it_present;     /* fields present */
  int8_t          tx_power;
  uint8_t         pad_for_tx_flags;
  u_int16_t       tx_flags;
  u_int8_t        known;
  u_int8_t        flags;
  u_int8_t        mcs;
} __attribute__((__packed__));

static const char ieee_hdr[] = {
  0x08, 0x01, 0x00, 0x00,
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  0x13, 0x22, 0x33, 0x44, 0x55, 0x66,
  0x13, 0x22, 0x33, 0x44, 0x55, 0x66,
  0x10, 0x86,
};

int main(int argc, char *argv[]) {

  struct dump_if *dump_if;
  ssize_t read_len;
  unsigned char packet_buff[2000];

  int ret = EXIT_FAILURE;

  struct ieee80211_radiotap_header header;

  int opt;
  int mcs_index = 0;
  int tx_power = 0;

  while((opt = getopt(argc, argv, "m:p:")) != -1) {
    switch(opt) {
      case 'm':
        mcs_index = atoi(optarg);
        break;
      case 'p':
        tx_power = atoi(optarg);
        break;
      default:
        fprintf(stderr, "Usage: %s [-m mcs_index -p tx_power] interface\n", argv[0]);
        exit(EXIT_FAILURE);
    }
  }
  if (optind == argc) {
    fprintf(stderr, "Interface argument required!\n");
    fprintf(stderr, "Usage: %s [-m mcs_index -p tx_power] interface\n", argv[0]);
    exit(EXIT_FAILURE);
  }

  header.it_version = 0x00;
  header.it_pad = 0x00;
  header.it_len = sizeof(header);
  header.it_present = 0;
  header.it_present |= (1 << 10) | (1 << 15) | (1<<19);
  header.tx_flags = 0x0800;
  header.known = MCS_KNOWN;
  header.flags = 0;
  header.flags |= IEEE80211_RADIOTAP_MCS_BW_20;
  header.mcs = mcs_index;
  header.tx_power = tx_power;

  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);

  fprintf(stderr, "Going to listen on: %s\n", argv[optind]);
  dump_if = create_dump_interface(argv[optind]);
  if (!dump_if) {
    close(dump_if->raw_sock);
    free(dump_if);
    return -1;
  }

  if (dump_if->hw_type != ARPHRD_IEEE80211_RADIOTAP) {
    return -1;
  }

  // copy headers to packet buffer once at the start
  memcpy(packet_buff, &header, sizeof(header));
  memcpy(packet_buff + sizeof(header), ieee_hdr, sizeof(ieee_hdr));

  // read payload data to packet buffer
  // payload length is read_len
  while(read_len = read(STDIN_FILENO, packet_buff + sizeof(header) + sizeof(ieee_hdr), 1024), read_len > 0 && !is_aborted) {

      //send foo here
      fprintf(stderr, "sending payload (%li bytes)\n", read_len);

      ret = send(dump_if->raw_sock, packet_buff, sizeof(header) + sizeof(ieee_hdr) + read_len, 0);
      if(ret == -1) {
        fprintf(stderr, "error sending palyload\n");
        fprintf(stderr, "%s\n", strerror(errno));
      }
  }
}
