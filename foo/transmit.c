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

#include "tcpdump.h"

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

void print_hex(const char *string, size_t len)
{
        unsigned char *p = (unsigned char *) string;

        for (int i=0; i < len; ++i) {
                if (! (i % 16) && i)
                        fprintf(stderr, "\n");

                fprintf(stderr, "0x%02x ", p[i]);
        }
        fprintf(stderr, "\n\n");
}

static int monitor_header_length(unsigned char *packet_buff, ssize_t buff_len, int32_t hw_type)
{
  struct radiotap_header *radiotap_hdr;
  switch (hw_type) {
  case ARPHRD_IEEE80211_PRISM:
    if (buff_len <= (ssize_t)PRISM_HEADER_LEN)
      return -1;
    else
      return PRISM_HEADER_LEN;

  case ARPHRD_IEEE80211_RADIOTAP:
    if (buff_len <= (ssize_t)RADIOTAP_HEADER_LEN)
      return -1;

    radiotap_hdr = (struct radiotap_header*)packet_buff;
    if (buff_len <= le16toh(radiotap_hdr->it_len))
      return -1;
    else
      return le16toh(radiotap_hdr->it_len);
  }

  return -1;
}

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

int main(int argc, char *argv[]) {

  struct timeval tv;
  struct dump_if *dump_if, *dump_if_tmp;
  fd_set wait_sockets, tmp_wait_sockets;
  ssize_t write_len;
  ssize_t read_len;
  unsigned char packet_buff[2000];
  unsigned char payload[1024];

  int ret = EXIT_FAILURE, res, optchar, found_args = 1, max_sock = 0, tmp;
  int monitor_header_len = -1;

  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);

  FD_ZERO(&wait_sockets);

  fprintf(stderr, "Going to listen on: %s", argv[1]);
  dump_if = create_dump_interface(argv[1]);
  if (!dump_if) {
    close(dump_if->raw_sock);
    free(dump_if);
    return -1;
  }

  if (dump_if->raw_sock > max_sock) {
    max_sock = dump_if->raw_sock;
  }

  FD_SET(dump_if->raw_sock, &wait_sockets);

  //TODO use select on STDIN_FILENO to trigger read
  while(read_len = read(STDIN_FILENO, &payload, 1024), read_len > 0 && !is_aborted) {

    switch (dump_if->hw_type) {
    case ARPHRD_ETHER:
      //parse_eth_hdr(packet_buff, read_len, read_opt, 0);
      break;
    case ARPHRD_IEEE80211_PRISM:
    case ARPHRD_IEEE80211_RADIOTAP:
      //send foo here
      fprintf(stderr, "sending payload (%i bytes)\n", read_len);

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

      struct ieee80211_radiotap_header header;
      header.it_version = 0x00;
      header.it_pad = 0x00;
      header.it_len = sizeof(header);
      header.it_present = 0;
      header.it_present |= (1 << 10) | (1 << 15) | (1<<19);
      header.tx_flags = 0x0800;
      header.known = MCS_KNOWN;
      header.flags = 0;
      header.flags |= IEEE80211_RADIOTAP_MCS_BW_20;
      header.mcs = 2;
      header.tx_power = 0;

      static char u8aRadiotapHeader[] = {
        0x00, 0x00, // <-- radiotap version
        0x0d, 0x00, // <- radiotap header length
        0x00, 0x80, 0x08, 0x00, // <-- radiotap present flags:  RADIOTAP_TX_FLAGS + RADIOTAP_MCS
        0x08, 0x00,  // RADIOTAP_F_TX_NOACK
        MCS_KNOWN , 0x00, 0x00 // bitmap, flags, mcs_index
      };
      uint8_t flags = 0;
      flags |= IEEE80211_RADIOTAP_MCS_BW_20;
      u8aRadiotapHeader[MCS_FLAGS_OFF] = flags;
      u8aRadiotapHeader[MCS_IDX_OFF] = 1;
      static const char ieee_hdr[] = {
        0x08, 0x01, 0x00, 0x00,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0x13, 0x22, 0x33, 0x44, 0x55, 0x66,
        0x13, 0x22, 0x33, 0x44, 0x55, 0x66,
        0x10, 0x86,
      };

      //ieee_hdr.frame_control = (2 << 2 | 0 << 4) << 8 | 0x02 ;
      //ieee_hdr.duration_id = 0xffff;
      //unsigned static char addr[] = { 0x13, 0x22, 0x33, 0x44, 0x55, 0x00 };
      //memcpy(ieee_hdr.addr1, addr, ETH_ALEN);
      //memcpy(ieee_hdr.addr2, addr, ETH_ALEN);
      //memcpy(ieee_hdr.addr3, addr, ETH_ALEN);
      //ieee_hdr.seq_ctrl = 0;
      //src, dst, size
      //memcpy(packet_buff, u8aRadiotapHeader, sizeof(u8aRadiotapHeader));
      memcpy(packet_buff, &header, sizeof(header));
      memcpy(packet_buff + sizeof(header), ieee_hdr, sizeof(ieee_hdr));
      memcpy(packet_buff + sizeof(header) + sizeof(ieee_hdr), payload, read_len);


      ret = send(dump_if->raw_sock, packet_buff, sizeof(header) + sizeof(ieee_hdr) + read_len, 0);
      if(ret == -1) {
        fprintf(stderr, "error sending palyload\n");
        fprintf(stderr, "%s\n", strerror(errno));
      }
      break;
    default:
      fprintf(stderr, "SHOULD_NOT_HAPPEN\n");
      /* should not happen */
      break;
    }
  }
}
