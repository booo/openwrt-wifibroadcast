#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

int main(int argc, char *argv[]) {
  struct packet {
    char data[1020];
    uint32_t seq;
  };
  struct packet p;
  p.seq = 0;
  memset(p.data, 0, sizeof(p.data));
  while(1) {
    write(STDOUT_FILENO, &p, sizeof(p));
    p.seq = p.seq + 1;
  }
}
