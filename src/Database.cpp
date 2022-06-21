#include "Database.h"
#include <stdio.h>
#include <string>
#include <cstddef>
#include "Arduino.h"

Database::Database() {

}

bool Database::init() {
  return true;
}

void Database::add(uint8_t *addr, char *ssid) {
  if(count >= MAX_SSIDs) {
    printf("Restarting counter...\n");
    count = 0;
  }
  printf("Adding... %s %s\n", ssid, this->mac2str(addr));
  memcpy(&ssids[count].mac, addr, 6);
  memcpy(&ssids[count].ssid, ssid, strlen(ssid));
  count++;
  //this->print();
}

char *Database::mac2str(const uint8_t *addr) {
  static char buf[18];
  snprintf( buf, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
    addr[0], addr[1],
    addr[2], addr[3],
    addr[4], addr[5]
  );
  return buf;
}

bool Database::isRandomMac(char *mac) {
  if(mac[1] == '2' || mac[1] == '6' || mac[1] == 'a' || mac[1] == 'e') {
    return true;
  }
  return false;
}

void Database::print() {
  int u = 0;
  printf("----------------\n");
  for (u = 0; u < count; u++) {
    printf("PRINT: %i %s %s\n", u, ssids[u].ssid, this->mac2str(ssids[u].mac));
  }
  printf("----------------\n");
} 

int Database::macExists(uint8_t *addr) {
  int u = 0;
  for (u = 0; u < count; u++) {
    //printf("Comparing... %s %s\n", this->mac2str(addr), this->mac2str(ssids[u].mac));
    if (memcmp(ssids[u].mac, addr, 6) == 0)  {
      return u;
    }
  }
  return -1;
}

int Database::ssidExists(char *ssid) {
  int u = 0;
  for (u = 0; u < count; u++) {
    if (memcmp(ssids[u].ssid, ssid, strlen(ssid)) == 0)  {
      return u;
    }
  }
  return -1;
}

ssid_info Database::getInfo(int u) {
  return ssids[u];
}
