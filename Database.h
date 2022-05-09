#ifndef Database_h
#define Database_h

#include <stdint.h>

#define MAX_SSIDs 1000

struct ssid_info
{
  uint8_t mac[6];
  char ssid[33];
  bool    ssid_eapol;
};

class Database {
  public:
    Database();
    bool init();
    void add(unsigned char *addr, char *ssid);
    int macExists(unsigned char *addr);
    int ssidExists(char *ssid);
    void print();
    char *mac2str(const uint8_t *addr);
    
  private:
    ssid_info ssids[MAX_SSIDs];
    uint32_t count = 0;
};

#endif
