#ifndef VendorCachee_h
#define VendorCache_h

#include <stdint.h>
#include "Arduino.h"

#define SHORT_MAC_LEN 6
#define MAX_FIELD_LEN 7
#define OUICACHE_SIZE 5000

static void copy(char* dest, const char* source, byte maxlen)
{
  if( source == nullptr || source == NULL ) return;
  byte sourcelen = strlen(source);
  if( sourcelen < maxlen ) {
    maxlen = sourcelen;
  }
  memcpy( dest, source, maxlen );
  if( maxlen > 0 && dest[maxlen-1]!='\0' ) {
    dest[maxlen] = '\0'; // append null terminate
  }
}

struct oui
{
  char *mac;
  char *vendor;
  
  void init() {
    mac        = (char*)calloc(SHORT_MAC_LEN+1, sizeof(char));
    vendor = (char*)calloc(MAX_FIELD_LEN+1, sizeof(char));
  }
  
  void setMac( const char* _mac ) {
    copy( mac, _mac, SHORT_MAC_LEN );
  }
  
  void setVendor( const char* _vendor ) {
    copy( vendor, _vendor, MAX_FIELD_LEN );
  }
};

class VendorCache {
  public:
    VendorCache();
    bool init();
    void setCache(uint16_t cacheindex, const char* shortmac, const char* vendor);

  private:
    oui ouicache[OUICACHE_SIZE];
};

#endif
