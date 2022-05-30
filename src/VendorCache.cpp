#include "VendorCache.h"
#include <stdio.h>
#include <string>
#include <cstddef>
#include "Arduino.h"

VendorCache::VendorCache() {

}

bool VendorCache::init() {
  for(uint16_t i=0; i < OUICACHE_SIZE; i++) {
    ouicache[i].init( );
  }
  
  return true;
}

void VendorCache::setCache(uint16_t cacheindex, const char* shortmac, const char* vendor) {
  memset(ouicache[cacheindex].mac, '\0', SHORT_MAC_LEN+1);
  memcpy(ouicache[cacheindex].mac, shortmac, strlen(shortmac));
  memset(ouicache[cacheindex].vendor, '\0', MAX_FIELD_LEN+1);
  memcpy(ouicache[cacheindex].vendor, vendor, strlen(vendor));
}
