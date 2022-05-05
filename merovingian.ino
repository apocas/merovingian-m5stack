#include "freertos/FreeRTOS.h"
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "esp_system.h"
#include "esp_event.h"
#include "nvs_flash.h"
#include "driver/gpio.h"
#include <M5Stack.h>
#include <M5GFX.h>

#include "Types.h"

M5GFX display;

M5Canvas canvas(&display);

#define WIFI_CHANNEL_SWITCH_INTERVAL  (500)
#define WIFI_CHANNEL_MAX               (13)

#define SSID_MAX_LEN (32+1)

uint8_t level = 0, channel = 1;

static wifi_country_t wifi_country = {.cc="CN", .schan = 1, .nchan = 13};

typedef struct {
  unsigned frame_ctrl:16;
  unsigned duration_id:16;
  uint8_t addr1[6];
  uint8_t addr2[6];
  uint8_t addr3[6];
  unsigned sequence_ctrl:16;
  uint8_t addr4[6];
} wifi_ieee80211_mac_hdr_t;

typedef struct {
  wifi_ieee80211_mac_hdr_t hdr;
  uint8_t payload[0];
} wifi_ieee80211_packet_t;

static esp_err_t event_handler(void *ctx, system_event_t *event);
static void initSniffer(void);
static const char *wifi_sniffer_packet_type2str(wifi_promiscuous_pkt_type_t type);
static void mainSniffer(void *buff, wifi_promiscuous_pkt_type_t type);
static void getSSID(unsigned char *data, char ssid[SSID_MAX_LEN], uint8_t ssid_len);
static void verifySSID(unsigned char *data, uint8_t ssid_len);

esp_err_t event_handler(void *ctx, system_event_t *event)
{
  return ESP_OK;
}

void initSniffer(void)
{
  nvs_flash_init();
  tcpip_adapter_init();
  ESP_ERROR_CHECK( esp_event_loop_init(event_handler, NULL) );
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK( esp_wifi_init(&cfg) );
  ESP_ERROR_CHECK( esp_wifi_set_country(&wifi_country) );
  ESP_ERROR_CHECK( esp_wifi_set_storage(WIFI_STORAGE_RAM) );
  ESP_ERROR_CHECK( esp_wifi_set_mode(WIFI_MODE_NULL) );
  ESP_ERROR_CHECK( esp_wifi_start() );
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&mainSniffer);
}

const char * wifi_sniffer_packet_type2str(wifi_promiscuous_pkt_type_t type)
{
  switch(type) {
    case WIFI_PKT_MGMT: return "MGMT";
    case WIFI_PKT_DATA: return "DATA";
  default:
    case WIFI_PKT_MISC: return "MISC";
  }
}

static void getSSID(unsigned char *data, char ssid[SSID_MAX_LEN], int index)
{
  int i, j;

  uint8_t ssid_len = data[index];

  for(i=index+1, j=0; i<index+1+ssid_len; i++, j++){
    ssid[j] = data[i];
  }

  ssid[j] = '\0';
}

static boolean verifySSID(unsigned char *data, int index)
{
  int u = 0;
  uint8_t SSID_length = data[index];
  if (SSID_length>32) return false;
  if (SSID_length == 0) return false;

  for (u =0; u<SSID_length;u++) {
    if (!isprint(data[index+1+u])) {
      return false;
    }
    if (!isAscii(data[index+1+u])) {
      return false;
    }
  }

  return true;
}

char *ether_ntoa_r( const uint8_t *addr, char * buf )
{
  snprintf( buf, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
    addr[0], addr[1],
    addr[2], addr[3],
    addr[4], addr[5]
  );
  return buf;
}

char *ether_ntoa( const uint8_t *addr )
{
  static char buf[18];
  return ether_ntoa_r( addr, buf );
}


void mainSniffer(void* buff, wifi_promiscuous_pkt_type_t type)
{
  wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buff;
  wifi_pkt_rx_ctrl_t ctrl = (wifi_pkt_rx_ctrl_t)ppkt->rx_ctrl;
  
  wifi_ieee80211_packet_t *ipkt = (wifi_ieee80211_packet_t *)ppkt->payload;
  wifi_ieee80211_mac_hdr_t *hdr = &ipkt->hdr;

  if (type == WIFI_PKT_MISC) return;
  if (ctrl.sig_len > 293) return;

  if (type == WIFI_PKT_MGMT) {
    //DEAUTH
    if (hdr->frame_ctrl == SUBTYPE_DIASSOC || hdr->frame_ctrl == SUBTYPE_DEAUTH ) {
      canvas.setTextColor(RED);
      canvas.printf("C=%02d S=%02d F=%s T=%s (DEAUTH)\n",
        ppkt->rx_ctrl.channel,
        ppkt->rx_ctrl.rssi,
        ether_ntoa(hdr->addr3),
        ether_ntoa(hdr->addr1)
      );
    }

    //BEACON
    if (hdr->frame_ctrl == SUBTYPE_BEACONS) {
      char ssid[SSID_MAX_LEN] = "\0";
  
      if(verifySSID(ppkt->payload, 37) == true) {
        getSSID(ppkt->payload, ssid, 37);
      } else {
        return;
      }

      canvas.setTextColor(LIGHTGREY);
      canvas.printf("SSID=%s C=%02d S=%02d F=%s (BEACON)\n",
        ssid,
        ppkt->rx_ctrl.channel,
        ppkt->rx_ctrl.rssi,
        ether_ntoa(hdr->addr2)
      );
    }

    //PROBE
    if (hdr->frame_ctrl == SUBTYPE_PROBE_REQUEST) {
      char ssid[SSID_MAX_LEN] = "\0";
  
      if(verifySSID(ppkt->payload, 25) == true) {
        getSSID(ppkt->payload, ssid, 25);
      } else {
        return;
      }

      canvas.setTextColor(GREEN);
      canvas.printf("SSID=%s C=%02d S=%02d F=%s (PROBE)\n",
        ssid,
        ppkt->rx_ctrl.channel,
        ppkt->rx_ctrl.rssi,
        ether_ntoa(hdr->addr2)
      );
    }
  }

  //EAPOL
  if (( (ppkt->payload[30] == 0x88 && ppkt->payload[31] == 0x8e)|| ( ppkt->payload[32] == 0x88 && ppkt->payload[33] == 0x8e) )){
    canvas.setTextColor(YELLOW);
    canvas.printf("C=%02d S=%02d F=%s (EAPOL)\n",
      ppkt->rx_ctrl.channel,
      ppkt->rx_ctrl.rssi,
      ether_ntoa(hdr->addr3)
    );
    M5.Speaker.tone(NOTE_DH2, 200);
  }
}

void setup() {
  M5.begin();

  M5.Power.begin();

  M5.Speaker.begin();

  display.begin();
  if (display.isEPD())
  {
    display.setEpdMode(epd_mode_t::epd_fastest);
    display.invertDisplay(true);
    display.clear(TFT_BLACK);
  }
  if (display.width() < display.height())
  {
    display.setRotation(display.getRotation() ^ 1);
  }

  canvas.setColorDepth(8);
  canvas.createSprite(display.width(), display.height());
  canvas.setTextSize(1);
  canvas.setTextScroll(true);

  canvas.printf("Merovingian booting...\n");

  initSniffer();

  canvas.printf("Running...\n");

  M5.Speaker.tone(NOTE_DH2, 200);

  canvas.pushSprite(0, 0);

  xTaskCreate( uiTask, "uiTask", 8192, NULL, 16, NULL);
  xTaskCreate( wifiTask, "wifiTask", 8192, NULL, 16, NULL);
}

void uiTask( void * p ) {
  while(true){
    canvas.pushSprite(0, 0);
    M5.Speaker.update();
    delay(100);
  }
}

void wifiTask( void * p ) {
  while(true){
    vTaskDelay(WIFI_CHANNEL_SWITCH_INTERVAL / portTICK_PERIOD_MS);
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    channel = (channel % WIFI_CHANNEL_MAX) + 1;
  }
}

void loop() {
  vTaskSuspend(NULL);
}
