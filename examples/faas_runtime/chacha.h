
#ifndef _CHACHA_H_
#define _CHACHA_H_

#include <string.h>
#include <stdint.h>

extern int chacha_payload_offset;
extern int chacha_rounds;
extern uint8_t tc_key[32];
extern uint8_t tc_iv[8];

// the chacha cipher context struct
typedef struct {
  uint32_t state[16];
  uint8_t rounds;
} chacha_ctx;

void chacha_module_init();

void chacha_process_packet(char* payload, int payload_size);

void chacha_init_ctx(chacha_ctx *ctx, uint8_t rounds);

void chacha_doublerounds(uint8_t output[64], 
    const uint32_t input[16], uint8_t rounds);

void chacha_init(chacha_ctx *x, uint8_t *key, uint32_t keylen, uint8_t *iv);

void chacha_next(chacha_ctx *ctx, uint8_t *m, uint8_t *m_end);

#endif // _CHACHA_H_
