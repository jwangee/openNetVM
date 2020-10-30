
#include "chacha.h"

int chacha_payload_offset = 20;
int chacha_rounds = 20;
uint8_t tc_key[32];
uint8_t tc_iv[8];
chacha_ctx chacha_local_ctx;

#define DEFAULT_CHACHA_ROUNDS 20
#define CHACHA_DATA_LOOPS 23 // 1500 / (512/8)

// Basic 32-bit operators.
#define ROTATE(v,c) ((uint32_t)((v) << (c)) | ((v) >> (32 - (c))))
#define XOR(v,w) ((v) ^ (w))
#define PLUS(v,w) ((uint32_t)((v) + (w)))
#define PLUSONE(v) (PLUS((v), 1))

// Little endian machine assumed (x86-64).
#define U32TO8_LITTLE(p, v) (((uint32_t*)(p))[0] = v)
#define U8TO32_LITTLE(p) (((uint32_t*)(p))[0])
#define QUARTERROUND(a, b, c, d) \
  x[a] = PLUS(x[a],x[b]); x[d] = ROTATE(XOR(x[d],x[a]),16); \
  x[c] = PLUS(x[c],x[d]); x[b] = ROTATE(XOR(x[b],x[c]),12); \
  x[a] = PLUS(x[a],x[b]); x[d] = ROTATE(XOR(x[d],x[a]), 8); \
  x[c] = PLUS(x[c],x[d]); x[b] = ROTATE(XOR(x[b],x[c]), 7);

//------------------------------------------------------------------
// Constants.
//------------------------------------------------------------------
const uint8_t SIGMA[17] = "expand 32-byte k";
const uint8_t TAU[17]   = "expand 16-byte k";
const uint8_t DEFAULT_CHACHA_KEY[32] =
                {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
const uint8_t DEFAULT_CHACHA_IV[8] = 
                {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};


// Two external functions.
void chacha_module_init() {
  memcpy(tc_key, DEFAULT_CHACHA_KEY, sizeof(DEFAULT_CHACHA_KEY));
  memcpy(tc_iv, DEFAULT_CHACHA_IV, sizeof(DEFAULT_CHACHA_IV));
}

void chacha_process_packet(char* payload, int payload_size) {
  chacha_init_ctx(&chacha_local_ctx, chacha_rounds);
  chacha_init(&chacha_local_ctx, tc_key, 128, tc_iv);

  char* payload_pos = NULL;
  for(int byte_cnt = 0; byte_cnt + 512/8 <= payload_size; byte_cnt += 512/8) {
    payload_pos = (char *)(payload + byte_cnt);
    chacha_next(&chacha_local_ctx, (uint8_t *)payload_pos, (uint8_t *)(payload_pos + 512/8));
  }
  return;
}

//------------------------------------------------------------------
// init_ctx()
//
// Init a given ChaCha context by setting state to zero and
// setting the given number of rounds.
//------------------------------------------------------------------
void chacha_init_ctx(chacha_ctx *ctx, uint8_t rounds) {
  uint8_t i;
  for (i = 0 ; i < 16 ; ++i) {
    ctx->state[i] = 0;
  }
  ctx->rounds = rounds;
}

//------------------------------------------------------------------
// chacha_doublerounds()
//
// Perform rounds/2 number of chacha_doublerounds.
// TODO: Change output format to 16 words.
//------------------------------------------------------------------
void chacha_doublerounds(uint8_t output[64], const uint32_t input[16], uint8_t rounds) {
  uint32_t x[16];
  int32_t i;
  for (i = 0;i < 16; ++i) {
    x[i] = input[i];
  }

  for (i = rounds ; i > 0; i -= 2) {
    QUARTERROUND( 0, 4, 8,12)
    QUARTERROUND( 1, 5, 9,13)
    QUARTERROUND( 2, 6,10,14)
    QUARTERROUND( 3, 7,11,15)

    QUARTERROUND( 0, 5,10,15)
    QUARTERROUND( 1, 6,11,12)
    QUARTERROUND( 2, 7, 8,13)
    QUARTERROUND( 3, 4, 9,14)
  }

  for (i = 0; i < 16; ++i) {
    x[i] = PLUS(x[i], input[i]);
  }
  for (i = 0; i < 16; ++i) {
    U32TO8_LITTLE(output + 4 * i, x[i]);
  }
}

//------------------------------------------------------------------
// init()
//
// Initializes the given cipher context with key, iv and constants.
// This also resets the block counter.
//------------------------------------------------------------------
void chacha_init(chacha_ctx *x, uint8_t *key, uint32_t keylen, uint8_t *iv)
{
  if (keylen == 256) {
  // 256 bit key.
  x->state[0]  = U8TO32_LITTLE(SIGMA + 0);
  x->state[1]  = U8TO32_LITTLE(SIGMA + 4);
  x->state[2]  = U8TO32_LITTLE(SIGMA + 8);
  x->state[3]  = U8TO32_LITTLE(SIGMA + 12);
  x->state[4]  = U8TO32_LITTLE(key + 0);
  x->state[5]  = U8TO32_LITTLE(key + 4);
  x->state[6]  = U8TO32_LITTLE(key + 8);
  x->state[7]  = U8TO32_LITTLE(key + 12);
  x->state[8]  = U8TO32_LITTLE(key + 16);
  x->state[9]  = U8TO32_LITTLE(key + 20);
  x->state[10] = U8TO32_LITTLE(key + 24);
  x->state[11] = U8TO32_LITTLE(key + 28);
  }

  else {
  // 128 bit key.
  x->state[0]  = U8TO32_LITTLE(TAU + 0);
  x->state[1]  = U8TO32_LITTLE(TAU + 4);
  x->state[2]  = U8TO32_LITTLE(TAU + 8);
  x->state[3]  = U8TO32_LITTLE(TAU + 12);
  x->state[4]  = U8TO32_LITTLE(key + 0);
  x->state[5]  = U8TO32_LITTLE(key + 4);
  x->state[6]  = U8TO32_LITTLE(key + 8);
  x->state[7]  = U8TO32_LITTLE(key + 12);
  x->state[8]  = U8TO32_LITTLE(key + 0);
  x->state[9]  = U8TO32_LITTLE(key + 4);
  x->state[10] = U8TO32_LITTLE(key + 8);
  x->state[11] = U8TO32_LITTLE(key + 12);
  }

  // Reset block counter and add IV to state.
  x->state[12] = 0;
  x->state[13] = 0;
  x->state[14] = U8TO32_LITTLE(iv + 0);
  x->state[15] = U8TO32_LITTLE(iv + 4);
}

//------------------------------------------------------------------
// next()
//
// Given a pointer to the next block m of 64 cleartext bytes will
// use the given context to transform (encrypt/decrypt) the
// block. The result will be stored in c (outdated).
//------------------------------------------------------------------
void chacha_next(chacha_ctx *ctx, uint8_t *m, uint8_t *m_end) {
  // Temporary internal state x.
  uint8_t x[64];
  uint8_t i;

  // Update the internal state and increase the block counter.
  chacha_doublerounds(x, ctx->state, ctx->rounds);
  ctx->state[12] = PLUSONE(ctx->state[12]);
  if (!ctx->state[12]) {
    ctx->state[13] = PLUSONE(ctx->state[13]);
  }

  // XOR the input block with the new temporal state to
  // create the transformed block.
  if (m + 64 > m_end) {
    return;
  }

  // Do not store intermediate results. Instead, the function modifies
  // the packet payload directly.
  // for (i = 0 ; i < 64 ; ++i) {
  //   c[i] = m[i] ^ x[i];
  // }

  uint64_t *m_pos;
  uint64_t *x_pos;
  for (i = 0; i < 8; i++) {
  m_pos = (uint64_t*)(m) + i;
  x_pos = (uint64_t*)(x) + i;
  *m_pos ^= *x_pos;
  }
}
