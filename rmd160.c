/*
 * Cryptographic API.
 *
 * RIPEMD-160 - RACE Integrity Primitives Evaluation Message Digest.
 *
 * Based on the reference implementation by Antoon Bosselaers, ESAT-COSIC
 *
 * Copyright (c) 2008 Adrian-Ken Rueegsegger <ken@codelabs.ch>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 */

#include "externs.h"

static u32 digest[5];

void rmd160_init()
{
  digest[0]=0x67452301;
  digest[1]=0xefcdab89;
  digest[2]=0x98badcfe;
  digest[3]=0x10325476;
  digest[4]=0xc3d2e1f0;
}

#define K1  0x00000000
#define K2  0x5a827999
#define K3  0x6ed9eba1
#define K4  0x8f1bbcdc
#define K5  0xa953fd4e
#define KK1 0x50a28be6
#define KK2 0x5c4dd124
#define KK3 0x6d703ef3
#define KK4 0x7a6d76e9
#define KK5 0x00000000

#define F1(x, y, z) (x ^ y ^ z)		/* XOR */
#define F2(x, y, z) (z ^ (x & (y ^ z)))	/* x ? y : z */
#define F3(x, y, z) ((x | ~y) ^ z)
#define F4(x, y, z) (y ^ (z & (x ^ y)))	/* z ? x : y */
#define F5(x, y, z) (x ^ (y | ~z))

#define ROUND(a, b, c, d, e, f, k, x, s) { \
  (a) += f((b), (c), (d)) + le32(x) + (k); \
  (a) = ROL((a), (s)) + (e); \
  (c) = ROL((c), 10); \
}

static void rmd160_transform(u32 state[5], const u32 in[16])
{
  u32 aa, bb, cc, dd, ee, aaa, bbb, ccc, ddd, eee;

  /* Initialize left lane */
  aa = state[0];
  bb = state[1];
  cc = state[2];
  dd = state[3];
  ee = state[4];

  /* Initialize right lane */
  aaa = state[0];
  bbb = state[1];
  ccc = state[2];
  ddd = state[3];
  eee = state[4];

  /* round 1: left lane */
  ROUND(aa, bb, cc, dd, ee, F1, K1, in[0],  11);
  ROUND(ee, aa, bb, cc, dd, F1, K1, in[1],  14);
  ROUND(dd, ee, aa, bb, cc, F1, K1, in[2],  15);
  ROUND(cc, dd, ee, aa, bb, F1, K1, in[3],  12);
  ROUND(bb, cc, dd, ee, aa, F1, K1, in[4],   5);
  ROUND(aa, bb, cc, dd, ee, F1, K1, in[5],   8);
  ROUND(ee, aa, bb, cc, dd, F1, K1, in[6],   7);
  ROUND(dd, ee, aa, bb, cc, F1, K1, in[7],   9);
  ROUND(cc, dd, ee, aa, bb, F1, K1, in[8],  11);
  ROUND(bb, cc, dd, ee, aa, F1, K1, in[9],  13);
  ROUND(aa, bb, cc, dd, ee, F1, K1, in[10], 14);
  ROUND(ee, aa, bb, cc, dd, F1, K1, in[11], 15);
  ROUND(dd, ee, aa, bb, cc, F1, K1, in[12],  6);
  ROUND(cc, dd, ee, aa, bb, F1, K1, in[13],  7);
  ROUND(bb, cc, dd, ee, aa, F1, K1, in[14],  9);
  ROUND(aa, bb, cc, dd, ee, F1, K1, in[15],  8);

  /* round 2: left lane */
  ROUND(ee, aa, bb, cc, dd, F2, K2, in[7],   7);
  ROUND(dd, ee, aa, bb, cc, F2, K2, in[4],   6);
  ROUND(cc, dd, ee, aa, bb, F2, K2, in[13],  8);
  ROUND(bb, cc, dd, ee, aa, F2, K2, in[1],  13);
  ROUND(aa, bb, cc, dd, ee, F2, K2, in[10], 11);
  ROUND(ee, aa, bb, cc, dd, F2, K2, in[6],   9);
  ROUND(dd, ee, aa, bb, cc, F2, K2, in[15],  7);
  ROUND(cc, dd, ee, aa, bb, F2, K2, in[3],  15);
  ROUND(bb, cc, dd, ee, aa, F2, K2, in[12],  7);
  ROUND(aa, bb, cc, dd, ee, F2, K2, in[0],  12);
  ROUND(ee, aa, bb, cc, dd, F2, K2, in[9],  15);
  ROUND(dd, ee, aa, bb, cc, F2, K2, in[5],   9);
  ROUND(cc, dd, ee, aa, bb, F2, K2, in[2],  11);
  ROUND(bb, cc, dd, ee, aa, F2, K2, in[14],  7);
  ROUND(aa, bb, cc, dd, ee, F2, K2, in[11], 13);
  ROUND(ee, aa, bb, cc, dd, F2, K2, in[8],  12);

  /* round 3: left lane */
  ROUND(dd, ee, aa, bb, cc, F3, K3, in[3],  11);
  ROUND(cc, dd, ee, aa, bb, F3, K3, in[10], 13);
  ROUND(bb, cc, dd, ee, aa, F3, K3, in[14],  6);
  ROUND(aa, bb, cc, dd, ee, F3, K3, in[4],   7);
  ROUND(ee, aa, bb, cc, dd, F3, K3, in[9],  14);
  ROUND(dd, ee, aa, bb, cc, F3, K3, in[15],  9);
  ROUND(cc, dd, ee, aa, bb, F3, K3, in[8],  13);
  ROUND(bb, cc, dd, ee, aa, F3, K3, in[1],  15);
  ROUND(aa, bb, cc, dd, ee, F3, K3, in[2],  14);
  ROUND(ee, aa, bb, cc, dd, F3, K3, in[7],   8);
  ROUND(dd, ee, aa, bb, cc, F3, K3, in[0],  13);
  ROUND(cc, dd, ee, aa, bb, F3, K3, in[6],   6);
  ROUND(bb, cc, dd, ee, aa, F3, K3, in[13],  5);
  ROUND(aa, bb, cc, dd, ee, F3, K3, in[11], 12);
  ROUND(ee, aa, bb, cc, dd, F3, K3, in[5],   7);
  ROUND(dd, ee, aa, bb, cc, F3, K3, in[12],  5);

  /* round 4: left lane */
  ROUND(cc, dd, ee, aa, bb, F4, K4, in[1],  11);
  ROUND(bb, cc, dd, ee, aa, F4, K4, in[9],  12);
  ROUND(aa, bb, cc, dd, ee, F4, K4, in[11], 14);
  ROUND(ee, aa, bb, cc, dd, F4, K4, in[10], 15);
  ROUND(dd, ee, aa, bb, cc, F4, K4, in[0],  14);
  ROUND(cc, dd, ee, aa, bb, F4, K4, in[8],  15);
  ROUND(bb, cc, dd, ee, aa, F4, K4, in[12],  9);
  ROUND(aa, bb, cc, dd, ee, F4, K4, in[4],   8);
  ROUND(ee, aa, bb, cc, dd, F4, K4, in[13],  9);
  ROUND(dd, ee, aa, bb, cc, F4, K4, in[3],  14);
  ROUND(cc, dd, ee, aa, bb, F4, K4, in[7],   5);
  ROUND(bb, cc, dd, ee, aa, F4, K4, in[15],  6);
  ROUND(aa, bb, cc, dd, ee, F4, K4, in[14],  8);
  ROUND(ee, aa, bb, cc, dd, F4, K4, in[5],   6);
  ROUND(dd, ee, aa, bb, cc, F4, K4, in[6],   5);
  ROUND(cc, dd, ee, aa, bb, F4, K4, in[2],  12);

  /* round 5: left lane */
  ROUND(bb, cc, dd, ee, aa, F5, K5, in[4],   9);
  ROUND(aa, bb, cc, dd, ee, F5, K5, in[0],  15);
  ROUND(ee, aa, bb, cc, dd, F5, K5, in[5],   5);
  ROUND(dd, ee, aa, bb, cc, F5, K5, in[9],  11);
  ROUND(cc, dd, ee, aa, bb, F5, K5, in[7],   6);
  ROUND(bb, cc, dd, ee, aa, F5, K5, in[12],  8);
  ROUND(aa, bb, cc, dd, ee, F5, K5, in[2],  13);
  ROUND(ee, aa, bb, cc, dd, F5, K5, in[10], 12);
  ROUND(dd, ee, aa, bb, cc, F5, K5, in[14],  5);
  ROUND(cc, dd, ee, aa, bb, F5, K5, in[1],  12);
  ROUND(bb, cc, dd, ee, aa, F5, K5, in[3],  13);
  ROUND(aa, bb, cc, dd, ee, F5, K5, in[8],  14);
  ROUND(ee, aa, bb, cc, dd, F5, K5, in[11], 11);
  ROUND(dd, ee, aa, bb, cc, F5, K5, in[6],   8);
  ROUND(cc, dd, ee, aa, bb, F5, K5, in[15],  5);
  ROUND(bb, cc, dd, ee, aa, F5, K5, in[13],  6);

  /* round 1: right lane */
  ROUND(aaa, bbb, ccc, ddd, eee, F5, KK1, in[5],   8);
  ROUND(eee, aaa, bbb, ccc, ddd, F5, KK1, in[14],  9);
  ROUND(ddd, eee, aaa, bbb, ccc, F5, KK1, in[7],   9);
  ROUND(ccc, ddd, eee, aaa, bbb, F5, KK1, in[0],  11);
  ROUND(bbb, ccc, ddd, eee, aaa, F5, KK1, in[9],  13);
  ROUND(aaa, bbb, ccc, ddd, eee, F5, KK1, in[2],  15);
  ROUND(eee, aaa, bbb, ccc, ddd, F5, KK1, in[11], 15);
  ROUND(ddd, eee, aaa, bbb, ccc, F5, KK1, in[4],   5);
  ROUND(ccc, ddd, eee, aaa, bbb, F5, KK1, in[13],  7);
  ROUND(bbb, ccc, ddd, eee, aaa, F5, KK1, in[6],   7);
  ROUND(aaa, bbb, ccc, ddd, eee, F5, KK1, in[15],  8);
  ROUND(eee, aaa, bbb, ccc, ddd, F5, KK1, in[8],  11);
  ROUND(ddd, eee, aaa, bbb, ccc, F5, KK1, in[1],  14);
  ROUND(ccc, ddd, eee, aaa, bbb, F5, KK1, in[10], 14);
  ROUND(bbb, ccc, ddd, eee, aaa, F5, KK1, in[3],  12);
  ROUND(aaa, bbb, ccc, ddd, eee, F5, KK1, in[12],  6);

  /* round 2: right lane */
  ROUND(eee, aaa, bbb, ccc, ddd, F4, KK2, in[6],   9);
  ROUND(ddd, eee, aaa, bbb, ccc, F4, KK2, in[11], 13);
  ROUND(ccc, ddd, eee, aaa, bbb, F4, KK2, in[3],  15);
  ROUND(bbb, ccc, ddd, eee, aaa, F4, KK2, in[7],   7);
  ROUND(aaa, bbb, ccc, ddd, eee, F4, KK2, in[0],  12);
  ROUND(eee, aaa, bbb, ccc, ddd, F4, KK2, in[13],  8);
  ROUND(ddd, eee, aaa, bbb, ccc, F4, KK2, in[5],   9);
  ROUND(ccc, ddd, eee, aaa, bbb, F4, KK2, in[10], 11);
  ROUND(bbb, ccc, ddd, eee, aaa, F4, KK2, in[14],  7);
  ROUND(aaa, bbb, ccc, ddd, eee, F4, KK2, in[15],  7);
  ROUND(eee, aaa, bbb, ccc, ddd, F4, KK2, in[8],  12);
  ROUND(ddd, eee, aaa, bbb, ccc, F4, KK2, in[12],  7);
  ROUND(ccc, ddd, eee, aaa, bbb, F4, KK2, in[4],   6);
  ROUND(bbb, ccc, ddd, eee, aaa, F4, KK2, in[9],  15);
  ROUND(aaa, bbb, ccc, ddd, eee, F4, KK2, in[1],  13);
  ROUND(eee, aaa, bbb, ccc, ddd, F4, KK2, in[2],  11);

  /* round 3: right lane */
  ROUND(ddd, eee, aaa, bbb, ccc, F3, KK3, in[15],  9);
  ROUND(ccc, ddd, eee, aaa, bbb, F3, KK3, in[5],   7);
  ROUND(bbb, ccc, ddd, eee, aaa, F3, KK3, in[1],  15);
  ROUND(aaa, bbb, ccc, ddd, eee, F3, KK3, in[3],  11);
  ROUND(eee, aaa, bbb, ccc, ddd, F3, KK3, in[7],   8);
  ROUND(ddd, eee, aaa, bbb, ccc, F3, KK3, in[14],  6);
  ROUND(ccc, ddd, eee, aaa, bbb, F3, KK3, in[6],   6);
  ROUND(bbb, ccc, ddd, eee, aaa, F3, KK3, in[9],  14);
  ROUND(aaa, bbb, ccc, ddd, eee, F3, KK3, in[11], 12);
  ROUND(eee, aaa, bbb, ccc, ddd, F3, KK3, in[8],  13);
  ROUND(ddd, eee, aaa, bbb, ccc, F3, KK3, in[12],  5);
  ROUND(ccc, ddd, eee, aaa, bbb, F3, KK3, in[2],  14);
  ROUND(bbb, ccc, ddd, eee, aaa, F3, KK3, in[10], 13);
  ROUND(aaa, bbb, ccc, ddd, eee, F3, KK3, in[0],  13);
  ROUND(eee, aaa, bbb, ccc, ddd, F3, KK3, in[4],   7);
  ROUND(ddd, eee, aaa, bbb, ccc, F3, KK3, in[13],  5);

  /* round 4: right lane */
  ROUND(ccc, ddd, eee, aaa, bbb, F2, KK4, in[8],  15);
  ROUND(bbb, ccc, ddd, eee, aaa, F2, KK4, in[6],   5);
  ROUND(aaa, bbb, ccc, ddd, eee, F2, KK4, in[4],   8);
  ROUND(eee, aaa, bbb, ccc, ddd, F2, KK4, in[1],  11);
  ROUND(ddd, eee, aaa, bbb, ccc, F2, KK4, in[3],  14);
  ROUND(ccc, ddd, eee, aaa, bbb, F2, KK4, in[11], 14);
  ROUND(bbb, ccc, ddd, eee, aaa, F2, KK4, in[15],  6);
  ROUND(aaa, bbb, ccc, ddd, eee, F2, KK4, in[0],  14);
  ROUND(eee, aaa, bbb, ccc, ddd, F2, KK4, in[5],   6);
  ROUND(ddd, eee, aaa, bbb, ccc, F2, KK4, in[12],  9);
  ROUND(ccc, ddd, eee, aaa, bbb, F2, KK4, in[2],  12);
  ROUND(bbb, ccc, ddd, eee, aaa, F2, KK4, in[13],  9);
  ROUND(aaa, bbb, ccc, ddd, eee, F2, KK4, in[9],  12);
  ROUND(eee, aaa, bbb, ccc, ddd, F2, KK4, in[7],   5);
  ROUND(ddd, eee, aaa, bbb, ccc, F2, KK4, in[10], 15);
  ROUND(ccc, ddd, eee, aaa, bbb, F2, KK4, in[14],  8);

  /* round 5: right lane */
  ROUND(bbb, ccc, ddd, eee, aaa, F1, KK5, in[12],  8);
  ROUND(aaa, bbb, ccc, ddd, eee, F1, KK5, in[15],  5);
  ROUND(eee, aaa, bbb, ccc, ddd, F1, KK5, in[10], 12);
  ROUND(ddd, eee, aaa, bbb, ccc, F1, KK5, in[4],   9);
  ROUND(ccc, ddd, eee, aaa, bbb, F1, KK5, in[1],  12);
  ROUND(bbb, ccc, ddd, eee, aaa, F1, KK5, in[5],   5);
  ROUND(aaa, bbb, ccc, ddd, eee, F1, KK5, in[8],  14);
  ROUND(eee, aaa, bbb, ccc, ddd, F1, KK5, in[7],   6);
  ROUND(ddd, eee, aaa, bbb, ccc, F1, KK5, in[6],   8);
  ROUND(ccc, ddd, eee, aaa, bbb, F1, KK5, in[2],  13);
  ROUND(bbb, ccc, ddd, eee, aaa, F1, KK5, in[13],  6);
  ROUND(aaa, bbb, ccc, ddd, eee, F1, KK5, in[14],  5);
  ROUND(eee, aaa, bbb, ccc, ddd, F1, KK5, in[0],  15);
  ROUND(ddd, eee, aaa, bbb, ccc, F1, KK5, in[3],  13);
  ROUND(ccc, ddd, eee, aaa, bbb, F1, KK5, in[9],  11);
  ROUND(bbb, ccc, ddd, eee, aaa, F1, KK5, in[11], 11);

  /* combine results */
  ddd += cc + state[1];		/* final result for state[0] */
  state[1] = state[2] + dd + eee;
  state[2] = state[3] + ee + aaa;
  state[3] = state[4] + aa + bbb;
  state[4] = state[0] + bb + ccc;
  state[0] = ddd;
}

void rmd160_process(const char input_block[64])
{
  rmd160_transform(digest, (const u32 *)input_block);
}

void rmd160_finish(char output[20])
{
  u32 *out=(u32 *)output;
  int i;

  /* Save output */
  for(i=0;i < 5;i++)
    out[i]=le32(digest[i]);
}

void rmd160_hash(char output[20], const char input[64])
{
  rmd160_init();
  rmd160_process(input);
  rmd160_finish(output);
}
