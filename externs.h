/* externs.h - System-specific declarations */

#define _GNU_SOURCE    // Use the GNU C Library Extensions

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <math.h>
#include <fcntl.h>
#include <errno.h>
#include <sched.h>
#include <sys/signal.h>
#include <sys/prctl.h>
#include <sys/mman.h>
#include <sys/sysinfo.h>
#include <arpa/inet.h>

/* Define our own set of types */
#undef quad
#define quad long long
#define bool _Bool

typedef char s8;
typedef short s16;
typedef int s32;
typedef quad s64;

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned quad u64;

#define align4 __attribute__((aligned(4)))
#define align8 __attribute__((aligned(8)))
#define align16 __attribute__((aligned(16)))

/* Path prediction */
#define likely(x)   __builtin_expect((x), 1)
#define unlikely(x) __builtin_expect((x), 0)

/* Little/big-endian byte conversions */
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
# define le16(x) ((u16)(x))
# define le32(x) ((u32)(x))
# define le64(x) ((u64)(x))
# define be16(x) __builtin_bswap16(x)
# define be32(x) __builtin_bswap32(x)
# define be64(x) __builtin_bswap64(x)
#else
# define le16(x) __builtin_bswap16(x)
# define le32(x) __builtin_bswap32(x)
# define le64(x) __builtin_bswap64(x)
# define be16(x) ((u16)(x))
# define be32(x) ((u32)(x))
# define be64(x) ((u64)(x))
#endif

/* Swap the values of two integers, quadwords, doubles, etc. */
#define XCHG(a,b) (void)({ typeof(a) _temp=a; a=b; b=_temp; })
/* ...The same thing can be done using:  a ^= b, b ^= a, a ^= b */

/* Rotate a 32-bit word right or left */
#define ROR(x,n) ({ u32 _x=(x), _n=(n); (_x >> _n) | (_x << (32-_n)); })
#define ROL(x,n) ({ u32 _x=(x), _n=(n); (_x << _n) | (_x >> (32-_n)); })

/* Generic min() and max() functions */
#undef min
#undef max
#define min(x,y) ({ typeof(x) _x=x; typeof(y) _y=y; (_x < _y)?_x:_y; })
#define max(x,y) ({ typeof(x) _x=x; typeof(y) _y=y; (_x > _y)?_x:_y; })

/* Optimal way of keeping a number within a set range */
#define RANGE(x,lo,hi) ({ typeof(x) _val=x, _lo=lo, _hi=hi; \
                          (_val < _lo)?_lo:(_val > _hi)?_hi:_val; })

/* Determines the number of elements in a static array */
#define NELEM(array) (int)(sizeof(array)/sizeof(array[0]))


/**** Module declarations ****************************************************/

/* libsecp256k1 */
#include "secp256k1.h"

/* base58.c */
extern bool b58tobin(void *bin, size_t *binszp, const char *b58, size_t b58sz);
extern bool b58enc(char *b58, const void *data, size_t binsz);

/* cpu.c */
extern int  get_num_cpus(void);
extern void set_working_cpu(int thread);

/* rmd160.c */
extern void rmd160_init(void);
extern void rmd160_process(const char input_block[64]);
extern void rmd160_finish(char output[20]);
extern void rmd160_hash(char output[20], const char input[64]);

#define rmd160_prepare(block, sz) ({ \
  int _sz=(sz); \
  memset(block, 0, 64); \
  block[_sz]=0x80; \
  block[57]=(_sz*8) >> 8;  /* Little-endian length in bits */ \
  block[56]=(_sz*8) & 0xff; \
})

/* sha256.c */
extern void sha256_init(void);
extern void sha256_process(const char input_block[64]);
extern void sha256_finish(char output[32]);
extern void sha256_hash(char output[32], const char input[64]);
extern void sha256_register(bool verbose);

#define sha256_prepare(block, sz) ({ \
  int _sz=(sz); \
  memset(block, 0, 64); \
  block[_sz]=0x80; \
  block[62]=(_sz*8) >> 8;  /* Big-endian length in bits */ \
  block[63]=(_sz*8) & 0xff; \
})
