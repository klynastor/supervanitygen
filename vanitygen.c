/* vanitygen.c - Super Vanitygen - Vanity Bitcoin address generator */

// Copyright (C) 2016 Byron Stanoszek  <gandalf@winds.org>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.

#include "externs.h"

/* Number of secp256k1 operations per batch */
#define STEP 3072

#include "src/libsecp256k1-config.h"
#include "src/secp256k1.c"

#define MY_VERSION "0.3"

/* List of public key byte patterns to match */
static struct {
  align8 u8 low[20];   // Low limit
  align8 u8 high[20];  // High limit
} *patterns;

static int num_patterns;

/* Global command-line settings */
static int  max_count=1;
static bool anycase;
static bool keep_going;
static bool quiet;
static bool verbose;

/* Difficulty (1 in x) */
static double difficulty;

/* Per-thread hash counter */
static u64 *thread_count;

/* Socket pair for sending up results */
static int sock[2];

/* Static Functions */
static void manager_loop(int threads);
static void announce_result(int found, const u8 result[52]);
static bool add_prefix(const char *prefix);
static bool add_anycase_prefix(const char *prefix);
static double get_difficulty(void);
static void engine(int thread);
static bool verify_key(const u8 result[52]);

static void my_secp256k1_ge_set_all_gej_var(secp256k1_ge *r,
                                            const secp256k1_gej *a);
static void my_secp256k1_gej_add_ge_var(secp256k1_gej *r,
                                        const secp256k1_gej *a,
                                        const secp256k1_ge *b);


/**** Main Program ***********************************************************/

#define parse_arg()     \
  if(argv[i][j+1])      \
    arg=&argv[i][j+1];  \
  else if(i+1 < argc)   \
    arg=argv[++i];      \
  else                  \
    goto no_arg

// Main program entry.
//
int main(int argc, char *argv[])
{
  char *arg;
  int i, j, digits, parent_pid, ncpus=get_num_cpus(), threads=ncpus;

  /* Process command-line arguments */
  for(i=1;i < argc;i++) {
    if(argv[i][0] != '-')
      break;
    for(j=1;argv[i][j];j++) {
      switch(argv[i][j]) {
      case 'c':  /* Count */
        parse_arg();
        max_count=max(atoi(arg), 1);
        goto end_arg;
      case 'i':  /* Case-insensitive matches */
        anycase=1;
        break;
      case 'k':  /* Keep going */
        keep_going=1;
        break;
      case 'q':  /* Quiet */
        quiet=1;
        verbose=0;
        break;
      case 't':  /* #Threads */
        parse_arg();
        threads=RANGE(atoi(arg), 1, ncpus*2);
        goto end_arg;
      case 'v':  /* Verbose */
        quiet=0;
        verbose=1;
        break;
      no_arg:
        fprintf(stderr, "%s: option requires an argument -- '%c'\n", *argv,
                argv[i][j]);
        goto error;
      default:
        fprintf(stderr, "%s: invalid option -- '%c'\n", *argv, argv[i][j]);
      case '?':
      error:
        fprintf(stderr,
                "Usage: %s [options] prefix ...\n"
                "Options:\n"
                "  -c count  Stop after 'count' solutions; default=%d\n"
                "  -i        Match case-insensitive prefixes\n"
                "  -k        Keep looking for solutions indefinitely\n"
                "  -q        Be quiet (report solutions in CSV format)\n"
                "  -t num    Run 'num' threads; default=%d\n"
                "  -v        Be verbose\n\n",
                *argv, max_count, threads);
        fprintf(stderr, "Super Vanitygen v" MY_VERSION "\n");
        return 1;
      }
    }
    end_arg:;
  }

  /* Auto-detect fastest SHA-256 function to use */
  sha256_register(verbose);

  // Convert specified prefixes into a global list of public key byte patterns.
  for(;i < argc;i++)
    if((!anycase && !add_prefix(argv[i])) ||
       (anycase && !add_anycase_prefix(argv[i])))
      return 1;
  if(!num_patterns)
    goto error;

  /* List patterns to match */
  if(verbose) {
    digits=(num_patterns > 999)?4:(num_patterns > 99)?3:(num_patterns > 9)?2:1;
    for(i=0;i < num_patterns;i++) {
      printf("P%0*d High limit: ", digits, i+1);
      for(j=0;j < 20;j++)
        printf("%02x", patterns[i].high[j]);
      printf("\nP%0*d Low limit:  ", digits, i+1);
      for(j=0;j < 20;j++)
        printf("%02x", patterns[i].low[j]);
      printf("\n");
    }
    printf("---\n");
  }

  difficulty=get_difficulty();
  if(difficulty < 1)
    difficulty=1;
  if(!quiet)
    printf("Difficulty: %.0f\n", difficulty);

  // Create memory-mapped area shared between all threads for reporting hash
  // counts.
  thread_count=mmap(NULL, threads*sizeof(u64), PROT_READ|PROT_WRITE,
                    MAP_SHARED|MAP_ANONYMOUS|MAP_LOCKED, -1, 0);
  if(thread_count == MAP_FAILED) {
    perror("mmap");
    return 1;
  }

  /* Create anonymous socket pair for children to send up solutions */
  if(socketpair(AF_UNIX, SOCK_DGRAM, 0, sock)) {
    perror("socketpair");
    return 1;
  }

  /* Ignore signals */
  signal(SIGPIPE, SIG_IGN);
  signal(SIGCHLD, SIG_IGN);

  /* Fork off the child processes */
  parent_pid=getpid();
  for(i=0;i < threads;i++) {
    if(!fork()) {
      /* In the child... */

      /* Close the read end of the socketpair */
      close(sock[0]);

      /* Kill child process whenever parent process dies */
      prctl(PR_SET_PDEATHSIG, SIGTERM);
      if(getppid() != parent_pid)
        return 0;  /* Parent process already died */

      /* Run hashing engine */
      engine(i);
      return 0;
    }
  }

  /* Close the write end of the socketpair */
  close(sock[1]);

  manager_loop(threads);
  return 1;
}

// Parent process loop, which tracks hash counts and announces new results to
// standard output.
//
static void manager_loop(int threads)
{
  static const int targets[]={50, 75, 80, 90, 95};
  static const int units[]={31536000, 86400, 3600, 60, 1};
  static const char units_str[]="ydhms";

  fd_set readset;
  struct timeval tv={1, 0};
  char msg[256];
  u8 result[52];
  u64 prev=0, last_result=0, count, avg, count_avg[8];
  int i, j, ret, len, found=0, count_index=0, count_max=0;
  double prob, secs;

  FD_ZERO(&readset);

  while(1) {
    /* Wait up to 1 second for hashes to be reported */
    FD_SET(sock[0], &readset);
    if((ret=select(sock[0]+1, &readset, NULL, NULL, quiet?NULL:&tv)) == -1) {
      perror("select");
      return;
    }

    if(ret) {
      /* Read the (PrivKey,PubKey) tuple from the socket */
      if((len=read(sock[0], result, 52)) != 52) {
        /* Datagram read wasn't 52 bytes; ignore message */
        if(len != -1)
          continue;

        /* Something went very wrong if this happens; exit */
        perror("read");
        return;
      }

      /* Verify we received a valid (PrivKey,PubKey) tuple */
      if(!verify_key(result))
        continue;

      announce_result(++found, result);

      /* Reset hash count */
      for(i=0,count=0;i < threads;i++)
        count += thread_count[i];
      last_result=count;
      continue;
    }

    /* Reset the select() timer */
    tv.tv_sec=1, tv.tv_usec=0;

    /* Collect updated hash counts */
    for(i=0,count=0;i < threads;i++)
      count += thread_count[i];
    count_avg[count_index]=count-prev;
    if(++count_index > count_max)
      count_max=count_index;
    if(count_index == NELEM(count_avg))
      count_index=0;
    prev=count;
    count -= last_result;

    /* Average the last 8 seconds */
    for(i=0,avg=0;i < count_max;i++)
      avg += count_avg[i];
    avg /= count_max;

    sprintf(msg, "[%llu Kkey/s][Total %llu]", (avg+500)/1000, count);

    /* Display probability */
    prob=(1-exp(count/-difficulty))*100;
    if(prob < 99.95)
      sprintf(msg+strlen(msg), "[Prob %.1f%%]", prob);

    if(avg >= 500) {
      /* Display target time */
      if(prob < targets[NELEM(targets)-1]) {
        for(i=0;prob >= targets[i];i++);
        secs=(-difficulty*log(1-targets[i]/100.0)-count)/avg;
        for(j=0;j < NELEM(units)-1 && secs < units[j];j++);
        secs /= units[j];
        if(secs >= 1e+8)
          sprintf(msg+strlen(msg), "[%d%% in %e%c]",
                  targets[i], secs, units_str[j]);
        else
          sprintf(msg+strlen(msg), "[%d%% in %.1f%c]",
                  targets[i], secs, units_str[j]);
      }
    }

    /* Display match count */
    if(found) {
      if(!keep_going && max_count > 1)
        sprintf(msg+strlen(msg), "[Found %d of %d]", found, max_count);
      else
        sprintf(msg+strlen(msg), "[Found %d]", found);
    }

    printf("\r%-78.78s", msg);
    fflush(stdout);
  }
}

static void announce_result(int found, const u8 result[52])
{
  align8 u8 priv_block[64], pub_block[64], cksum_block[64];
  align8 u8 wif[64], checksum[32];
  int j;

  if(!quiet)
    printf("\n");

  /* Display matching keys in hexadecimal */
  if(verbose) {
    printf("Private match: ");
    for(j=0;j < 32;j++)
      printf("%02x", result[j]);
    printf("\n");

    printf("Public match:  ");
    for(j=0;j < 20;j++)
      printf("%02x", result[j+32]);
    printf("\n");
  }

  /* Convert Private Key to WIF */

  /* Set up sha256 block for hashing the private key; length of 34 bytes */
  sha256_prepare(priv_block, 34);
  priv_block[0]=0x80;
  memcpy(priv_block+1, result, 32);
  priv_block[33]=0x01;  /* 1=Compressed Public Key */

  /* Set up checksum block; length of 32 bytes */
  sha256_prepare(cksum_block, 32);

  /* Compute checksum and copy first 4-bytes to end of private key */
  sha256_hash(cksum_block, priv_block);
  sha256_hash(checksum, cksum_block);
  memcpy(priv_block+34, checksum, 4);

  b58enc(wif, priv_block, 38);
  if(quiet)
    printf("%s", wif);
  else
    printf("Private Key:   %s\n", wif);

  /* Convert Public Key to Compressed WIF */

  /* Set up sha256 block for hashing the public key; length of 21 bytes */
  sha256_prepare(pub_block, 21);
  memcpy(pub_block+1, result+32, 20);

  /* Compute checksum and copy first 4-bytes to end of public key */
  sha256_hash(cksum_block, pub_block);
  sha256_hash(checksum, cksum_block);
  memcpy(pub_block+21, checksum, 4);

  b58enc(wif, pub_block, 25);
  if(quiet)
    printf(",%s\n", wif);
  else
    printf("Address:       %s\n", wif);

  /* Exit after we find 'max_count' solutions */
  if(!keep_going && found >= max_count)
    exit(0);

  if(!quiet)
    printf("---\n");
}


/**** Pattern Matching *******************************************************/

// Add a low/high pattern range to the patterns[] array, coalescing adjacent or
// overlapping patterns into one.
//
static void add_pattern(void *low, void *high)
{
  u32 low_minus_one[5], high_plus_one[5];
  int i;

  rescan:

  memcpy(low_minus_one, low, 20);
  if(!low_minus_one[4]--)
    if(!low_minus_one[3]--)
      if(!low_minus_one[2]--)
        if(!low_minus_one[1]--)
          if(!low_minus_one[0]--)
            memset(low_minus_one, 0x00, 20);

  memcpy(high_plus_one, high, 20);
  if(!++high_plus_one[4])
    if(!++high_plus_one[3])
      if(!++high_plus_one[2])
        if(!++high_plus_one[1])
          if(!++high_plus_one[0])
            memset(high_plus_one, 0xff, 20);

  /* Loop through existing patterns */
  for(i=0;i < num_patterns;i++) {
    /* Ignore new pattern if completely surrounded by existing pattern */
    if(memcmp(low, patterns[i].low, 20) >= 0 &&
       memcmp(high, patterns[i].high, 20) <= 0)
      return;

    /* Extend an existing pattern downward */
    if(memcmp(low, patterns[i].low, 20) < 0 &&
       memcmp(high_plus_one, patterns[i].low, 20) >= 0) {
      if(memcmp(high, patterns[i].high, 20) < 0)
        memcpy(high, patterns[i].high, 20);
      memmove(patterns+i, patterns+i+1, (--num_patterns-i)*sizeof(*patterns));
      goto rescan;
    }

    /* Extend an existing pattern upward */
    if(memcmp(high, patterns[i].high, 20) > 0 &&
       memcmp(low_minus_one, patterns[i].high, 20) <= 0) {
      memcpy(low, patterns[i].low, 20);
      memmove(patterns+i, patterns+i+1, (--num_patterns-i)*sizeof(*patterns));
      goto rescan;
    }
  }

  /* Resize the array every 100 elements */
  if(!(num_patterns % 100)) {
    if(!(patterns=realloc(patterns, (num_patterns+100)*sizeof(*patterns)))) {
      perror("realloc");
      exit(1);
    }
  }

  memcpy(patterns[num_patterns].low, low, 20);
  memcpy(patterns[num_patterns].high, high, 20);
  num_patterns++;

  /* Searching for addresses gets very slow with too many patterns */
  if(num_patterns > 10000) {
    fprintf(stderr, "Error: Too many patterns!\n");
    exit(0);
  }
}

// Convert an address prefix to one or more 20-byte patterns to match on the
// binary level.
//
static bool add_prefix(const char *prefix)
{
  /* Determine range of matching public keys */
  size_t pattern_sz=25;
  size_t b58sz=strlen(prefix);
  u8 pattern1[32], pattern2[32];
  char pat1[64], pat2[64], test[64];
  int i, j, nonzero, offset=0, plen=strlen(prefix);
  bool lt;

  /* Validate prefix */
  if(prefix[0] != '1') {
    fprintf(stderr, "Error: Prefix must start with '1'.\n");
    return 0;
  } if(plen > 28) {
    fprintf(stderr, "Error: Prefix too long.\n");
    return 0;
  } if(!b58tobin(pattern1, &pattern_sz, prefix, b58sz)) {
    fprintf(stderr, "Error: Address '%s' contains an invalid character.\n",
            prefix);
    return 0;
  }

  /* Special case when prefix is all 1's */
  for(i=0;prefix[i] == '1';i++);
  if(!prefix[i]) {
    memset(pattern1+1, 0, 24);
    pattern2[0]=0;
    memset(pattern2+1, 0xff, 24);
    for(j=1;j < 25;j++) {
      b58enc(test, pattern2, 25);
      if(!strncmp(test, prefix, plen))
        break;
      pattern2[j]=0;
    }
    add_pattern(pattern1+1, pattern2+1);
    return 1;
  }

  do {
    strcpy(pat1+offset, prefix);
    strcpy(pat2+offset, prefix);
    lt=(strcmp(pat1, "1QLbz7JHiBTspS962RLKV8GndWFw") < 0);
    for(i=strlen(pat1);i < (lt?34:33);i++) {
      pat1[i]='1';
      pat2[i]='z';
    }
    pat1[i]='\0';
    pat2[i]='\0';

    b58sz=i;
    pattern_sz=25;
    b58tobin(pattern1, &pattern_sz, pat1, b58sz);
    b58sz=i;
    pattern_sz=25;
    b58tobin(pattern2, &pattern_sz, pat2, b58sz);

    offset++;
    b58enc(test, pattern1, 25);
  } while(offset < 28 && strncmp(test, prefix, plen));

#if 0
  printf("X Low limit:   ");
  for(j=0;j < 20;j++)
    printf("%02x", pattern1[j+1]);
  printf("\nX High limit:  ");
  for(j=0;j < 20;j++)
    printf("%02x", pattern2[j+1]);
  printf("\n");
#endif

  /* Search for the first nonzero byte in either pattern */
  for(i=0;i < 25 && !(pattern1[i] | pattern2[i]);i++);
  nonzero=i;
  if(pattern1[nonzero])
    add_pattern(pattern1+1, pattern2+1);
  else {
    pattern2[nonzero]=0;
    memset(pattern2+nonzero+1, 0xff, 20-nonzero);
    add_pattern(pattern1+1, pattern2+1);
    nonzero++;
  }

  if(!lt)
    return 1;

  strcpy(pat1+offset, prefix);
  strcpy(pat2+offset, prefix);
  for(i=strlen(pat1);i < 34;i++) {
    pat1[i]='1';
    pat2[i]='z';
  }
  pat1[i]='\0';
  pat2[i]='\0';

  b58sz=i;
  pattern_sz=25;
  b58tobin(pattern1, &pattern_sz, pat1, b58sz);
  b58sz=i;
  pattern_sz=25;
  b58tobin(pattern2, &pattern_sz, pat2, b58sz);

#if 0
  printf("Y Low limit:   ");
  for(j=0;j < 20;j++)
    printf("%02x", pattern1[j+1]);
  printf("\nY High limit:  ");
  for(j=0;j < 20;j++)
    printf("%02x", pattern2[j+1]);
  printf("\n");
#endif

  if(pattern1[nonzero] && pattern2[nonzero])
    add_pattern(pattern1+1, pattern2+1);
  else if(!pattern1[nonzero] && pattern2[nonzero]) {
    pattern1[nonzero]=1;
    memset(pattern1+nonzero+1, 0, 20-nonzero);
    for(i=nonzero-1;i >= 0;i--)
      if(pattern2[i])
        break;
    if(i >= 0) {
      memset(pattern2, 0, i+1);
      memset(pattern2+i+1, 0xff, 21-i-1);
    }
    add_pattern(pattern1+1, pattern2+1);
  }

  return 1;
}

// Add pattern matches for all upper and lowercase variants of 'prefix'.
//
static bool add_anycase_prefix(const char *prefix)
{
  /* Letters that can appear in an address as both upper and lowercase */
  static const char letters[]="abcdefghjkmnpqrstuvwxyz";

  u8 positions[32];
  char lowercase[32], temp[32];
  int i, j, plen=strlen(prefix), num_positions=0;

  /* Validate prefix */
  if(prefix[0] != '1') {
    fprintf(stderr, "Error: Prefix must start with '1'.\n");
    return 0;
  } if(plen > 28) {
    fprintf(stderr, "Error: Prefix too long.\n");
    return 0;
  }

  /* Convert prefix to all lowercase */
  for(i=0;i < plen;i++) {
    lowercase[i]=(prefix[i] >= 'A' && prefix[i] <= 'Z') ?
                 (prefix[i]|32) : prefix[i];

    /* "L" must always be uppercase */
    if(lowercase[i] == 'l')
      lowercase[i]='L';

    /* Remember which letter positions can shift case */
    else if(strchr(letters, lowercase[i]))
      positions[num_positions++]=i;
  }
  lowercase[i]='\0';

  /* Add prefixes for all upper/lowercase variants */
  for(i=0;i < (1 << num_positions);i++) {
    strcpy(temp, lowercase);

    /* Uppercase some positions in the prefix */
    for(j=0;j < num_positions;j++)
      if(i & (1 << j))
        temp[positions[j]] &= ~32;

    if(!add_prefix(temp))
      return 0;
  }

  return 1;
}

// Calculate the difficulty of finding a match from the pattern list, where
// difficulty = 1/{valid pattern space}.
//
static double get_difficulty()
{
  u32 total[5]={}, *low, *high;
  u64 temp;
  double freq;
  int i, j;

  /* Loop for each pattern */
  for(i=0;i < num_patterns;i++) {
    low=(u32 *)patterns[i].low;
    high=(u32 *)patterns[i].high;

    /* total += high-low */
    for(j=4,temp=0;j >= 0;j--) {
      temp += (u64)total[j]+be32(high[j])+(~be32(low[j])+(j == 4));
      total[j]=temp;
      temp >>= 32;
    }
  }

  /* Add up fractions, from least significant to most significant */
  freq  = total[4] / 1461501637330902918203684832716283019655932542976.0;
  freq += total[3] / 340282366920938463463374607431768211456.0;
  freq += total[2] / 79228162514264337593543950336.0;
  freq += total[1] / 18446744073709551616.0;
  freq += total[0] / 4294967296.0;

  return 1/freq;
}

#ifdef __LP64__

// Returns 1 if the 20-byte hashed public key 'key' is between 'low' and
// 'high', inclusive. For 64-bit CPUs.
//
static bool pubkeycmp(void *low, void *high, void *key)
{
  u64 *low64=low, *high64=high, *key64=key;
  u32 *low32=low, *high32=high, *key32=key;

  if(be64(key64[0]) < be64(low64[0])) return 0;
  if(be64(key64[0]) > be64(low64[0])) goto next;
  if(be64(key64[1]) < be64(low64[1])) return 0;
  if(be64(key64[1]) > be64(low64[1])) goto next;
  if(be32(key32[4]) < be32(low32[4])) return 0;

  next:
  if(be64(key64[0]) > be64(high64[0])) return 0;
  if(be64(key64[0]) < be64(high64[0])) return 1;
  if(be64(key64[1]) > be64(high64[1])) return 0;
  if(be64(key64[1]) < be64(high64[1])) return 1;
  if(be32(key32[4]) > be32(high32[4])) return 0;

  return 1;
}

#else

// Returns 1 if the 20-byte hashed public key 'key' is between 'low' and
// 'high', inclusive. For 32-bit CPUs.
//
static bool pubkeycmp(void *low, void *high, void *key)
{
  u32 *low32=low, *high32=high, *key32=key;
  int i;

  for(i=0;i < 4;i++) {
    if(be32(key32[i]) < be32(low32[i])) return 0;
    if(be32(key32[i]) > be32(low32[i])) goto next;
  }
  if(be32(key32[i]) < be32(low32[i])) return 0;

  next:
  for(i=0;i < 4;i++) {
    if(be32(key32[i]) > be32(high32[i])) return 0;
    if(be32(key32[i]) < be32(high32[i])) return 1;
  }
  if(be32(key32[i]) > be32(high32[i])) return 0;

  return 1;
}

#endif


/**** Hash Engine ************************************************************/

// Per-thread entry point.
//
static void engine(int thread)
{
  static secp256k1_gej base[STEP];
  static secp256k1_ge rslt[STEP];
  secp256k1_context *sec_ctx;
  secp256k1_scalar scalar_key, scalar_one={{1}};
  secp256k1_gej temp;
  secp256k1_ge offset;

  align8 u8 sha_block[64], rmd_block[64], result[52], *pubkey=result+32;
  u64 privkey[4], *key=(u64 *)result;
  int i, k, fd, len;

  /* Set CPU affinity for this thread# (ignore any failures) */
  set_working_cpu(thread);

  /* Initialize the secp256k1 context */
  sec_ctx=secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

  /* Set up sha256 block for an input length of 33 bytes */
  sha256_prepare(sha_block, 33);

  /* Set up rmd160 block for an input length of 32 bytes */
  rmd160_prepare(rmd_block, 32);

  rekey:

  // Generate a random private key. Specifically, any 256-bit number from 0x1
  // to 0xFFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFE BAAE DCE6 AF48 A03B BFD2 5E8C
  // D036 4140 is a valid private key.

  if((fd=open("/dev/urandom", O_RDONLY|O_NOCTTY)) == -1) {
    perror("/dev/urandom");
    return;
  }

  /* Use 32 bytes from /dev/urandom as starting private key */
  do {
    if((len=read(fd, privkey, 32)) != 32) {
      if(len != -1)
        errno=EAGAIN;
      perror("/dev/urandom");
      return;
    }
  } while(privkey[0]+1 < 2);  /* Ensure only valid private keys */

  close(fd);

  /* Copy private key to secp256k1 scalar format */
  secp256k1_scalar_set_b32(&scalar_key, (u8 *)privkey, NULL);

  /* Convert key to cpu endianness */
  privkey[0]=be64(privkey[0]);
  privkey[1]=be64(privkey[1]);
  privkey[2]=be64(privkey[2]);
  privkey[3]=be64(privkey[3]);

  /* Create group elements for both the random private key and the value 1 */
  secp256k1_ecmult_gen(&sec_ctx->ecmult_gen_ctx, &base[STEP-1], &scalar_key);
  secp256k1_ecmult_gen(&sec_ctx->ecmult_gen_ctx, &temp, &scalar_one);
  secp256k1_ge_set_gej_var(&offset, &temp);

  /* Main Loop */

  printf("\r");  // This magically makes the loop faster by a smidge

  while(1) {
    /* Add 1 in Jacobian coordinates and save the result; repeat STEP times */
    my_secp256k1_gej_add_ge_var(&base[0], &base[STEP-1], &offset);
    for(k=1;k < STEP;k++)
      my_secp256k1_gej_add_ge_var(&base[k], &base[k-1], &offset);

    /* Convert all group elements from Jacobian to affine coordinates */
    my_secp256k1_ge_set_all_gej_var(rslt, base);

    for(k=0;k < STEP;k++) {
      thread_count[thread]++;

      /* Extract the 33-byte compressed public key from the group element */
      sha_block[0]=(secp256k1_fe_is_odd(&rslt[k].y) ? 0x03 : 0x02);
      secp256k1_fe_get_b32(sha_block+1, &rslt[k].x);

      /* Hash public key */
      sha256_hash(rmd_block, sha_block);
      rmd160_hash(pubkey, rmd_block);

      /* Compare hashed public key with byte patterns */
      for(i=0;i < num_patterns;i++) {
        if(unlikely(pubkeycmp(patterns[i].low, patterns[i].high, pubkey))) {
          /* key := privkey+k+1 */
          key[0]=privkey[0];
          key[1]=privkey[1];
          key[2]=privkey[2];
          if((key[3]=privkey[3]+k+1) < privkey[3])
            if(!++key[2])
              if(!++key[1])
                ++key[0];

          /* Convert key to big-endian byte format */
          key[0]=be64(key[0]);
          key[1]=be64(key[1]);
          key[2]=be64(key[2]);
          key[3]=be64(key[3]);

          /* Announce (PrivKey,PubKey) result */
          if(write(sock[1], result, 52) != 52)
            return;

          /* Pick a new random starting private key */
          goto rekey;
        }
      }
    }

    /* Increment privkey by STEP */
    if((privkey[3] += STEP) < STEP)  /* Check for overflow */
      if(!++privkey[2])
        if(!++privkey[1])
          ++privkey[0];
  }
}

// Returns 1 if the private key (first 32 bytes of 'result') correctly produces
// the public key (last 20 bytes of 'result').
//
static bool verify_key(const u8 result[52])
{
  secp256k1_context *sec_ctx;
  secp256k1_scalar scalar;
  secp256k1_gej gej;
  secp256k1_ge ge;
  align8 u8 sha_block[64], rmd_block[64], pubkey[20];
  int ret, overflow;

  /* Set up sha256 block for an input length of 33 bytes */
  sha256_prepare(sha_block, 33);

  /* Set up rmd160 block for an input length of 32 bytes */
  rmd160_prepare(rmd_block, 32);

  /* Initialize the secp256k1 context */
  sec_ctx=secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

  /* Copy private key to secp256k1 scalar format */
  secp256k1_scalar_set_b32(&scalar, result, &overflow);
  if(overflow) {
    secp256k1_context_destroy(sec_ctx);
    return 0;  /* Invalid private key */
  }

  /* Create a group element for the private key we're verifying */
  secp256k1_ecmult_gen(&sec_ctx->ecmult_gen_ctx, &gej, &scalar);

  /* Convert to affine coordinates */
  secp256k1_ge_set_gej_var(&ge, &gej);

  /* Extract the 33-byte compressed public key from the group element */
  sha_block[0]=(secp256k1_fe_is_odd(&ge.y) ? 0x03 : 0x02);
  secp256k1_fe_get_b32(sha_block+1, &ge.x);

  /* Hash public key */
  sha256_hash(rmd_block, sha_block);
  rmd160_hash(pubkey, rmd_block);

  /* Verify that the hashed public key matches the result */
  ret=!memcmp(pubkey, result+32, 20);

  secp256k1_context_destroy(sec_ctx);
  return ret;
}


/**** libsecp256k1 Overrides *************************************************/

static void my_secp256k1_fe_inv_all_gej_var(secp256k1_fe *r,
                                            const secp256k1_gej *a)
{
  secp256k1_fe u;
  int i;

  r[0]=a[0].z;

  for(i=1;i < STEP;i++)
    secp256k1_fe_mul(&r[i], &r[i-1], &a[i].z);

  secp256k1_fe_inv_var(&u, &r[--i]);

  for(;i > 0;i--) {
    secp256k1_fe_mul(&r[i], &r[i-1], &u);
    secp256k1_fe_mul(&u, &u, &a[i].z);
  }

  r[0]=u;
}

static void my_secp256k1_ge_set_all_gej_var(secp256k1_ge *r,
                                            const secp256k1_gej *a)
{
  static secp256k1_fe azi[STEP];
  int i;

  my_secp256k1_fe_inv_all_gej_var(azi, a);

  for(i=0;i < STEP;i++)
    secp256k1_ge_set_gej_zinv(&r[i], &a[i], &azi[i]);
}

static void my_secp256k1_gej_add_ge_var(secp256k1_gej *r,
                                        const secp256k1_gej *a,
                                        const secp256k1_ge *b)
{
  /* 8 mul, 3 sqr, 4 normalize, 12 mul_int/add/negate */
  secp256k1_fe z12, u1, u2, s1, s2, h, i, i2, h2, h3, t;

  secp256k1_fe_sqr(&z12, &a->z);
  u1 = a->x; secp256k1_fe_normalize_weak(&u1);
  secp256k1_fe_mul(&u2, &b->x, &z12);
  s1 = a->y; secp256k1_fe_normalize_weak(&s1);
  secp256k1_fe_mul(&s2, &b->y, &z12); secp256k1_fe_mul(&s2, &s2, &a->z);
  secp256k1_fe_negate(&h, &u1, 1); secp256k1_fe_add(&h, &u2);
  secp256k1_fe_negate(&i, &s1, 1); secp256k1_fe_add(&i, &s2);
  secp256k1_fe_sqr(&i2, &i);
  secp256k1_fe_sqr(&h2, &h);
  secp256k1_fe_mul(&h3, &h, &h2);
  secp256k1_fe_mul(&r->z, &a->z, &h);
  secp256k1_fe_mul(&t, &u1, &h2);
  r->x = t; secp256k1_fe_mul_int(&r->x, 2); secp256k1_fe_add(&r->x, &h3);
  secp256k1_fe_negate(&r->x, &r->x, 3); secp256k1_fe_add(&r->x, &i2);
  secp256k1_fe_negate(&r->y, &r->x, 5); secp256k1_fe_add(&r->y, &t);
  secp256k1_fe_mul(&r->y, &r->y, &i);
  secp256k1_fe_mul(&h3, &h3, &s1); secp256k1_fe_negate(&h3, &h3, 1);
  secp256k1_fe_add(&r->y, &h3);
}
