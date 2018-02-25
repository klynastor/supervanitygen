/* cpu.c - CPU scheduler routines */

#include "externs.h"

static cpu_set_t *cpuset;
static int cpuset_ncpu;
static size_t cpuset_size;


// Return a count of the CPUs currently available to this process.
//
int get_num_cpus()
{
  cpuset_ncpu=1024;  /* Starting number of CPUs */

  while(1) {
    cpuset=CPU_ALLOC(cpuset_ncpu);
    cpuset_size=CPU_ALLOC_SIZE(cpuset_ncpu);

    if(!sched_getaffinity(0, cpuset_size, cpuset))
      return CPU_COUNT_S(cpuset_size, cpuset);

    if(errno == EINVAL) {
      /* Loop, doubling the cpuset, until sched_getaffinity() succeeds */
      CPU_FREE(cpuset);
      cpuset_ncpu *= 2;
      continue;
    }

    /* Unexpected error, but at least 1 CPU has to be available */
    CPU_FREE(cpuset);
    cpuset=NULL;
    cpuset_ncpu=0;
    cpuset_size=0;
    return 1;
  }
}

// Set this thread's CPU affinity to the Nth CPU in the list.
//
void set_working_cpu(int thread)
{
  int i;

  if(!cpuset_size)
    return;

  // The cpuset is already populated with the available CPUs on this system
  // from the call to get_num_cpus(). Look for the Nth one.

  for(i=0;;) {
    if(CPU_ISSET_S(i, cpuset_size, cpuset) && !thread--) {
      CPU_ZERO_S(cpuset_size, cpuset);
      CPU_SET_S(i, cpuset_size, cpuset);
      sched_setaffinity(0, cpuset_size, cpuset);  /* Ignore any errors */
      return;
    }

    if(++i >= cpuset_ncpu)
      i=0;  /* Wrap around */
  }
}
