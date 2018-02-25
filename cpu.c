/* cpu.c - CPU scheduler routines */

#include "externs.h"

static cpu_set_t *cpuset;
static size_t cpuset_size;


// Return a count of the CPUs currently available to this process.
//
int get_num_cpus()
{
  int i, count=0;

  cpuset_size=1024;  /* Starting buffer size */

  do {
    cpuset=CPU_ALLOC(cpuset_size+1);

    if(sched_getaffinity(0, CPU_ALLOC_SIZE(cpuset_size+1), cpuset) == -1) {
      if(errno == EINVAL) {
        /* Loop, doubling the cpuset, until sched_getaffinity() succeeds */
        CPU_FREE(cpuset);
        cpuset_size *= 2;
        continue;
      }

      /* Unexpected error, but at least 1 CPU has to be available */
      CPU_FREE(cpuset);
      cpuset_size=0;
      return 1;
    }
  } while(0);

  // Count CPUs in set. Note: CPU_COUNT_S() is unreliable, so it is not used
  // here.
  for(i=0;i < cpuset_size;i++)
    if(CPU_ISSET_S(i, cpuset_size+1, cpuset))
      count++;

  return count;
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
    if(CPU_ISSET_S(i, cpuset_size+1, cpuset) && !thread--) {
      CPU_ZERO_S(cpuset_size+1, cpuset);
      CPU_SET_S(i, cpuset_size+1, cpuset);
      sched_setaffinity(0, cpuset_size+1, cpuset);  /* Ignore any errors */
      return;
    }

    if(++i >= cpuset_size)
      i=0;  /* Wrap around */
  }
}
