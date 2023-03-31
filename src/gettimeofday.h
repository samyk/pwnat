/*
 * From http://www.openasthra.com/c-tidbits/gettimeofday-function-for-windows/
 */
#include <time.h>
//#include <windows.h>
#include <winsock2.h>

/*
#if defined(_MSC_VER) || defined(_MSC_EXTENSIONS)
  #define DELTA_EPOCH_IN_MICROSECS  11644473600000000Ui64
#else
  #define DELTA_EPOCH_IN_MICROSECS  11644473600000000ULL
#endif

struct timezone
{
  int  tz_minuteswest; /* minutes W of Greenwich *
  int  tz_dsttime;     /* type of dst correction *
};

int gettimeofday(struct timeval *tv, struct timezone *tz);

#define timeradd(a, b, result)                                                \
    do {                                                                      \
        (result)->tv_sec = (a)->tv_sec + (b)->tv_sec;                         \
        (result)->tv_usec = (a)->tv_usec + (b)->tv_usec;                      \
        if ((result)->tv_usec >= 1000000)                                     \
        {                                                                     \
            ++(result)->tv_sec;                                               \
            (result)->tv_usec -= 1000000;                                     \
        }                                                                     \
    } while (0)
*/
