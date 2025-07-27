// To enable the extension functions define SQLITE_ENABLE_EXTFUNC on compiling this module
#ifdef SQLITE_ENABLE_EXTFUNC
#define sqlite3_open    sqlite3_open_internal
#define sqlite3_open16  sqlite3_open16_internal
#define sqlite3_open_v2 sqlite3_open_v2_internal
#endif

// Enable the user authentication feature
#ifndef SQLITE_USER_AUTHENTICATION
#define SQLITE_USER_AUTHENTICATION 1
#endif

#include "sqlite3.c"
#ifdef SQLITE_USER_AUTHENTICATION
#include "sha2.h"
#include "sha2.c"
#endif

#ifdef SQLITE_ENABLE_EXTFUNC
#undef sqlite3_open
#undef sqlite3_open16
#undef sqlite3_open_v2
#endif


/*
** Get the codec argument for this pager
*/

void* mySqlite3PagerGetCodec(
  Pager *pPager
){
#if (SQLITE_VERSION_NUMBER >= 3006016)
  return sqlite3PagerGetCodec(pPager);
#else
  return (pPager->xCodec) ? pPager->pCodecArg : NULL;
#endif
}

/*
** Set the codec argument for this pager
*/

void mySqlite3PagerSetCodec(
  Pager *pPager,
  void *(*xCodec)(void*,void*,Pgno,int),
  void (*xCodecSizeChng)(void*,int,int),
  void (*xCodecFree)(void*),
  void *pCodec
){
  sqlite3PagerSetCodec(pPager, xCodec, xCodecSizeChng, xCodecFree, pCodec);
}
