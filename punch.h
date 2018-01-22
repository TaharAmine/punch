/*
 * $Id: punch.h,v 1.2 2002/03/24 20:06:38 route Exp $
 *
 * Building Open Source Network Security Tools
 * punch.h - libnet example code
 *
 * Copyright (c) 2002 Mike D. Schiffman <mike@infonexus.com>
 * All rights reserved.
 *
 */

#include <libnet.h>

/*
 * Simple way to subtract timeval based timers. Not every OS has this,
 * so we'll just define it here.
 */
#define PTIMERSUB(tvp, uvp, vvp)			\
  do {							\
  (vvp)->tv_sec = (tvp)->tv_sec - (uvp)->tv_sec;	\
  (vvp)->tv_usec = (tvp)->tv_usec - (uvp)->tv_usec;	\
  if ((vvp)->tv_usec < 0) {				\
    (vvp)->tv_sec--;					\
    (vvp)->tv_usec += 1000000;				\
  }							\
} while (0)

/* Check the OUI table for this one! */
u_char enet_src[6] = { 0x00, 0x50, 0x58, 0x0d, 0x0d, 0x0d };
u_char enet_dst[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

void usage(char *);
/* EOF */
