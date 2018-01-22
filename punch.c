/*
 * $Id: punch.c,v 1.2 2002/03/24 20:06:38 route Exp $
 *
 * Building Open Source Network Security Tools
 * punch.c - libnet 1.1.0 example code
 *
 * Copyright (c) 2002 Mike D Schiffman <mike@infonexus.com>
 * All rights reserved.
 *
 */

#include "punch.h"

int main(int argc, char *argv[]) {
  u_short		sleep;
  libnet_t		*l;
  char			*payload;
  libnet_ptag_t		t, udp;
  int			c, fast, timer, build_ip;
  u_long		src_ip, dst_ip;
  struct timeval	r, s, e;
  struct libnet_stats	ls;
  char			dot = '.', bs = '\b';
  libnet_plist_t	plist, *plist_p;
  char			errbuf[LIBNET_ERRBUF_SIZE];
  u_short		payload_s, bport, eport, cport;

  printf("Punch 1.0 [UDP packet shaping/blasting tool]\n");

  /*
   * Power up libnet using the link-layer interface. We're going to
   * rely on libnet to find a device to use and 'errbuf' will hold 
   * the error if something breaks.
   */
  l = libnet_init(
		  LIBNET_LINK, /* injection type */
		  NULL,        /* network interface */
		  errbuf);     /* errbuf */
  if (l == NULL) {
    fprintf(stderr, "libnet_init() failed: %s", errbuf);
    exit(EXIT_FAILURE);
  }

  fast = 0;
  timer = 1;
  sleep = 0;
  src_ip = 0;
  dst_ip = 0;
  payload_s = 0;
  payload = NULL;
  plist_p = NULL;

  while ((c = getopt(argc, argv, "d:fS:s:p:P:")) != EOF) {
    switch (c) {
    case 'd':
      dst_ip = libnet_name2addr4(l, optarg, LIBNET_RESOLVE);
      if (dst_ip == -1) {
	fprintf(stderr, "Bad IP address %s\n", optarg);
	exit(EXIT_FAILURE);
      }
      break;
    case 'f':
      fast = 1;
      break;
    case 'S':
      sleep = atoi(optarg);
      break;
    case 's':
      src_ip = libnet_name2addr4(l, optarg, LIBNET_RESOLVE);
      if (src_ip == -1) {
	fprintf(stderr, "Bad IP address: %s\n", optarg);
	exit(EXIT_FAILURE);
      }
      break;
    case 'P':
      /*
       * Initialize the port list chain. Libnet's expecting
       * the port list to be specified in the format "x - y, z"
       * or some combination thereof.
       */
      plist_p = &plist;
      if (libnet_plist_chain_new(l, &plist_p, optarg) == -1) {
	fprintf(stderr, "Bad token: %s\n", libnet_geterror(l));
	exit(EXIT_FAILURE);
      }
      break;
    case'p':
      payload = optarg;
      payload_s = strlen(payload);
      break;
    default:
      usage(argv[0]);
      exit(EXIT_FAILURE);
    }
  }

  if (!src_ip || !dst_ip || !plist_p) {
    usage(argv[0]);
    exit(EXIT_FAILURE);
  }

  /* initialize these guys */
  udp = t = LIBNET_PTAG_INITIALIZER;

  /* start the loop timer */
  if (gettimeofday(&s, NULL) == -1) {
    fprintf(stderr, "Can't set timer\n");
    timer = 0;
  }

  /*
   * Only the first time we run through the loop will we need to
   * build an IPv4 and and Ethernet header.
   */
  build_ip = 1;

  /*
   * Start through the packet sending loop pulling out port list
   * numbers as we go. This will terminate when we run out of port
   * list pairs.
   */
  for (; libnet_plist_chain_next_pair(plist_p, &bport, &eport); ) {
    while (!(bport > eport) && bport != 0) {
      cport = bport++;
      /*
       * Start our packet building process. Remember we have to
       * the packet in order as it will appear on the wire. We
       * go from highest protocol to lowest, so we start with
       * our UDP header (and any user supplied payload data).
       * Since we're going to be modifying this packet header
       * throughout the loop, we'll save the ptag 'udp' and
       * reuse it.
       */
      udp = libnet_build_udp(
			     1025,                     /* source port */
			     cport,                    /* destination port */
			     LIBNET_UDP_H + payload_s, /* packet size */
			     0,                        /* checksum */
			     payload,                  /* payload */
			     payload_s,                /* payload size */
			     l,                        /* libnet context */
			     udp);                     /* ptag */
      if (udp == -1) {
	fprintf(stderr, "Can't build UDP header (port %d): %s\n",
		cport, libnet_geterror(l));
	goto bad;
      }

      /*
       * The first time through the loop we'll build an IPv4 and
       * an Ethernet header. Since we're not going to modify
       * either one of them again, we only need to do this once.
       */
      if (build_ip) {
	build_ip = 0;
	/*
	 * Build the IPv4 header. Note that we have to pass in
	 * the ENTIRE IP packet length, including the IP header
	 * itself. Previous versions of libnet would assume a
	 * length of at least 20 bytes and would add to that
	 * value whatever the app programmer passed in. Also
	 * note the checksum of 0, which tells libnet to
	 * compute the checksum before writing the packet to
	 * the wire. The payload functionality isn't used here
	 * since we have libnet functionality to build our UDP
	 * header. The ptag 't' is thrown away since we're not
	 * going to modify the IP header again.
	 */
	t = libnet_build_ipv4(
			      LIBNET_IPV4_H + LIBNET_UDP_H + payload_s,
			      0,           /* type of service */
			      242,         /* identification */
			      0,           /* fragmentation */
			      64,          /* time to live */
			      IPPROTO_UDP, /* protocol */
			      0,           /* checksum */
			      src_ip,      /* source */
			      dst_ip,      /* destination */
			      NULL,        /* payload */
			      0,           /* payload size */
			      l,           /* libnet context */
			      0);          /* ptag */
	if (t == -1) {
	  fprintf(stderr, "Can't build IP header: %s\n", libnet_geterror(l));
	  goto bad;
	}

	/*
	 * Build the Ethernet header and discard the ptag.
	 */
	t = libnet_build_ethernet(
				  enet_dst,     /* ethernet destination */
				  enet_src,     /* ethernet source */
				  ETHERTYPE_IP, /* protocol type */
				  NULL,         /* payload */
				  0,            /* payload size */
				  l,            /* libnet context */
				  0);           /* ptag */
	if (t == -1) {
	  fprintf(stderr, "Can't build ethernet header: %s\n",
		  libnet_geterror(l));
	  goto bad;
	}
      }

      if (sleep) {
	/* even 1 usec makes a huge difference */
	usleep(sleep);
      }

      if (fast) {
	/* this is needed to set up the screen properly */
	write(STDERR_FILENO, &dot, 1);
      }

      /*
       * Write the packet to the wire. Libnet will handle the
       * checksum calculation here for IP (since we're at the
       * link-layer) and UDP.
       */
      c = libnet_write(l);
      if (c == -1) {
	if (fast) {
	  write(STDERR_FILENO, &dot, 1);
	} else {
	  fprintf(stderr, "write error: %s\n", libnet_geterror(l));
	}
      } else {
	if (fast) {
	  write(STDERR_FILENO, &bs, 1);
	} else {
	  fprintf(stderr, "wrote %d byte UDP packet to port %d\n", c, cport);
	}
      }
    }
  }

  if (timer) {
    if (gettimeofday(&e, NULL) == -1) {
      fprintf(stderr, "Can't set timer\n");
    } else {
      PTIMERSUB(&e, &s, &r);
      fprintf(stderr, "\nTime spent in loop: %ld.%ld seconds\n",
	      r.tv_sec, r.tv_usec);
    }
  }

  libnet_stats(l, &ls);
  printf("Packets sent: %ld\nPacket errors: %ld\nBytes written: %ld\n",
	 ls.packets_sent, ls.packet_errors, ls.bytes_written);
  libnet_destroy(l);
  return EXIT_SUCCESS;
 bad:
  libnet_destroy(l);
  return EXIT_FAILURE;
}

void usage(char *name) {
  fprintf(stderr,
	  "usage: %s:\n"
	  "-s ip\t\tSource IP address\n"
	  "-d ip\t\tDestination IP address\n"
	  "-P port list\tUDP port list (x-y,z)\n"
	  "[-f]\t\tFast mode, minimal screen output\n"
	  "[-p payload]\tPayload\n"
	  "[-S usec]\tMicrosecond pause between writing\n",
	  name);
}

/* EOF */
