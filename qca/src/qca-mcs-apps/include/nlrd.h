/*
* Copyright (c) 2019 Qualcomm Technologies, Inc.
*
* All Rights Reserved.
* Confidential and Proprietary - Qualcomm Technologies, Inc.
*
*/

#ifndef nlrd__h
#define nlrd__h
/*-M- nlrd -- netlink socket read wrapper.
 *
 * The reason for netlink socket reader is to allow the application to
 * group data out of the netlink socket.
 * Since the input stream may come in in chunks unaligned to the
 * intended blocking of the data, using buffering becomes essential.
 * The nlrd module also track the netlink socet creation and destroy
 *
 * The application maintains a "struct nlrd" control block.
 * After creating the netlink socket, the application
 * intializes the control block via a call to nlrdCreate(),
 * which sets up the buffering and polling of descriptor.
 * Thereafter, the application callback function is called whenever
 * more data is added (by nlrd) to the buffer.
 * The callback function should do the following:
 * -- Check for errors / EOF via nlrdErrorGet(). Close out if error.
 * -- Obtain buffer address and content size via calls to
 *      nlrdBufGet() and nlrdNBytesGet().
 * -- Check if the buffer obtains complete parsing units or not.
 *      If so, parse the unit and call nlrdConsume for each parsing unit
 *      (call nlrdBufGet() and nlrdNBytesGet() each time).
 *      It is permissible to modify the parsing unit in place if that
 *      helps.
 * When the buffering is no longer needed, it should be closed out
 * with nlrdDestroy() call. (This closes the file descriptor..).
 *
 * In case the application is not ready to process the data when the
 * callback is called, it may simply do nothing, but at some later
 * time the above described processing should be done from another context.
 *
 * Up to three cookies (Cookie1, Cookie2 and Cookie3) may be stored
 * by the application in the nlrd object.
 * Cookie1 is normally set by the Create() call, and may be changed
 * thereafter using the SetCookie1 function, and the other cookies
 * may be set after the Create() call using the SetCookie* functions.
 * The current value of Cookie1 is passed to the callback function,
 * and the other cookies can be obtained using the GetCookie* functions
 * provided that the nlrd object can be located; one possibility
 * is to use the ptr to the nlrd object as Cookie1 and then use
 * the GetCookie2 and GetCookie3 functions to get two cookies.
 */

/*-D- required includes
*/
#include <evloop.h>

/*-D- nlrd -- control structure for netlink socket buffered reading.
 */
struct nlrd {
	struct evloopReady Ready;   /* Direct interface to event loop */
	/* CB: NULL or called when more is added to Buf.  */
	void (*CB)(void *Cookie1);
	void *Cookie1;              /* app use */
	unsigned char *Buf;         /* NULL or buffering */
	int BufSize;                /* nbytes alloc in *Buf if Buf != NULL */
	int NBytes;                 /* no. of bytes waiting in Buf */
	int Fatal;                  /* nonzero on fatal error or EOF */
	struct sockaddr_nl Local;	/* netlink local addresss */
	struct sockaddr_nl Peer;	/* netlink peer address */
};

/*-D- nlrdErrorGet -- returns nonzero on fatal error.
 */
static inline int nlrdErrorGet(struct nlrd *B)
{
	return B->Fatal;
}

/*-D- nlrdBufGet -- get buffer location.
 * May return NULL if nothing is buffered.
 */
static inline void *nlrdBufGet(struct nlrd *B)
{
	return B->Buf;
}

/*-D- nlrdNBytesGet -- get buffer content size.
 */
static inline int nlrdNBytesGet(struct nlrd *B)
{
	return B->NBytes;
}

/*-D- nlrdDescriptionGet -- return buffer description.
 */
static inline const char *nlrdDescriptionGet(struct nlrd *B)
{
	return evloopReadyDescriptionGet(&B->Ready);
}

/*-D- nlrdFdGet -- return which descriptor.
 */
static inline int nlrdFdGet(struct nlrd *B)
{
	return evloopReadyFdGet(&B->Ready);
}

/*-D- nlrdCookie1Get -- return 1st application cookie.
 */
static inline void *nlrdCookie1Get(struct nlrd *B)
{
	return B->Cookie1;
}

/*-D- nlrdCookie2Get -- return 2nd application cookie.
 */
static inline void *nlrdCookie2Get(struct nlrd *B)
{
	return evloopReadyCookie2Get(&B->Ready);
}

/*-D- nlrdCookie3Get -- return 3rd application cookie.
 */
static inline void *nlrdCookie3Get(struct nlrd *B)
{
	return evloopReadyCookie3Get(&B->Ready);
}

/*-D- nlrdCookie1Set -- set 1st application cookie.
 */
static inline void nlrdCookie1Set(
		struct nlrd *B,
		void *Cookie1)
{
	B->Cookie1 = Cookie1;
}

/*-D- nlrdCookie2Set -- set 2nd application cookie.
 */
static inline void nlrdCookie2Set(
		struct nlrd *B,
		void *Cookie2)
{
	evloopReadyCookie2Set(&B->Ready, Cookie2);
}

/*-D- nlrdCookie3Set -- set 3rd application cookie.
 */
static inline void nlrdCookie3Set(
		struct nlrd *B,
		void *Cookie3)
{
	evloopReadyCookie3Set(&B->Ready, Cookie3);
}

/*-F- nlrdCreate -- set up netlink socket with specified protocol and group to
 * join
 * Create NL socket and add it to the evloop
 * nlrdDestroy() ... dup it if you need to keep it.
 */
extern void nlrdCreate(
		struct nlrd *B,			/* control struct provided by app */
		const char *Description,	/* of nonvolatile string! for debugging */
		int Protocol,			/*Netlink message protocol */
		int Group,			/*Multicast Netlink message group to join */
		void (*CB)(void *Cookie1),	/* NULL, or called when ready */
		void *Cookie1			/* app use */
		);


/*-F- nlrdDestroy -- take down read buffering
 * This unregisters and frees allocated buffer if any.
 */
extern void nlrdDestroy(
		struct nlrd *B         /* control struct provided by app */
		);

/*-F- nlrdConsume -- call when one or more bytes from front of buffer
 * have been processed and should not be seen again.
 */
extern void nlrdConsume(
		struct nlrd *B,        /* control struct provided by app */
		int NBytes             /* no. of bytes to take off of buffer */
		);

extern struct rtattr *nlrdGetRta(struct nlmsghdr *H, int RtaType);
extern int nlrdDumpLinkReq(struct nlrd *B);

#endif  /* nlrd__h */
