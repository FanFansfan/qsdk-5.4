/*
* Copyright (c) 2019 Qualcomm Technologies, Inc.
*
* All Rights Reserved.
* Confidential and Proprietary - Qualcomm Technologies, Inc.
*
*/

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

#include <stdlib.h>
#include <poll.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <dbg.h>
#include <nlrd.h>

#if 0   /* auto-extract only */
/*-D- Required includes
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

/*----------------------------------------------*/
#endif  /* auto-extract only */

static size_t defaultMsgSize;

/*--- nlrdState -- global data for nlrd
 */
struct nlrdState {
	int IsInit;
	struct dbgModule *DebugModule;
} nlrdS;

/*-D- nlrdDebug -- print debug messages (see dbgf documentation)
 */
#define nlrdDebug(level, ...)         dbgf(nlrdS.DebugModule,(level),__VA_ARGS__)

/*-D- nlrdInit -- first time init.
 */
static void nlrdInit(void)
{
	if (nlrdS.IsInit)
		return;

	nlrdS.IsInit = 1;

	defaultMsgSize = getpagesize();
	nlrdS.DebugModule = dbgModuleFind("nlrd");
	nlrdDebug(DBGINFO, "nlrdInit Done.");
}

/* -D- nlrdReady -- internal function, called back when we are ready to read.
 */
static void nlrdReady(void *Cookie)
{
	/* We are called because we should be able to read w/out blocking */
	struct nlrd *B = Cookie;
	struct evloopReady *R = &B->Ready;
	int NToRead = B->BufSize - B->NBytes;

retry:
	if (NToRead > 0) {
		int NRead, Flags = 0;
		struct iovec Vec;
		struct sockaddr_nl Address = {/*0*/};
		struct msghdr Message = {
			.msg_name = (void *) &Address,
			.msg_namelen = sizeof(struct sockaddr_nl),
			.msg_iov = &Vec,
			.msg_iovlen = 1,
			.msg_control = NULL,
			.msg_controllen = 0,
			.msg_flags = 0,
		};

		Vec.iov_len = NToRead;
		Vec.iov_base = B->Buf + B->NBytes;

		NRead = recvmsg(evloopReadyFdGet(R), &Message, Flags);
		if (!NRead)
			goto abort;
		else if (NRead < 0) {
			if (errno == EINTR) {
				nlrdDebug(DBGINFO, "recvmsg() returned EINTR, retrying");
				goto retry;
			} else if (errno == EAGAIN) {
				nlrdDebug(DBGINFO, "recvmsg() returned EAGAIN, aborting\n");
				goto abort;
			} else {
				B->Fatal = 1;
				goto abort;
			}
		}

		if (Vec.iov_len < NRead || Message.msg_flags & MSG_TRUNC) {
			/* Provided buffer is not long enough, enlarge it and try again. */
			B->BufSize *= 2;
			B->Buf = realloc(B->Buf, B->BufSize);
			NToRead = B->BufSize - B->NBytes;
			Vec.iov_len = NToRead;
			Vec.iov_base = B->Buf + B->NBytes;
			goto retry;
		} else if (Flags != 0) {
			/* Buffer is big enough, do the actual reading */
			Flags = 0;
			goto retry;
		}

		if (Message.msg_namelen != sizeof(struct sockaddr_nl)) {
			B->Fatal = 1;
		}

		if (Address.nl_pid == 0) {
			nlrdDebug(DBGINFO, "%s:rcvm message from the kernel:%d\n", __func__, B->NBytes);
		}

		B->NBytes += NRead;
	}

abort:
	/* If full, unregister; consume call will register again */
	if (B->NBytes >= B->BufSize || B->Fatal) {
		evloopReadyUnregister(R);
	}

	/* Call callback function so long as we are making progress. */

	while (B->CB) {
		int NBytes = B->NBytes;
		(*B->CB)(B->Cookie1);
		if (B->NBytes == NBytes)
			break;      /* no progress made */
	}
}

/*-F- nlrdCreate -- set up netlink socket with specified protocol and group to
 * join
 * Create NL socket and add it to the evloop
 * nlrdDestroy() ... dup it if you need to keep it.
 */
void nlrdCreate(
		struct nlrd *B,			/* control struct provided by app */
		const char *Description,	/* of nonvolatile string! for debugging */
		int Protocol,			/*Netlink message protocol */
		int Group,			/*Multicast Netlink message group to join */
		void (*CB)(void *Cookie1),	/* NULL, or called when ready */
		void *Cookie1			/* app use */
		)
{
	int32_t Fd;
	int Error;
	socklen_t SockLen;
	int TxSize = 32768, RxSize = 32768;

	if (!nlrdS.IsInit)
		nlrdInit();

	nlrdDebug(DBGINFO, "ENTER nlrdCreate `%s'", Description);
	memset(B, 0, sizeof(*B));
	Fd = socket(AF_NETLINK, SOCK_RAW, Protocol);
	if (Fd < 0) {
		nlrdDebug(DBGERR, "Create netlink socket failed for rotocol:%d", Protocol);
		return;
	}

	if (fcntl(Fd, F_SETFL, fcntl(Fd, F_GETFL) | O_NONBLOCK)) {
		nlrdDebug(DBGERR, "%s fcntl set non block failed", __func__);
		goto errout;
	}

	if (Group) {
		B->Local.nl_groups |= Group;
	}

	B->Local.nl_family = AF_NETLINK;
	B->Local.nl_pid = getpid();
	B->Peer.nl_family = AF_NETLINK;

	Error = setsockopt(Fd, SOL_SOCKET, SO_SNDBUF, &TxSize, sizeof(TxSize));
	if (Error < 0) {
		nlrdDebug(DBGERR, "%s Set Tx Size option failed:%s", __func__, strerror(errno));
		goto errout;
	}

	Error = setsockopt(Fd, SOL_SOCKET, SO_RCVBUF, &RxSize, sizeof(RxSize));
	if (Error < 0) {
		nlrdDebug(DBGERR, "%s Set receive buffer size failed:%s", __func__, strerror(errno));
		goto errout;
	}

	Error = bind(Fd, (struct sockaddr *)&B->Local, sizeof B->Local);
	if (Error < 0) {
		nlrdDebug(DBGERR, "%s Bind netlink socket failed", __func__);
		goto errout;
	}

	SockLen = sizeof B->Local;
	Error = getsockname(Fd, (struct sockaddr *) &B->Local, &SockLen);
	if (Error < 0) {
		nlrdDebug(DBGERR, "%s:%s", __func__, strerror(errno));
		goto errout;
	}

	if (SockLen != sizeof(B->Local)) {
		nlrdDebug(DBGERR, "%s:Address Length is not Match", __func__);
		goto errout;
	}

	if (B->Local.nl_family != AF_NETLINK) {
		nlrdDebug(DBGERR, "%s:Netlink is not supported", __func__);
		goto errout;
	}

	B->CB = CB;
	B->Cookie1 = Cookie1;
	B->BufSize = getpagesize() * 4;
	B->Buf = malloc(B->BufSize);
	if (B->Buf == NULL) {
		nlrdDebug(DBGERR, "Malloc failure!");
		B->Fatal = 1;
	}

	evloopReadReadyCreate(&B->Ready, Description, Fd, nlrdReady, B);
	evloopReadyRegister(&B->Ready);
	return;
errout:
	close(Fd);
	B->Fatal = 1;
	return;
}

/*-F- nlrdDestroy -- take down netlink socket read buffering
 * This unregisters and frees allocated buffer if any.
 */
void nlrdDestroy(
		struct nlrd *B         /* control struct provided by app */
		)
{
	if (!nlrdS.IsInit)
		nlrdInit();

	nlrdDebug(DBGINFO, "ENTER nlrdDestroy `%s'", evloopReadyDescriptionGet(&B->Ready));

	evloopReadyUnregister(&B->Ready);

	if (evloopReadyFdGet(&B->Ready) > 0)
		close(evloopReadyFdGet(&B->Ready));

	if(B->Buf)free(B->Buf);

	memset(B, 0, sizeof(*B));
}

/*-F- nlrdConsume -- call when one or more bytes from front of buffer
 * have been processed and should not be seen again.
 */
void nlrdConsume(
		struct nlrd *B,		/* control struct provided by app */
		int NBytes)		/* no. of bytes to take off of buffer*/
{
	int NLeft;
	if (!nlrdS.IsInit)
		nlrdInit();

	nlrdDebug(DBGDEBUG, "ENTER nlrdConsume `%s' %d bytes", evloopReadyDescriptionGet(&B->Ready), NBytes);

	NLeft = B->NBytes - NBytes;
	if (NLeft < 0) {
		nlrdDebug(DBGERR, "Redundant nlrdConsume call!");
		return;
	}

	if (NLeft > 0)
		memmove(B->Buf, B->Buf+NBytes, NLeft);
	B->NBytes = NLeft;
	if (B->NBytes < B->BufSize)
		evloopReadyRegister(&B->Ready);
}

/*-F- nlrdGetRta -- Get rta in the data of a netlink message by type
 */
struct rtattr *nlrdGetRta(struct nlmsghdr *H, int RtaType)
{
	struct rtattr *Ra;
	int NLeft;
	NLeft = H->nlmsg_len - NLMSG_LENGTH(sizeof(struct ifinfomsg));
	for (Ra = IFLA_RTA(NLMSG_DATA(H)); RTA_OK(Ra, NLeft); Ra = RTA_NEXT(Ra, NLeft))
	{
		if (Ra->rta_type == RtaType) {
			return Ra;
		}
	}

	return NULL;
}

/*-F- nlrdDumpLinkReq -- Send a link dump message to linux kernel
 */
int nlrdDumpLinkReq(struct nlrd *B)
{
	struct nlrtmessage {
		struct nlmsghdr NLHeader;
		struct rtgenmsg RTGMessage;
	} nlrtRequest;

	if (!nlrdS.IsInit)
		nlrdInit();

	memset(&nlrtRequest, 0, sizeof(nlrtRequest));
	nlrtRequest.NLHeader.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtgenmsg));
	nlrtRequest.NLHeader.nlmsg_type = RTM_GETLINK;
	nlrtRequest.NLHeader.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	nlrtRequest.NLHeader.nlmsg_pid = B->Local.nl_pid ;
	nlrtRequest.RTGMessage.rtgen_family = AF_INET;

	struct msghdr Message = {
		.msg_name = (void *) &B->Peer,
		.msg_namelen = sizeof(struct sockaddr_nl),
	};

	struct iovec IVector = {
		.iov_base = (void *)&nlrtRequest,
		.iov_len =nlrtRequest.NLHeader.nlmsg_len,
	};

	Message.msg_iov = &IVector;
	Message.msg_iovlen = 1;
	sendmsg(nlrdFdGet(B), &Message, 0);
	nlrdDebug(DBGDEBUG, "Send the message to kernel!");

	return 0;
}
