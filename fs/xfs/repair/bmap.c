/*
 * Copyright (C) 2016-2017 Oracle.  All Rights Reserved.
 *
 * Author: Darrick J. Wong <darrick.wong@oracle.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it would be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write the Free Software Foundation,
 * Inc.,  51 Franklin St, Fifth Floor, Boston, MA  02110-1301, USA.
 */
#include "xfs.h"
#include "xfs_fs.h"
#include "xfs_shared.h"
#include "xfs_format.h"
#include "xfs_trans_resv.h"
#include "xfs_mount.h"
#include "xfs_defer.h"
#include "xfs_btree.h"
#include "xfs_bit.h"
#include "xfs_log_format.h"
#include "xfs_trans.h"
#include "xfs_trace.h"
#include "xfs_sb.h"
#include "xfs_inode.h"
#include "xfs_inode_fork.h"
#include "xfs_bmap.h"
#include "xfs_bmap_util.h"
#include "xfs_bmap_btree.h"
#include "xfs_rmap.h"
#include "xfs_alloc.h"
#include "repair/common.h"
#include "repair/btree.h"

/*
 * Inode fork block mapping (BMBT) scrubber.
 * More complex than the others because we have to scrub
 * all the extents regardless of whether or not the fork
 * is in btree format.
 */

struct xfs_scrub_bmap_info {
	struct xfs_scrub_context	*sc;
	const char			*type;
	xfs_daddr_t			eofs;
	xfs_fileoff_t			lastoff;
	bool				is_rt;
	bool				is_shared;
	bool				scrub_btrec;
	int				whichfork;
};

#define XFS_SCRUB_BMAP_CHECK(fs_ok) \
	XFS_SCRUB_INO_CHECK(info->sc, info->sc->ip->i_ino, bp, info->type, fs_ok)
#define XFS_SCRUB_BMAP_GOTO(fs_ok, label) \
	XFS_SCRUB_INO_GOTO(info->sc, info->sc->ip->i_ino, bp, info->type, fs_ok, label)
#define XFS_SCRUB_BMAP_OP_ERROR_GOTO(label) \
	XFS_SCRUB_OP_ERROR_GOTO(info->sc, agno, 0, "bmap", &error, label);
/* Scrub a single extent record. */
STATIC int
xfs_scrub_bmap_extent(
	struct xfs_inode		*ip,
	struct xfs_btree_cur		*cur,
	struct xfs_scrub_bmap_info	*info,
	struct xfs_bmbt_irec		*irec)
{
	struct xfs_scrub_ag		sa = {0};
	struct xfs_mount		*mp = ip->i_mount;
	struct xfs_buf			*bp = NULL;
	xfs_daddr_t			daddr;
	xfs_daddr_t			dlen;
	xfs_agnumber_t			agno;
	xfs_fsblock_t			bno;
	bool				is_freesp;
	int				error = 0;
	int				err2 = 0;

	if (cur)
		xfs_btree_get_block(cur, 0, &bp);

	XFS_SCRUB_BMAP_CHECK(irec->br_startoff >= info->lastoff);
	XFS_SCRUB_BMAP_CHECK(irec->br_startblock != HOLESTARTBLOCK);

	if (isnullstartblock(irec->br_startblock)) {
		XFS_SCRUB_BMAP_CHECK(irec->br_state == XFS_EXT_NORM);
		goto out;
	}

	/* Actual mapping, so check the block ranges. */
	if (info->is_rt) {
		daddr = XFS_FSB_TO_BB(mp, irec->br_startblock);
		agno = NULLAGNUMBER;
		bno = irec->br_startblock;
	} else {
		daddr = XFS_FSB_TO_DADDR(mp, irec->br_startblock);
		agno = XFS_FSB_TO_AGNO(mp, irec->br_startblock);
		XFS_SCRUB_BMAP_GOTO(agno < mp->m_sb.sb_agcount, out);
		bno = XFS_FSB_TO_AGBNO(mp, irec->br_startblock);
	}
	dlen = XFS_FSB_TO_BB(mp, irec->br_blockcount);
	XFS_SCRUB_BMAP_CHECK(daddr < info->eofs);
	XFS_SCRUB_BMAP_CHECK(daddr + dlen < info->eofs);
	XFS_SCRUB_BMAP_CHECK(irec->br_state != XFS_EXT_UNWRITTEN ||
			xfs_sb_version_hasextflgbit(&mp->m_sb));
	if (error)
		goto out;

	/* Set ourselves up for cross-referencing later. */
	if (!info->is_rt) {
		if (!xfs_scrub_ag_can_lock(info->sc, agno))
			return -EDEADLOCK;
		error = xfs_scrub_ag_init(info->sc, agno, &sa);
		XFS_SCRUB_BMAP_OP_ERROR_GOTO(out);
	}

	/* Make sure we don't cover the AG headers. */
	if (!info->is_rt)
		XFS_SCRUB_BMAP_CHECK(!xfs_scrub_extent_covers_ag_head(mp,
				bno, irec->br_blockcount));

	/* Cross-reference with the bnobt. */
	if (sa.bno_cur) {
		err2 = xfs_alloc_has_record(sa.bno_cur, bno,
				irec->br_blockcount, &is_freesp);
		if (xfs_scrub_should_xref(info->sc, err2, &sa.bno_cur))
			XFS_SCRUB_BMAP_CHECK(!is_freesp);
	}

	xfs_scrub_ag_free(&sa);
out:
	info->lastoff = irec->br_startoff + irec->br_blockcount;
	return error;
}
#undef XFS_SCRUB_BMAP_OP_ERROR_GOTO
#undef XFS_SCRUB_BMAP_GOTO

/* Scrub a bmbt record. */
STATIC int
xfs_scrub_bmapbt_helper(
	struct xfs_scrub_btree		*bs,
	union xfs_btree_rec		*rec)
{
	struct xfs_bmbt_rec_host	ihost;
	struct xfs_bmbt_irec		irec;
	struct xfs_scrub_bmap_info	*info = bs->private;
	struct xfs_inode		*ip = bs->cur->bc_private.b.ip;
	struct xfs_buf			*bp = NULL;
	struct xfs_btree_block		*block;
	uint64_t			owner;
	int				i;

	/*
	 * Check the owners of the btree blocks up to the level below
	 * the root since the verifiers don't do that.
	 */
	if (xfs_sb_version_hascrc(&bs->cur->bc_mp->m_sb) &&
	    bs->cur->bc_ptrs[0] == 1) {
		for (i = 0; i < bs->cur->bc_nlevels - 1; i++) {
			block = xfs_btree_get_block(bs->cur, i, &bp);
			owner = be64_to_cpu(block->bb_u.l.bb_owner);
			XFS_SCRUB_BMAP_CHECK(owner == ip->i_ino);
		}
	}

	if (!info->scrub_btrec)
		return 0;

	/* Set up the in-core record and scrub it. */
	ihost.l0 = be64_to_cpu(rec->bmbt.l0);
	ihost.l1 = be64_to_cpu(rec->bmbt.l1);
	xfs_bmbt_get_all(&ihost, &irec);
	return xfs_scrub_bmap_extent(ip, bs->cur, info, &irec);
}
#undef XFS_SCRUB_BMAP_CHECK

#define XFS_SCRUB_FORK_CHECK(fs_ok) \
	XFS_SCRUB_INO_CHECK(sc, ip->i_ino, NULL, info.type, fs_ok);
#define XFS_SCRUB_FORK_GOTO(fs_ok, label) \
	XFS_SCRUB_INO_GOTO(sc, ip->i_ino, NULL, info.type, fs_ok, label);
#define XFS_SCRUB_FORK_OP_ERROR_GOTO(label) \
	XFS_SCRUB_OP_ERROR_GOTO(sc, \
			XFS_INO_TO_AGNO(ip->i_mount, ip->i_ino), \
			XFS_INO_TO_AGBNO(ip->i_mount, ip->i_ino), \
			info.type, &error, label)
/* Scrub an inode fork's block mappings. */
STATIC int
xfs_scrub_bmap(
	struct xfs_scrub_context	*sc,
	int				whichfork)
{
	struct xfs_bmbt_irec		irec;
	struct xfs_scrub_bmap_info	info = {0};
	struct xfs_owner_info		oinfo;
	struct xfs_mount		*mp = sc->tp->t_mountp;
	struct xfs_inode		*ip = sc->ip;
	struct xfs_ifork		*ifp;
	struct xfs_btree_cur		*cur;
	xfs_fileoff_t			off;
	xfs_fileoff_t			endoff;
	int				nmaps;
	int				flags = 0;
	int				error = 0;
	int				err2 = 0;

	switch (whichfork) {
	case XFS_DATA_FORK:
		info.type = "data fork";
		break;
	case XFS_ATTR_FORK:
		info.type = "attr fork";
		break;
	case XFS_COW_FORK:
		info.type = "CoW fork";
		break;
	}
	ifp = XFS_IFORK_PTR(ip, whichfork);

	info.is_rt = whichfork == XFS_DATA_FORK && XFS_IS_REALTIME_INODE(ip);
	info.eofs = XFS_FSB_TO_BB(mp, info.is_rt ? mp->m_sb.sb_rblocks :
					      mp->m_sb.sb_dblocks);
	info.whichfork = whichfork;
	info.is_shared = whichfork == XFS_DATA_FORK && xfs_is_reflink_inode(ip);
	info.sc = sc;

	switch (whichfork) {
	case XFS_COW_FORK:
		/* Non-existent CoW forks are ignorable. */
		if (!ifp)
			goto out_unlock;
		/* No CoW forks on non-reflink inodes/filesystems. */
		XFS_SCRUB_FORK_GOTO(xfs_is_reflink_inode(ip), out_unlock);
		break;
	case XFS_ATTR_FORK:
		if (!ifp)
			goto out_unlock;
		XFS_SCRUB_FORK_CHECK(xfs_sb_version_hasattr(&mp->m_sb));
		break;
	}

	/* Check the fork values */
	switch (XFS_IFORK_FORMAT(ip, whichfork)) {
	case XFS_DINODE_FMT_UUID:
	case XFS_DINODE_FMT_DEV:
	case XFS_DINODE_FMT_LOCAL:
		/* No mappings to check. */
		goto out_unlock;
	case XFS_DINODE_FMT_EXTENTS:
		XFS_SCRUB_FORK_GOTO(ifp->if_flags & XFS_IFEXTENTS, out_unlock);
		break;
	case XFS_DINODE_FMT_BTREE:
		XFS_SCRUB_FORK_CHECK(whichfork != XFS_COW_FORK);
		/*
		 * Scan the btree.  If extents aren't loaded, have the btree
		 * scrub routine examine the extent records.
		 */
		info.scrub_btrec = !(ifp->if_flags & XFS_IFEXTENTS);

		cur = xfs_bmbt_init_cursor(mp, sc->tp, ip, whichfork);
		xfs_rmap_ino_bmbt_owner(&oinfo, ip->i_ino, whichfork);
		err2 = xfs_scrub_btree(sc, cur, xfs_scrub_bmapbt_helper,
				&oinfo, &info);
		xfs_btree_del_cursor(cur, err2 ? XFS_BTREE_ERROR :
						 XFS_BTREE_NOERROR);
		if (err2 == -EDEADLOCK)
			return err2;
		else if (err2)
			goto out_unlock;
		/* Skip in-core extent checking if we did it in the btree */
		if (info.scrub_btrec)
			goto out_unlock;
		break;
	default:
		XFS_SCRUB_FORK_GOTO(false, out_unlock);
		break;
	}

	/* Extent data is in memory, so scrub that. */
	switch (whichfork) {
	case XFS_ATTR_FORK:
		flags |= XFS_BMAPI_ATTRFORK;
		break;
	case XFS_COW_FORK:
		flags |= XFS_BMAPI_COWFORK;
		break;
	default:
		break;
	}

	/* Find the offset of the last extent in the mapping. */
	error = xfs_bmap_last_offset(ip, &endoff, whichfork);
	XFS_SCRUB_FORK_OP_ERROR_GOTO(out_unlock);

	/* Scrub extent records. */
	off = 0;
	while (true) {
		nmaps = 1;
		err2 = xfs_bmapi_read(ip, off, endoff - off, &irec,
				&nmaps, flags);
		if (err2 || nmaps == 0 || irec.br_startoff > endoff)
			break;
		/* Scrub non-hole extent. */
		if (irec.br_startblock != HOLESTARTBLOCK) {
			err2 = xfs_scrub_bmap_extent(ip, NULL, &info, &irec);
			if (err2 == -EDEADLOCK)
				return err2;
			else if (!error && err2)
				error = err2;
			if (xfs_scrub_should_terminate(&error))
				break;
		}

		off += irec.br_blockcount;
	}

out_unlock:
	if (error == 0 && err2 != 0)
		error = err2;
	return error;
}
#undef XFS_SCRUB_FORK_CHECK
#undef XFS_SCRUB_FORK_GOTO

/* Scrub an inode's data fork. */
int
xfs_scrub_bmap_data(
	struct xfs_scrub_context	*sc)
{
	return xfs_scrub_bmap(sc, XFS_DATA_FORK);
}

/* Scrub an inode's attr fork. */
int
xfs_scrub_bmap_attr(
	struct xfs_scrub_context	*sc)
{
	return xfs_scrub_bmap(sc, XFS_ATTR_FORK);
}

/* Scrub an inode's CoW fork. */
int
xfs_scrub_bmap_cow(
	struct xfs_scrub_context	*sc)
{
	if (!xfs_is_reflink_inode(sc->ip))
		return -ENOENT;

	return xfs_scrub_bmap(sc, XFS_COW_FORK);
}
