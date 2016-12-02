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
#include "xfs_rmap_btree.h"
#include "xfs_alloc.h"
#include "xfs_ialloc.h"
#include "xfs_refcount.h"
#include "xfs_rtalloc.h"
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
	struct xfs_rmap_irec		rmap;
	struct xfs_refcount_irec	rc;
	uint64_t			owner;
	xfs_fileoff_t			offset;
	xfs_agblock_t			fbno;
	xfs_extlen_t			flen;
	bool				is_freesp;
	bool				has_inodes;
	bool				has_cowflag;
	bool				is_free;
	unsigned int			rflags;
	int				has_rmap;
	int				has_refcount;
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
	} else {
		xfs_ilock(mp->m_rbmip, XFS_ILOCK_SHARED | XFS_ILOCK_RTBITMAP);
		err2 = xfs_rtbitmap_extent_is_free(mp, info->sc->tp,
				irec->br_startblock, irec->br_blockcount,
				&is_free);
		if (xfs_scrub_should_xref(info->sc, err2, NULL))
			XFS_SCRUB_BMAP_CHECK(!is_free);
		xfs_iunlock(mp->m_rbmip, XFS_ILOCK_SHARED | XFS_ILOCK_RTBITMAP);
	}

	/* Cross-reference with inobt. */
	if (sa.ino_cur) {
		err2 = xfs_ialloc_has_inodes_at_extent(sa.ino_cur,
				irec->br_startblock, irec->br_blockcount,
				&has_inodes);
		if (xfs_scrub_should_xref(info->sc, err2, &sa.ino_cur))
			XFS_SCRUB_BMAP_CHECK(!has_inodes);
	}

	/* Cross-reference with finobt. */
	if (sa.fino_cur) {
		err2 = xfs_ialloc_has_inodes_at_extent(sa.fino_cur,
				irec->br_startblock, irec->br_blockcount,
				&has_inodes);
		if (xfs_scrub_should_xref(info->sc, err2, &sa.fino_cur))
			XFS_SCRUB_BMAP_CHECK(!has_inodes);
	}

	/* Cross-reference with rmapbt. */
	if (sa.rmap_cur) {
		if (info->whichfork == XFS_COW_FORK) {
			owner = XFS_RMAP_OWN_COW;
			offset = 0;
		} else {
			owner = ip->i_ino;
			offset = irec->br_startoff;
		}

		/* Look for a corresponding rmap. */
		rflags = 0;
		if (info->whichfork == XFS_ATTR_FORK)
			rflags |= XFS_RMAP_ATTR_FORK;

		if (info->is_shared) {
			err2 = xfs_rmap_lookup_le_range(sa.rmap_cur, bno, owner,
					offset, rflags, &rmap,
					&has_rmap);
			if (xfs_scrub_should_xref(info->sc, err2,
					&sa.rmap_cur)) {
				XFS_SCRUB_BMAP_GOTO(has_rmap, skip_rmap_xref);
			} else
				goto skip_rmap_xref;
		} else {
			err2 = xfs_rmap_lookup_le(sa.rmap_cur, bno, 0, owner,
					offset, rflags, &has_rmap);
			if (xfs_scrub_should_xref(info->sc, err2,
					&sa.rmap_cur)) {
				XFS_SCRUB_BMAP_GOTO(has_rmap, skip_rmap_xref);
			} else
				goto skip_rmap_xref;

			err2 = xfs_rmap_get_rec(sa.rmap_cur, &rmap,
					&has_rmap);
			if (xfs_scrub_should_xref(info->sc, err2,
					&sa.rmap_cur)) {
				XFS_SCRUB_BMAP_GOTO(has_rmap, skip_rmap_xref);
			} else
				goto skip_rmap_xref;
		}

		/* Check the rmap. */
		XFS_SCRUB_BMAP_CHECK(rmap.rm_startblock <= bno);
		XFS_SCRUB_BMAP_CHECK(rmap.rm_startblock <
				rmap.rm_startblock + rmap.rm_blockcount);
		XFS_SCRUB_BMAP_CHECK(bno + irec->br_blockcount <=
				rmap.rm_startblock + rmap.rm_blockcount);
		if (owner != XFS_RMAP_OWN_COW) {
			XFS_SCRUB_BMAP_CHECK(rmap.rm_offset <= offset);
			XFS_SCRUB_BMAP_CHECK(rmap.rm_offset <
					rmap.rm_offset + rmap.rm_blockcount);
			XFS_SCRUB_BMAP_CHECK(offset + irec->br_blockcount <=
					rmap.rm_offset + rmap.rm_blockcount);
		}
		XFS_SCRUB_BMAP_CHECK(rmap.rm_owner == owner);
		switch (irec->br_state) {
		case XFS_EXT_UNWRITTEN:
			XFS_SCRUB_BMAP_CHECK(
					rmap.rm_flags & XFS_RMAP_UNWRITTEN);
			break;
		case XFS_EXT_NORM:
			XFS_SCRUB_BMAP_CHECK(
					!(rmap.rm_flags & XFS_RMAP_UNWRITTEN));
			break;
		default:
			break;
		}
		switch (info->whichfork) {
		case XFS_ATTR_FORK:
			XFS_SCRUB_BMAP_CHECK(
					rmap.rm_flags & XFS_RMAP_ATTR_FORK);
			break;
		case XFS_DATA_FORK:
		case XFS_COW_FORK:
			XFS_SCRUB_BMAP_CHECK(
					!(rmap.rm_flags & XFS_RMAP_ATTR_FORK));
			break;
		}
		XFS_SCRUB_BMAP_CHECK(!(rmap.rm_flags & XFS_RMAP_BMBT_BLOCK));
skip_rmap_xref:
		;
	}

	/*
	 * If this is a non-shared file on a reflink filesystem,
	 * check the refcountbt to see if the flag is wrong.
	 */
	if (sa.refc_cur) {
		if (info->whichfork == XFS_COW_FORK) {
			/* Check this CoW staging extent. */
			err2 = xfs_refcount_lookup_le(sa.refc_cur,
					bno + XFS_REFC_COW_START,
					&has_refcount);
			if (xfs_scrub_should_xref(info->sc, err2,
					&sa.refc_cur)) {
				XFS_SCRUB_BMAP_GOTO(has_refcount,
						skip_refc_xref);
			} else
				goto skip_refc_xref;

			err2 = xfs_refcount_get_rec(sa.refc_cur, &rc,
					&has_refcount);
			if (xfs_scrub_should_xref(info->sc, err2,
					&sa.refc_cur)) {
				XFS_SCRUB_BMAP_GOTO(has_refcount,
						skip_refc_xref);
			} else
				goto skip_refc_xref;

			has_cowflag = !!(rc.rc_startblock & XFS_REFC_COW_START);
			XFS_SCRUB_BMAP_CHECK(
					(rc.rc_refcount == 1 && has_cowflag) ||
					(rc.rc_refcount != 1 && !has_cowflag));
			rc.rc_startblock &= ~XFS_REFC_COW_START;
			XFS_SCRUB_BMAP_CHECK(rc.rc_startblock <= bno);
			XFS_SCRUB_BMAP_CHECK(rc.rc_startblock <
					rc.rc_startblock + rc.rc_blockcount);
			XFS_SCRUB_BMAP_CHECK(bno + irec->br_blockcount <=
					rc.rc_startblock + rc.rc_blockcount);
			XFS_SCRUB_BMAP_CHECK(rc.rc_refcount == 1);
		} else {
			/* If this is shared, the inode flag must be set. */
			err2 = xfs_refcount_find_shared(sa.refc_cur, bno,
					irec->br_blockcount, &fbno, &flen,
					false);
			if (xfs_scrub_should_xref(info->sc, err2,
					&sa.refc_cur))
				XFS_SCRUB_BMAP_CHECK(flen == 0 ||
						xfs_is_reflink_inode(ip));
		}
skip_refc_xref:
		;
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

/* Inode fork block mapping (BMBT) repair. */

struct xfs_repair_bmap_extent {
	struct list_head		list;
	struct xfs_rmap_irec		rmap;
	xfs_agnumber_t			agno;
};

struct xfs_repair_bmap {
	struct list_head		extlist;
	struct list_head		btlist;
	xfs_ino_t			ino;
	xfs_rfsblock_t			bmbt_blocks;
	int				whichfork;
};

/* Record extents that belong to this inode's fork. */
STATIC int
xfs_repair_bmap_extent_fn(
	struct xfs_btree_cur		*cur,
	struct xfs_rmap_irec		*rec,
	void				*priv)
{
	struct xfs_repair_bmap		*rb = priv;
	struct xfs_repair_bmap_extent	*rbe;
	struct xfs_mount		*mp = cur->bc_mp;
	xfs_fsblock_t			fsbno;
	int				error = 0;

	if (xfs_scrub_should_terminate(&error))
		return error;

	/* Skip extents which are not owned by this inode and fork. */
	if (rec->rm_owner != rb->ino)
		return 0;
	else if (rb->whichfork == XFS_DATA_FORK &&
		 (rec->rm_flags & XFS_RMAP_ATTR_FORK))
		return 0;
	else if (rb->whichfork == XFS_ATTR_FORK &&
		 !(rec->rm_flags & XFS_RMAP_ATTR_FORK))
		return 0;

	/* Delete the old bmbt blocks later. */
	if (rec->rm_flags & XFS_RMAP_BMBT_BLOCK) {
		fsbno = XFS_AGB_TO_FSB(mp, cur->bc_private.a.agno,
				rec->rm_startblock);
		rb->bmbt_blocks += rec->rm_blockcount;
		return xfs_repair_collect_btree_extent(mp, &rb->btlist,
				fsbno, rec->rm_blockcount);
	}

	/* Remember this rmap. */
	trace_xfs_repair_bmap_extent_fn(mp, cur->bc_private.a.agno,
			rec->rm_startblock, rec->rm_blockcount, rec->rm_owner,
			rec->rm_offset, rec->rm_flags);

	rbe = kmem_alloc(sizeof(*rbe), KM_NOFS);
	if (!rbe)
		return -ENOMEM;

	INIT_LIST_HEAD(&rbe->list);
	rbe->rmap = *rec;
	rbe->agno = cur->bc_private.a.agno;
	list_add_tail(&rbe->list, &rb->extlist);

	return 0;
}

/* Compare two bmap extents. */
static int
xfs_repair_bmap_extent_cmp(
	void				*priv,
	struct list_head		*a,
	struct list_head		*b)
{
	struct xfs_repair_bmap_extent	*ap;
	struct xfs_repair_bmap_extent	*bp;

	ap = container_of(a, struct xfs_repair_bmap_extent, list);
	bp = container_of(b, struct xfs_repair_bmap_extent, list);

	if (ap->rmap.rm_offset > bp->rmap.rm_offset)
		return 1;
	else if (ap->rmap.rm_offset < bp->rmap.rm_offset)
		return -1;
	return 0;
}

/* Repair an inode fork. */
STATIC int
xfs_repair_bmap(
	struct xfs_scrub_context	*sc,
	int				whichfork)
{
	struct xfs_repair_bmap		rb = {0};
	struct xfs_bmbt_irec		bmap;
	struct xfs_defer_ops		dfops;
	struct xfs_owner_info		oinfo;
	struct xfs_inode		*ip = sc->ip;
	struct xfs_mount		*mp = ip->i_mount;
	struct xfs_buf			*agf_bp = NULL;
	struct xfs_repair_bmap_extent	*rbe;
	struct xfs_repair_bmap_extent	*n;
	struct xfs_btree_cur		*cur;
	xfs_fsblock_t			firstfsb;
	xfs_agnumber_t			agno;
	xfs_extlen_t			extlen;
	int				baseflags;
	int				flags;
	int				nimaps;
	int				error = 0;

	ASSERT(whichfork == XFS_DATA_FORK || whichfork == XFS_ATTR_FORK);

	/* Don't know how to repair the other fork formats. */
	if (XFS_IFORK_FORMAT(sc->ip, whichfork) != XFS_DINODE_FMT_EXTENTS &&
	    XFS_IFORK_FORMAT(sc->ip, whichfork) != XFS_DINODE_FMT_BTREE)
		return -ENOTTY;

	/* Only files, symlinks, and directories get to have data forks. */
	if (whichfork == XFS_DATA_FORK && !S_ISREG(VFS_I(ip)->i_mode) &&
	    !S_ISDIR(VFS_I(ip)->i_mode) && !S_ISLNK(VFS_I(ip)->i_mode))
		return -EINVAL;

	/* If we somehow have delalloc extents, forget it. */
	if (whichfork == XFS_DATA_FORK && ip->i_delayed_blks)
		return -EBUSY;

	/* We require the rmapbt to rebuild anything. */
	if (!xfs_sb_version_hasrmapbt(&mp->m_sb))
		return -EOPNOTSUPP;

	/* Don't know how to rebuild realtime data forks. */
	if (XFS_IS_REALTIME_INODE(ip) && whichfork == XFS_DATA_FORK)
		return -EOPNOTSUPP;

	/*
	 * If this is a file data fork, wait for all pending directio to
	 * complete, then tear everything out of the page cache.
	 */
	if (S_ISREG(VFS_I(ip)->i_mode) && whichfork == XFS_DATA_FORK) {
		inode_dio_wait(VFS_I(ip));
		truncate_inode_pages(VFS_I(ip)->i_mapping, 0);
	}

	/* Collect all reverse mappings for this fork's extents. */
	INIT_LIST_HEAD(&rb.extlist);
	INIT_LIST_HEAD(&rb.btlist);
	rb.ino = ip->i_ino;
	rb.whichfork = whichfork;
	for (agno = 0; agno < mp->m_sb.sb_agcount; agno++) {
		ASSERT(xfs_scrub_ag_can_lock(sc, agno));
		error = xfs_alloc_read_agf(mp, sc->tp, agno, 0, &agf_bp);
		if (error)
			goto out;
		cur = xfs_rmapbt_init_cursor(mp, sc->tp, agf_bp, agno);
		error = xfs_rmap_query_all(cur, xfs_repair_bmap_extent_fn, &rb);
		xfs_btree_del_cursor(cur, error ? XFS_BTREE_ERROR :
				XFS_BTREE_NOERROR);
		if (error)
			goto out;
	}

	/* Blow out the in-core fork and zero the on-disk fork. */
	if (XFS_IFORK_PTR(ip, whichfork) != NULL)
		xfs_idestroy_fork(sc->ip, whichfork);
	XFS_IFORK_FMT_SET(sc->ip, whichfork, XFS_DINODE_FMT_EXTENTS);
	XFS_IFORK_NEXT_SET(sc->ip, whichfork, 0);
	xfs_trans_ijoin(sc->tp, sc->ip, 0);

	/* Reinitialize the on-disk fork. */
	if (whichfork == XFS_DATA_FORK) {
		memset(&ip->i_df, 0, sizeof(struct xfs_ifork));
		ip->i_df.if_flags |= XFS_IFEXTENTS;
	} else if (whichfork == XFS_ATTR_FORK) {
		if (list_empty(&rb.extlist))
			ip->i_afp = NULL;
		else {
			ip->i_afp = kmem_zone_zalloc(xfs_ifork_zone, KM_NOFS);
			ip->i_afp->if_flags |= XFS_IFEXTENTS;
		}
	}
	xfs_trans_log_inode(sc->tp, sc->ip, XFS_ILOG_CORE);
	error = xfs_trans_roll(&sc->tp, sc->ip);
	if (error)
		goto out;

	baseflags = XFS_BMAPI_REMAP | XFS_BMAPI_NORMAP;
	if (whichfork == XFS_ATTR_FORK)
		baseflags |= XFS_BMAPI_ATTRFORK;

	/* "Remap" the extents into the fork. */
	list_sort(NULL, &rb.extlist, xfs_repair_bmap_extent_cmp);
	list_for_each_entry_safe(rbe, n, &rb.extlist, list) {
		/* Form the "new" mapping... */
		bmap.br_startblock = XFS_AGB_TO_FSB(mp, rbe->agno,
				rbe->rmap.rm_startblock);
		bmap.br_startoff = rbe->rmap.rm_offset;
		flags = 0;
		if (rbe->rmap.rm_flags & XFS_RMAP_UNWRITTEN)
			flags = XFS_BMAPI_PREALLOC;
		while (rbe->rmap.rm_blockcount > 0) {
			xfs_defer_init(&dfops, &firstfsb);
			extlen = min_t(xfs_extlen_t, rbe->rmap.rm_blockcount,
					MAXEXTLEN);
			bmap.br_blockcount = extlen;

			/* Drop the block counter... */
			sc->ip->i_d.di_nblocks -= extlen;
			xfs_trans_ijoin(sc->tp, sc->ip, 0);

			/* Re-add the extent to the fork. */
			nimaps = 1;
			firstfsb = bmap.br_startblock;
			error = xfs_bmapi_write(sc->tp, sc->ip,
					bmap.br_startoff,
					extlen, baseflags | flags, &firstfsb,
					extlen, &bmap, &nimaps,
					&dfops);
			if (error)
				goto out;

			bmap.br_startblock += extlen;
			bmap.br_startoff += extlen;
			rbe->rmap.rm_blockcount -= extlen;
			error = xfs_defer_finish(&sc->tp, &dfops, sc->ip);
			if (error)
				goto out;
			/* Make sure we roll the transaction. */
			error = xfs_trans_roll(&sc->tp, sc->ip);
			if (error)
				goto out;
		}
		list_del(&rbe->list);
		kmem_free(rbe);
	}

	/* Decrease nblocks to reflect the freed bmbt blocks. */
	if (rb.bmbt_blocks) {
		sc->ip->i_d.di_nblocks -= rb.bmbt_blocks;
		xfs_trans_ijoin(sc->tp, sc->ip, 0);
		xfs_trans_log_inode(sc->tp, sc->ip, XFS_ILOG_CORE);
		error = xfs_trans_roll(&sc->tp, sc->ip);
		if (error)
			goto out;
	}

	/* Dispose of all the old bmbt blocks. */
	xfs_rmap_ino_bmbt_owner(&oinfo, sc->ip->i_ino, whichfork);
	error = xfs_repair_reap_btree_extents(sc, &rb.btlist, &oinfo,
			XFS_AG_RESV_NONE);
	if (error)
		goto out;

	return error;
out:
	xfs_repair_cancel_btree_extents(sc, &rb.btlist);
	list_for_each_entry_safe(rbe, n, &rb.extlist, list) {
		list_del(&rbe->list);
		kmem_free(rbe);
	}
	return error;
}

/* Repair an inode's data fork. */
int
xfs_repair_bmap_data(
	struct xfs_scrub_context	*sc)
{
	return xfs_repair_bmap(sc, XFS_DATA_FORK);
}

/* Repair an inode's attr fork. */
int
xfs_repair_bmap_attr(
	struct xfs_scrub_context	*sc)
{
	return xfs_repair_bmap(sc, XFS_ATTR_FORK);
}
