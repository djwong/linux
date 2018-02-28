/*
 * Copyright (C) 2018 Oracle.  All Rights Reserved.
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
#include "xfs_sb.h"
#include "xfs_inode.h"
#include "xfs_inode_fork.h"
#include "xfs_alloc.h"
#include "xfs_rtalloc.h"
#include "xfs_bmap.h"
#include "xfs_bmap_util.h"
#include "xfs_bmap_btree.h"
#include "xfs_rmap.h"
#include "xfs_rmap_btree.h"
#include "xfs_refcount.h"
#include "xfs_quota.h"
#include "scrub/xfs_scrub.h"
#include "scrub/scrub.h"
#include "scrub/common.h"
#include "scrub/btree.h"
#include "scrub/trace.h"
#include "scrub/repair.h"

/* Inode fork block mapping (BMBT) repair. */

struct xfs_repair_bmap_extent {
	struct list_head		list;
	struct xfs_rmap_irec		rmap;
	xfs_agnumber_t			agno;
};

struct xfs_repair_bmap {
	struct list_head		extlist;
	struct xfs_repair_extent_list	btlist;
	struct xfs_repair_bmap_extent	ext;	/* most files have 1 extent */
	struct xfs_scrub_context	*sc;
	xfs_ino_t			ino;
	xfs_rfsblock_t			otherfork_blocks;
	xfs_rfsblock_t			bmbt_blocks;
	xfs_extnum_t			extents;
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

	if (xfs_scrub_should_terminate(rb->sc, &error))
		return error;

	/* Skip extents which are not owned by this inode and fork. */
	if (rec->rm_owner != rb->ino) {
		return 0;
	} else if (rb->whichfork == XFS_DATA_FORK &&
		 (rec->rm_flags & XFS_RMAP_ATTR_FORK)) {
		rb->otherfork_blocks += rec->rm_blockcount;
		return 0;
	} else if (rb->whichfork == XFS_ATTR_FORK &&
		 !(rec->rm_flags & XFS_RMAP_ATTR_FORK)) {
		rb->otherfork_blocks += rec->rm_blockcount;
		return 0;
	}

	rb->extents++;

	/* Delete the old bmbt blocks later. */
	if (rec->rm_flags & XFS_RMAP_BMBT_BLOCK) {
		fsbno = XFS_AGB_TO_FSB(mp, cur->bc_private.a.agno,
				rec->rm_startblock);
		rb->bmbt_blocks += rec->rm_blockcount;
		return xfs_repair_collect_btree_extent(rb->sc, &rb->btlist,
				fsbno, rec->rm_blockcount);
	}

	/* Remember this rmap. */
	trace_xfs_repair_bmap_extent_fn(mp, cur->bc_private.a.agno,
			rec->rm_startblock, rec->rm_blockcount, rec->rm_owner,
			rec->rm_offset, rec->rm_flags);

	if (list_empty(&rb->extlist)) {
		rbe = &rb->ext;
	} else {
		rbe = kmem_alloc(sizeof(struct xfs_repair_bmap_extent),
				KM_MAYFAIL | KM_NOFS);
		if (!rbe)
			return -ENOMEM;
	}

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

/* Scan one AG for reverse mappings that we can turn into extent maps. */
STATIC int
xfs_repair_bmap_scan_ag(
	struct xfs_repair_bmap		*rb,
	xfs_agnumber_t			agno)
{
	struct xfs_scrub_context	*sc = rb->sc;
	struct xfs_mount		*mp = sc->mp;
	struct xfs_buf			*agf_bp = NULL;
	struct xfs_btree_cur		*cur;
	int				error;

	error = xfs_alloc_read_agf(mp, sc->tp, agno, 0, &agf_bp);
	if (error)
		return error;
	if (!agf_bp)
		return -ENOMEM;
	cur = xfs_rmapbt_init_cursor(mp, sc->tp, agf_bp, agno);
	error = xfs_rmap_query_all(cur, xfs_repair_bmap_extent_fn, rb);
	if (error == XFS_BTREE_QUERY_RANGE_ABORT)
		error = 0;
	xfs_btree_del_cursor(cur, error ? XFS_BTREE_ERROR :
			XFS_BTREE_NOERROR);
	xfs_trans_brelse(sc->tp, agf_bp);
	return error;
}

/* Insert bmap records into an inode fork, given an rmap. */
STATIC int
xfs_repair_bmap_insert_rec(
	struct xfs_scrub_context	*sc,
	struct xfs_repair_bmap_extent	*rbe,
	int				baseflags)
{
	struct xfs_bmbt_irec		bmap;
	struct xfs_defer_ops		dfops;
	xfs_fsblock_t			firstfsb;
	xfs_extlen_t			extlen;
	int				flags;
	int				error = 0;

	/* Form the "new" mapping... */
	bmap.br_startblock = XFS_AGB_TO_FSB(sc->mp, rbe->agno,
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

		/* Re-add the extent to the fork. */
		error = xfs_bmapi_remap(sc->tp, sc->ip,
				bmap.br_startoff, extlen,
				bmap.br_startblock, &dfops,
				baseflags | flags);
		if (error)
			goto out_cancel;

		bmap.br_startblock += extlen;
		bmap.br_startoff += extlen;
		rbe->rmap.rm_blockcount -= extlen;
		error = xfs_defer_ijoin(&dfops, sc->ip);
		if (error)
			goto out_cancel;
		error = xfs_defer_finish(&sc->tp, &dfops);
		if (error)
			goto out;
		/* Make sure we roll the transaction. */
		error = xfs_trans_roll_inode(&sc->tp, sc->ip);
		if (error)
			goto out;
	}

	return 0;
out_cancel:
	xfs_defer_cancel(&dfops);
out:
	return error;
}

/* Repair an inode fork. */
STATIC int
xfs_repair_bmap(
	struct xfs_scrub_context	*sc,
	int				whichfork)
{
	struct xfs_repair_bmap		rb;
	struct xfs_owner_info		oinfo;
	struct xfs_inode		*ip = sc->ip;
	struct xfs_mount		*mp = ip->i_mount;
	struct xfs_repair_bmap_extent	*rbe;
	struct xfs_repair_bmap_extent	*n;
	xfs_agnumber_t			agno;
	unsigned int			resblks;
	int				baseflags;
	int				error = 0;

	ASSERT(whichfork == XFS_DATA_FORK || whichfork == XFS_ATTR_FORK);

	/* Don't know how to repair the other fork formats. */
	if (XFS_IFORK_FORMAT(sc->ip, whichfork) != XFS_DINODE_FMT_EXTENTS &&
	    XFS_IFORK_FORMAT(sc->ip, whichfork) != XFS_DINODE_FMT_BTREE)
		return -EOPNOTSUPP;

	/* Only files, symlinks, and directories get to have data forks. */
	if (whichfork == XFS_DATA_FORK && !S_ISREG(VFS_I(ip)->i_mode) &&
	    !S_ISDIR(VFS_I(ip)->i_mode) && !S_ISLNK(VFS_I(ip)->i_mode))
		return -EINVAL;

	/* If we somehow have delalloc extents, forget it. */
	if (whichfork == XFS_DATA_FORK && ip->i_delayed_blks)
		return -EBUSY;

	/*
	 * If there's no attr fork area in the inode, there's
	 * no attr fork to rebuild.
	 */
	if (whichfork == XFS_ATTR_FORK && !XFS_IFORK_Q(ip))
		return -ENOENT;

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
	memset(&rb, 0, sizeof(rb));
	INIT_LIST_HEAD(&rb.extlist);
	xfs_repair_init_extent_list(&rb.btlist);
	rb.ino = ip->i_ino;
	rb.whichfork = whichfork;
	rb.sc = sc;

	/* Iterate the rmaps for extents. */
	for (agno = 0; agno < mp->m_sb.sb_agcount; agno++) {
		error = xfs_repair_bmap_scan_ag(&rb, agno);
		if (error)
			goto out;
	}

	/*
	 * Guess how many blocks we're going to need to rebuild an entire bmap
	 * from the number of extents we found, and get ourselves a new
	 * transaction with proper block reservations.
	 */
	resblks = xfs_bmbt_calc_size(mp, rb.extents);
	error = xfs_trans_reserve_more(sc->tp, resblks, 0);
	if (error)
		goto out;

	/* Blow out the in-core fork and zero the on-disk fork. */
	sc->ip->i_d.di_nblocks = rb.otherfork_blocks;
	xfs_trans_ijoin(sc->tp, sc->ip, 0);
	if (XFS_IFORK_PTR(ip, whichfork) != NULL)
		xfs_idestroy_fork(sc->ip, whichfork);
	XFS_IFORK_FMT_SET(sc->ip, whichfork, XFS_DINODE_FMT_EXTENTS);
	XFS_IFORK_NEXT_SET(sc->ip, whichfork, 0);

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
	error = xfs_trans_roll_inode(&sc->tp, sc->ip);
	if (error)
		goto out;

	baseflags = XFS_BMAPI_NORMAP;
	if (whichfork == XFS_ATTR_FORK)
		baseflags |= XFS_BMAPI_ATTRFORK;

	/* Release quota counts for the old bmbt blocks. */
	if (rb.bmbt_blocks) {
		xfs_trans_mod_dquot_byino(sc->tp, sc->ip, XFS_TRANS_DQ_BCOUNT,
				-rb.bmbt_blocks);
		error = xfs_trans_roll_inode(&sc->tp, sc->ip);
		if (error)
			goto out;
	}

	/* "Remap" the extents into the fork. */
	list_sort(NULL, &rb.extlist, xfs_repair_bmap_extent_cmp);
	list_for_each_entry_safe(rbe, n, &rb.extlist, list) {
		error = xfs_repair_bmap_insert_rec(sc, rbe, baseflags);
		if (error)
			goto out;
		list_del(&rbe->list);
		if (rbe != &rb.ext)
			kmem_free(rbe);
	}

	/* Dispose of all the old bmbt blocks. */
	xfs_rmap_ino_bmbt_owner(&oinfo, sc->ip->i_ino, whichfork);
	return xfs_repair_reap_btree_extents(sc, &rb.btlist, &oinfo,
			XFS_AG_RESV_NONE);
out:
	xfs_repair_cancel_btree_extents(sc, &rb.btlist);
	list_for_each_entry_safe(rbe, n, &rb.extlist, list) {
		list_del(&rbe->list);
		if (rbe != &rb.ext)
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
