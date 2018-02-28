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
#include "xfs_alloc.h"
#include "xfs_alloc_btree.h"
#include "xfs_ialloc.h"
#include "xfs_ialloc_btree.h"
#include "xfs_rmap.h"
#include "xfs_rmap_btree.h"
#include "xfs_inode.h"
#include "xfs_icache.h"
#include "xfs_bmap.h"
#include "xfs_bmap_btree.h"
#include "xfs_refcount.h"
#include "xfs_refcount_btree.h"
#include "scrub/xfs_scrub.h"
#include "scrub/scrub.h"
#include "scrub/common.h"
#include "scrub/btree.h"
#include "scrub/trace.h"
#include "scrub/repair.h"

/* Reverse-mapping repair. */

/* Set us up to repair reverse mapping btrees. */
int
xfs_repair_rmapbt_setup(
	struct xfs_scrub_context	*sc,
	struct xfs_inode		*ip)
{
	int				error;

	/*
	 * Freeze out anything that can lock an inode.  We reconstruct
	 * the rmapbt by reading inode bmaps with the AGF held, which is
	 * only safe w.r.t. ABBA deadlocks if we're the only ones locking
	 * inodes.
	 */
	error = xfs_repair_fs_freeze(sc);
	if (error)
		return error;

	/* Check the AG number and set up the scrub context. */
	error = xfs_scrub_setup_fs(sc, ip);
	if (error)
		return error;

	/*
	 * Lock all the AG header buffers so that we can read all the
	 * per-AG metadata too.
	 */
	error = xfs_repair_grab_all_ag_headers(sc);
	if (error)
		return error;

	return xfs_scrub_ag_init(sc, sc->sm->sm_agno, &sc->sa);
}

struct xfs_repair_rmapbt_extent {
	struct list_head		list;
	struct xfs_rmap_irec		rmap;
};

struct xfs_repair_rmapbt {
	struct list_head		rmaplist;
	struct xfs_repair_extent_list	rmap_freelist;
	struct xfs_repair_extent_list	bno_freelist;
	struct xfs_scrub_context	*sc;
	uint64_t			owner;
	xfs_extlen_t			btblocks;
	xfs_agblock_t			next_bno;
	uint64_t			nr_records;
};

/* Initialize an rmap. */
static inline int
xfs_repair_rmapbt_new_rmap(
	struct xfs_repair_rmapbt	*rr,
	xfs_agblock_t			startblock,
	xfs_extlen_t			blockcount,
	uint64_t			owner,
	uint64_t			offset,
	unsigned int			flags)
{
	struct xfs_repair_rmapbt_extent	*rre;
	int				error = 0;

	trace_xfs_repair_rmap_extent_fn(rr->sc->mp, rr->sc->sa.agno,
			startblock, blockcount, owner, offset, flags);

	if (xfs_scrub_should_terminate(rr->sc, &error))
		return error;

	rre = kmem_alloc(sizeof(struct xfs_repair_rmapbt_extent),
			KM_MAYFAIL | KM_NOFS);
	if (!rre)
		return -ENOMEM;
	INIT_LIST_HEAD(&rre->list);
	rre->rmap.rm_startblock = startblock;
	rre->rmap.rm_blockcount = blockcount;
	rre->rmap.rm_owner = owner;
	rre->rmap.rm_offset = offset;
	rre->rmap.rm_flags = flags;
	list_add_tail(&rre->list, &rr->rmaplist);
	rr->nr_records++;

	return 0;
}

/* Add an AGFL block to the rmap list. */
STATIC int
xfs_repair_rmapbt_walk_agfl(
	struct xfs_mount		*mp,
	xfs_agblock_t			bno,
	void				*priv)
{
	struct xfs_repair_rmapbt	*rr = priv;

	return xfs_repair_rmapbt_new_rmap(rr, bno, 1, XFS_RMAP_OWN_AG, 0, 0);
}

/* Add a btree block to the rmap list. */
STATIC int
xfs_repair_rmapbt_visit_btblock(
	struct xfs_btree_cur		*cur,
	int				level,
	void				*priv)
{
	struct xfs_repair_rmapbt	*rr = priv;
	struct xfs_buf			*bp;
	xfs_fsblock_t			fsb;

	xfs_btree_get_block(cur, level, &bp);
	if (!bp)
		return 0;

	rr->btblocks++;
	fsb = XFS_DADDR_TO_FSB(cur->bc_mp, bp->b_bn);
	return xfs_repair_rmapbt_new_rmap(rr, XFS_FSB_TO_AGBNO(cur->bc_mp, fsb),
			1, rr->owner, 0, 0);
}

/* Record inode btree rmaps. */
STATIC int
xfs_repair_rmapbt_inodes(
	struct xfs_btree_cur		*cur,
	union xfs_btree_rec		*rec,
	void				*priv)
{
	struct xfs_inobt_rec_incore	irec;
	struct xfs_repair_rmapbt	*rr = priv;
	struct xfs_mount		*mp = cur->bc_mp;
	struct xfs_buf			*bp;
	xfs_fsblock_t			fsb;
	xfs_agino_t			agino;
	xfs_agino_t			iperhole;
	unsigned int			i;
	int				error;

	/* Record the inobt blocks */
	for (i = 0; i < cur->bc_nlevels && cur->bc_ptrs[i] == 1; i++) {
		xfs_btree_get_block(cur, i, &bp);
		if (!bp)
			continue;
		fsb = XFS_DADDR_TO_FSB(mp, bp->b_bn);
		error = xfs_repair_rmapbt_new_rmap(rr,
				XFS_FSB_TO_AGBNO(mp, fsb), 1,
				XFS_RMAP_OWN_INOBT, 0, 0);
		if (error)
			return error;
	}

	xfs_inobt_btrec_to_irec(mp, rec, &irec);

	/* Record a non-sparse inode chunk. */
	if (irec.ir_holemask == XFS_INOBT_HOLEMASK_FULL)
		return xfs_repair_rmapbt_new_rmap(rr,
				XFS_AGINO_TO_AGBNO(mp, irec.ir_startino),
				XFS_INODES_PER_CHUNK / mp->m_sb.sb_inopblock,
				XFS_RMAP_OWN_INODES, 0, 0);

	/* Iterate each chunk. */
	iperhole = max_t(xfs_agino_t, mp->m_sb.sb_inopblock,
			XFS_INODES_PER_HOLEMASK_BIT);
	for (i = 0, agino = irec.ir_startino;
	     i < XFS_INOBT_HOLEMASK_BITS;
	     i += iperhole / XFS_INODES_PER_HOLEMASK_BIT, agino += iperhole) {
		/* Skip holes. */
		if (irec.ir_holemask & (1 << i))
			continue;

		/* Record the inode chunk otherwise. */
		error = xfs_repair_rmapbt_new_rmap(rr,
				XFS_AGINO_TO_AGBNO(mp, agino),
				iperhole / mp->m_sb.sb_inopblock,
				XFS_RMAP_OWN_INODES, 0, 0);
		if (error)
			return error;
	}

	return 0;
}

/* Record a CoW staging extent. */
STATIC int
xfs_repair_rmapbt_refcount(
	struct xfs_btree_cur		*cur,
	union xfs_btree_rec		*rec,
	void				*priv)
{
	struct xfs_repair_rmapbt	*rr = priv;
	struct xfs_refcount_irec	refc;

	xfs_refcount_btrec_to_irec(rec, &refc);
	if (refc.rc_refcount != 1)
		return -EFSCORRUPTED;

	return xfs_repair_rmapbt_new_rmap(rr,
			refc.rc_startblock - XFS_REFC_COW_START,
			refc.rc_blockcount, XFS_RMAP_OWN_COW, 0, 0);
}

/* Add a bmbt block to the rmap list. */
STATIC int
xfs_repair_rmapbt_visit_bmbt(
	struct xfs_btree_cur		*cur,
	int				level,
	void				*priv)
{
	struct xfs_repair_rmapbt	*rr = priv;
	struct xfs_buf			*bp;
	xfs_fsblock_t			fsb;
	unsigned int			flags = XFS_RMAP_BMBT_BLOCK;

	xfs_btree_get_block(cur, level, &bp);
	if (!bp)
		return 0;

	fsb = XFS_DADDR_TO_FSB(cur->bc_mp, bp->b_bn);
	if (XFS_FSB_TO_AGNO(cur->bc_mp, fsb) != rr->sc->sa.agno)
		return 0;

	if (cur->bc_private.b.whichfork == XFS_ATTR_FORK)
		flags |= XFS_RMAP_ATTR_FORK;
	return xfs_repair_rmapbt_new_rmap(rr,
			XFS_FSB_TO_AGBNO(cur->bc_mp, fsb), 1,
			cur->bc_private.b.ip->i_ino, 0, flags);
}

/* Determine rmap flags from fork and bmbt state. */
static inline unsigned int
xfs_repair_rmapbt_bmap_flags(
	int			whichfork,
	xfs_exntst_t		state)
{
	return  (whichfork == XFS_ATTR_FORK ? XFS_RMAP_ATTR_FORK : 0) |
		(state == XFS_EXT_UNWRITTEN ? XFS_RMAP_UNWRITTEN : 0);
}

/* Find all the extents from a given AG in an inode fork. */
STATIC int
xfs_repair_rmapbt_scan_ifork(
	struct xfs_repair_rmapbt	*rr,
	struct xfs_inode		*ip,
	int				whichfork)
{
	struct xfs_bmbt_irec		rec;
	struct xfs_iext_cursor		icur;
	struct xfs_mount		*mp = rr->sc->mp;
	struct xfs_btree_cur		*cur = NULL;
	struct xfs_ifork		*ifp;
	unsigned int			rflags;
	int				fmt;
	int				error = 0;

	/* Do we even have data mapping extents? */
	fmt = XFS_IFORK_FORMAT(ip, whichfork);
	ifp = XFS_IFORK_PTR(ip, whichfork);
	switch (fmt) {
	case XFS_DINODE_FMT_BTREE:
		if (!(ifp->if_flags & XFS_IFEXTENTS)) {
			error = xfs_iread_extents(rr->sc->tp, ip, whichfork);
			if (error)
				return error;
		}
		break;
	case XFS_DINODE_FMT_EXTENTS:
		break;
	default:
		return 0;
	}
	if (!ifp)
		return 0;

	/* Find all the BMBT blocks in the AG. */
	if (fmt == XFS_DINODE_FMT_BTREE) {
		cur = xfs_bmbt_init_cursor(mp, rr->sc->tp, ip, whichfork);
		error = xfs_btree_visit_blocks(cur,
				xfs_repair_rmapbt_visit_bmbt, rr);
		if (error)
			goto out;
		xfs_btree_del_cursor(cur, XFS_BTREE_NOERROR);
		cur = NULL;
	}

	/* We're done if this is an rt inode's data fork. */
	if (whichfork == XFS_DATA_FORK && XFS_IS_REALTIME_INODE(ip))
		return 0;

	/* Find all the extents in the AG. */
	for_each_xfs_iext(ifp, &icur, &rec) {
		if (isnullstartblock(rec.br_startblock))
			continue;
		/* Stash non-hole extent. */
		if (XFS_FSB_TO_AGNO(mp, rec.br_startblock) == rr->sc->sa.agno) {
			rflags = xfs_repair_rmapbt_bmap_flags(whichfork,
					rec.br_state);
			error = xfs_repair_rmapbt_new_rmap(rr,
					XFS_FSB_TO_AGBNO(mp, rec.br_startblock),
					rec.br_blockcount, ip->i_ino,
					rec.br_startoff, rflags);
			if (error)
				goto out;
		}
	}
out:
	if (cur)
		xfs_btree_del_cursor(cur, XFS_BTREE_ERROR);
	return error;
}

/* Iterate all the inodes in an AG group. */
STATIC int
xfs_repair_rmapbt_scan_inobt(
	struct xfs_btree_cur		*cur,
	union xfs_btree_rec		*rec,
	void				*priv)
{
	struct xfs_inobt_rec_incore	irec;
	struct xfs_mount		*mp = cur->bc_mp;
	struct xfs_inode		*ip = NULL;
	xfs_ino_t			ino;
	xfs_agino_t			agino;
	int				chunkidx;
	int				lock_mode = 0;
	int				error = 0;

	xfs_inobt_btrec_to_irec(mp, rec, &irec);

	for (chunkidx = 0, agino = irec.ir_startino;
	     chunkidx < XFS_INODES_PER_CHUNK;
	     chunkidx++, agino++) {
		bool	inuse;

		/* Skip if this inode is free */
		if (XFS_INOBT_MASK(chunkidx) & irec.ir_free)
			continue;
		ino = XFS_AGINO_TO_INO(mp, cur->bc_private.a.agno, agino);

		/* Back off and try again if an inode is being reclaimed */
		error = xfs_icache_inode_is_allocated(mp, cur->bc_tp, ino,
				&inuse);
		if (error == -EAGAIN)
			return -EDEADLOCK;

		/*
		 * Grab inode for scanning.  We cannot use DONTCACHE here
		 * because we already have a transaction so the iput must not
		 * trigger inode reclaim (which might allocate a transaction
		 * to clean up posteof blocks).
		 */
		error = xfs_iget(mp, cur->bc_tp, ino, 0, 0, &ip);
		if (error)
			return error;

		if ((ip->i_d.di_format == XFS_DINODE_FMT_BTREE &&
		     !(ip->i_df.if_flags & XFS_IFEXTENTS)) ||
		    (ip->i_d.di_aformat == XFS_DINODE_FMT_BTREE &&
		     !(ip->i_afp->if_flags & XFS_IFEXTENTS)))
			lock_mode = XFS_ILOCK_EXCL;
		else
			lock_mode = XFS_ILOCK_SHARED;
		if (!xfs_ilock_nowait(ip, lock_mode)) {
			error = -EBUSY;
			goto out_rele;
		}

		/* Check the data fork. */
		error = xfs_repair_rmapbt_scan_ifork(priv, ip, XFS_DATA_FORK);
		if (error)
			goto out_unlock;

		/* Check the attr fork. */
		error = xfs_repair_rmapbt_scan_ifork(priv, ip, XFS_ATTR_FORK);
		if (error)
			goto out_unlock;

		xfs_iunlock(ip, lock_mode);
		iput(VFS_I(ip));
		ip = NULL;
	}

	return error;
out_unlock:
	xfs_iunlock(ip, lock_mode);
out_rele:
	iput(VFS_I(ip));
	return error;
}

/* Record extents that aren't in use from gaps in the rmap records. */
STATIC int
xfs_repair_rmapbt_record_rmap_freesp(
	struct xfs_btree_cur		*cur,
	struct xfs_rmap_irec		*rec,
	void				*priv)
{
	struct xfs_repair_rmapbt	*rr = priv;
	xfs_fsblock_t			fsb;
	int				error;

	/* Record the free space we find. */
	if (rec->rm_startblock > rr->next_bno) {
		fsb = XFS_AGB_TO_FSB(cur->bc_mp, cur->bc_private.a.agno,
				rr->next_bno);
		error = xfs_repair_collect_btree_extent(rr->sc,
				&rr->rmap_freelist, fsb,
				rec->rm_startblock - rr->next_bno);
		if (error)
			return error;
	}
	rr->next_bno = max_t(xfs_agblock_t, rr->next_bno,
			rec->rm_startblock + rec->rm_blockcount);
	return 0;
}

/* Record extents that aren't in use from the bnobt records. */
STATIC int
xfs_repair_rmapbt_record_bno_freesp(
	struct xfs_btree_cur		*cur,
	struct xfs_alloc_rec_incore	*rec,
	void				*priv)
{
	struct xfs_repair_rmapbt	*rr = priv;
	xfs_fsblock_t			fsb;

	/* Record the free space we find. */
	fsb = XFS_AGB_TO_FSB(cur->bc_mp, cur->bc_private.a.agno,
			rec->ar_startblock);
	return xfs_repair_collect_btree_extent(rr->sc, &rr->bno_freelist,
			fsb, rec->ar_blockcount);
}

/* Compare two rmapbt extents. */
static int
xfs_repair_rmapbt_extent_cmp(
	void				*priv,
	struct list_head		*a,
	struct list_head		*b)
{
	struct xfs_repair_rmapbt_extent	*ap;
	struct xfs_repair_rmapbt_extent	*bp;

	ap = container_of(a, struct xfs_repair_rmapbt_extent, list);
	bp = container_of(b, struct xfs_repair_rmapbt_extent, list);
	return xfs_rmap_compare(&ap->rmap, &bp->rmap);
}

#define RMAP(type, startblock, blockcount) xfs_repair_rmapbt_new_rmap( \
		&rr, (startblock), (blockcount), \
		XFS_RMAP_OWN_##type, 0, 0)
/* Repair the rmap btree for some AG. */
int
xfs_repair_rmapbt(
	struct xfs_scrub_context	*sc)
{
	struct xfs_repair_rmapbt	rr;
	struct xfs_owner_info		oinfo;
	struct xfs_repair_rmapbt_extent	*rre;
	struct xfs_repair_rmapbt_extent	*n;
	struct xfs_mount		*mp = sc->mp;
	struct xfs_btree_cur		*cur = NULL;
	struct xfs_buf			*bp = NULL;
	struct xfs_agf			*agf;
	struct xfs_agi			*agi;
	struct xfs_perag		*pag;
	xfs_fsblock_t			btfsb;
	xfs_agnumber_t			ag;
	xfs_agblock_t			agend;
	xfs_extlen_t			freesp_btblocks;
	int				error;

	INIT_LIST_HEAD(&rr.rmaplist);
	xfs_repair_init_extent_list(&rr.rmap_freelist);
	xfs_repair_init_extent_list(&rr.bno_freelist);
	rr.sc = sc;
	rr.nr_records = 0;

	/* Collect rmaps for all AG headers. */
	error = RMAP(FS, XFS_SB_BLOCK(mp), 1);
	if (error)
		goto out;
	rre = list_last_entry(&rr.rmaplist, struct xfs_repair_rmapbt_extent,
			list);

	if (rre->rmap.rm_startblock != XFS_AGF_BLOCK(mp)) {
		error = RMAP(FS, XFS_AGF_BLOCK(mp), 1);
		if (error)
			goto out;
		rre = list_last_entry(&rr.rmaplist,
				struct xfs_repair_rmapbt_extent, list);
	}

	if (rre->rmap.rm_startblock != XFS_AGI_BLOCK(mp)) {
		error = RMAP(FS, XFS_AGI_BLOCK(mp), 1);
		if (error)
			goto out;
		rre = list_last_entry(&rr.rmaplist,
				struct xfs_repair_rmapbt_extent, list);
	}

	if (rre->rmap.rm_startblock != XFS_AGFL_BLOCK(mp)) {
		error = RMAP(FS, XFS_AGFL_BLOCK(mp), 1);
		if (error)
			goto out;
	}

	error = xfs_agfl_walk(sc->mp, XFS_BUF_TO_AGF(sc->sa.agf_bp),
			sc->sa.agfl_bp, xfs_repair_rmapbt_walk_agfl, &rr);
	if (error)
		goto out;

	/* Collect rmap for the log if it's in this AG. */
	if (mp->m_sb.sb_logstart &&
	    XFS_FSB_TO_AGNO(mp, mp->m_sb.sb_logstart) == sc->sa.agno) {
		error = RMAP(LOG, XFS_FSB_TO_AGBNO(mp, mp->m_sb.sb_logstart),
				mp->m_sb.sb_logblocks);
		if (error)
			goto out;
	}

	/* Collect rmaps for the free space btrees. */
	rr.owner = XFS_RMAP_OWN_AG;
	rr.btblocks = 0;
	cur = xfs_allocbt_init_cursor(mp, sc->tp, sc->sa.agf_bp, sc->sa.agno,
			XFS_BTNUM_BNO);
	error = xfs_btree_visit_blocks(cur, xfs_repair_rmapbt_visit_btblock,
			&rr);
	if (error)
		goto out;
	xfs_btree_del_cursor(cur, XFS_BTREE_NOERROR);
	cur = NULL;

	/* Collect rmaps for the cntbt. */
	cur = xfs_allocbt_init_cursor(mp, sc->tp, sc->sa.agf_bp, sc->sa.agno,
			XFS_BTNUM_CNT);
	error = xfs_btree_visit_blocks(cur, xfs_repair_rmapbt_visit_btblock,
			&rr);
	if (error)
		goto out;
	xfs_btree_del_cursor(cur, XFS_BTREE_NOERROR);
	cur = NULL;
	freesp_btblocks = rr.btblocks;

	/* Collect rmaps for the inode btree. */
	cur = xfs_inobt_init_cursor(mp, sc->tp, sc->sa.agi_bp, sc->sa.agno,
			XFS_BTNUM_INO);
	error = xfs_btree_query_all(cur, xfs_repair_rmapbt_inodes, &rr);
	if (error)
		goto out;
	xfs_btree_del_cursor(cur, XFS_BTREE_NOERROR);

	/* If there are no inodes, we have to include the inobt root. */
	agi = XFS_BUF_TO_AGI(sc->sa.agi_bp);
	if (agi->agi_count == cpu_to_be32(0)) {
		error = xfs_repair_rmapbt_new_rmap(&rr,
				be32_to_cpu(agi->agi_root), 1,
				XFS_RMAP_OWN_INOBT, 0, 0);
		if (error)
			goto out;
	}

	/* Collect rmaps for the free inode btree. */
	if (xfs_sb_version_hasfinobt(&mp->m_sb)) {
		rr.owner = XFS_RMAP_OWN_INOBT;
		cur = xfs_inobt_init_cursor(mp, sc->tp, sc->sa.agi_bp,
				sc->sa.agno, XFS_BTNUM_FINO);
		error = xfs_btree_visit_blocks(cur,
				xfs_repair_rmapbt_visit_btblock, &rr);
		if (error)
			goto out;
		xfs_btree_del_cursor(cur, XFS_BTREE_NOERROR);
		cur = NULL;
	}

	/* Collect rmaps for the refcount btree. */
	if (xfs_sb_version_hasreflink(&mp->m_sb)) {
		union xfs_btree_irec		low;
		union xfs_btree_irec		high;

		rr.owner = XFS_RMAP_OWN_REFC;
		cur = xfs_refcountbt_init_cursor(mp, sc->tp, sc->sa.agf_bp,
				sc->sa.agno, NULL);
		error = xfs_btree_visit_blocks(cur,
				xfs_repair_rmapbt_visit_btblock, &rr);
		if (error)
			goto out;

		/* Collect rmaps for CoW staging extents. */
		memset(&low, 0, sizeof(low));
		low.rc.rc_startblock = XFS_REFC_COW_START;
		memset(&high, 0xFF, sizeof(high));
		error = xfs_btree_query_range(cur, &low, &high,
				xfs_repair_rmapbt_refcount, &rr);
		if (error)
			goto out;
		xfs_btree_del_cursor(cur, XFS_BTREE_NOERROR);
		cur = NULL;
	}

	/* Iterate all AGs for inodes. */
	for (ag = 0; ag < mp->m_sb.sb_agcount; ag++) {
		error = xfs_ialloc_read_agi(mp, sc->tp, ag, &bp);
		if (error)
			goto out;
		cur = xfs_inobt_init_cursor(mp, sc->tp, bp, ag, XFS_BTNUM_INO);
		error = xfs_btree_query_all(cur, xfs_repair_rmapbt_scan_inobt,
				&rr);
		if (error)
			goto out;
		xfs_btree_del_cursor(cur, XFS_BTREE_NOERROR);
		cur = NULL;
		xfs_trans_brelse(sc->tp, bp);
		bp = NULL;
	}

	/* Do we actually have enough space to do this? */
	pag = xfs_perag_get(mp, sc->sa.agno);
	if (!xfs_repair_ag_has_space(pag,
			xfs_rmapbt_calc_size(mp, rr.nr_records),
			XFS_AG_RESV_AGFL)) {
		xfs_perag_put(pag);
		error = -ENOSPC;
		goto out;
	}

	/* XXX: Do we need to invalidate buffers here? */

	/* Initialize a new rmapbt root. */
	xfs_rmap_ag_owner(&oinfo, XFS_RMAP_OWN_UNKNOWN);
	agf = XFS_BUF_TO_AGF(sc->sa.agf_bp);
	error = xfs_repair_alloc_ag_block(sc, &oinfo, &btfsb, XFS_AG_RESV_AGFL);
	if (error) {
		xfs_perag_put(pag);
		goto out;
	}
	error = xfs_repair_init_btblock(sc, btfsb, &bp, XFS_BTNUM_RMAP,
			&xfs_rmapbt_buf_ops);
	if (error) {
		xfs_perag_put(pag);
		goto out;
	}
	agf->agf_roots[XFS_BTNUM_RMAPi] = cpu_to_be32(XFS_FSB_TO_AGBNO(mp,
			btfsb));
	agf->agf_levels[XFS_BTNUM_RMAPi] = cpu_to_be32(1);
	agf->agf_rmap_blocks = cpu_to_be32(1);

	/* Reset the perag info. */
	pag->pagf_btreeblks = freesp_btblocks - 2;
	pag->pagf_levels[XFS_BTNUM_RMAPi] =
			be32_to_cpu(agf->agf_levels[XFS_BTNUM_RMAPi]);

	/* Now reset the AGF counters. */
	agf->agf_btreeblks = cpu_to_be32(pag->pagf_btreeblks);
	xfs_perag_put(pag);
	xfs_alloc_log_agf(sc->tp, sc->sa.agf_bp, XFS_AGF_ROOTS |
			XFS_AGF_LEVELS | XFS_AGF_RMAP_BLOCKS |
			XFS_AGF_BTREEBLKS);
	bp = NULL;
	error = xfs_repair_roll_ag_trans(sc);
	if (error)
		goto out;

	/* Insert all the metadata rmaps. */
	list_sort(NULL, &rr.rmaplist, xfs_repair_rmapbt_extent_cmp);
	list_for_each_entry_safe(rre, n, &rr.rmaplist, list) {
		/* Add the rmap. */
		cur = xfs_rmapbt_init_cursor(mp, sc->tp, sc->sa.agf_bp,
				sc->sa.agno);
		error = xfs_rmap_map_raw(cur, &rre->rmap);
		if (error)
			goto out;
		xfs_btree_del_cursor(cur, XFS_BTREE_NOERROR);
		cur = NULL;

		error = xfs_repair_roll_ag_trans(sc);
		if (error)
			goto out;

		list_del(&rre->list);
		kmem_free(rre);

		/*
		 * Ensure the freelist is full, but don't let it shrink.
		 * The rmapbt isn't fully set up yet, which means that
		 * the current AGFL blocks might not be reflected in the
		 * rmapbt, which is a problem if we want to unmap blocks
		 * from the AGFL.
		 */
		error = xfs_repair_fix_freelist(sc, false);
		if (error)
			goto out;
	}

	/* Compute free space from the new rmapbt. */
	rr.next_bno = 0;
	cur = xfs_rmapbt_init_cursor(mp, sc->tp, sc->sa.agf_bp, sc->sa.agno);
	error = xfs_rmap_query_all(cur, xfs_repair_rmapbt_record_rmap_freesp,
			&rr);
	if (error)
		goto out;
	xfs_btree_del_cursor(cur, XFS_BTREE_NOERROR);
	cur = NULL;

	/* Insert a record for space between the last rmap and EOAG. */
	agf = XFS_BUF_TO_AGF(sc->sa.agf_bp);
	agend = be32_to_cpu(agf->agf_length);
	if (rr.next_bno < agend) {
		btfsb = XFS_AGB_TO_FSB(mp, sc->sa.agno, rr.next_bno);
		error = xfs_repair_collect_btree_extent(sc, &rr.rmap_freelist,
				btfsb, agend - rr.next_bno);
		if (error)
			goto out;
	}

	/* Compute free space from the existing bnobt. */
	cur = xfs_allocbt_init_cursor(mp, sc->tp, sc->sa.agf_bp, sc->sa.agno,
			XFS_BTNUM_BNO);
	error = xfs_alloc_query_all(cur, xfs_repair_rmapbt_record_bno_freesp,
			&rr);
	if (error)
		goto out;
	xfs_btree_del_cursor(cur, XFS_BTREE_NOERROR);
	cur = NULL;

	/*
	 * Free the "free" blocks that the new rmapbt knows about but
	 * the old bnobt doesn't.  These are the old rmapbt blocks.
	 */
	error = xfs_repair_subtract_extents(sc, &rr.rmap_freelist,
			&rr.bno_freelist);
	if (error)
		goto out;
	xfs_repair_cancel_btree_extents(sc, &rr.bno_freelist);
	return xfs_repair_reap_btree_extents(sc, &rr.rmap_freelist, &oinfo,
			XFS_AG_RESV_AGFL);
out:
	if (cur)
		xfs_btree_del_cursor(cur, XFS_BTREE_ERROR);
	if (bp)
		xfs_trans_brelse(sc->tp, bp);
	xfs_repair_cancel_btree_extents(sc, &rr.bno_freelist);
	xfs_repair_cancel_btree_extents(sc, &rr.rmap_freelist);
	list_for_each_entry_safe(rre, n, &rr.rmaplist, list) {
		list_del(&rre->list);
		kmem_free(rre);
	}
	return error;
}
#undef RMAP
