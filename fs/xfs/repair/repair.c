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
#include "xfs_alloc.h"
#include "xfs_alloc_btree.h"
#include "xfs_ialloc.h"
#include "xfs_ialloc_btree.h"
#include "xfs_rmap.h"
#include "xfs_rmap_btree.h"
#include "xfs_refcount.h"
#include "xfs_refcount_btree.h"
#include "xfs_extent_busy.h"
#include "xfs_ag_resv.h"
#include "xfs_trans_space.h"
#include "repair/common.h"

/*
 * Roll a transaction, keeping the AG headers locked and reinitializing
 * the btree cursors.
 */
int
xfs_repair_roll_ag_trans(
	struct xfs_scrub_context	*sc)
{
	struct xfs_trans		*tp;
	int				error;

	/* Keep the AG header buffers locked so we can keep going. */
	xfs_trans_bhold(sc->tp, sc->sa.agi_bp);
	xfs_trans_bhold(sc->tp, sc->sa.agf_bp);
	xfs_trans_bhold(sc->tp, sc->sa.agfl_bp);

	/* Roll the transaction. */
	tp = sc->tp;
	error = xfs_trans_roll(&sc->tp, NULL);
	if (error)
		return error;

	/* Join the buffer to the new transaction or release the hold. */
	if (sc->tp != tp) {
		xfs_trans_bjoin(sc->tp, sc->sa.agi_bp);
		xfs_trans_bjoin(sc->tp, sc->sa.agf_bp);
		xfs_trans_bjoin(sc->tp, sc->sa.agfl_bp);
	} else {
		xfs_trans_bhold_release(sc->tp, sc->sa.agi_bp);
		xfs_trans_bhold_release(sc->tp, sc->sa.agf_bp);
		xfs_trans_bhold_release(sc->tp, sc->sa.agfl_bp);
	}

	return error;
}

/*
 * Does the given AG have enough space to rebuild a btree?  Neither AG
 * reservation can be critical, and we must have enough space (factoring
 * in AG reservations) to construct a whole btree.
 */
bool
xfs_repair_ag_has_space(
	struct xfs_perag		*pag,
	xfs_extlen_t			nr_blocks,
	enum xfs_ag_resv_type		type)
{
	return  !xfs_ag_resv_critical(pag, XFS_AG_RESV_AGFL) &&
		!xfs_ag_resv_critical(pag, XFS_AG_RESV_METADATA) &&
		pag->pagf_freeblks - xfs_ag_resv_needed(pag, type) > nr_blocks;
}

/* Allocate a block in an AG. */
int
xfs_repair_alloc_ag_block(
	struct xfs_scrub_context	*sc,
	struct xfs_owner_info		*oinfo,
	xfs_fsblock_t			*fsbno,
	enum xfs_ag_resv_type		resv)
{
	struct xfs_alloc_arg		args = {0};
	xfs_agblock_t			bno;
	int				error;

	if (resv == XFS_AG_RESV_AGFL) {
		error = xfs_alloc_get_freelist(sc->tp, sc->sa.agf_bp, &bno, 1);
		if (error)
			return error;
		xfs_extent_busy_reuse(sc->tp->t_mountp, sc->sa.agno, bno,
				1, false);
		*fsbno = XFS_AGB_TO_FSB(sc->tp->t_mountp, sc->sa.agno, bno);
		return 0;
	}

	args.tp = sc->tp;
	args.mp = sc->tp->t_mountp;
	args.oinfo = *oinfo;
	args.fsbno = XFS_AGB_TO_FSB(args.mp, sc->sa.agno, 0);
	args.minlen = 1;
	args.maxlen = 1;
	args.prod = 1;
	args.type = XFS_ALLOCTYPE_NEAR_BNO;
	args.resv = resv;

	error = xfs_alloc_vextent(&args);
	if (error)
		return error;
	if (args.fsbno == NULLFSBLOCK)
		return -ENOSPC;
	ASSERT(args.len == 1);
	*fsbno = args.fsbno;

	return 0;
}

/* Initialize an AG block to a zeroed out btree header. */
int
xfs_repair_init_btblock(
	struct xfs_scrub_context	*sc,
	xfs_fsblock_t			fsb,
	struct xfs_buf			**bpp,
	__u32				magic,
	const struct xfs_buf_ops	*ops)
{
	struct xfs_trans		*tp = sc->tp;
	struct xfs_mount		*mp = tp->t_mountp;
	struct xfs_buf			*bp;

	trace_xfs_repair_init_btblock(mp, XFS_FSB_TO_AGNO(mp, fsb),
			XFS_FSB_TO_AGBNO(mp, fsb), magic);

	ASSERT(XFS_FSB_TO_AGNO(mp, fsb) == sc->sa.agno);
	bp = xfs_trans_get_buf(tp, mp->m_ddev_targp, XFS_FSB_TO_DADDR(mp, fsb),
			XFS_FSB_TO_BB(mp, 1), 0);
	xfs_buf_zero(bp, 0, BBTOB(bp->b_length));
	xfs_btree_init_block(mp, bp, magic, 0, 0, sc->sa.agno,
			XFS_BTREE_CRC_BLOCKS);
	xfs_trans_buf_set_type(tp, bp, XFS_BLFT_BTREE_BUF);
	xfs_trans_log_buf(tp, bp, 0, bp->b_length);
	bp->b_ops = ops;
	*bpp = bp;

	return 0;
}

/* Ensure the freelist is full. */
int
xfs_repair_fix_freelist(
	struct xfs_scrub_context	*sc,
	bool				can_shrink)
{
	struct xfs_alloc_arg		args = {0};
	int				error;

	args.mp = sc->tp->t_mountp;
	args.tp = sc->tp;
	args.agno = sc->sa.agno;
	args.alignment = 1;
	args.pag = xfs_perag_get(args.mp, sc->sa.agno);

	error = xfs_alloc_fix_freelist(&args,
			can_shrink ? 0 : XFS_ALLOC_FLAG_NOSHRINK);
	xfs_perag_put(args.pag);

	return error;
}

/* Put a block back on the AGFL. */
int
xfs_repair_put_freelist(
	struct xfs_scrub_context	*sc,
	xfs_agblock_t			agbno)
{
	struct xfs_owner_info		oinfo;
	int				error;

	/*
	 * Since we're "freeing" a lost block onto the AGFL, we have to
	 * create an rmap for the block prior to merging it or else other
	 * parts will break.
	 */
	xfs_rmap_ag_owner(&oinfo, XFS_RMAP_OWN_AG);
	error = xfs_rmap_alloc(sc->tp, sc->sa.agf_bp, sc->sa.agno, agbno, 1,
			&oinfo);
	if (error)
		return error;

	/* Put the block on the AGFL. */
	error = xfs_alloc_put_freelist(sc->tp, sc->sa.agf_bp, sc->sa.agfl_bp,
			agbno, 0);
	if (error)
		return error;
	xfs_extent_busy_insert(sc->tp, sc->sa.agno, agbno, 1,
			XFS_EXTENT_BUSY_SKIP_DISCARD);

	/* Make sure the AGFL doesn't overfill. */
	return xfs_repair_fix_freelist(sc, true);
}

/*
 * For a given metadata extent and owner, delete the associated rmap.
 * If the block has no other owners, free it.
 */
STATIC int
xfs_repair_free_or_unmap_extent(
	struct xfs_scrub_context	*sc,
	xfs_fsblock_t			fsbno,
	xfs_extlen_t			len,
	struct xfs_owner_info		*oinfo,
	enum xfs_ag_resv_type		resv)
{
	struct xfs_mount		*mp = sc->tp->t_mountp;
	struct xfs_btree_cur		*rmap_cur;
	struct xfs_buf			*agf_bp = NULL;
	xfs_agnumber_t			agno;
	xfs_agblock_t			agbno;
	bool				has_other_rmap;
	int				error = 0;

	ASSERT(xfs_sb_version_hasrmapbt(&mp->m_sb));
	agno = XFS_FSB_TO_AGNO(mp, fsbno);
	agbno = XFS_FSB_TO_AGBNO(mp, fsbno);

	trace_xfs_repair_free_or_unmap_extent(mp, agno, agbno, len);

	for (; len > 0 && !error; len--, agbno++, fsbno++) {
		ASSERT(sc->ip != NULL || agno == sc->sa.agno);

		/* Can we find any other rmappings? */
		if (sc->ip) {
			error = xfs_alloc_read_agf(mp, sc->tp, agno, 0,
					&agf_bp);
			if (error)
				break;
		}
		rmap_cur = xfs_rmapbt_init_cursor(mp, sc->tp,
				agf_bp ? agf_bp : sc->sa.agf_bp, agno);
		error = xfs_rmap_has_other_keys(rmap_cur, agbno, 1, oinfo,
				&has_other_rmap);
		if (error)
			goto out_cur;
		xfs_btree_del_cursor(rmap_cur, XFS_BTREE_NOERROR);
		if (agf_bp)
			xfs_trans_brelse(sc->tp, agf_bp);

		/*
		 * If there are other rmappings, this block is cross
		 * linked and must not be freed.  Remove the reverse
		 * mapping and move on.  Otherwise, we were the only
		 * owner of the block, so free the extent, which will
		 * also remove the rmap.
		 */
		if (has_other_rmap)
			error = xfs_rmap_free(sc->tp, agf_bp, agno, agbno, 1,
					oinfo);
		else if (resv == XFS_AG_RESV_AGFL)
			error = xfs_repair_put_freelist(sc, agbno);
		else
			error = xfs_free_extent(sc->tp, fsbno, 1, oinfo, resv);
		if (error)
			break;

		if (sc->ip)
			error = xfs_trans_roll(&sc->tp, sc->ip);
		else
			error = xfs_repair_roll_ag_trans(sc);
	}

	return error;
out_cur:
	xfs_btree_del_cursor(rmap_cur, XFS_BTREE_ERROR);
	if (agf_bp)
		xfs_trans_brelse(sc->tp, agf_bp);
	return error;
}

/* Collect a dead btree extent for later disposal. */
int
xfs_repair_collect_btree_extent(
	struct xfs_mount		*mp,
	struct list_head		*btlist,
	xfs_fsblock_t			fsbno,
	xfs_extlen_t			len)
{
	struct xfs_repair_btree_extent	*rbe;

	trace_xfs_repair_collect_btree_extent(mp, XFS_FSB_TO_AGNO(mp, fsbno),
			XFS_FSB_TO_AGBNO(mp, fsbno), len);

	rbe = kmem_alloc(sizeof(*rbe), KM_NOFS);
	if (!rbe)
		return -ENOMEM;

	INIT_LIST_HEAD(&rbe->list);
	rbe->fsbno = fsbno;
	rbe->len = len;
	list_add_tail(&rbe->list, btlist);

	return 0;
}

/* Dispose of dead btree extents.  If oinfo is NULL, just delete the list. */
int
xfs_repair_reap_btree_extents(
	struct xfs_scrub_context	*sc,
	struct list_head		*btlist,
	struct xfs_owner_info		*oinfo,
	enum xfs_ag_resv_type		type)
{
	struct xfs_repair_btree_extent	*rbe;
	struct xfs_repair_btree_extent	*n;
	int				error = 0;

	list_for_each_entry_safe(rbe, n, btlist, list) {
		if (oinfo) {
			error = xfs_repair_free_or_unmap_extent(sc, rbe->fsbno,
					rbe->len, oinfo, type);
			if (error)
				oinfo = NULL;
		}
		list_del(&rbe->list);
		kmem_free(rbe);
	}

	return error;
}

/* Errors happened, just delete the dead btree extent list. */
void
xfs_repair_cancel_btree_extents(
	struct xfs_scrub_context	*sc,
	struct list_head		*btlist)
{
	xfs_repair_reap_btree_extents(sc, btlist, NULL, XFS_AG_RESV_NONE);
}

/* Compare two btree extents. */
static int
xfs_repair_btree_extent_cmp(
	void				*priv,
	struct list_head		*a,
	struct list_head		*b)
{
	struct xfs_repair_btree_extent	*ap;
	struct xfs_repair_btree_extent	*bp;

	ap = container_of(a, struct xfs_repair_btree_extent, list);
	bp = container_of(b, struct xfs_repair_btree_extent, list);

	if (ap->fsbno > bp->fsbno)
		return 1;
	else if (ap->fsbno < bp->fsbno)
		return -1;
	return 0;
}

/* Remove all the blocks in sublist from exlist. */
int
xfs_repair_subtract_extents(
	struct xfs_mount		*mp,
	struct list_head		*exlist,
	struct list_head		*sublist)
{
	struct xfs_repair_btree_extent	*newrbe;
	struct xfs_repair_btree_extent	*rbe;
	struct xfs_repair_btree_extent	*n;
	struct xfs_repair_btree_extent	*subp;
	struct xfs_repair_btree_extent	sub;
	xfs_fsblock_t			fsb;
	xfs_fsblock_t			newfsb;
	xfs_extlen_t			newlen;

	list_sort(NULL, exlist, xfs_repair_btree_extent_cmp);
	list_sort(NULL, sublist, xfs_repair_btree_extent_cmp);

	subp = list_first_entry(sublist, struct xfs_repair_btree_extent, list);
	if (subp == NULL)
		return 0;

	sub = *subp;
	/* For every block mentioned in exlist... */
	list_for_each_entry_safe(rbe, n, exlist, list) {
		newfsb = NULLFSBLOCK;
		newlen = 0;
		for (fsb = rbe->fsbno; fsb < rbe->fsbno + rbe->len; fsb++) {
			/*
			 * If the current location of the extent list is
			 * beyond the subtract list, move the subtract list
			 * forward by one block or by one record.
			 */
			while (fsb > sub.fsbno || sub.len == 0) {
				if (sub.len) {
					sub.len--;
					sub.fsbno++;
				} else {
					/*
					 * Get the next subtract extent.  If
					 * there isn't one, make the current
					 * extent match the unprocessed part of
					 * that extent, and jump out.
					 */
					if (subp->list.next == sublist ||
					    subp->list.next == NULL) {
						rbe->len -= fsb - rbe->fsbno;
						rbe->fsbno = fsb;
						subp = NULL;
						rbe = NULL;
						goto out_frag;
					}
					subp = list_next_entry(subp, list);
					sub = *subp;
				}
			}

			if (fsb != sub.fsbno) {
				/*
				 * Block not in the subtract list; stash
				 * it for later reinsertion in the list.
				 */
				if (newfsb == NULLFSBLOCK) {
					newfsb = fsb;
					newlen = 1;
				} else
					newlen++;
			} else {
				/* Match! */
				if (newfsb != NULLFSBLOCK) {
					/*
					 * Last block of the extent and we have
					 * a saved extent.  Store the saved
					 * extent in this extent.
					 */
					if (fsb == rbe->fsbno + rbe->len - 1) {
						rbe->fsbno = newfsb;
						rbe->len = newlen;
						newfsb = NULLFSBLOCK;
						rbe = NULL;
						goto out_frag;
					}
					/* Stash the new extent in the list. */
					newrbe = kmem_alloc(sizeof(*newrbe),
							KM_NOFS);
					if (!newrbe)
						return -ENOMEM;
					INIT_LIST_HEAD(&newrbe->list);
					newrbe->fsbno = newfsb;
					newrbe->len = newlen;
					list_add_tail(&newrbe->list,
							&rbe->list);
				}

				newfsb = NULLFSBLOCK;
				newlen = 0;
			}
		} /* end for loop */

out_frag:
		/* If we have an extent to add back, do that now. */
		if (newfsb != NULLFSBLOCK) {
			if (rbe) {
				newrbe = rbe;
				rbe = NULL;
			} else {
				newrbe = kmem_alloc(sizeof(*newrbe), KM_NOFS);
				if (!newrbe)
					return -ENOMEM;
				INIT_LIST_HEAD(&newrbe->list);
				list_add_tail(&newrbe->list, &rbe->list);
			}
			newrbe->fsbno = newfsb;
			newrbe->len = newlen;
		}
		if (rbe) {
			list_del(&rbe->list);
			kmem_free(rbe);
		}
		if (subp == NULL)
			break;
	}

	return 0;
}

/* Find btree roots from the AGF. */
STATIC int
xfs_repair_find_ag_btree_roots_helper(
	struct xfs_btree_cur		*cur,
	struct xfs_rmap_irec		*rec,
	void				*priv)
{
	struct xfs_mount		*mp = cur->bc_mp;
	struct xfs_repair_find_ag_btree	*btree_info = priv;
	struct xfs_repair_find_ag_btree	*fab;
	struct xfs_buf			*bp;
	struct xfs_btree_block		*btblock;
	xfs_daddr_t			daddr;
	xfs_agblock_t			agbno;
	int				error;

	if (!XFS_RMAP_NON_INODE_OWNER(rec->rm_owner))
		return 0;

	for (agbno = 0; agbno < rec->rm_blockcount; agbno++) {
		daddr = XFS_AGB_TO_DADDR(mp, cur->bc_private.a.agno,
				rec->rm_startblock + agbno);
		for (fab = btree_info; fab->buf_ops; fab++) {
			if (rec->rm_owner != fab->rmap_owner)
				continue;

			error = xfs_trans_read_buf(mp, cur->bc_tp,
					mp->m_ddev_targp, daddr, mp->m_bsize,
					0, &bp, NULL);
			if (error)
				return error;

			btblock = XFS_BUF_TO_BLOCK(bp);
			if (be32_to_cpu(btblock->bb_magic) != fab->magic)
				goto next_fab;
			if (fab->root != NULLAGBLOCK &&
			    xfs_btree_get_level(btblock) <= fab->level)
				goto next_fab;

			bp->b_ops = fab->buf_ops;
			bp->b_ops->verify_read(bp);
			if (bp->b_error)
				goto next_fab;
			fab->root = rec->rm_startblock + agbno;
			fab->level = xfs_btree_get_level(btblock);

			trace_xfs_repair_find_ag_btree_roots_helper(mp,
					cur->bc_private.a.agno,
					rec->rm_startblock + agbno,
					be32_to_cpu(btblock->bb_magic),
					fab->level);
next_fab:
			xfs_trans_brelse(cur->bc_tp, bp);
			if (be32_to_cpu(btblock->bb_magic) == fab->magic)
				break;
		}
	}

	return error;
}

/* Find the roots of the given btrees from the rmap info. */
int
xfs_repair_find_ag_btree_roots(
	struct xfs_scrub_context	*sc,
	struct xfs_buf			*agf_bp,
	struct xfs_repair_find_ag_btree	*btree_info)
{
	struct xfs_mount		*mp = sc->tp->t_mountp;
	struct xfs_repair_find_ag_btree	*fab;
	struct xfs_btree_cur		*cur;
	int				error;

	for (fab = btree_info; fab->buf_ops; fab++) {
		fab->root = NULLAGBLOCK;
		fab->level = 0;
	}

	cur = xfs_rmapbt_init_cursor(mp, sc->tp, agf_bp, sc->sa.agno);
	error = xfs_rmap_query_all(cur, xfs_repair_find_ag_btree_roots_helper,
			btree_info);
	xfs_btree_del_cursor(cur, error ? XFS_BTREE_ERROR : XFS_BTREE_NOERROR);

	for (fab = btree_info; !error && fab->buf_ops; fab++)
		if (fab->root != NULLAGBLOCK)
			fab->level++;

	return error;
}

/* Reset the superblock counters from the AGF/AGI. */
int
xfs_repair_reset_counters(
	struct xfs_mount	*mp)
{
	struct xfs_trans	*tp;
	struct xfs_buf		*agi_bp;
	struct xfs_buf		*agf_bp;
	struct xfs_agi		*agi;
	struct xfs_agf		*agf;
	xfs_agnumber_t		agno;
	xfs_ino_t		icount = 0;
	xfs_ino_t		ifree = 0;
	xfs_filblks_t		fdblocks = 0;
	int64_t			delta_icount;
	int64_t			delta_ifree;
	int64_t			delta_fdblocks;
	int			error;

	trace_xfs_repair_reset_counters(mp);

	error = xfs_trans_alloc_empty(mp, &tp);
	if (error)
		return error;

	for (agno = 0; agno < mp->m_sb.sb_agcount; agno++) {
		/* Count all the inodes... */
		error = xfs_ialloc_read_agi(mp, tp, agno, &agi_bp);
		if (error)
			goto out;
		agi = XFS_BUF_TO_AGI(agi_bp);
		icount += be32_to_cpu(agi->agi_count);
		ifree += be32_to_cpu(agi->agi_freecount);

		/* Add up the free/freelist/bnobt/cntbt blocks... */
		error = xfs_alloc_read_agf(mp, tp, agno, 0, &agf_bp);
		if (error)
			goto out;
		agf = XFS_BUF_TO_AGF(agf_bp);
		fdblocks += be32_to_cpu(agf->agf_freeblks);
		fdblocks += be32_to_cpu(agf->agf_flcount);
		fdblocks += be32_to_cpu(agf->agf_btreeblks);
	}

	/*
	 * Reinitialize the counters.  The on-disk and in-core counters
	 * differ by the number of inodes/blocks reserved by the admin,
	 * the per-AG reservation, and any transactions in progress, so
	 * we have to account for that.
	 */
	spin_lock(&mp->m_sb_lock);
	delta_icount = (int64_t)mp->m_sb.sb_icount - icount;
	delta_ifree = (int64_t)mp->m_sb.sb_ifree - ifree;
	delta_fdblocks = (int64_t)mp->m_sb.sb_fdblocks - fdblocks;
	mp->m_sb.sb_icount = icount;
	mp->m_sb.sb_ifree = ifree;
	mp->m_sb.sb_fdblocks = fdblocks;
	spin_unlock(&mp->m_sb_lock);

	if (delta_icount) {
		error = xfs_mod_icount(mp, delta_icount);
		if (error)
			goto out;
	}
	if (delta_ifree) {
		error = xfs_mod_ifree(mp, delta_ifree);
		if (error)
			goto out;
	}
	if (delta_fdblocks) {
		error = xfs_mod_fdblocks(mp, delta_fdblocks, false);
		if (error)
			goto out;
	}

out:
	xfs_trans_cancel(tp);
	return error;
}

/* Figure out how many blocks to reserve for an AG repair. */
xfs_extlen_t
xfs_repair_calc_ag_resblks(
	struct xfs_scrub_context	*sc,
	struct xfs_inode		*ip,
	struct xfs_scrub_metadata	*sm)
{
	struct xfs_mount		*mp = ip->i_mount;
	struct xfs_agi			*agi;
	struct xfs_agf			*agf;
	struct xfs_buf			*bp;
	xfs_agino_t			icount;
	xfs_extlen_t			aglen;
	xfs_extlen_t			usedlen;
	xfs_extlen_t			freelen;
	xfs_extlen_t			bnobt_sz;
	xfs_extlen_t			inobt_sz;
	xfs_extlen_t			rmapbt_sz;
	xfs_extlen_t			refcbt_sz;
	int				error;

	if (!(sm->sm_flags & XFS_SCRUB_FLAG_REPAIR))
		return 0;

	if (sm->sm_agno >= mp->m_sb.sb_agcount)
		return -EINVAL;

	/*
	 * Try to get the actual counters from disk; if not, make
	 * some worst case assumptions.
	 */
	error = xfs_read_agi(mp, NULL, sm->sm_agno, &bp);
	if (!error) {
		agi = XFS_BUF_TO_AGI(bp);
		icount = be32_to_cpu(agi->agi_count);
		xfs_trans_brelse(NULL, bp);
	} else
		icount = mp->m_sb.sb_agblocks / mp->m_sb.sb_inopblock;

	error = xfs_alloc_read_agf(mp, NULL, sm->sm_agno, 0, &bp);
	if (!error) {
		agf = XFS_BUF_TO_AGF(bp);
		aglen = be32_to_cpu(agf->agf_length);
		freelen = be32_to_cpu(agf->agf_freeblks);
		usedlen = aglen - freelen;
		xfs_trans_brelse(NULL, bp);
	} else {
		aglen = mp->m_sb.sb_agblocks;
		freelen = aglen;
		usedlen = aglen;
	}

	trace_xfs_repair_calc_ag_resblks(mp, sm->sm_agno, icount, aglen,
			freelen, usedlen);

	/*
	 * Figure out how many blocks we'd need worst case to rebuild
	 * each type of btree.  Note that we can only rebuild the
	 * bnobt/cntbt or inobt/finobt as pairs.
	 */
	bnobt_sz = 2 * xfs_allocbt_calc_size(mp, freelen);
	if (xfs_sb_version_hassparseinodes(&mp->m_sb))
		inobt_sz = xfs_iallocbt_calc_size(mp, icount /
				XFS_INODES_PER_HOLEMASK_BIT);
	else
		inobt_sz = xfs_iallocbt_calc_size(mp, icount /
				XFS_INODES_PER_CHUNK);
	if (xfs_sb_version_hasfinobt(&mp->m_sb))
		inobt_sz *= 2;
	if (xfs_sb_version_hasreflink(&mp->m_sb)) {
		rmapbt_sz = xfs_rmapbt_calc_size(mp, aglen);
		refcbt_sz = xfs_refcountbt_calc_size(mp, usedlen);
	} else {
		rmapbt_sz = xfs_rmapbt_calc_size(mp, usedlen);
		refcbt_sz = 0;
	}
	if (!xfs_sb_version_hasrmapbt(&mp->m_sb))
		rmapbt_sz = 0;

	trace_xfs_repair_calc_ag_resblks_btsize(mp, sm->sm_agno, bnobt_sz,
			inobt_sz, rmapbt_sz, refcbt_sz);

	return max(max(bnobt_sz, inobt_sz), max(rmapbt_sz, refcbt_sz));
}
