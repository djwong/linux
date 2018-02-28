/*
 * Copyright (C) 2017 Oracle.  All Rights Reserved.
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
#include "xfs_rmap.h"
#include "xfs_rmap_btree.h"
#include "xfs_inode.h"
#include "xfs_refcount.h"
#include "scrub/xfs_scrub.h"
#include "scrub/scrub.h"
#include "scrub/common.h"
#include "scrub/btree.h"
#include "scrub/trace.h"
#include "scrub/repair.h"

/* Free space btree repair. */

struct xfs_repair_alloc_extent {
	struct list_head		list;
	xfs_agblock_t			bno;
	xfs_extlen_t			len;
};

struct xfs_repair_alloc {
	struct list_head		extlist;
	struct xfs_repair_extent_list	btlist;	  /* OWN_AG blocks */
	struct xfs_repair_extent_list	nobtlist; /* rmapbt/agfl blocks */
	struct xfs_scrub_context	*sc;
	xfs_agblock_t			next_bno;
	uint64_t			nr_records;
};

/* Record extents that aren't in use from gaps in the rmap records. */
STATIC int
xfs_repair_alloc_extent_fn(
	struct xfs_btree_cur		*cur,
	struct xfs_rmap_irec		*rec,
	void				*priv)
{
	struct xfs_repair_alloc		*ra = priv;
	struct xfs_repair_alloc_extent	*rae;
	struct xfs_buf			*bp;
	xfs_fsblock_t			fsb;
	int				i;
	int				error;

	/* Record all the OWN_AG blocks... */
	if (rec->rm_owner == XFS_RMAP_OWN_AG) {
		fsb = XFS_AGB_TO_FSB(cur->bc_mp, cur->bc_private.a.agno,
				rec->rm_startblock);
		error = xfs_repair_collect_btree_extent(ra->sc,
				&ra->btlist, fsb, rec->rm_blockcount);
		if (error)
			return error;
	}

	/* ...and all the rmapbt blocks... */
	for (i = 0; i < cur->bc_nlevels && cur->bc_ptrs[i] == 1; i++) {
		xfs_btree_get_block(cur, i, &bp);
		if (!bp)
			continue;
		fsb = XFS_DADDR_TO_FSB(cur->bc_mp, bp->b_bn);
		error = xfs_repair_collect_btree_extent(ra->sc,
				&ra->nobtlist, fsb, 1);
		if (error)
			return error;
	}

	/* ...and all the free space. */
	if (rec->rm_startblock > ra->next_bno) {
		trace_xfs_repair_alloc_extent_fn(cur->bc_mp,
				cur->bc_private.a.agno,
				ra->next_bno, rec->rm_startblock - ra->next_bno,
				XFS_RMAP_OWN_NULL, 0, 0);

		rae = kmem_alloc(sizeof(struct xfs_repair_alloc_extent),
				KM_MAYFAIL | KM_NOFS);
		if (!rae)
			return -ENOMEM;
		INIT_LIST_HEAD(&rae->list);
		rae->bno = ra->next_bno;
		rae->len = rec->rm_startblock - ra->next_bno;
		list_add_tail(&rae->list, &ra->extlist);
		ra->nr_records++;
	}
	ra->next_bno = max_t(xfs_agblock_t, ra->next_bno,
			rec->rm_startblock + rec->rm_blockcount);
	return 0;
}

/* Find the longest free extent in the list. */
static struct xfs_repair_alloc_extent *
xfs_repair_allocbt_get_longest(
	struct xfs_repair_alloc		*ra)
{
	struct xfs_repair_alloc_extent	*rae;
	struct xfs_repair_alloc_extent	*longest = NULL;

	list_for_each_entry(rae, &ra->extlist, list) {
		if (!longest || rae->len > longest->len)
			longest = rae;
	}
	return longest;
}

/* Collect an AGFL block for the not-to-release list. */
static int
xfs_repair_collect_agfl_block(
	struct xfs_mount		*mp,
	xfs_agblock_t			bno,
	void				*priv)
{
	struct xfs_repair_alloc		*ra = priv;
	xfs_fsblock_t			fsb;

	fsb = XFS_AGB_TO_FSB(mp, ra->sc->sa.agno, bno);
	return xfs_repair_collect_btree_extent(ra->sc, &ra->nobtlist, fsb, 1);
}

/* Compare two btree extents. */
static int
xfs_repair_allocbt_extent_cmp(
	void				*priv,
	struct list_head		*a,
	struct list_head		*b)
{
	struct xfs_repair_alloc_extent	*ap;
	struct xfs_repair_alloc_extent	*bp;

	ap = container_of(a, struct xfs_repair_alloc_extent, list);
	bp = container_of(b, struct xfs_repair_alloc_extent, list);

	if (ap->bno > bp->bno)
		return 1;
	else if (ap->bno < bp->bno)
		return -1;
	return 0;
}

/* Put an extent onto the free list. */
STATIC int
xfs_repair_allocbt_free_extent(
	struct xfs_scrub_context	*sc,
	xfs_fsblock_t			fsbno,
	xfs_extlen_t			len,
	struct xfs_owner_info		*oinfo)
{
	int				error;

	error = xfs_free_extent(sc->tp, fsbno, len, oinfo, 0);
	if (error)
		return error;
	error = xfs_repair_roll_ag_trans(sc);
	if (error)
		return error;
	return xfs_mod_fdblocks(sc->mp, -(int64_t)len, false);
}

/* Allocate a block from the (cached) longest extent in the AG. */
STATIC xfs_fsblock_t
xfs_repair_allocbt_alloc_from_longest(
	struct xfs_repair_alloc		*ra,
	struct xfs_repair_alloc_extent	**longest)
{
	xfs_fsblock_t			fsb;

	if (*longest && (*longest)->len == 0) {
		list_del(&(*longest)->list);
		kmem_free(*longest);
		*longest = NULL;
	}

	if (*longest == NULL) {
		*longest = xfs_repair_allocbt_get_longest(ra);
		if (*longest == NULL)
			return NULLFSBLOCK;
	}

	fsb = XFS_AGB_TO_FSB(ra->sc->mp, ra->sc->sa.agno, (*longest)->bno);
	(*longest)->bno++;
	(*longest)->len--;
	return fsb;
}

/* Repair the freespace btrees for some AG. */
int
xfs_repair_allocbt(
	struct xfs_scrub_context	*sc)
{
	struct xfs_repair_alloc		ra;
	struct xfs_owner_info		oinfo;
	struct xfs_mount		*mp = sc->mp;
	struct xfs_btree_cur		*cur = NULL;
	struct xfs_repair_alloc_extent	*longest = NULL;
	struct xfs_repair_alloc_extent	*rae;
	struct xfs_repair_alloc_extent	*n;
	struct xfs_perag		*pag;
	struct xfs_agf			*agf;
	struct xfs_buf			*bp;
	xfs_fsblock_t			bnofsb;
	xfs_fsblock_t			cntfsb;
	xfs_extlen_t			oldf;
	xfs_extlen_t			nr_blocks;
	xfs_agblock_t			agend;
	int				error;

	/* We require the rmapbt to rebuild anything. */
	if (!xfs_sb_version_hasrmapbt(&mp->m_sb))
		return -EOPNOTSUPP;

	/*
	 * Make sure the busy extent list is clear because we can't put
	 * extents on there twice.
	 */
	pag = xfs_perag_get(sc->mp, sc->sa.agno);
	spin_lock(&pag->pagb_lock);
	if (pag->pagb_tree.rb_node) {
		spin_unlock(&pag->pagb_lock);
		xfs_perag_put(pag);
		return -EDEADLOCK;
	}
	spin_unlock(&pag->pagb_lock);
	xfs_perag_put(pag);

	/*
	 * Collect all reverse mappings for free extents, and the rmapbt
	 * blocks.  We can discover the rmapbt blocks completely from a
	 * query_all handler because there are always rmapbt entries.
	 * (One cannot use on query_all to visit all of a btree's blocks
	 * unless that btree is guaranteed to have at least one entry.)
	 */
	INIT_LIST_HEAD(&ra.extlist);
	xfs_repair_init_extent_list(&ra.btlist);
	xfs_repair_init_extent_list(&ra.nobtlist);
	ra.next_bno = 0;
	ra.nr_records = 0;
	ra.sc = sc;

	cur = xfs_rmapbt_init_cursor(mp, sc->tp, sc->sa.agf_bp, sc->sa.agno);
	error = xfs_rmap_query_all(cur, xfs_repair_alloc_extent_fn, &ra);
	if (error)
		goto out;
	xfs_btree_del_cursor(cur, XFS_BTREE_NOERROR);
	cur = NULL;

	/* Insert a record for space between the last rmap and EOAG. */
	agf = XFS_BUF_TO_AGF(sc->sa.agf_bp);
	agend = be32_to_cpu(agf->agf_length);
	if (ra.next_bno < agend) {
		rae = kmem_alloc(sizeof(struct xfs_repair_alloc_extent),
				KM_MAYFAIL | KM_NOFS);
		if (!rae) {
			error = -ENOMEM;
			goto out;
		}
		INIT_LIST_HEAD(&rae->list);
		rae->bno = ra.next_bno;
		rae->len = agend - ra.next_bno;
		list_add_tail(&rae->list, &ra.extlist);
		ra.nr_records++;
	}

	/* Collect all the AGFL blocks. */
	error = xfs_agfl_walk(sc->mp, XFS_BUF_TO_AGF(sc->sa.agf_bp),
			sc->sa.agfl_bp, xfs_repair_collect_agfl_block, &ra);
	if (error)
		goto out;

	/* Do we actually have enough space to do this? */
	pag = xfs_perag_get(mp, sc->sa.agno);
	nr_blocks = 2 * xfs_allocbt_calc_size(mp, ra.nr_records);
	if (!xfs_repair_ag_has_space(pag, nr_blocks, XFS_AG_RESV_NONE)) {
		xfs_perag_put(pag);
		error = -ENOSPC;
		goto out;
	}
	xfs_perag_put(pag);

	/* Invalidate all the bnobt/cntbt blocks in btlist. */
	error = xfs_repair_subtract_extents(sc, &ra.btlist, &ra.nobtlist);
	if (error)
		goto out;
	xfs_repair_cancel_btree_extents(sc, &ra.nobtlist);
	error = xfs_repair_invalidate_blocks(sc, &ra.btlist);
	if (error)
		goto out;

	/* Allocate new bnobt root. */
	bnofsb = xfs_repair_allocbt_alloc_from_longest(&ra, &longest);
	if (bnofsb == NULLFSBLOCK) {
		error = -ENOSPC;
		goto out;
	}

	/* Allocate new cntbt root. */
	cntfsb = xfs_repair_allocbt_alloc_from_longest(&ra, &longest);
	if (cntfsb == NULLFSBLOCK) {
		error = -ENOSPC;
		goto out;
	}

	agf = XFS_BUF_TO_AGF(sc->sa.agf_bp);
	/* Initialize new bnobt root. */
	error = xfs_repair_init_btblock(sc, bnofsb, &bp, XFS_BTNUM_BNO,
			&xfs_allocbt_buf_ops);
	if (error)
		goto out;
	agf->agf_roots[XFS_BTNUM_BNOi] =
			cpu_to_be32(XFS_FSB_TO_AGBNO(mp, bnofsb));
	agf->agf_levels[XFS_BTNUM_BNOi] = cpu_to_be32(1);

	/* Initialize new cntbt root. */
	error = xfs_repair_init_btblock(sc, cntfsb, &bp, XFS_BTNUM_CNT,
			&xfs_allocbt_buf_ops);
	if (error)
		goto out;
	agf->agf_roots[XFS_BTNUM_CNTi] =
			cpu_to_be32(XFS_FSB_TO_AGBNO(mp, cntfsb));
	agf->agf_levels[XFS_BTNUM_CNTi] = cpu_to_be32(1);

	/*
	 * Since we're abandoning the old bnobt/cntbt, we have to
	 * decrease fdblocks by the # of blocks in those trees.
	 * btreeblks counts the non-root blocks of the free space
	 * and rmap btrees.  Do this before resetting the AGF counters.
	 */
	pag = xfs_perag_get(mp, sc->sa.agno);
	oldf = pag->pagf_btreeblks + 2;
	oldf -= (be32_to_cpu(agf->agf_rmap_blocks) - 1);
	error = xfs_mod_fdblocks(mp, -(int64_t)oldf, false);
	if (error) {
		xfs_perag_put(pag);
		goto out;
	}

	/* Reset the perag info. */
	pag->pagf_btreeblks = be32_to_cpu(agf->agf_rmap_blocks) - 1;
	pag->pagf_freeblks = 0;
	pag->pagf_longest = 0;
	pag->pagf_levels[XFS_BTNUM_BNOi] =
			be32_to_cpu(agf->agf_levels[XFS_BTNUM_BNOi]);
	pag->pagf_levels[XFS_BTNUM_CNTi] =
			be32_to_cpu(agf->agf_levels[XFS_BTNUM_CNTi]);

	/* Now reset the AGF counters. */
	agf->agf_btreeblks = cpu_to_be32(pag->pagf_btreeblks);
	agf->agf_freeblks = cpu_to_be32(pag->pagf_freeblks);
	agf->agf_longest = cpu_to_be32(pag->pagf_longest);
	xfs_perag_put(pag);
	xfs_alloc_log_agf(sc->tp, sc->sa.agf_bp,
			XFS_AGF_ROOTS | XFS_AGF_LEVELS | XFS_AGF_BTREEBLKS |
			XFS_AGF_LONGEST | XFS_AGF_FREEBLKS);
	error = xfs_repair_roll_ag_trans(sc);
	if (error)
		goto out;

	/*
	 * Insert the longest free extent in case it's necessary to
	 * refresh the AGFL with multiple blocks.
	 */
	xfs_rmap_skip_owner_update(&oinfo);
	if (longest && longest->len == 0) {
		error = xfs_repair_allocbt_free_extent(sc,
				XFS_AGB_TO_FSB(sc->mp, sc->sa.agno,
					longest->bno),
				longest->len, &oinfo);
		if (error)
			goto out;
		list_del(&longest->list);
		kmem_free(longest);
	}

	/* Insert records into the new btrees. */
	list_sort(NULL, &ra.extlist, xfs_repair_allocbt_extent_cmp);
	list_for_each_entry_safe(rae, n, &ra.extlist, list) {
		error = xfs_repair_allocbt_free_extent(sc,
				XFS_AGB_TO_FSB(sc->mp, sc->sa.agno, rae->bno),
				rae->len, &oinfo);
		if (error)
			goto out;
		list_del(&rae->list);
		kmem_free(rae);
	}

	/* Add rmap records for the btree roots */
	xfs_rmap_ag_owner(&oinfo, XFS_RMAP_OWN_AG);
	error = xfs_rmap_alloc(sc->tp, sc->sa.agf_bp, sc->sa.agno,
			XFS_FSB_TO_AGBNO(mp, bnofsb), 1, &oinfo);
	if (error)
		goto out;
	error = xfs_rmap_alloc(sc->tp, sc->sa.agf_bp, sc->sa.agno,
			XFS_FSB_TO_AGBNO(mp, cntfsb), 1, &oinfo);
	if (error)
		goto out;

	/* Free all the OWN_AG blocks that are not in the rmapbt/agfl. */
	return xfs_repair_reap_btree_extents(sc, &ra.btlist, &oinfo,
			XFS_AG_RESV_NONE);
out:
	xfs_repair_cancel_btree_extents(sc, &ra.btlist);
	xfs_repair_cancel_btree_extents(sc, &ra.nobtlist);
	if (cur)
		xfs_btree_del_cursor(cur, XFS_BTREE_ERROR);
	list_for_each_entry_safe(rae, n, &ra.extlist, list) {
		list_del(&rae->list);
		kmem_free(rae);
	}
	return error;
}
