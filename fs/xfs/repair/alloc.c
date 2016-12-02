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
#include "xfs_rmap.h"
#include "xfs_alloc.h"
#include "xfs_alloc_btree.h"
#include "xfs_ialloc.h"
#include "xfs_rmap_btree.h"
#include "xfs_refcount.h"
#include "repair/common.h"
#include "repair/btree.h"

/* Free space btree scrubber. */

/* Scrub a bnobt/cntbt record. */
STATIC int
xfs_scrub_allocbt_helper(
	struct xfs_scrub_btree		*bs,
	union xfs_btree_rec		*rec)
{
	struct xfs_mount		*mp = bs->cur->bc_mp;
	struct xfs_agf			*agf;
	struct xfs_btree_cur		**xcur;
	struct xfs_scrub_ag		*psa;
	xfs_agblock_t			fbno;
	xfs_agblock_t			bno;
	xfs_extlen_t			flen;
	xfs_extlen_t			len;
	bool				has_rmap;
	bool				has_inodes;
	bool				has_refcount;
	int				has_otherrec;
	int				error = 0;
	int				err2;

	bno = be32_to_cpu(rec->alloc.ar_startblock);
	len = be32_to_cpu(rec->alloc.ar_blockcount);
	agf = XFS_BUF_TO_AGF(bs->sc->sa.agf_bp);

	XFS_SCRUB_BTREC_CHECK(bs, bno < mp->m_sb.sb_agblocks);
	XFS_SCRUB_BTREC_CHECK(bs, bno < be32_to_cpu(agf->agf_length));
	XFS_SCRUB_BTREC_CHECK(bs, bno < bno + len);
	XFS_SCRUB_BTREC_CHECK(bs, (unsigned long long)bno + len <=
			mp->m_sb.sb_agblocks);
	XFS_SCRUB_BTREC_CHECK(bs, (unsigned long long)bno + len <=
			be32_to_cpu(agf->agf_length));

	if (error)
		goto out;

	/* Make sure we don't cover the AG headers. */
	XFS_SCRUB_BTREC_CHECK(bs,
			!xfs_scrub_extent_covers_ag_head(mp, bno, len));

	psa = &bs->sc->sa;
	/*
	 * Ensure there's a corresponding cntbt/bnobt record matching
	 * this bnobt/cntbt record, respectively.
	 */
	xcur = bs->cur == psa->bno_cur ? &psa->cnt_cur : &psa->bno_cur;
	if (*xcur) {
		err2 = xfs_alloc_lookup_le(*xcur, bno, len, &has_otherrec);
		if (xfs_scrub_btree_should_xref(bs, err2, xcur)) {
			XFS_SCRUB_BTREC_GOTO(bs, has_otherrec, out);
			err2 = xfs_alloc_get_rec(*xcur, &fbno, &flen,
					&has_otherrec);
			if (xfs_scrub_btree_should_xref(bs, err2, xcur)) {
				XFS_SCRUB_BTREC_GOTO(bs, has_otherrec, out);
				XFS_SCRUB_BTREC_CHECK(bs, fbno == bno);
				XFS_SCRUB_BTREC_CHECK(bs, flen == len);
			}
		}
	}

	/* Cross-reference with inobt. */
	if (psa->ino_cur) {
		err2 = xfs_ialloc_has_inodes_at_extent(psa->ino_cur, bno,
				len, &has_inodes);
		if (xfs_scrub_btree_should_xref(bs, err2, &psa->ino_cur))
			XFS_SCRUB_BTREC_CHECK(bs, !has_inodes);
	}

	/* Cross-reference with finobt. */
	if (psa->fino_cur) {
		err2 = xfs_ialloc_has_inodes_at_extent(psa->fino_cur, bno,
				len, &has_inodes);
		if (xfs_scrub_btree_should_xref(bs, err2, &psa->fino_cur))
			XFS_SCRUB_BTREC_CHECK(bs, !has_inodes);
	}

	/* Cross-reference with the rmapbt. */
	if (psa->rmap_cur) {
		err2 = xfs_rmap_has_record(psa->rmap_cur, bno, len,
				&has_rmap);
		if (xfs_scrub_btree_should_xref(bs, err2, &psa->rmap_cur))
			XFS_SCRUB_BTREC_CHECK(bs, !has_rmap);
	}

	/* Cross-reference with the refcountbt. */
	if (psa->refc_cur) {
		err2 = xfs_refcount_has_record(psa->refc_cur, bno, len,
				&has_refcount);
		if (xfs_scrub_btree_should_xref(bs, err2, &psa->refc_cur))
			XFS_SCRUB_BTREC_CHECK(bs, !has_refcount);
	}

out:
	return error;
}

/* Scrub the freespace btrees for some AG. */
STATIC int
xfs_scrub_allocbt(
	struct xfs_scrub_context	*sc,
	xfs_btnum_t			which)
{
	struct xfs_owner_info		oinfo;
	struct xfs_btree_cur		*cur;

	xfs_rmap_ag_owner(&oinfo, XFS_RMAP_OWN_AG);
	cur = which == XFS_BTNUM_BNO ? sc->sa.bno_cur : sc->sa.cnt_cur;
	return xfs_scrub_btree(sc, cur, xfs_scrub_allocbt_helper,
			&oinfo, NULL);
}

int
xfs_scrub_bnobt(
	struct xfs_scrub_context	*sc)
{
	return xfs_scrub_allocbt(sc, XFS_BTNUM_BNO);
}

int
xfs_scrub_cntbt(
	struct xfs_scrub_context	*sc)
{
	return xfs_scrub_allocbt(sc, XFS_BTNUM_CNT);
}

/* Free space btree repair. */

struct xfs_repair_alloc_extent {
	struct list_head		list;
	xfs_agblock_t			bno;
	xfs_extlen_t			len;
};

struct xfs_repair_alloc {
	struct list_head		extlist;
	struct list_head		btlist;	  /* OWN_AG blocks */
	struct list_head		nobtlist; /* rmapbt/agfl blocks */
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
	struct xfs_mount		*mp = cur->bc_mp;
	xfs_fsblock_t			fsb;
	int				i;
	int				error;

	/* Record all the OWN_AG blocks... */
	if (rec->rm_owner == XFS_RMAP_OWN_AG) {
		fsb = XFS_AGB_TO_FSB(cur->bc_mp, cur->bc_private.a.agno,
				rec->rm_startblock);
		error = xfs_repair_collect_btree_extent(cur->bc_mp,
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
		error = xfs_repair_collect_btree_extent(cur->bc_mp,
				&ra->nobtlist, fsb, 1);
		if (error)
			return error;
	}

	/* ...and all the free space. */
	if (rec->rm_startblock > ra->next_bno) {
		trace_xfs_repair_alloc_extent_fn(mp, cur->bc_private.a.agno,
				rec->rm_startblock, rec->rm_blockcount,
				rec->rm_owner, rec->rm_offset, rec->rm_flags);

		rae = kmem_alloc(sizeof(*rae), KM_NOFS);
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

	list_for_each_entry(rae, &ra->extlist, list)
		if (!longest || rae->len > longest->len)
			longest = rae;
	return longest;
}

/* Collect an AGFL block for the not-to-release list. */
static int
xfs_repair_collect_agfl_block(
	struct xfs_scrub_context	*sc,
	xfs_agblock_t			bno,
	void				*data)
{
	struct xfs_repair_alloc		*ra = data;
	xfs_fsblock_t			fsb;

	fsb = XFS_AGB_TO_FSB(sc->tp->t_mountp, sc->sa.agno, bno);
	return xfs_repair_collect_btree_extent(sc->tp->t_mountp,
			&ra->nobtlist, fsb, 1);
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
	return xfs_mod_fdblocks(sc->tp->t_mountp, -(int64_t)len, false);
}

/* Repair the freespace btrees for some AG. */
int
xfs_repair_allocbt(
	struct xfs_scrub_context	*sc)
{
	struct xfs_repair_alloc		ra;
	struct xfs_owner_info		oinfo;
	struct xfs_mount		*mp = sc->tp->t_mountp;
	struct xfs_btree_cur		*cur = NULL;
	struct xfs_repair_alloc_extent	*longest;
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
	 * Collect all reverse mappings for free extents, and the rmapbt
	 * blocks.  We can discover the rmapbt blocks completely from a
	 * query_all handler because there are always rmapbt entries.
	 * (One cannot use on query_all to visit all of a btree's blocks
	 * unless that btree is guaranteed to have at least one entry.)
	 */
	INIT_LIST_HEAD(&ra.extlist);
	INIT_LIST_HEAD(&ra.btlist);
	INIT_LIST_HEAD(&ra.nobtlist);
	ra.next_bno = 0;
	ra.nr_records = 0;
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
		rae = kmem_alloc(sizeof(*rae), KM_NOFS);
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
	error = xfs_scrub_walk_agfl(sc, xfs_repair_collect_agfl_block, &ra);
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

	/* Allocate new bnobt root. */
	longest = xfs_repair_allocbt_get_longest(&ra);
	if (longest == NULL) {
		error = -ENOSPC;
		goto out;
	}
	bnofsb = XFS_AGB_TO_FSB(mp, sc->sa.agno, longest->bno);
	longest->bno++;
	longest->len--;

	/* Allocate new cntbt root. */
	if (longest->len == 0) {
		list_del(&longest->list);
		kmem_free(longest);
		longest = xfs_repair_allocbt_get_longest(&ra);
		if (longest == NULL) {
			error = -ENOSPC;
			goto out;
		}
	}
	cntfsb = XFS_AGB_TO_FSB(mp, sc->sa.agno, longest->bno);
	longest->bno++;
	longest->len--;
	if (longest->len == 0) {
		list_del(&longest->list);
		kmem_free(longest);
		longest = xfs_repair_allocbt_get_longest(&ra);
	}

	agf = XFS_BUF_TO_AGF(sc->sa.agf_bp);
	/* Initialize new bnobt root. */
	error = xfs_repair_init_btblock(sc, bnofsb, &bp, XFS_ABTB_CRC_MAGIC,
			&xfs_allocbt_buf_ops);
	if (error)
		goto out;
	agf->agf_roots[XFS_BTNUM_BNOi] =
			cpu_to_be32(XFS_FSB_TO_AGBNO(mp, bnofsb));
	agf->agf_levels[XFS_BTNUM_BNOi] = cpu_to_be32(1);

	/* Initialize new cntbt root. */
	error = xfs_repair_init_btblock(sc, cntfsb, &bp, XFS_ABTC_CRC_MAGIC,
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
	xfs_rmap_ag_owner(&oinfo, XFS_RMAP_OWN_UNKNOWN);
	if (longest && longest->len == 0) {
		error = xfs_repair_allocbt_free_extent(sc,
				XFS_AGB_TO_FSB(mp, sc->sa.agno, longest->bno),
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
				XFS_AGB_TO_FSB(mp, sc->sa.agno, rae->bno),
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
	error = xfs_repair_subtract_extents(mp, &ra.btlist, &ra.nobtlist);
	if (error)
		goto out;
	xfs_repair_cancel_btree_extents(sc, &ra.nobtlist);
	error = xfs_repair_reap_btree_extents(sc, &ra.btlist, &oinfo,
			XFS_AG_RESV_NONE);
	if (error)
		goto out;

	return 0;
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
