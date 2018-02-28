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
#include "xfs_alloc.h"
#include "xfs_alloc_btree.h"
#include "xfs_ialloc.h"
#include "xfs_ialloc_btree.h"
#include "xfs_rmap.h"
#include "xfs_rmap_btree.h"
#include "xfs_refcount.h"
#include "xfs_refcount_btree.h"
#include "scrub/xfs_scrub.h"
#include "scrub/scrub.h"
#include "scrub/common.h"
#include "scrub/trace.h"
#include "scrub/repair.h"

/* Superblock */

/* Repair the superblock. */
int
xfs_repair_superblock(
	struct xfs_scrub_context	*sc)
{
	struct xfs_mount		*mp = sc->mp;
	struct xfs_buf			*bp;
	struct xfs_dsb			*sbp;
	xfs_agnumber_t			agno;
	int				error;

	/* Don't try to repair AG 0's sb; let xfs_repair deal with it. */
	agno = sc->sm->sm_agno;
	if (agno == 0)
		return -EOPNOTSUPP;

	error = xfs_trans_read_buf(mp, sc->tp, mp->m_ddev_targp,
		  XFS_AG_DADDR(mp, agno, XFS_SB_BLOCK(mp)),
		  XFS_FSS_TO_BB(mp, 1), 0, &bp, NULL);
	if (error)
		return error;
	bp->b_ops = &xfs_sb_buf_ops;

	/* Copy AG 0's superblock to this one. */
	sbp = XFS_BUF_TO_SBP(bp);
	memset(sbp, 0, mp->m_sb.sb_sectsize);
	xfs_sb_to_disk(sbp, &mp->m_sb);
	sbp->sb_bad_features2 = sbp->sb_features2;

	/* Write this to disk. */
	xfs_trans_buf_set_type(sc->tp, bp, XFS_BLFT_SB_BUF);
	xfs_trans_log_buf(sc->tp, bp, 0, mp->m_sb.sb_sectsize - 1);
	return error;
}

/* AGF */

struct xfs_repair_agf_allocbt {
	struct xfs_scrub_context	*sc;
	xfs_agblock_t			freeblks;
	xfs_agblock_t			longest;
};

/* Record free space shape information. */
STATIC int
xfs_repair_agf_walk_allocbt(
	struct xfs_btree_cur		*cur,
	struct xfs_alloc_rec_incore	*rec,
	void				*priv)
{
	struct xfs_repair_agf_allocbt	*raa = priv;
	int				error = 0;

	if (xfs_scrub_should_terminate(raa->sc, &error))
		return error;

	raa->freeblks += rec->ar_blockcount;
	if (rec->ar_blockcount > raa->longest)
		raa->longest = rec->ar_blockcount;
	return error;
}

/* Does this AGFL look sane? */
STATIC int
xfs_repair_agf_check_agfl(
	struct xfs_scrub_context	*sc,
	struct xfs_agf			*agf,
	__be32				*agfl_bno)
{
	struct xfs_mount		*mp = sc->mp;
	xfs_agblock_t			bno;
	unsigned int			flfirst;
	unsigned int			fllast;
	int				i;

	if (agf->agf_flcount == cpu_to_be32(0))
		return 0;

	flfirst = be32_to_cpu(agf->agf_flfirst);
	fllast = be32_to_cpu(agf->agf_fllast);

	/* first to last is a consecutive list. */
	if (fllast >= flfirst) {
		for (i = flfirst; i <= fllast; i++) {
			bno = be32_to_cpu(agfl_bno[i]);
			if (!xfs_verify_agbno(mp, sc->sa.agno, bno))
				return -EFSCORRUPTED;
		}

		return 0;
	}

	/* first to the end */
	for (i = flfirst; i < xfs_agfl_size(mp); i++) {
		bno = be32_to_cpu(agfl_bno[i]);
		if (!xfs_verify_agbno(mp, sc->sa.agno, bno))
			return -EFSCORRUPTED;
	}

	/* the start to last. */
	for (i = 0; i <= fllast; i++) {
		bno = be32_to_cpu(agfl_bno[i]);
		if (!xfs_verify_agbno(mp, sc->sa.agno, bno))
			return -EFSCORRUPTED;
	}
	return 0;
}

/* Repair the AGF. */
int
xfs_repair_agf(
	struct xfs_scrub_context	*sc)
{
	struct xfs_repair_find_ag_btree	fab[] = {
		{
			.rmap_owner = XFS_RMAP_OWN_AG,
			.buf_ops = &xfs_allocbt_buf_ops,
			.magic = XFS_ABTB_CRC_MAGIC,
		},
		{
			.rmap_owner = XFS_RMAP_OWN_AG,
			.buf_ops = &xfs_allocbt_buf_ops,
			.magic = XFS_ABTC_CRC_MAGIC,
		},
		{
			.rmap_owner = XFS_RMAP_OWN_AG,
			.buf_ops = &xfs_rmapbt_buf_ops,
			.magic = XFS_RMAP_CRC_MAGIC,
		},
		{
			.rmap_owner = XFS_RMAP_OWN_REFC,
			.buf_ops = &xfs_refcountbt_buf_ops,
			.magic = XFS_REFC_CRC_MAGIC,
		},
		{
			.buf_ops = NULL,
		},
	};
	struct xfs_repair_agf_allocbt	raa;
	struct xfs_agf			old_agf;
	struct xfs_mount		*mp = sc->mp;
	struct xfs_buf			*agf_bp;
	struct xfs_buf			*agfl_bp;
	struct xfs_agf			*agf;
	struct xfs_btree_cur		*cur = NULL;
	struct xfs_perag		*pag;
	xfs_agblock_t			blocks;
	xfs_agblock_t			freesp_blocks;
	int				error;

	/* We require the rmapbt to rebuild anything. */
	if (!xfs_sb_version_hasrmapbt(&mp->m_sb))
		return -EOPNOTSUPP;

	memset(&raa, 0, sizeof(raa));
	error = xfs_trans_read_buf(mp, sc->tp, mp->m_ddev_targp,
			XFS_AG_DADDR(mp, sc->sa.agno, XFS_AGF_DADDR(mp)),
			XFS_FSS_TO_BB(mp, 1), 0, &agf_bp, NULL);
	if (error)
		return error;
	agf_bp->b_ops = &xfs_agf_buf_ops;

	/*
	 * Load the AGFL so that we can screen out OWN_AG blocks that
	 * are on the AGFL now; these blocks might have once been part
	 * of the bno/cnt/rmap btrees but are not now.
	 */
	error = xfs_alloc_read_agfl(mp, sc->tp, sc->sa.agno, &agfl_bp);
	if (error)
		return error;
	error = xfs_repair_agf_check_agfl(sc, XFS_BUF_TO_AGF(agf_bp),
			XFS_BUF_TO_AGFL_BNO(mp, agfl_bp));
	if (error)
		return error;

	/* Find the btree roots. */
	error = xfs_repair_find_ag_btree_roots(sc, agf_bp, fab, agfl_bp);
	if (error)
		return error;
	if (fab[0].root == NULLAGBLOCK || fab[0].level > XFS_BTREE_MAXLEVELS ||
	    fab[1].root == NULLAGBLOCK || fab[1].level > XFS_BTREE_MAXLEVELS ||
	    fab[2].root == NULLAGBLOCK || fab[2].level > XFS_BTREE_MAXLEVELS)
		return -EFSCORRUPTED;
	if (xfs_sb_version_hasreflink(&mp->m_sb) &&
	    (fab[3].root == NULLAGBLOCK || fab[3].level > XFS_BTREE_MAXLEVELS))
		return -EFSCORRUPTED;

	/* Start rewriting the header. */
	agf = XFS_BUF_TO_AGF(agf_bp);
	old_agf = *agf;
	/*
	 * We relied on the rmapbt to reconstruct the AGF.  If we get a
	 * different root then something's seriously wrong.
	 */
	if (be32_to_cpu(old_agf.agf_roots[XFS_BTNUM_RMAPi]) != fab[2].root)
		return -EFSCORRUPTED;
	memset(agf, 0, mp->m_sb.sb_sectsize);
	agf->agf_magicnum = cpu_to_be32(XFS_AGF_MAGIC);
	agf->agf_versionnum = cpu_to_be32(XFS_AGF_VERSION);
	agf->agf_seqno = cpu_to_be32(sc->sa.agno);
	agf->agf_length = cpu_to_be32(xfs_ag_block_count(mp, sc->sa.agno));
	agf->agf_roots[XFS_BTNUM_BNOi] = cpu_to_be32(fab[0].root);
	agf->agf_roots[XFS_BTNUM_CNTi] = cpu_to_be32(fab[1].root);
	agf->agf_roots[XFS_BTNUM_RMAPi] = cpu_to_be32(fab[2].root);
	agf->agf_levels[XFS_BTNUM_BNOi] = cpu_to_be32(fab[0].level);
	agf->agf_levels[XFS_BTNUM_CNTi] = cpu_to_be32(fab[1].level);
	agf->agf_levels[XFS_BTNUM_RMAPi] = cpu_to_be32(fab[2].level);
	agf->agf_flfirst = old_agf.agf_flfirst;
	agf->agf_fllast = old_agf.agf_fllast;
	agf->agf_flcount = old_agf.agf_flcount;
	if (xfs_sb_version_hascrc(&mp->m_sb))
		uuid_copy(&agf->agf_uuid, &mp->m_sb.sb_meta_uuid);
	if (xfs_sb_version_hasreflink(&mp->m_sb)) {
		agf->agf_refcount_root = cpu_to_be32(fab[3].root);
		agf->agf_refcount_level = cpu_to_be32(fab[3].level);
	}

	/* Update the AGF counters from the bnobt. */
	cur = xfs_allocbt_init_cursor(mp, sc->tp, agf_bp, sc->sa.agno,
			XFS_BTNUM_BNO);
	raa.sc = sc;
	error = xfs_alloc_query_all(cur, xfs_repair_agf_walk_allocbt, &raa);
	if (error)
		goto err;
	error = xfs_btree_count_blocks(cur, &blocks);
	if (error)
		goto err;
	xfs_btree_del_cursor(cur, XFS_BTREE_NOERROR);
	freesp_blocks = blocks - 1;
	agf->agf_freeblks = cpu_to_be32(raa.freeblks);
	agf->agf_longest = cpu_to_be32(raa.longest);

	/* Update the AGF counters from the cntbt. */
	cur = xfs_allocbt_init_cursor(mp, sc->tp, agf_bp, sc->sa.agno,
			XFS_BTNUM_CNT);
	error = xfs_btree_count_blocks(cur, &blocks);
	if (error)
		goto err;
	xfs_btree_del_cursor(cur, XFS_BTREE_NOERROR);
	freesp_blocks += blocks - 1;

	/* Update the AGF counters from the rmapbt. */
	cur = xfs_rmapbt_init_cursor(mp, sc->tp, agf_bp, sc->sa.agno);
	error = xfs_btree_count_blocks(cur, &blocks);
	if (error)
		goto err;
	xfs_btree_del_cursor(cur, XFS_BTREE_NOERROR);
	agf->agf_rmap_blocks = cpu_to_be32(blocks);
	freesp_blocks += blocks - 1;

	/* Update the AGF counters from the refcountbt. */
	if (xfs_sb_version_hasreflink(&mp->m_sb)) {
		cur = xfs_refcountbt_init_cursor(mp, sc->tp, agf_bp,
				sc->sa.agno, NULL);
		error = xfs_btree_count_blocks(cur, &blocks);
		if (error)
			goto err;
		xfs_btree_del_cursor(cur, XFS_BTREE_NOERROR);
		agf->agf_refcount_blocks = cpu_to_be32(blocks);
	}
	agf->agf_btreeblks = cpu_to_be32(freesp_blocks);
	cur = NULL;

	/* Trigger reinitialization of the in-core data. */
	if (raa.freeblks != be32_to_cpu(old_agf.agf_freeblks) ||
	    freesp_blocks != be32_to_cpu(old_agf.agf_btreeblks) ||
	    raa.longest != be32_to_cpu(old_agf.agf_longest) ||
	    fab[0].level != be32_to_cpu(old_agf.agf_levels[XFS_BTNUM_BNOi]) ||
	    fab[1].level != be32_to_cpu(old_agf.agf_levels[XFS_BTNUM_CNTi]) ||
	    fab[2].level != be32_to_cpu(old_agf.agf_levels[XFS_BTNUM_RMAPi]) ||
	    fab[3].level != be32_to_cpu(old_agf.agf_refcount_level)) {
		pag = xfs_perag_get(mp, sc->sa.agno);
		if (pag->pagf_init) {
			pag->pagf_freeblks = be32_to_cpu(agf->agf_freeblks);
			pag->pagf_btreeblks = be32_to_cpu(agf->agf_btreeblks);
			pag->pagf_flcount = be32_to_cpu(agf->agf_flcount);
			pag->pagf_longest = be32_to_cpu(agf->agf_longest);
			pag->pagf_levels[XFS_BTNUM_BNOi] =
				be32_to_cpu(agf->agf_levels[XFS_BTNUM_BNOi]);
			pag->pagf_levels[XFS_BTNUM_CNTi] =
				be32_to_cpu(agf->agf_levels[XFS_BTNUM_CNTi]);
			pag->pagf_levels[XFS_BTNUM_RMAPi] =
				be32_to_cpu(agf->agf_levels[XFS_BTNUM_RMAPi]);
			pag->pagf_refcount_level =
				be32_to_cpu(agf->agf_refcount_level);
		}
		xfs_perag_put(pag);
		sc->reset_counters = true;
	}

	/* Write this to disk. */
	xfs_trans_buf_set_type(sc->tp, agf_bp, XFS_BLFT_AGF_BUF);
	xfs_trans_log_buf(sc->tp, agf_bp, 0, mp->m_sb.sb_sectsize - 1);
	return error;

err:
	if (cur)
		xfs_btree_del_cursor(cur, error ? XFS_BTREE_ERROR :
				XFS_BTREE_NOERROR);
	*agf = old_agf;
	return error;
}

/* AGFL */

struct xfs_repair_agfl {
	struct xfs_repair_extent_list	freesp_list;
	struct xfs_repair_extent_list	agmeta_list;
	struct xfs_scrub_context	*sc;
};

/* Record all freespace information. */
STATIC int
xfs_repair_agfl_rmap_fn(
	struct xfs_btree_cur		*cur,
	struct xfs_rmap_irec		*rec,
	void				*priv)
{
	struct xfs_repair_agfl		*ra = priv;
	struct xfs_buf			*bp;
	xfs_fsblock_t			fsb;
	int				i;
	int				error = 0;

	if (xfs_scrub_should_terminate(ra->sc, &error))
		return error;

	/* Record all the OWN_AG blocks... */
	if (rec->rm_owner == XFS_RMAP_OWN_AG) {
		fsb = XFS_AGB_TO_FSB(cur->bc_mp, cur->bc_private.a.agno,
				rec->rm_startblock);
		error = xfs_repair_collect_btree_extent(ra->sc,
				&ra->freesp_list, fsb, rec->rm_blockcount);
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
				&ra->agmeta_list, fsb, 1);
		if (error)
			return error;
	}

	return 0;
}

/* Add a btree block to the agmeta list. */
STATIC int
xfs_repair_agfl_visit_btblock(
	struct xfs_btree_cur		*cur,
	int				level,
	void				*priv)
{
	struct xfs_repair_agfl		*ra = priv;
	struct xfs_buf			*bp;
	xfs_fsblock_t			fsb;
	int				error = 0;

	if (xfs_scrub_should_terminate(ra->sc, &error))
		return error;

	xfs_btree_get_block(cur, level, &bp);
	if (!bp)
		return 0;

	fsb = XFS_DADDR_TO_FSB(cur->bc_mp, bp->b_bn);
	return xfs_repair_collect_btree_extent(ra->sc, &ra->agmeta_list,
			fsb, 1);
}

/* Repair the AGFL. */
int
xfs_repair_agfl(
	struct xfs_scrub_context	*sc)
{
	struct xfs_repair_agfl		ra;
	struct xfs_owner_info		oinfo;
	struct xfs_mount		*mp = sc->mp;
	struct xfs_buf			*agf_bp;
	struct xfs_buf			*agfl_bp;
	struct xfs_agf			*agf;
	struct xfs_agfl			*agfl;
	struct xfs_btree_cur		*cur = NULL;
	struct xfs_perag		*pag;
	__be32				*agfl_bno;
	struct xfs_repair_extent	*rae;
	struct xfs_repair_extent	*n;
	xfs_agblock_t			flcount;
	xfs_agblock_t			agbno;
	xfs_agblock_t			bno;
	xfs_agblock_t			old_flcount;
	int				error;

	/* We require the rmapbt to rebuild anything. */
	if (!xfs_sb_version_hasrmapbt(&mp->m_sb))
		return -EOPNOTSUPP;

	xfs_repair_init_extent_list(&ra.freesp_list);
	xfs_repair_init_extent_list(&ra.agmeta_list);
	ra.sc = sc;

	error = xfs_alloc_read_agf(mp, sc->tp, sc->sa.agno, 0, &agf_bp);
	if (error)
		return error;
	if (!agf_bp)
		return -ENOMEM;

	error = xfs_trans_read_buf(mp, sc->tp, mp->m_ddev_targp,
			XFS_AG_DADDR(mp, sc->sa.agno, XFS_AGFL_DADDR(mp)),
			XFS_FSS_TO_BB(mp, 1), 0, &agfl_bp, NULL);
	if (error)
		return error;
	agfl_bp->b_ops = &xfs_agfl_buf_ops;

	/* Find all space used by the free space btrees & rmapbt. */
	cur = xfs_rmapbt_init_cursor(mp, sc->tp, agf_bp, sc->sa.agno);
	error = xfs_rmap_query_all(cur, xfs_repair_agfl_rmap_fn, &ra);
	if (error)
		goto err;
	xfs_btree_del_cursor(cur, XFS_BTREE_NOERROR);

	/* Find all space used by bnobt. */
	cur = xfs_allocbt_init_cursor(mp, sc->tp, agf_bp, sc->sa.agno,
			XFS_BTNUM_BNO);
	error = xfs_btree_visit_blocks(cur, xfs_repair_agfl_visit_btblock,
			&ra);
	if (error)
		goto err;
	xfs_btree_del_cursor(cur, XFS_BTREE_NOERROR);

	/* Find all space used by cntbt. */
	cur = xfs_allocbt_init_cursor(mp, sc->tp, agf_bp, sc->sa.agno,
			XFS_BTNUM_CNT);
	error = xfs_btree_visit_blocks(cur, xfs_repair_agfl_visit_btblock,
			&ra);
	if (error)
		goto err;
	xfs_btree_del_cursor(cur, XFS_BTREE_NOERROR);
	cur = NULL;

	/*
	 * Drop the freesp meta blocks that are in use by btrees.
	 * The remaining blocks /should/ be AGFL blocks.
	 */
	error = xfs_repair_subtract_extents(sc, &ra.freesp_list,
			&ra.agmeta_list);
	if (error)
		goto err;
	xfs_repair_cancel_btree_extents(sc, &ra.agmeta_list);

	/* Start rewriting the header. */
	agfl = XFS_BUF_TO_AGFL(agfl_bp);
	memset(agfl, 0xFF, mp->m_sb.sb_sectsize);
	agfl->agfl_magicnum = cpu_to_be32(XFS_AGFL_MAGIC);
	agfl->agfl_seqno = cpu_to_be32(sc->sa.agno);
	uuid_copy(&agfl->agfl_uuid, &mp->m_sb.sb_meta_uuid);

	/* Fill the AGFL with the remaining blocks. */
	flcount = 0;
	agfl_bno = XFS_BUF_TO_AGFL_BNO(mp, agfl_bp);
	for_each_xfs_repair_extent_safe(rae, n, &ra.freesp_list) {
		agbno = XFS_FSB_TO_AGBNO(mp, rae->fsbno);

		trace_xfs_repair_agfl_insert(mp, sc->sa.agno, agbno, rae->len);

		for (bno = 0; bno < rae->len; bno++) {
			if (flcount >= xfs_agfl_size(mp) - 1)
				break;
			agfl_bno[flcount + 1] = cpu_to_be32(agbno + bno);
			flcount++;
		}
		rae->fsbno += bno;
		rae->len -= bno;
		if (rae->len)
			break;
		list_del(&rae->list);
		kmem_free(rae);
	}

	/* Update the AGF counters. */
	agf = XFS_BUF_TO_AGF(agf_bp);
	old_flcount = be32_to_cpu(agf->agf_flcount);
	agf->agf_flfirst = cpu_to_be32(1);
	agf->agf_flcount = cpu_to_be32(flcount);
	agf->agf_fllast = cpu_to_be32(flcount);

	/* Trigger reinitialization of the in-core data. */
	if (flcount != old_flcount) {
		pag = xfs_perag_get(mp, sc->sa.agno);
		if (pag->pagf_init)
			pag->pagf_flcount = flcount;
		xfs_perag_put(pag);
		sc->reset_counters = true;
	}

	/* Write AGF and AGFL to disk. */
	xfs_alloc_log_agf(sc->tp, agf_bp,
			XFS_AGF_FLFIRST | XFS_AGF_FLLAST | XFS_AGF_FLCOUNT);
	xfs_trans_buf_set_type(sc->tp, agfl_bp, XFS_BLFT_AGFL_BUF);
	xfs_trans_log_buf(sc->tp, agfl_bp, 0, mp->m_sb.sb_sectsize - 1);

	/* Dump any AGFL overflow. */
	xfs_rmap_ag_owner(&oinfo, XFS_RMAP_OWN_AG);
	return xfs_repair_reap_btree_extents(sc, &ra.freesp_list, &oinfo,
			XFS_AG_RESV_AGFL);
err:
	xfs_repair_cancel_btree_extents(sc, &ra.agmeta_list);
	xfs_repair_cancel_btree_extents(sc, &ra.freesp_list);
	if (cur)
		xfs_btree_del_cursor(cur, error ? XFS_BTREE_ERROR :
				XFS_BTREE_NOERROR);
	return error;
}

/* AGI */

int
xfs_repair_agi(
	struct xfs_scrub_context	*sc)
{
	struct xfs_repair_find_ag_btree	fab[] = {
		{
			.rmap_owner = XFS_RMAP_OWN_INOBT,
			.buf_ops = &xfs_inobt_buf_ops,
			.magic = XFS_IBT_CRC_MAGIC,
		},
		{
			.rmap_owner = XFS_RMAP_OWN_INOBT,
			.buf_ops = &xfs_inobt_buf_ops,
			.magic = XFS_FIBT_CRC_MAGIC,
		},
		{
			.buf_ops = NULL
		},
	};
	struct xfs_agi			old_agi;
	struct xfs_mount		*mp = sc->mp;
	struct xfs_buf			*agi_bp;
	struct xfs_buf			*agf_bp;
	struct xfs_agi			*agi;
	struct xfs_btree_cur		*cur;
	struct xfs_perag		*pag;
	xfs_agino_t			old_count;
	xfs_agino_t			old_freecount;
	xfs_agino_t			count;
	xfs_agino_t			freecount;
	int				bucket;
	int				error;

	/* We require the rmapbt to rebuild anything. */
	if (!xfs_sb_version_hasrmapbt(&mp->m_sb))
		return -EOPNOTSUPP;

	error = xfs_trans_read_buf(mp, sc->tp, mp->m_ddev_targp,
			XFS_AG_DADDR(mp, sc->sa.agno, XFS_AGI_DADDR(mp)),
			XFS_FSS_TO_BB(mp, 1), 0, &agi_bp, NULL);
	if (error)
		return error;
	agi_bp->b_ops = &xfs_agi_buf_ops;

	error = xfs_alloc_read_agf(mp, sc->tp, sc->sa.agno, 0, &agf_bp);
	if (error)
		return error;
	if (!agf_bp)
		return -ENOMEM;

	/* Find the btree roots. */
	error = xfs_repair_find_ag_btree_roots(sc, agf_bp, fab, NULL);
	if (error)
		return error;
	if (fab[0].root == NULLAGBLOCK || fab[0].level > XFS_BTREE_MAXLEVELS)
		return -EFSCORRUPTED;
	if (xfs_sb_version_hasfinobt(&mp->m_sb) &&
	    (fab[1].root == NULLAGBLOCK || fab[1].level > XFS_BTREE_MAXLEVELS))
		return -EFSCORRUPTED;

	/* Start rewriting the header. */
	agi = XFS_BUF_TO_AGI(agi_bp);
	old_agi = *agi;
	old_count = be32_to_cpu(old_agi.agi_count);
	old_freecount = be32_to_cpu(old_agi.agi_freecount);
	memset(agi, 0, mp->m_sb.sb_sectsize);
	agi->agi_magicnum = cpu_to_be32(XFS_AGI_MAGIC);
	agi->agi_versionnum = cpu_to_be32(XFS_AGI_VERSION);
	agi->agi_seqno = cpu_to_be32(sc->sa.agno);
	agi->agi_length = cpu_to_be32(xfs_ag_block_count(mp, sc->sa.agno));
	agi->agi_newino = cpu_to_be32(NULLAGINO);
	agi->agi_dirino = cpu_to_be32(NULLAGINO);
	if (xfs_sb_version_hascrc(&mp->m_sb))
		uuid_copy(&agi->agi_uuid, &mp->m_sb.sb_meta_uuid);
	for (bucket = 0; bucket < XFS_AGI_UNLINKED_BUCKETS; bucket++)
		agi->agi_unlinked[bucket] = cpu_to_be32(NULLAGINO);
	agi->agi_root = cpu_to_be32(fab[0].root);
	agi->agi_level = cpu_to_be32(fab[0].level);
	if (xfs_sb_version_hasfinobt(&mp->m_sb)) {
		agi->agi_free_root = cpu_to_be32(fab[1].root);
		agi->agi_free_level = cpu_to_be32(fab[1].level);
	}

	/* Update the AGI counters. */
	cur = xfs_inobt_init_cursor(mp, sc->tp, agi_bp, sc->sa.agno,
			XFS_BTNUM_INO);
	error = xfs_ialloc_count_inodes(cur, &count, &freecount);
	xfs_btree_del_cursor(cur, XFS_BTREE_NOERROR);
	if (error)
		goto err;
	agi->agi_count = cpu_to_be32(count);
	agi->agi_freecount = cpu_to_be32(freecount);
	if (old_count != count || old_freecount != freecount) {
		pag = xfs_perag_get(mp, sc->sa.agno);
		pag->pagi_init = 0;
		xfs_perag_put(pag);
		sc->reset_counters = true;
	}

	/* Write this to disk. */
	xfs_trans_buf_set_type(sc->tp, agi_bp, XFS_BLFT_AGI_BUF);
	xfs_trans_log_buf(sc->tp, agi_bp, 0, mp->m_sb.sb_sectsize - 1);
	return error;

err:
	*agi = old_agi;
	return error;
}
