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
#include "xfs_ialloc.h"
#include "xfs_ialloc_btree.h"
#include "xfs_icache.h"
#include "xfs_rmap.h"
#include "xfs_alloc.h"
#include "xfs_rmap_btree.h"
#include "xfs_refcount.h"
#include "xfs_error.h"
#include "repair/common.h"
#include "repair/btree.h"

/* Inode btree scrubber. */

/* Scrub a chunk of an inobt record. */
STATIC int
xfs_scrub_iallocbt_chunk(
	struct xfs_scrub_btree		*bs,
	struct xfs_inobt_rec_incore	*irec,
	xfs_agino_t			agino,
	xfs_extlen_t			len,
	bool				*keep_scanning)
{
	struct xfs_mount		*mp = bs->cur->bc_mp;
	struct xfs_agf			*agf;
	struct xfs_scrub_ag		*psa;
	struct xfs_btree_cur		**xcur;
	struct xfs_owner_info		oinfo;
	xfs_agblock_t			eoag;
	xfs_agblock_t			bno;
	bool				is_freesp;
	bool				has_inodes;
	bool				has_rmap;
	bool				has_refcount;
	int				error = 0;
	int				err2;

	agf = XFS_BUF_TO_AGF(bs->sc->sa.agf_bp);
	eoag = be32_to_cpu(agf->agf_length);
	bno = XFS_AGINO_TO_AGBNO(mp, agino);
	xfs_rmap_ag_owner(&oinfo, XFS_RMAP_OWN_INODES);

	*keep_scanning = true;
	XFS_SCRUB_BTREC_CHECK(bs, bno < mp->m_sb.sb_agblocks);
	XFS_SCRUB_BTREC_CHECK(bs, bno < eoag);
	XFS_SCRUB_BTREC_CHECK(bs, bno < bno + len);
	XFS_SCRUB_BTREC_CHECK(bs, (unsigned long long)bno + len <=
			mp->m_sb.sb_agblocks);
	XFS_SCRUB_BTREC_CHECK(bs, (unsigned long long)bno + len <=
			eoag);
	if (error) {
		*keep_scanning = false;
		goto out;
	}

	/* Make sure we don't cover the AG headers. */
	XFS_SCRUB_BTREC_CHECK(bs,
			!xfs_scrub_extent_covers_ag_head(mp, bno, len));

	psa = &bs->sc->sa;
	/* Cross-reference with the bnobt. */
	if (psa->bno_cur) {
		err2 = xfs_alloc_has_record(psa->bno_cur, bno, len,
				&is_freesp);
		if (xfs_scrub_btree_should_xref(bs, err2, &psa->bno_cur))
			XFS_SCRUB_BTREC_CHECK(bs, !is_freesp);
	}

	/* If we have a finobt, cross-reference with it. */
	if (bs->cur == psa->fino_cur)
		xcur = &psa->ino_cur;
	else if (bs->cur == psa->ino_cur && irec->ir_freecount > 0)
		xcur = &psa->fino_cur;
	else
		xcur = NULL;
	if (xcur && *xcur) {
		err2 = xfs_ialloc_has_inode_record(*xcur,
				agino, agino, &has_inodes);
		if (xfs_scrub_btree_should_xref(bs, err2, xcur))
			XFS_SCRUB_BTREC_CHECK(bs, has_inodes);
	}

	/* Cross-reference with rmapbt. */
	if (psa->rmap_cur) {
		err2 = xfs_rmap_record_exists(psa->rmap_cur, bno,
				len, &oinfo, &has_rmap);
		if (xfs_scrub_btree_should_xref(bs, err2, &psa->rmap_cur))
			XFS_SCRUB_BTREC_CHECK(bs, has_rmap);
	}

	/* Cross-reference with the refcountbt. */
	if (psa->refc_cur) {
		err2 = xfs_refcount_has_record(psa->refc_cur, bno,
				len, &has_refcount);
		if (xfs_scrub_btree_should_xref(bs, err2, &psa->refc_cur))
			XFS_SCRUB_BTREC_CHECK(bs, !has_refcount);
	}

out:
	return error;
}

/* Count the number of free inodes. */
static unsigned int
xfs_scrub_iallocbt_freecount(
	xfs_inofree_t			freemask)
{
	int				bits = XFS_INODES_PER_CHUNK;
	unsigned int			ret = 0;

	while (bits--) {
		if (freemask & 1)
			ret++;
		freemask >>= 1;
	}

	return ret;
}

/* Make sure the free mask is consistent with what the inodes think. */
STATIC int
xfs_scrub_iallocbt_check_freemask(
	struct xfs_scrub_btree		*bs,
	struct xfs_inobt_rec_incore	*irec)
{
	struct xfs_owner_info		oinfo;
	struct xfs_imap			imap;
	struct xfs_mount		*mp = bs->cur->bc_mp;
	struct xfs_dinode		*dip;
	struct xfs_buf			*bp;
	struct xfs_scrub_ag		*psa;
	xfs_ino_t			fsino;
	xfs_agino_t			nr_inodes;
	xfs_agino_t			agino;
	xfs_agino_t			chunkino;
	xfs_agino_t			clusterino;
	xfs_agblock_t			agbno;
	int				blks_per_cluster;
	__uint16_t			holemask;
	__uint16_t			ir_holemask;
	bool				has;
	int				error = 0;
	int				err2;

	/* Make sure the freemask matches the inode records. */
	blks_per_cluster = xfs_icluster_size_fsb(mp);
	nr_inodes = XFS_OFFBNO_TO_AGINO(mp, blks_per_cluster, 0);
	xfs_rmap_ag_owner(&oinfo, XFS_RMAP_OWN_INODES);
	psa = &bs->sc->sa;

	for (agino = irec->ir_startino;
	     agino < irec->ir_startino + XFS_INODES_PER_CHUNK;
	     agino += blks_per_cluster * mp->m_sb.sb_inopblock) {
		fsino = XFS_AGINO_TO_INO(mp, bs->cur->bc_private.a.agno, agino);
		chunkino = agino - irec->ir_startino;
		agbno = XFS_AGINO_TO_AGBNO(mp, agino);

		/* Compute the holemask mask for this cluster. */
		for (clusterino = 0, holemask = 0; clusterino < nr_inodes;
		     clusterino += XFS_INODES_PER_HOLEMASK_BIT)
			holemask |= XFS_INOBT_MASK((chunkino + clusterino) /
					XFS_INODES_PER_HOLEMASK_BIT);

		/* The whole cluster must be a hole or not a hole. */
		ir_holemask = (irec->ir_holemask & holemask);
		XFS_SCRUB_BTREC_CHECK(bs, ir_holemask == holemask ||
				ir_holemask == 0);

		/* Does the rmap agree that we have inodes here? */
		if (psa->rmap_cur) {
			err2 = xfs_rmap_record_exists(psa->rmap_cur, agbno,
					blks_per_cluster, &oinfo, &has);
			if (!xfs_scrub_btree_should_xref(bs, err2,
					&psa->rmap_cur))
				goto skip_xref;
			if (has)
				XFS_SCRUB_BTREC_CHECK(bs, ir_holemask == 0);
			else
				XFS_SCRUB_BTREC_CHECK(bs,
						ir_holemask == holemask);
		}

skip_xref:
		/* If any part of this is a hole, skip it. */
		if (ir_holemask)
			goto next_cluster;

		/* Grab the inode cluster buffer. */
		imap.im_blkno = XFS_AGB_TO_DADDR(mp, bs->cur->bc_private.a.agno,
				agbno);
		imap.im_len = XFS_FSB_TO_BB(mp, blks_per_cluster);
		imap.im_boffset = 0;

		error = xfs_imap_to_bp(mp, bs->cur->bc_tp, &imap,
				&dip, &bp, 0, 0);
		XFS_SCRUB_BTREC_OP_ERROR_GOTO(bs, &error, next_cluster);

		/* Which inodes are free? */
		for (clusterino = 0; clusterino < nr_inodes; clusterino++) {
			dip = xfs_buf_offset(bp, clusterino * mp->m_sb.sb_inodesize);
			XFS_SCRUB_BTREC_GOTO(bs,
					be16_to_cpu(dip->di_magic) ==
					XFS_DINODE_MAGIC, next_cluster_brelse);
			XFS_SCRUB_BTREC_GOTO(bs,
					dip->di_version < 3 ||
					be64_to_cpu(dip->di_ino) ==
						fsino + clusterino,
					next_cluster_brelse);
			XFS_SCRUB_BTREC_CHECK(bs,
					!!(dip->di_nlink || dip->di_onlink) ^
					!!(irec->ir_free &
					XFS_INOBT_MASK(chunkino + clusterino)));
		}
next_cluster_brelse:
		xfs_trans_brelse(bs->cur->bc_tp, bp);
next_cluster:
		;
	}

	return error;
}

/* Scrub an inobt/finobt record. */
STATIC int
xfs_scrub_iallocbt_helper(
	struct xfs_scrub_btree		*bs,
	union xfs_btree_rec		*rec)
{
	struct xfs_mount		*mp = bs->cur->bc_mp;
	struct xfs_agi			*agi;
	struct xfs_inobt_rec_incore	irec;
	uint64_t			holes;
	xfs_agino_t			agino;
	xfs_agblock_t			agbno;
	xfs_extlen_t			len;
	bool				keep_scanning;
	int				holecount;
	int				i;
	int				error = 0;
	int				err2 = 0;
	unsigned int			real_freecount;
	__uint16_t			holemask;

	xfs_inobt_btrec_to_irec(mp, rec, &irec);

	XFS_SCRUB_BTREC_CHECK(bs, irec.ir_count <= XFS_INODES_PER_CHUNK);
	XFS_SCRUB_BTREC_CHECK(bs, irec.ir_freecount <= XFS_INODES_PER_CHUNK);
	real_freecount = irec.ir_freecount +
			(XFS_INODES_PER_CHUNK - irec.ir_count);
	XFS_SCRUB_BTREC_CHECK(bs, real_freecount ==
			xfs_scrub_iallocbt_freecount(irec.ir_free));
	agi = XFS_BUF_TO_AGI(bs->sc->sa.agi_bp);
	agino = irec.ir_startino;
	agbno = XFS_AGINO_TO_AGBNO(mp, irec.ir_startino);
	XFS_SCRUB_BTREC_GOTO(bs, agbno < be32_to_cpu(agi->agi_length), out);

	/* Handle non-sparse inodes */
	if (!xfs_inobt_issparse(irec.ir_holemask)) {
		len = XFS_B_TO_FSB(mp,
				XFS_INODES_PER_CHUNK * mp->m_sb.sb_inodesize);
		XFS_SCRUB_BTREC_CHECK(bs,
				irec.ir_count == XFS_INODES_PER_CHUNK);

		error = xfs_scrub_iallocbt_chunk(bs, &irec, agino, len,
				&keep_scanning);
		if (error)
			goto out;
		goto check_freemask;
	}

	/* Check each chunk of a sparse inode cluster. */
	holemask = irec.ir_holemask;
	holecount = 0;
	len = XFS_B_TO_FSB(mp,
			XFS_INODES_PER_HOLEMASK_BIT * mp->m_sb.sb_inodesize);
	holes = ~xfs_inobt_irec_to_allocmask(&irec);
	XFS_SCRUB_BTREC_CHECK(bs, (holes & irec.ir_free) == holes);
	XFS_SCRUB_BTREC_CHECK(bs, irec.ir_freecount <= irec.ir_count);

	for (i = 0; i < XFS_INOBT_HOLEMASK_BITS; holemask >>= 1,
			i++, agino += XFS_INODES_PER_HOLEMASK_BIT) {
		if (holemask & 1) {
			holecount += XFS_INODES_PER_HOLEMASK_BIT;
			continue;
		}

		err2 = xfs_scrub_iallocbt_chunk(bs, &irec, agino, len,
				&keep_scanning);
		if (!error && err2)
			error = err2;
		if (!keep_scanning)
			break;
	}

	XFS_SCRUB_BTREC_CHECK(bs, holecount <= XFS_INODES_PER_CHUNK);
	XFS_SCRUB_BTREC_CHECK(bs, holecount + irec.ir_count ==
			XFS_INODES_PER_CHUNK);

check_freemask:
	error = xfs_scrub_iallocbt_check_freemask(bs, &irec);
	if (error)
		goto out;

out:
	return error;
}

/* Scrub the inode btrees for some AG. */
STATIC int
xfs_scrub_iallocbt(
	struct xfs_scrub_context	*sc,
	xfs_btnum_t			which)
{
	struct xfs_btree_cur		*cur;
	struct xfs_owner_info		oinfo;

	xfs_rmap_ag_owner(&oinfo, XFS_RMAP_OWN_INOBT);
	cur = which == XFS_BTNUM_INO ? sc->sa.ino_cur : sc->sa.fino_cur;
	return xfs_scrub_btree(sc, cur, xfs_scrub_iallocbt_helper,
			&oinfo, NULL);
}

int
xfs_scrub_inobt(
	struct xfs_scrub_context	*sc)
{
	return xfs_scrub_iallocbt(sc, XFS_BTNUM_INO);
}

int
xfs_scrub_finobt(
	struct xfs_scrub_context	*sc)
{
	return xfs_scrub_iallocbt(sc, XFS_BTNUM_FINO);
}

/* Inode btree repair. */

struct xfs_repair_ialloc_extent {
	struct list_head		list;
	xfs_inofree_t			freemask;
	xfs_agino_t			startino;
	unsigned int			count;
	unsigned int			usedcount;
	__uint16_t			holemask;
};

struct xfs_repair_ialloc {
	struct list_head		extlist;
	struct list_head		btlist;
	uint64_t			nr_records;
};

/* Record extents that belong to inode btrees. */
STATIC int
xfs_repair_ialloc_extent_fn(
	struct xfs_btree_cur		*cur,
	struct xfs_rmap_irec		*rec,
	void				*priv)
{
	struct xfs_imap			imap;
	struct xfs_repair_ialloc	*ri = priv;
	struct xfs_repair_ialloc_extent	*rie;
	struct xfs_dinode		*dip;
	struct xfs_buf			*bp;
	struct xfs_mount		*mp = cur->bc_mp;
	xfs_ino_t			fsino;
	xfs_inofree_t			usedmask;
	xfs_fsblock_t			fsbno;
	xfs_agnumber_t			agno;
	xfs_agblock_t			agbno;
	xfs_agino_t			agino;
	xfs_agino_t			startino;
	xfs_agino_t			chunkino;
	xfs_agino_t			nr_inodes;
	xfs_agino_t			i;
	__uint16_t			fillmask;
	int				blks_per_cluster;
	int				usedcount;
	int				error = 0;

	if (xfs_scrub_should_terminate(&error))
		return error;

	/* Fragment of the old btrees; dispose of them later. */
	if (rec->rm_owner == XFS_RMAP_OWN_INOBT) {
		fsbno = XFS_AGB_TO_FSB(cur->bc_mp, cur->bc_private.a.agno,
				rec->rm_startblock);
		return xfs_repair_collect_btree_extent(mp, &ri->btlist,
				fsbno, rec->rm_blockcount);
	}

	/* Skip extents which are not owned by this inode and fork. */
	if (rec->rm_owner != XFS_RMAP_OWN_INODES)
		return 0;

	agno = cur->bc_private.a.agno;
	blks_per_cluster = xfs_icluster_size_fsb(mp);
	nr_inodes = XFS_OFFBNO_TO_AGINO(mp, blks_per_cluster, 0);

	ASSERT(rec->rm_startblock % blks_per_cluster == 0);

	trace_xfs_repair_ialloc_extent_fn(mp, cur->bc_private.a.agno,
			rec->rm_startblock, rec->rm_blockcount, rec->rm_owner,
			rec->rm_offset, rec->rm_flags);

	for (agbno = rec->rm_startblock;
	     agbno < rec->rm_startblock + rec->rm_blockcount;
	     agbno += blks_per_cluster) {
		agino = XFS_OFFBNO_TO_AGINO(mp, agbno, 0);
		fsino = XFS_AGINO_TO_INO(mp, agno, agino);
		chunkino = agino & (XFS_INODES_PER_CHUNK - 1);
		startino = agino & ~(XFS_INODES_PER_CHUNK - 1);

		/* Which inodes are not holes? */
		fillmask = xfs_inobt_maskn(
				chunkino / XFS_INODES_PER_HOLEMASK_BIT,
				nr_inodes / XFS_INODES_PER_HOLEMASK_BIT);

		/* Grab the inode cluster buffer. */
		imap.im_blkno = XFS_AGB_TO_DADDR(mp, agno, agbno);
		imap.im_len = XFS_FSB_TO_BB(mp, blks_per_cluster);
		imap.im_boffset = 0;

		error = xfs_imap_to_bp(mp, cur->bc_tp, &imap,
				&dip, &bp, 0, XFS_IGET_UNTRUSTED);
		if (error)
			return error;

		/* Which inodes are free? */
		for (usedmask = 0, usedcount = 0, i = 0; i < nr_inodes; i++) {
			dip = xfs_buf_offset(bp, i * mp->m_sb.sb_inodesize);
			if (be16_to_cpu(dip->di_magic) != XFS_DINODE_MAGIC) {
				xfs_trans_brelse(cur->bc_tp, bp);
				return -EFSCORRUPTED;
			}
			if (dip->di_version >= 3 &&
			    be64_to_cpu(dip->di_ino) != fsino + i) {
				xfs_trans_brelse(cur->bc_tp, bp);
				return -EFSCORRUPTED;
			}

			if (dip->di_nlink || dip->di_onlink) {
				usedmask |= 1ULL << (chunkino + i);
				usedcount++;
			}
		}
		xfs_trans_brelse(cur->bc_tp, bp);

		/*
		 * If the last item in the list is our chunk record,
		 * update that.
		 */
		if (!list_empty(&ri->extlist)) {
			rie = list_last_entry(&ri->extlist,
					struct xfs_repair_ialloc_extent, list);
			if (rie->startino == startino) {
				rie->freemask &= ~usedmask;
				rie->holemask &= ~fillmask;
				rie->count += nr_inodes;
				rie->usedcount += usedcount;
				continue;
			}
		}

		/* New inode chunk; add to the list. */
		rie = kmem_alloc(sizeof(*rie), KM_NOFS);
		if (!rie)
			return -ENOMEM;

		INIT_LIST_HEAD(&rie->list);
		rie->startino = startino;
		rie->freemask = XFS_INOBT_ALL_FREE & ~usedmask;
		rie->holemask = XFS_INOBT_ALL_FREE & ~fillmask;
		rie->count = nr_inodes;
		rie->usedcount = usedcount;
		list_add_tail(&rie->list, &ri->extlist);
		ri->nr_records++;
	}

	return 0;
}

/* Compare two ialloc extents. */
static int
xfs_repair_ialloc_extent_cmp(
	void				*priv,
	struct list_head		*a,
	struct list_head		*b)
{
	struct xfs_repair_ialloc_extent	*ap;
	struct xfs_repair_ialloc_extent	*bp;

	ap = container_of(a, struct xfs_repair_ialloc_extent, list);
	bp = container_of(b, struct xfs_repair_ialloc_extent, list);

	if (ap->startino > bp->startino)
		return 1;
	else if (ap->startino < bp->startino)
		return -1;
	return 0;
}

/* Repair both inode btrees. */
int
xfs_repair_iallocbt(
	struct xfs_scrub_context	*sc)
{
	struct xfs_repair_ialloc	ri;
	struct xfs_owner_info		oinfo;
	struct xfs_mount		*mp = sc->tp->t_mountp;
	struct xfs_buf			*bp;
	struct xfs_repair_ialloc_extent	*rie;
	struct xfs_repair_ialloc_extent	*n;
	struct xfs_agi			*agi;
	struct xfs_btree_cur		*cur = NULL;
	struct xfs_perag		*pag;
	xfs_fsblock_t			inofsb;
	xfs_fsblock_t			finofsb;
	xfs_extlen_t			nr_blocks;
	unsigned int			count;
	unsigned int			usedcount;
	int				stat;
	int				logflags;
	int				error = 0;

	/* We require the rmapbt to rebuild anything. */
	if (!xfs_sb_version_hasrmapbt(&mp->m_sb))
		return -EOPNOTSUPP;

	/* Collect all reverse mappings for inode blocks. */
	xfs_rmap_ag_owner(&oinfo, XFS_RMAP_OWN_INOBT);
	INIT_LIST_HEAD(&ri.extlist);
	INIT_LIST_HEAD(&ri.btlist);
	ri.nr_records = 0;
	cur = xfs_rmapbt_init_cursor(mp, sc->tp, sc->sa.agf_bp, sc->sa.agno);
	error = xfs_rmap_query_all(cur, xfs_repair_ialloc_extent_fn, &ri);
	if (error)
		goto out;
	xfs_btree_del_cursor(cur, XFS_BTREE_NOERROR);
	cur = NULL;

	/* Do we actually have enough space to do this? */
	pag = xfs_perag_get(mp, sc->sa.agno);
	nr_blocks = xfs_iallocbt_calc_size(mp, ri.nr_records);
	if (xfs_sb_version_hasfinobt(&mp->m_sb))
		nr_blocks *= 2;
	if (!xfs_repair_ag_has_space(pag, nr_blocks, XFS_AG_RESV_NONE)) {
		xfs_perag_put(pag);
		error = -ENOSPC;
		goto out;
	}
	xfs_perag_put(pag);

	agi = XFS_BUF_TO_AGI(sc->sa.agi_bp);
	/* Initialize new btree roots. */
	error = xfs_repair_alloc_ag_block(sc, &oinfo, &inofsb,
			XFS_AG_RESV_NONE);
	if (error)
		goto out;
	error = xfs_repair_init_btblock(sc, inofsb, &bp, XFS_IBT_CRC_MAGIC,
			&xfs_inobt_buf_ops);
	if (error)
		goto out;
	agi->agi_root = cpu_to_be32(XFS_FSB_TO_AGBNO(mp, inofsb));
	agi->agi_level = cpu_to_be32(1);
	logflags = XFS_AGI_ROOT | XFS_AGI_LEVEL;

	if (xfs_sb_version_hasfinobt(&mp->m_sb)) {
		error = xfs_repair_alloc_ag_block(sc, &oinfo, &finofsb,
				XFS_AG_RESV_NONE);
		if (error)
			goto out;
		error = xfs_repair_init_btblock(sc, finofsb, &bp,
				XFS_FIBT_CRC_MAGIC, &xfs_inobt_buf_ops);
		if (error)
			goto out;
		agi->agi_free_root = cpu_to_be32(XFS_FSB_TO_AGBNO(mp, finofsb));
		agi->agi_free_level = cpu_to_be32(1);
		logflags |= XFS_AGI_FREE_ROOT | XFS_AGI_FREE_LEVEL;
	}

	xfs_ialloc_log_agi(sc->tp, sc->sa.agi_bp, logflags);
	error = xfs_repair_roll_ag_trans(sc);
	if (error)
		goto out;

	/* Insert records into the new btrees. */
	count = 0;
	usedcount = 0;
	list_sort(NULL, &ri.extlist, xfs_repair_ialloc_extent_cmp);
	list_for_each_entry_safe(rie, n, &ri.extlist, list) {
		count += rie->count;
		usedcount += rie->usedcount;

		trace_xfs_repair_ialloc_insert(mp, sc->sa.agno, rie->startino,
				rie->holemask, rie->count,
				rie->count - rie->usedcount, rie->freemask);

		/* Insert into the inobt. */
		cur = xfs_inobt_init_cursor(mp, sc->tp, sc->sa.agi_bp,
				sc->sa.agno, XFS_BTNUM_INO);
		error = xfs_inobt_lookup(cur, rie->startino, XFS_LOOKUP_EQ,
				&stat);
		if (error)
			goto out;
		XFS_WANT_CORRUPTED_GOTO(mp, stat == 0, out);
		error = xfs_inobt_insert_rec(cur, rie->holemask, rie->count,
				rie->count - rie->usedcount, rie->freemask,
				&stat);
		if (error)
			goto out;
		XFS_WANT_CORRUPTED_GOTO(mp, stat == 1, out);
		xfs_btree_del_cursor(cur, XFS_BTREE_NOERROR);
		cur = NULL;

		/* Insert into the finobt. */
		if (rie->count != rie->usedcount &&
		    xfs_sb_version_hasfinobt(&mp->m_sb)) {
			cur = xfs_inobt_init_cursor(mp, sc->tp, sc->sa.agi_bp,
					sc->sa.agno, XFS_BTNUM_FINO);
			error = xfs_inobt_lookup(cur, rie->startino,
					XFS_LOOKUP_EQ, &stat);
			if (error)
				goto out;
			XFS_WANT_CORRUPTED_GOTO(mp, stat == 0, out);
			error = xfs_inobt_insert_rec(cur, rie->holemask,
					rie->count, rie->count - rie->usedcount,
					rie->freemask, &stat);
			if (error)
				goto out;
			XFS_WANT_CORRUPTED_GOTO(mp, stat == 1, out);
			xfs_btree_del_cursor(cur, XFS_BTREE_NOERROR);
			cur = NULL;
		}

		error = xfs_repair_roll_ag_trans(sc);
		if (error)
			goto out;

		list_del(&rie->list);
		kmem_free(rie);
	}

	/* Update the AGI counters. */
	agi = XFS_BUF_TO_AGI(sc->sa.agi_bp);
	if (be32_to_cpu(agi->agi_count) != count ||
	    be32_to_cpu(agi->agi_freecount) != count - usedcount) {
		pag = xfs_perag_get(mp, sc->sa.agno);
		pag->pagi_init = 0;
		xfs_perag_put(pag);

		agi->agi_count = cpu_to_be32(count);
		agi->agi_freecount = cpu_to_be32(count - usedcount);
		xfs_ialloc_log_agi(sc->tp, sc->sa.agi_bp,
				XFS_AGI_COUNT | XFS_AGI_FREECOUNT);
		sc->reset_counters = true;
	}

	/* Free the old inode btree blocks if they're not in use. */
	error = xfs_repair_reap_btree_extents(sc, &ri.btlist, &oinfo,
			XFS_AG_RESV_NONE);
	if (error)
		goto out;

	return error;
out:
	if (cur)
		xfs_btree_del_cursor(cur, XFS_BTREE_ERROR);
	xfs_repair_cancel_btree_extents(sc, &ri.btlist);
	list_for_each_entry_safe(rie, n, &ri.extlist, list) {
		list_del(&rie->list);
		kmem_free(rie);
	}
	return error;
}
