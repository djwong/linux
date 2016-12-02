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
	xfs_agblock_t			eoag;
	xfs_agblock_t			bno;
	int				error = 0;

	agf = XFS_BUF_TO_AGF(bs->sc->sa.agf_bp);
	eoag = be32_to_cpu(agf->agf_length);
	bno = XFS_AGINO_TO_AGBNO(mp, agino);

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
	xfs_ino_t			fsino;
	xfs_agino_t			nr_inodes;
	xfs_agino_t			agino;
	xfs_agino_t			chunkino;
	xfs_agino_t			clusterino;
	xfs_agblock_t			agbno;
	int				blks_per_cluster;
	__uint16_t			holemask;
	__uint16_t			ir_holemask;
	int				error = 0;

	/* Make sure the freemask matches the inode records. */
	blks_per_cluster = xfs_icluster_size_fsb(mp);
	nr_inodes = XFS_OFFBNO_TO_AGINO(mp, blks_per_cluster, 0);
	xfs_rmap_ag_owner(&oinfo, XFS_RMAP_OWN_INODES);

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
