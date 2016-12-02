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
#include "repair/common.h"
#include "repair/btree.h"

/* Reverse-mapping scrubber. */

/* Scrub an rmapbt record. */
STATIC int
xfs_scrub_rmapbt_helper(
	struct xfs_scrub_btree		*bs,
	union xfs_btree_rec		*rec)
{
	struct xfs_mount		*mp = bs->cur->bc_mp;
	struct xfs_agf			*agf;
	struct xfs_scrub_ag		*psa;
	struct xfs_rmap_irec		irec;
	xfs_agblock_t			eoag;
	bool				is_freesp;
	bool				non_inode;
	bool				is_unwritten;
	bool				is_bmbt;
	bool				is_attr;
	int				error = 0;
	int				err2;

	error = xfs_rmap_btrec_to_irec(rec, &irec);
	XFS_SCRUB_BTREC_OP_ERROR_GOTO(bs, &error, out);

	/* Check extent. */
	agf = XFS_BUF_TO_AGF(bs->sc->sa.agf_bp);
	eoag = be32_to_cpu(agf->agf_length);
	XFS_SCRUB_BTREC_CHECK(bs, irec.rm_startblock < mp->m_sb.sb_agblocks);
	XFS_SCRUB_BTREC_CHECK(bs, irec.rm_startblock < eoag);
	XFS_SCRUB_BTREC_CHECK(bs, irec.rm_startblock < irec.rm_startblock +
			irec.rm_blockcount);
	XFS_SCRUB_BTREC_CHECK(bs, irec.rm_startblock + irec.rm_blockcount <=
			mp->m_sb.sb_agblocks);
	XFS_SCRUB_BTREC_CHECK(bs, irec.rm_startblock + irec.rm_blockcount <=
			eoag);

	/* Check flags. */
	non_inode = XFS_RMAP_NON_INODE_OWNER(irec.rm_owner);
	is_bmbt = irec.rm_flags & XFS_RMAP_BMBT_BLOCK;
	is_attr = irec.rm_flags & XFS_RMAP_ATTR_FORK;
	is_unwritten = irec.rm_flags & XFS_RMAP_UNWRITTEN;

	XFS_SCRUB_BTREC_CHECK(bs, !is_bmbt || irec.rm_offset == 0);
	XFS_SCRUB_BTREC_CHECK(bs, !non_inode || irec.rm_offset == 0);
	XFS_SCRUB_BTREC_CHECK(bs, !is_unwritten || !(is_bmbt || non_inode ||
			is_attr));
	XFS_SCRUB_BTREC_CHECK(bs, !non_inode || !(is_bmbt || is_unwritten ||
			is_attr));

	/* Owner inode within an AG? */
	XFS_SCRUB_BTREC_CHECK(bs, non_inode ||
			(XFS_INO_TO_AGNO(mp, irec.rm_owner) <
							mp->m_sb.sb_agcount &&
			 XFS_AGINO_TO_AGBNO(mp,
				XFS_INO_TO_AGINO(mp, irec.rm_owner)) <
							mp->m_sb.sb_agblocks));
	/* Owner inode within the FS? */
	XFS_SCRUB_BTREC_CHECK(bs, non_inode ||
			XFS_AGB_TO_DADDR(mp,
				XFS_INO_TO_AGNO(mp, irec.rm_owner),
				XFS_AGINO_TO_AGBNO(mp,
					XFS_INO_TO_AGINO(mp, irec.rm_owner))) <
			XFS_FSB_TO_BB(mp, mp->m_sb.sb_dblocks));

	/* Non-inode owner within the magic values? */
	XFS_SCRUB_BTREC_CHECK(bs, !non_inode ||
			(irec.rm_owner > XFS_RMAP_OWN_MIN &&
			 irec.rm_owner <= XFS_RMAP_OWN_FS));
	if (error)
		goto out;

	psa = &bs->sc->sa;
	/* check there's no record in freesp btrees */
	if (psa->bno_cur) {
		err2 = xfs_alloc_has_record(psa->bno_cur, irec.rm_startblock,
				irec.rm_blockcount, &is_freesp);
		if (xfs_scrub_btree_should_xref(bs, err2, &psa->bno_cur))
			XFS_SCRUB_BTREC_CHECK(bs, !is_freesp);
	}

out:
	return error;
}

/* Scrub the rmap btree for some AG. */
int
xfs_scrub_rmapbt(
	struct xfs_scrub_context	*sc)
{
	struct xfs_owner_info		oinfo;

	xfs_rmap_ag_owner(&oinfo, XFS_RMAP_OWN_AG);
	return xfs_scrub_btree(sc, sc->sa.rmap_cur, xfs_scrub_rmapbt_helper,
			&oinfo, NULL);
}
