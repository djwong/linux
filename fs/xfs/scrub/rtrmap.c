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
#include "xfs_rmap.h"
#include "xfs_rmap_btree.h"
#include "xfs_rtrmap_btree.h"
#include "xfs_inode.h"
#include "xfs_rtalloc.h"
#include "scrub/xfs_scrub.h"
#include "scrub/scrub.h"
#include "scrub/common.h"
#include "scrub/btree.h"
#include "scrub/trace.h"

/* Set us up with the realtime metadata and AG headers locked. */
int
xfs_scrub_setup_rtrmapbt(
	struct xfs_scrub_context	*sc,
	struct xfs_inode		*ip)
{
	struct xfs_mount		*mp = sc->mp;
	int				lockmode;
	int				error = 0;

	if (sc->sm->sm_agno || sc->sm->sm_ino || sc->sm->sm_gen)
		return -EINVAL;

	error = xfs_scrub_setup_fs(sc, ip);
	if (error)
		return error;

	lockmode = XFS_ILOCK_EXCL;
	xfs_ilock(mp->m_rrmapip, lockmode);
	xfs_trans_ijoin(sc->tp, mp->m_rrmapip, lockmode);

	lockmode = XFS_ILOCK_EXCL | XFS_ILOCK_RTBITMAP;
	xfs_ilock(mp->m_rbmip, lockmode);
	xfs_trans_ijoin(sc->tp, mp->m_rbmip, lockmode);

	return 0;
}

/* Realtime reverse mapping. */

/* Scrub a realtime rmapbt record. */
STATIC int
xfs_scrub_rtrmapbt_helper(
	struct xfs_scrub_btree		*bs,
	union xfs_btree_rec		*rec)
{
	struct xfs_mount		*mp = bs->cur->bc_mp;
	struct xfs_rmap_irec		irec;
	bool				non_inode;
	bool				is_bmbt;
	bool				is_attr;
	int				error;

	error = xfs_rmap_btrec_to_irec(bs->cur, rec, &irec);
	if (!xfs_scrub_btree_process_error(bs->sc, bs->cur, 0, &error))
		goto out;

	if (irec.rm_startblock + irec.rm_blockcount <= irec.rm_startblock ||
	    (!xfs_verify_rtbno(mp, irec.rm_startblock) ||
	     !xfs_verify_rtbno(mp, irec.rm_startblock +
				irec.rm_blockcount - 1)))
		xfs_scrub_btree_set_corrupt(bs->sc, bs->cur, 0);

	non_inode = XFS_RMAP_NON_INODE_OWNER(irec.rm_owner);
	is_bmbt = irec.rm_flags & XFS_RMAP_BMBT_BLOCK;
	is_attr = irec.rm_flags & XFS_RMAP_ATTR_FORK;

	if (is_bmbt || non_inode || is_attr)
		xfs_scrub_btree_set_corrupt(bs->sc, bs->cur, 0);

out:
	return error;
}

/* Scrub the realtime rmap btree. */
int
xfs_scrub_rtrmapbt(
	struct xfs_scrub_context	*sc)
{
	struct xfs_owner_info		oinfo;
	struct xfs_mount		*mp = sc->mp;
	struct xfs_btree_cur		*cur;
	int				error;

	cur = xfs_rtrmapbt_init_cursor(mp, sc->tp, mp->m_rrmapip);
	xfs_rmap_ino_bmbt_owner(&oinfo, mp->m_sb.sb_rrmapino, XFS_DATA_FORK);
	error = xfs_scrub_btree(sc, cur, xfs_scrub_rtrmapbt_helper,
			&oinfo, NULL);
	xfs_btree_del_cursor(cur, XFS_BTREE_ERROR);

	return error;
}
