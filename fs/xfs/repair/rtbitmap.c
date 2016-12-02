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
#include "xfs_alloc.h"
#include "xfs_rtalloc.h"
#include "repair/common.h"

/* Realtime bitmap. */

#define XFS_SCRUB_RTBITMAP_CHECK(fs_ok) \
	XFS_SCRUB_CHECK(sc, bp, "rtbitmap", fs_ok);
#define XFS_SCRUB_RTBITMAP_OP_ERROR_GOTO(error, label) \
	XFS_SCRUB_OP_ERROR_GOTO(sc, 0, 0, "rtbitmap", error, label)
/* Scrub the realtime bitmap. */
int
xfs_scrub_rtbitmap(
	struct xfs_scrub_context	*sc)
{
	struct xfs_mount		*mp = sc->tp->t_mountp;
	struct xfs_buf			*bp = NULL;
	xfs_rtblock_t			rtstart;
	xfs_rtblock_t			rtend;
	xfs_rtblock_t			block;
	xfs_rtblock_t			rem;
	int				is_free;
	int				error = 0;
	int				err2 = 0;

	/* Iterate the bitmap, looking for discrepancies. */
	rtstart = 0;
	rem = mp->m_sb.sb_rblocks;
	while (rem) {
		if (xfs_scrub_should_terminate(&error))
			break;

		/* Is the first block free? */
		err2 = xfs_rtcheck_range(mp, sc->tp, rtstart, 1, 1, &rtend,
				&is_free);
		XFS_SCRUB_RTBITMAP_OP_ERROR_GOTO(&err2, out);

		/* How long does the extent go for? */
		err2 = xfs_rtfind_forw(mp, sc->tp, rtstart,
				mp->m_sb.sb_rblocks - 1, &rtend);
		XFS_SCRUB_RTBITMAP_OP_ERROR_GOTO(&err2, out);

		/* Find the buffer for error reporting. */
		block = XFS_BITTOBLOCK(mp, rtstart);
		err2 = xfs_rtbuf_get(mp, sc->tp, block, 0, &bp);
		XFS_SCRUB_RTBITMAP_OP_ERROR_GOTO(&err2, out);
		XFS_SCRUB_RTBITMAP_CHECK(rtend >= rtstart);

		xfs_trans_brelse(sc->tp, bp);
		bp = NULL;
		rem -= rtend - rtstart + 1;
		rtstart = rtend + 1;
	}

out:
	if (bp)
		xfs_trans_brelse(sc->tp, bp);
	if (!error && err2)
		error = err2;
	return error;
}
#undef XFS_SCRUB_RTBITMAP_OP_ERROR_GOTO
#undef XFS_SCRUB_RTBITMAP_CHECK

/* Scrub the realtime summary. */
int
xfs_scrub_rtsummary(
	struct xfs_scrub_context	*sc)
{
	/* XXX: implement this some day */
	return -ENOENT;
}
