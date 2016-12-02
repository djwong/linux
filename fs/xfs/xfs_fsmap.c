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
#include "xfs_log_format.h"
#include "xfs_trans_resv.h"
#include "xfs_sb.h"
#include "xfs_mount.h"
#include "xfs_defer.h"
#include "xfs_inode.h"
#include "xfs_trans.h"
#include "xfs_error.h"
#include "xfs_btree.h"
#include "xfs_rmap_btree.h"
#include "xfs_trace.h"
#include "xfs_log.h"
#include "xfs_rmap.h"
#include "xfs_alloc.h"
#include "xfs_bit.h"
#include "xfs_fsmap.h"
#include "xfs_refcount.h"
#include "xfs_refcount_btree.h"

/* Convert an xfs_fsmap to an fsmap. */
void
xfs_fsmap_from_internal(
	struct fsmap		*dest,
	struct xfs_fsmap	*src)
{
	dest->fmr_device = src->fmr_device;
	dest->fmr_flags = src->fmr_flags;
	dest->fmr_physical = BBTOB(src->fmr_physical);
	dest->fmr_owner = src->fmr_owner;
	dest->fmr_offset = BBTOB(src->fmr_offset);
	dest->fmr_length = BBTOB(src->fmr_length);
	dest->fmr_reserved[0] = 0;
	dest->fmr_reserved[1] = 0;
	dest->fmr_reserved[2] = 0;
}

/* Convert an fsmap to an xfs_fsmap. */
void
xfs_fsmap_to_internal(
	struct xfs_fsmap	*dest,
	struct fsmap		*src)
{
	dest->fmr_device = src->fmr_device;
	dest->fmr_flags = src->fmr_flags;
	dest->fmr_physical = BTOBBT(src->fmr_physical);
	dest->fmr_owner = src->fmr_owner;
	dest->fmr_offset = BTOBBT(src->fmr_offset);
	dest->fmr_length = BTOBBT(src->fmr_length);
}

/* Convert an fsmap owner into an rmapbt owner. */
static int
xfs_fsmap_owner_to_rmap(
	struct xfs_fsmap	*fmr,
	struct xfs_rmap_irec	*rm)
{
	if (!(fmr->fmr_flags & FMR_OF_SPECIAL_OWNER)) {
		if (XFS_RMAP_NON_INODE_OWNER(fmr->fmr_owner))
			return -EINVAL;
		rm->rm_owner = fmr->fmr_owner;
		return 0;
	}

	switch (fmr->fmr_owner) {
	case 0:			/* "lowest owner id possible" */
	case FMR_OWN_FREE:
	case FMR_OWN_UNKNOWN:
	case FMR_OWN_FS:
	case FMR_OWN_LOG:
	case FMR_OWN_AG:
	case FMR_OWN_INOBT:
	case FMR_OWN_INODES:
	case FMR_OWN_REFC:
	case FMR_OWN_COW:
		rm->rm_owner = fmr->fmr_owner;
		return 0;
	case FMR_OWN_DEFECTIVE:
		/* fall through */
	default:
		return -EINVAL;
	}
}

/* Convert an rmapbt owner into an fsmap owner. */
static int
xfs_fsmap_owner_from_rmap(
	struct xfs_rmap_irec	*rm,
	struct xfs_fsmap	*fmr)
{
	fmr->fmr_flags = 0;
	if (!XFS_RMAP_NON_INODE_OWNER(rm->rm_owner)) {
		fmr->fmr_owner = rm->rm_owner;
		return 0;
	}
	fmr->fmr_flags |= FMR_OF_SPECIAL_OWNER;

	switch (rm->rm_owner) {
	case XFS_RMAP_OWN_FS:
	case XFS_RMAP_OWN_LOG:
	case XFS_RMAP_OWN_AG:
	case XFS_RMAP_OWN_INOBT:
	case XFS_RMAP_OWN_INODES:
	case XFS_RMAP_OWN_REFC:
	case XFS_RMAP_OWN_COW:
		fmr->fmr_owner = rm->rm_owner;
		return 0;
	default:
		return -EFSCORRUPTED;
	}
}

/* getfsmap query state */
struct xfs_getfsmap_info {
	struct xfs_fsmap_head	*head;
	struct xfs_fsmap	*rkey_low;	/* lowest key */
	xfs_fsmap_format_t	formatter;	/* formatting fn */
	void			*format_arg;	/* format buffer */
	bool			last;		/* last extent? */
	xfs_daddr_t		next_daddr;	/* next daddr we expect */
	u32			dev;		/* device id */
	u64			missing_owner;	/* owner of holes */

	xfs_agnumber_t		agno;		/* AG number, if applicable */
	struct xfs_buf		*agf_bp;	/* AGF, for refcount queries */
	struct xfs_rmap_irec	low;		/* low rmap key */
	struct xfs_rmap_irec	high;		/* high rmap key */
};

/* Associate a device with a getfsmap handler. */
struct xfs_getfsmap_dev {
	u32			dev;
	int			(*fn)(struct xfs_trans *tp,
				      struct xfs_fsmap *keys,
				      struct xfs_getfsmap_info *info);
};

/* Compare two getfsmap device handlers. */
static int
xfs_getfsmap_dev_compare(
	const void			*p1,
	const void			*p2)
{
	const struct xfs_getfsmap_dev	*d1 = p1;
	const struct xfs_getfsmap_dev	*d2 = p2;

	return d1->dev - d2->dev;
}

/* Compare a record against our starting point */
static bool
xfs_getfsmap_rec_before_low_key(
	struct xfs_getfsmap_info	*info,
	struct xfs_rmap_irec		*rec)
{
	uint64_t			x, y;

	if (rec->rm_startblock < info->low.rm_startblock)
		return true;
	if (rec->rm_startblock > info->low.rm_startblock)
		return false;

	if (rec->rm_owner < info->low.rm_owner)
		return true;
	if (rec->rm_owner > info->low.rm_owner)
		return false;

	x = xfs_rmap_irec_offset_pack(rec);
	y = xfs_rmap_irec_offset_pack(&info->low);
	if (x < y)
		return true;
	return false;
}

/* Decide if this mapping is shared. */
STATIC int
xfs_getfsmap_is_shared(
	struct xfs_mount		*mp,
	struct xfs_getfsmap_info	*info,
	struct xfs_rmap_irec		*rec,
	bool				*stat)
{
	struct xfs_btree_cur		*cur;
	xfs_agblock_t			fbno;
	xfs_extlen_t			flen;
	int				error;

	*stat = false;
	if (!xfs_sb_version_hasreflink(&mp->m_sb))
		return 0;
	/* rt files will have agno set to NULLAGNUMBER */
	if (info->agno == NULLAGNUMBER)
		return 0;

	/* Are there any shared blocks here? */
	flen = 0;
	cur = xfs_refcountbt_init_cursor(mp, NULL, info->agf_bp,
			info->agno, NULL);

	error = xfs_refcount_find_shared(cur, rec->rm_startblock,
			rec->rm_blockcount, &fbno, &flen, false);

	xfs_btree_del_cursor(cur, error ? XFS_BTREE_ERROR : XFS_BTREE_NOERROR);
	if (error)
		return error;

	*stat = flen > 0;
	return 0;
}

/*
 * Format a reverse mapping for getfsmap, having translated rm_startblock
 * into the appropriate daddr units.
 */
STATIC int
xfs_getfsmap_helper(
	struct xfs_mount		*mp,
	struct xfs_getfsmap_info	*info,
	struct xfs_rmap_irec		*rec,
	xfs_daddr_t			rec_daddr)
{
	struct xfs_fsmap		fmr;
	xfs_daddr_t			key_end;
	bool				shared;
	int				error;

	/*
	 * Filter out records that start before our startpoint, if the
	 * caller requested that.
	 */
	if (xfs_getfsmap_rec_before_low_key(info, rec)) {
		rec_daddr += XFS_FSB_TO_BB(mp, rec->rm_blockcount);
		if (info->next_daddr < rec_daddr)
			info->next_daddr = rec_daddr;
		return XFS_BTREE_QUERY_RANGE_CONTINUE;
	}

	/*
	 * If the caller passed in a length with the low record and
	 * the record represents a file data extent, we incremented
	 * the offset in the low key by the length in the hopes of
	 * finding reverse mappings for the physical blocks we just
	 * saw.  We did /not/ increment next_daddr by the length
	 * because the range query would not be able to find shared
	 * extents within the same physical block range.
	 *
	 * However, the extent we've been fed could have a startblock
	 * past the passed-in low record.  If this is the case,
	 * advance next_daddr to the end of the passed-in low record
	 * so we don't report the extent prior to this extent as
	 * free.
	 */
	key_end = info->rkey_low->fmr_physical + info->rkey_low->fmr_length;
	if (info->dev == info->rkey_low->fmr_device &&
	    info->next_daddr < key_end && rec_daddr >= key_end)
		info->next_daddr = key_end;

	/* Are we just counting mappings? */
	if (info->head->fmh_count == 0) {
		if (rec_daddr > info->next_daddr)
			info->head->fmh_entries++;

		if (info->last)
			return XFS_BTREE_QUERY_RANGE_CONTINUE;

		info->head->fmh_entries++;

		rec_daddr += XFS_FSB_TO_BB(mp, rec->rm_blockcount);
		if (info->next_daddr < rec_daddr)
			info->next_daddr = rec_daddr;
		return XFS_BTREE_QUERY_RANGE_CONTINUE;
	}

	/*
	 * If the record starts past the last physical block we saw,
	 * then we've found some free space.  Report that too.
	 */
	if (rec_daddr > info->next_daddr) {
		if (info->head->fmh_entries >= info->head->fmh_count)
			return XFS_BTREE_QUERY_RANGE_ABORT;

		trace_xfs_fsmap_mapping(mp, info->dev, info->agno,
				XFS_DADDR_TO_FSB(mp, info->next_daddr),
				XFS_DADDR_TO_FSB(mp, rec_daddr -
						info->next_daddr),
				info->missing_owner, 0);

		fmr.fmr_device = info->dev;
		fmr.fmr_physical = info->next_daddr;
		fmr.fmr_owner = info->missing_owner;
		fmr.fmr_offset = 0;
		fmr.fmr_length = rec_daddr - info->next_daddr;
		fmr.fmr_flags = FMR_OF_SPECIAL_OWNER;
		error = info->formatter(&fmr, info->format_arg);
		if (error)
			return error;
		info->head->fmh_entries++;
	}

	if (info->last)
		goto out;

	/* Fill out the extent we found */
	if (info->head->fmh_entries >= info->head->fmh_count)
		return XFS_BTREE_QUERY_RANGE_ABORT;

	trace_xfs_fsmap_mapping(mp, info->dev, info->agno,
			rec->rm_startblock, rec->rm_blockcount, rec->rm_owner,
			rec->rm_offset);

	fmr.fmr_device = info->dev;
	fmr.fmr_physical = rec_daddr;
	error = xfs_fsmap_owner_from_rmap(rec, &fmr);
	if (error)
		return error;
	fmr.fmr_offset = XFS_FSB_TO_BB(mp, rec->rm_offset);
	fmr.fmr_length = XFS_FSB_TO_BB(mp, rec->rm_blockcount);
	if (rec->rm_flags & XFS_RMAP_UNWRITTEN)
		fmr.fmr_flags |= FMR_OF_PREALLOC;
	if (rec->rm_flags & XFS_RMAP_ATTR_FORK)
		fmr.fmr_flags |= FMR_OF_ATTR_FORK;
	if (rec->rm_flags & XFS_RMAP_BMBT_BLOCK)
		fmr.fmr_flags |= FMR_OF_EXTENT_MAP;
	if (fmr.fmr_flags == 0) {
		error = xfs_getfsmap_is_shared(mp, info, rec, &shared);
		if (error)
			return error;
		if (shared)
			fmr.fmr_flags |= FMR_OF_SHARED;
	}
	error = info->formatter(&fmr, info->format_arg);
	if (error)
		return error;
	info->head->fmh_entries++;

out:
	rec_daddr += XFS_FSB_TO_BB(mp, rec->rm_blockcount);
	if (info->next_daddr < rec_daddr)
		info->next_daddr = rec_daddr;
	return XFS_BTREE_QUERY_RANGE_CONTINUE;
}

/* Transform a rmapbt irec into a fsmap */
STATIC int
xfs_getfsmap_datadev_helper(
	struct xfs_btree_cur		*cur,
	struct xfs_rmap_irec		*rec,
	void				*priv)
{
	struct xfs_mount		*mp = cur->bc_mp;
	struct xfs_getfsmap_info	*info = priv;
	xfs_fsblock_t			fsb;
	xfs_daddr_t			rec_daddr;

	fsb = XFS_AGB_TO_FSB(mp, cur->bc_private.a.agno, rec->rm_startblock);
	rec_daddr = XFS_FSB_TO_DADDR(mp, fsb);

	return xfs_getfsmap_helper(mp, info, rec, rec_daddr);
}

/* Transform a absolute-startblock rmap (rtdev, logdev) into a fsmap */
STATIC int
xfs_getfsmap_rtdev_helper(
	struct xfs_btree_cur		*cur,
	struct xfs_rmap_irec		*rec,
	void				*priv)
{
	struct xfs_mount		*mp = cur->bc_mp;
	struct xfs_getfsmap_info	*info = priv;
	xfs_daddr_t			rec_daddr;

	rec_daddr = XFS_FSB_TO_BB(mp, rec->rm_startblock);

	return xfs_getfsmap_helper(mp, info, rec, rec_daddr);
}

/* Set rmap flags based on the getfsmap flags */
static void
xfs_getfsmap_set_irec_flags(
	struct xfs_rmap_irec	*irec,
	struct xfs_fsmap	*fmr)
{
	irec->rm_flags = 0;
	if (fmr->fmr_flags & FMR_OF_ATTR_FORK)
		irec->rm_flags |= XFS_RMAP_ATTR_FORK;
	if (fmr->fmr_flags & FMR_OF_EXTENT_MAP)
		irec->rm_flags |= XFS_RMAP_BMBT_BLOCK;
	if (fmr->fmr_flags & FMR_OF_PREALLOC)
		irec->rm_flags |= XFS_RMAP_UNWRITTEN;
}

/* Execute a getfsmap query against the log device. */
STATIC int
xfs_getfsmap_logdev(
	struct xfs_trans		*tp,
	struct xfs_fsmap		*keys,
	struct xfs_getfsmap_info	*info)
{
	struct xfs_mount		*mp = tp->t_mountp;
	struct xfs_fsmap		*dkey_low = keys;
	struct xfs_btree_cur		cur;
	struct xfs_rmap_irec		rmap;
	int				error;

	/* Set up search keys */
	info->low.rm_startblock = XFS_BB_TO_FSBT(mp, dkey_low->fmr_physical);
	info->low.rm_offset = XFS_BB_TO_FSBT(mp, dkey_low->fmr_offset);
	error = xfs_fsmap_owner_to_rmap(keys, &info->low);
	if (error)
		return error;
	info->low.rm_blockcount = 0;
	xfs_getfsmap_set_irec_flags(&info->low, dkey_low);

	error = xfs_fsmap_owner_to_rmap(keys + 1, &info->high);
	if (error)
		return error;
	info->high.rm_startblock = -1U;
	info->high.rm_owner = ULLONG_MAX;
	info->high.rm_offset = ULLONG_MAX;
	info->high.rm_blockcount = 0;
	info->high.rm_flags = XFS_RMAP_KEY_FLAGS | XFS_RMAP_REC_FLAGS;
	info->missing_owner = FMR_OWN_FREE;

	trace_xfs_fsmap_low_key(mp, info->dev, info->agno,
			info->low.rm_startblock,
			info->low.rm_blockcount,
			info->low.rm_owner,
			info->low.rm_offset);

	trace_xfs_fsmap_high_key(mp, info->dev, info->agno,
			info->high.rm_startblock,
			info->high.rm_blockcount,
			info->high.rm_owner,
			info->high.rm_offset);


	if (dkey_low->fmr_physical > 0)
		return 0;

	rmap.rm_startblock = 0;
	rmap.rm_blockcount = mp->m_sb.sb_logblocks;
	rmap.rm_owner = XFS_RMAP_OWN_LOG;
	rmap.rm_offset = 0;
	rmap.rm_flags = 0;

	cur.bc_mp = mp;
	return xfs_getfsmap_rtdev_helper(&cur, &rmap, info);
}

/* Execute a getfsmap query against the regular data device. */
STATIC int
xfs_getfsmap_datadev(
	struct xfs_trans		*tp,
	struct xfs_fsmap		*keys,
	struct xfs_getfsmap_info	*info)
{
	struct xfs_mount		*mp = tp->t_mountp;
	struct xfs_btree_cur		*bt_cur = NULL;
	struct xfs_fsmap		*dkey_low;
	struct xfs_fsmap		*dkey_high;
	xfs_fsblock_t			start_fsb;
	xfs_fsblock_t			end_fsb;
	xfs_agnumber_t			start_ag;
	xfs_agnumber_t			end_ag;
	xfs_daddr_t			eofs;
	int				error = 0;

	dkey_low = keys;
	dkey_high = keys + 1;
	eofs = XFS_FSB_TO_BB(mp, mp->m_sb.sb_dblocks);
	if (dkey_low->fmr_physical >= eofs)
		return 0;
	if (dkey_high->fmr_physical >= eofs)
		dkey_high->fmr_physical = eofs - 1;
	start_fsb = XFS_DADDR_TO_FSB(mp, dkey_low->fmr_physical);
	end_fsb = XFS_DADDR_TO_FSB(mp, dkey_high->fmr_physical);

	/* Set up search keys */
	info->low.rm_startblock = XFS_FSB_TO_AGBNO(mp, start_fsb);
	info->low.rm_offset = XFS_BB_TO_FSBT(mp, dkey_low->fmr_offset);
	error = xfs_fsmap_owner_to_rmap(dkey_low, &info->low);
	if (error)
		return error;
	info->low.rm_blockcount = 0;
	xfs_getfsmap_set_irec_flags(&info->low, dkey_low);

	info->high.rm_startblock = -1U;
	info->high.rm_owner = ULLONG_MAX;
	info->high.rm_offset = ULLONG_MAX;
	info->high.rm_blockcount = 0;
	info->high.rm_flags = XFS_RMAP_KEY_FLAGS | XFS_RMAP_REC_FLAGS;
	info->missing_owner = FMR_OWN_FREE;

	start_ag = XFS_FSB_TO_AGNO(mp, start_fsb);
	end_ag = XFS_FSB_TO_AGNO(mp, end_fsb);

	/* Query each AG */
	for (info->agno = start_ag; info->agno <= end_ag; info->agno++) {
		if (info->agno == end_ag) {
			info->high.rm_startblock = XFS_FSB_TO_AGBNO(mp,
					end_fsb);
			info->high.rm_offset = XFS_BB_TO_FSBT(mp,
					dkey_high->fmr_offset);
			error = xfs_fsmap_owner_to_rmap(dkey_high, &info->high);
			if (error)
				goto err;
			xfs_getfsmap_set_irec_flags(&info->high, dkey_high);
		}

		if (bt_cur) {
			xfs_btree_del_cursor(bt_cur, XFS_BTREE_NOERROR);
			bt_cur = NULL;
			info->agf_bp = NULL;
		}

		error = xfs_alloc_read_agf(mp, tp, info->agno, 0,
				&info->agf_bp);
		if (error)
			goto err;

		trace_xfs_fsmap_low_key(mp, info->dev, info->agno,
				info->low.rm_startblock,
				info->low.rm_blockcount,
				info->low.rm_owner,
				info->low.rm_offset);

		trace_xfs_fsmap_high_key(mp, info->dev, info->agno,
				info->high.rm_startblock,
				info->high.rm_blockcount,
				info->high.rm_owner,
				info->high.rm_offset);

		bt_cur = xfs_rmapbt_init_cursor(mp, tp, info->agf_bp,
				info->agno);
		error = xfs_rmap_query_range(bt_cur, &info->low, &info->high,
				xfs_getfsmap_datadev_helper, info);
		if (error)
			goto err;

		if (info->agno == start_ag) {
			info->low.rm_startblock = 0;
			info->low.rm_owner = 0;
			info->low.rm_offset = 0;
			info->low.rm_flags = 0;
		}
	}

	/* Report any free space at the end of the AG */
	info->last = true;
	error = xfs_getfsmap_datadev_helper(bt_cur, &info->high, info);
	if (error)
		goto err;

err:
	if (bt_cur)
		xfs_btree_del_cursor(bt_cur, error < 0 ? XFS_BTREE_ERROR :
							 XFS_BTREE_NOERROR);
	if (info->agf_bp)
		info->agf_bp = NULL;

	return error;
}

/* Do we recognize the device? */
STATIC bool
xfs_getfsmap_is_valid_device(
	struct xfs_mount	*mp,
	struct xfs_fsmap	*fm)
{
	if (fm->fmr_device == 0 || fm->fmr_device == UINT_MAX ||
	    fm->fmr_device == new_encode_dev(mp->m_ddev_targp->bt_dev))
		return true;
	if (mp->m_logdev_targp &&
	    fm->fmr_device == new_encode_dev(mp->m_logdev_targp->bt_dev))
		return true;
	return false;
}

/* Ensure that the low key is less than the high key. */
STATIC bool
xfs_getfsmap_check_keys(
	struct xfs_fsmap		*low_key,
	struct xfs_fsmap		*high_key)
{
	if (low_key->fmr_device > high_key->fmr_device)
		return false;
	if (low_key->fmr_device < high_key->fmr_device)
		return true;

	if (low_key->fmr_physical > high_key->fmr_physical)
		return false;
	if (low_key->fmr_physical < high_key->fmr_physical)
		return true;

	if (low_key->fmr_owner > high_key->fmr_owner)
		return false;
	if (low_key->fmr_owner < high_key->fmr_owner)
		return true;

	if (low_key->fmr_offset > high_key->fmr_offset)
		return false;
	if (low_key->fmr_offset < high_key->fmr_offset)
		return true;

	return false;
}

#define XFS_GETFSMAP_DEVS	3
/*
 * Get filesystem's extents as described in head, and format for
 * output.  Calls formatter to fill the user's buffer until all
 * extents are mapped, until the passed-in head->fmh_count slots have
 * been filled, or until the formatter short-circuits the loop, if it
 * is tracking filled-in extents on its own.
 */
int
xfs_getfsmap(
	struct xfs_mount		*mp,
	struct xfs_fsmap_head		*head,
	xfs_fsmap_format_t		formatter,
	void				*arg)
{
	struct xfs_trans		*tp;
	struct xfs_fsmap		*rkey_low;	/* request keys */
	struct xfs_fsmap		*rkey_high;
	struct xfs_fsmap		dkeys[2];	/* per-dev keys */
	struct xfs_getfsmap_dev		handlers[XFS_GETFSMAP_DEVS];
	struct xfs_getfsmap_info	info = {0};
	int				i;
	int				error = 0;

	if (!xfs_sb_version_hasrmapbt(&mp->m_sb))
		return -EOPNOTSUPP;
	if (head->fmh_iflags & ~FMH_IF_VALID)
		return -EINVAL;
	rkey_low = head->fmh_keys;
	rkey_high = rkey_low + 1;
	if (!xfs_getfsmap_is_valid_device(mp, rkey_low) ||
	    !xfs_getfsmap_is_valid_device(mp, rkey_high))
		return -EINVAL;

	head->fmh_entries = 0;

	/* Set up our device handlers. */
	memset(handlers, 0, sizeof(handlers));
	handlers[0].dev = new_encode_dev(mp->m_ddev_targp->bt_dev);
	handlers[0].fn = xfs_getfsmap_datadev;
	if (mp->m_logdev_targp != mp->m_ddev_targp) {
		handlers[1].dev = new_encode_dev(mp->m_logdev_targp->bt_dev);
		handlers[1].fn = xfs_getfsmap_logdev;
	}

	xfs_sort(handlers, XFS_GETFSMAP_DEVS, sizeof(struct xfs_getfsmap_dev),
			xfs_getfsmap_dev_compare);

	/*
	 * Since we allow the user to copy the last mapping from a previous
	 * call into the low key slot, we have to advance the low key by
	 * whatever the reported length is.  If the offset field doesn't apply,
	 * move up the start block to the next extent and start over with the
	 * lowest owner/offset possible; otherwise it's file data, so move up
	 * the offset only.
	 */
	dkeys[0] = *rkey_low;
	if (dkeys[0].fmr_flags & (FMR_OF_SPECIAL_OWNER | FMR_OF_EXTENT_MAP)) {
		dkeys[0].fmr_physical += dkeys[0].fmr_length;
		dkeys[0].fmr_owner = 0;
		dkeys[0].fmr_offset = 0;
	} else
		dkeys[0].fmr_offset += dkeys[0].fmr_length;
	memset(&dkeys[1], 0xFF, sizeof(struct xfs_fsmap));

	if (!xfs_getfsmap_check_keys(dkeys, rkey_high))
		return -EINVAL;

	info.rkey_low = rkey_low;
	info.formatter = formatter;
	info.format_arg = arg;
	info.head = head;

	/* For each device we support... */
	for (i = 0; i < XFS_GETFSMAP_DEVS; i++) {
		/* Is this device within the range the user asked for? */
		if (!handlers[i].fn)
			continue;
		if (rkey_low->fmr_device > handlers[i].dev)
			continue;
		if (rkey_high->fmr_device < handlers[i].dev)
			break;

		/*
		 * If this device number matches the high key, we have
		 * to pass the high key to the handler to limit the
		 * query results.  If the device number exceeds the
		 * low key, zero out the low key so that we get
		 * everything from the beginning.
		 */
		if (handlers[i].dev == rkey_high->fmr_device)
			dkeys[1] = *rkey_high;
		if (handlers[i].dev > rkey_low->fmr_device)
			memset(&dkeys[0], 0, sizeof(struct xfs_fsmap));

		error = xfs_trans_alloc_empty(mp, &tp);
		if (error)
			break;

		info.next_daddr = dkeys[0].fmr_physical;
		info.dev = handlers[i].dev;
		info.last = false;
		info.agno = NULLAGNUMBER;
		error = handlers[i].fn(tp, dkeys, &info);
		if (error)
			break;
		xfs_trans_cancel(tp);
		tp = NULL;
	}

	if (tp)
		xfs_trans_cancel(tp);
	head->fmh_oflags = FMH_OF_DEV_T;
	return error;
}
