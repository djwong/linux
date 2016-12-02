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
#include "xfs_ialloc.h"
#include "repair/common.h"
#include "repair/btree.h"

/* Reference count btree scrubber. */

struct xfs_scrub_refcountbt_fragment {
	struct xfs_rmap_irec		rm;
	struct list_head		list;
};

struct xfs_scrub_refcountbt_rmap_check_info {
	struct xfs_scrub_btree		*bs;
	xfs_nlink_t			nr;
	struct xfs_refcount_irec	rc;
	struct list_head		fragments;
};

/*
 * Decide if the given rmap is large enough that we can redeem it
 * towards refcount verification now, or if it's a fragment, in
 * which case we'll hang onto it in the hopes that we'll later
 * discover that we've collected exactly the correct number of
 * fragments as the refcountbt says we should have.
 */
STATIC int
xfs_scrub_refcountbt_rmap_check(
	struct xfs_btree_cur		*cur,
	struct xfs_rmap_irec		*rec,
	void				*priv)
{
	struct xfs_scrub_refcountbt_rmap_check_info	*rsrci = priv;
	struct xfs_scrub_refcountbt_fragment		*frag;
	xfs_agblock_t			rm_last;
	xfs_agblock_t			rc_last;

	rm_last = rec->rm_startblock + rec->rm_blockcount;
	rc_last = rsrci->rc.rc_startblock + rsrci->rc.rc_blockcount;
	XFS_SCRUB_BTREC_CHECK(rsrci->bs, rsrci->rc.rc_refcount != 1 ||
			rec->rm_owner == XFS_RMAP_OWN_COW);
	if (rec->rm_startblock <= rsrci->rc.rc_startblock && rm_last >= rc_last)
		rsrci->nr++;
	else {
		frag = kmem_zalloc(sizeof(struct xfs_scrub_refcountbt_fragment),
				KM_SLEEP);
		frag->rm = *rec;
		list_add_tail(&frag->list, &rsrci->fragments);
	}

	return 0;
}

/*
 * Given a bunch of rmap fragments, iterate through them, keeping
 * a running tally of the refcount.  If this ever deviates from
 * what we expect (which is the refcountbt's refcount minus the
 * number of extents that totally covered the refcountbt extent),
 * we have a refcountbt error.
 */
STATIC void
xfs_scrub_refcountbt_process_rmap_fragments(
	struct xfs_mount				*mp,
	struct xfs_scrub_refcountbt_rmap_check_info	*rsrci)
{
	struct list_head				worklist;
	struct xfs_scrub_refcountbt_fragment		*cur;
	struct xfs_scrub_refcountbt_fragment		*n;
	xfs_agblock_t					bno;
	xfs_agblock_t					rbno;
	xfs_agblock_t					next_rbno;
	xfs_nlink_t					nr;
	xfs_nlink_t					target_nr;

	target_nr = rsrci->rc.rc_refcount - rsrci->nr;
	if (target_nr == 0)
		return;

	/*
	 * There are (rsrci->rc.rc_refcount - rsrci->nr refcount)
	 * references we haven't found yet.  Pull that many off the
	 * fragment list and figure out where the smallest rmap ends
	 * (and therefore the next rmap should start).  All the rmaps
	 * we pull off should start at or before the beginning of the
	 * refcount record's range.
	 */
	INIT_LIST_HEAD(&worklist);
	rbno = NULLAGBLOCK;
	nr = 1;
	list_for_each_entry_safe(cur, n, &rsrci->fragments, list) {
		if (cur->rm.rm_startblock > rsrci->rc.rc_startblock)
			goto fail;
		bno = cur->rm.rm_startblock + cur->rm.rm_blockcount;
		if (rbno > bno)
			rbno = bno;
		list_del(&cur->list);
		list_add_tail(&cur->list, &worklist);
		if (nr == target_nr)
			break;
		nr++;
	}

	if (nr != target_nr)
		goto fail;

	while (!list_empty(&rsrci->fragments)) {
		/* Discard any fragments ending at rbno. */
		nr = 0;
		next_rbno = NULLAGBLOCK;
		list_for_each_entry_safe(cur, n, &worklist, list) {
			bno = cur->rm.rm_startblock + cur->rm.rm_blockcount;
			if (bno != rbno) {
				if (next_rbno > bno)
					next_rbno = bno;
				continue;
			}
			list_del(&cur->list);
			kmem_free(cur);
			nr++;
		}

		/* Empty list?  We're done. */
		if (list_empty(&rsrci->fragments))
			break;

		/* Try to add nr rmaps starting at rbno to the worklist. */
		list_for_each_entry_safe(cur, n, &rsrci->fragments, list) {
			bno = cur->rm.rm_startblock + cur->rm.rm_blockcount;
			if (cur->rm.rm_startblock != rbno)
				goto fail;
			list_del(&cur->list);
			list_add_tail(&cur->list, &worklist);
			if (next_rbno > bno)
				next_rbno = bno;
			nr--;
			if (nr == 0)
				break;
		}

		rbno = next_rbno;
	}

	/*
	 * Make sure the last extent we processed ends at or beyond
	 * the end of the refcount extent.
	 */
	if (rbno < rsrci->rc.rc_startblock + rsrci->rc.rc_blockcount)
		goto fail;

	rsrci->nr = rsrci->rc.rc_refcount;
fail:
	/* Delete fragments and work list. */
	list_for_each_entry_safe(cur, n, &worklist, list) {
		list_del(&cur->list);
		kmem_free(cur);
	}
	list_for_each_entry_safe(cur, n, &rsrci->fragments, list) {
		cur = list_first_entry(&rsrci->fragments,
				struct xfs_scrub_refcountbt_fragment, list);
		list_del(&cur->list);
		kmem_free(cur);
	}
}

/* Scrub a refcountbt record. */
STATIC int
xfs_scrub_refcountbt_helper(
	struct xfs_scrub_btree		*bs,
	union xfs_btree_rec		*rec)
{
	struct xfs_mount		*mp = bs->cur->bc_mp;
	struct xfs_agf			*agf;
	struct xfs_scrub_ag		*psa;
	struct xfs_refcount_irec	irec;
	struct xfs_rmap_irec		low;
	struct xfs_rmap_irec		high;
	struct xfs_scrub_refcountbt_rmap_check_info	rsrci;
	struct xfs_scrub_refcountbt_fragment		*cur;
	struct xfs_scrub_refcountbt_fragment		*n;
	xfs_agblock_t			eoag;
	bool				has_cowflag;
	bool				is_freesp;
	bool				has_inodes;
	int				error = 0;
	int				err2;

	irec.rc_startblock = be32_to_cpu(rec->refc.rc_startblock);
	irec.rc_blockcount = be32_to_cpu(rec->refc.rc_blockcount);
	irec.rc_refcount = be32_to_cpu(rec->refc.rc_refcount);
	agf = XFS_BUF_TO_AGF(bs->sc->sa.agf_bp);
	eoag = be32_to_cpu(agf->agf_length);

	has_cowflag = !!(irec.rc_startblock & XFS_REFC_COW_START);
	XFS_SCRUB_BTREC_CHECK(bs, (irec.rc_refcount == 1 && has_cowflag) ||
				  (irec.rc_refcount != 1 && !has_cowflag));
	irec.rc_startblock &= ~XFS_REFC_COW_START;
	XFS_SCRUB_BTREC_CHECK(bs, irec.rc_startblock < mp->m_sb.sb_agblocks);
	XFS_SCRUB_BTREC_CHECK(bs, irec.rc_startblock < eoag);
	XFS_SCRUB_BTREC_CHECK(bs, irec.rc_startblock < irec.rc_startblock +
			irec.rc_blockcount);
	XFS_SCRUB_BTREC_CHECK(bs, (unsigned long long)irec.rc_startblock +
			irec.rc_blockcount <= mp->m_sb.sb_agblocks);
	XFS_SCRUB_BTREC_CHECK(bs, (unsigned long long)irec.rc_startblock +
			irec.rc_blockcount <= eoag);
	XFS_SCRUB_BTREC_CHECK(bs, irec.rc_refcount >= 1);

	if (error)
		goto out;

	/* Make sure we don't cover the AG headers. */
	XFS_SCRUB_BTREC_CHECK(bs, !xfs_scrub_extent_covers_ag_head(mp,
			irec.rc_startblock, irec.rc_blockcount));

	psa = &bs->sc->sa;
	/* Cross-reference with the bnobt. */
	if (psa->bno_cur) {
		err2 = xfs_alloc_has_record(psa->bno_cur, irec.rc_startblock,
				irec.rc_blockcount, &is_freesp);
		if (xfs_scrub_btree_should_xref(bs, err2, &psa->bno_cur))
			XFS_SCRUB_BTREC_CHECK(bs, !is_freesp);
	}

	/* Cross-reference with inobt. */
	if (psa->ino_cur) {
		err2 = xfs_ialloc_has_inodes_at_extent(psa->ino_cur,
				irec.rc_startblock, irec.rc_blockcount,
				&has_inodes);
		if (xfs_scrub_btree_should_xref(bs, err2, &psa->ino_cur))
			XFS_SCRUB_BTREC_CHECK(bs, !has_inodes);
	}

	/* Cross-reference with finobt. */
	if (psa->fino_cur) {
		err2 = xfs_ialloc_has_inodes_at_extent(psa->fino_cur,
				irec.rc_startblock, irec.rc_blockcount,
				&has_inodes);
		if (xfs_scrub_btree_should_xref(bs, err2, &psa->fino_cur))
			XFS_SCRUB_BTREC_CHECK(bs, !has_inodes);
	}

	/* Cross-reference with the rmapbt to confirm the refcount. */
	if (psa->rmap_cur) {
		memset(&low, 0, sizeof(low));
		low.rm_startblock = irec.rc_startblock;
		memset(&high, 0xFF, sizeof(high));
		high.rm_startblock = irec.rc_startblock +
				irec.rc_blockcount - 1;

		rsrci.bs = bs;
		rsrci.nr = 0;
		rsrci.rc = irec;
		INIT_LIST_HEAD(&rsrci.fragments);
		err2 = xfs_rmap_query_range(psa->rmap_cur, &low, &high,
				&xfs_scrub_refcountbt_rmap_check, &rsrci);
		if (xfs_scrub_btree_should_xref(bs, err2, &psa->rmap_cur)) {
			xfs_scrub_refcountbt_process_rmap_fragments(mp, &rsrci);
			XFS_SCRUB_BTREC_CHECK(bs, irec.rc_refcount == rsrci.nr);
		}

		list_for_each_entry_safe(cur, n, &rsrci.fragments, list) {
			list_del(&cur->list);
			kmem_free(cur);
		}
	}

out:
	return error;
}

/* Scrub the refcount btree for some AG. */
int
xfs_scrub_refcountbt(
	struct xfs_scrub_context	*sc)
{
	struct xfs_owner_info		oinfo;

	xfs_rmap_ag_owner(&oinfo, XFS_RMAP_OWN_REFC);
	return xfs_scrub_btree(sc, sc->sa.refc_cur, xfs_scrub_refcountbt_helper,
			&oinfo, NULL);
}
