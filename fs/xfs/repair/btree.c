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
#include "xfs_alloc.h"
#include "repair/common.h"
#include "repair/btree.h"

/* btree scrubbing */

const char * const btree_types[] = {
	[XFS_BTNUM_BNO]		= "bnobt",
	[XFS_BTNUM_CNT]		= "cntbt",
	[XFS_BTNUM_RMAP]	= "rmapbt",
	[XFS_BTNUM_BMAP]	= "bmapbt",
	[XFS_BTNUM_INO]		= "inobt",
	[XFS_BTNUM_FINO]	= "finobt",
	[XFS_BTNUM_REFC]	= "refcountbt",
};

/* Format the trace parameters for the tree cursor. */
static inline void
xfs_scrub_btree_format(
	struct xfs_btree_cur		*cur,
	int				level,
	char				*bt_type,
	size_t				type_len,
	char				*bt_ptr,
	size_t				ptr_len,
	xfs_fsblock_t			*fsbno)
{
	char				*type = NULL;
	struct xfs_btree_block		*block;
	struct xfs_buf			*bp;

	switch (cur->bc_btnum) {
	case XFS_BTNUM_BMAP:
		switch (cur->bc_private.b.whichfork) {
		case XFS_DATA_FORK:
			type = "data";
			break;
		case XFS_ATTR_FORK:
			type = "attr";
			break;
		case XFS_COW_FORK:
			type = "CoW";
			break;
		}
		snprintf(bt_type, type_len, "inode %llu %s fork",
				(unsigned long long)cur->bc_private.b.ip->i_ino,
				type);
		break;
	default:
		strncpy(bt_type, btree_types[cur->bc_btnum], type_len);
		break;
	}

	if (level < cur->bc_nlevels && cur->bc_ptrs[level] >= 1) {
		block = xfs_btree_get_block(cur, level, &bp);
		snprintf(bt_ptr, ptr_len, " %s %d/%d",
				level == 0 ? "rec" : "ptr",
				cur->bc_ptrs[level],
				be16_to_cpu(block->bb_numrecs));
	} else
		bt_ptr[0] = 0;

	if (level < cur->bc_nlevels && cur->bc_bufs[level])
		*fsbno = XFS_DADDR_TO_FSB(cur->bc_mp,
				cur->bc_bufs[level]->b_bn);
	else if (cur->bc_flags & XFS_BTREE_LONG_PTRS)
		*fsbno = XFS_INO_TO_FSB(cur->bc_mp,
				cur->bc_private.b.ip->i_ino);
	else
		*fsbno = XFS_AGB_TO_FSB(cur->bc_mp, cur->bc_private.a.agno, 0);
}

/* Check for btree corruption. */
bool
xfs_scrub_btree_ok(
	struct xfs_scrub_context	*sc,
	struct xfs_btree_cur		*cur,
	int				level,
	bool				fs_ok,
	const char			*check,
	const char			*func,
	int				line)
{
	char				bt_ptr[24];
	char				bt_type[48];
	xfs_fsblock_t			fsbno;

	if (fs_ok)
		return fs_ok;

	sc->sm->sm_flags |= XFS_SCRUB_FLAG_CORRUPT;
	xfs_scrub_btree_format(cur, level, bt_type, 48, bt_ptr, 24, &fsbno);

	trace_xfs_scrub_btree_error(cur->bc_mp, bt_type, bt_ptr,
			XFS_FSB_TO_AGNO(cur->bc_mp, fsbno),
			XFS_FSB_TO_AGBNO(cur->bc_mp, fsbno),
			check, func, line);
	return fs_ok;
}

/* Check for btree operation errors . */
bool
xfs_scrub_btree_op_ok(
	struct xfs_scrub_context	*sc,
	struct xfs_btree_cur		*cur,
	int				level,
	int				*error,
	const char			*func,
	int				line)
{
	char				bt_ptr[24];
	char				bt_type[48];
	xfs_fsblock_t			fsbno;

	if (*error == 0)
		return true;

	xfs_scrub_btree_format(cur, level, bt_type, 48, bt_ptr, 24, &fsbno);

	return xfs_scrub_op_ok(sc,
			XFS_FSB_TO_AGNO(cur->bc_mp, fsbno),
			XFS_FSB_TO_AGBNO(cur->bc_mp, fsbno),
			bt_type, error, func, line);
}

/*
 * Make sure this record is in order and doesn't stray outside of the parent
 * keys.
 */
STATIC int
xfs_scrub_btree_rec(
	struct xfs_scrub_btree	*bs)
{
	struct xfs_btree_cur	*cur = bs->cur;
	union xfs_btree_rec	*rec;
	union xfs_btree_key	key;
	union xfs_btree_key	hkey;
	union xfs_btree_key	*keyp;
	struct xfs_btree_block	*block;
	struct xfs_btree_block	*keyblock;
	struct xfs_buf		*bp;

	block = xfs_btree_get_block(cur, 0, &bp);
	rec = xfs_btree_rec_addr(cur, cur->bc_ptrs[0], block);

	if (bp)
		trace_xfs_scrub_btree_rec(cur->bc_mp,
				XFS_FSB_TO_AGNO(cur->bc_mp,
					XFS_DADDR_TO_FSB(cur->bc_mp, bp->b_bn)),
				XFS_FSB_TO_AGBNO(cur->bc_mp,
					XFS_DADDR_TO_FSB(cur->bc_mp, bp->b_bn)),
				cur->bc_btnum, 0, cur->bc_nlevels,
				cur->bc_ptrs[0]);
	else if (cur->bc_flags & XFS_BTREE_ROOT_IN_INODE)
		trace_xfs_scrub_btree_rec(cur->bc_mp,
				XFS_INO_TO_AGNO(cur->bc_mp,
					cur->bc_private.b.ip->i_ino),
				XFS_INO_TO_AGBNO(cur->bc_mp,
					cur->bc_private.b.ip->i_ino),
				cur->bc_btnum, 0, cur->bc_nlevels,
				cur->bc_ptrs[0]);
	else
		trace_xfs_scrub_btree_rec(cur->bc_mp,
				NULLAGNUMBER, NULLAGBLOCK,
				cur->bc_btnum, 0, cur->bc_nlevels,
				cur->bc_ptrs[0]);

	/* If this isn't the first record, are they in order? */
	XFS_SCRUB_BTREC_CHECK(bs, bs->firstrec ||
			cur->bc_ops->recs_inorder(cur, &bs->lastrec, rec));
	bs->firstrec = false;
	bs->lastrec = *rec;

	if (cur->bc_nlevels == 1)
		return 0;

	/* Is this at least as large as the parent low key? */
	cur->bc_ops->init_key_from_rec(&key, rec);
	keyblock = xfs_btree_get_block(cur, 1, &bp);
	keyp = xfs_btree_key_addr(cur, cur->bc_ptrs[1], keyblock);
	XFS_SCRUB_BTKEY_CHECK(bs, 1,
			cur->bc_ops->diff_two_keys(cur, &key, keyp) >= 0);

	if (!(cur->bc_flags & XFS_BTREE_OVERLAPPING))
		return 0;

	/* Is this no larger than the parent high key? */
	cur->bc_ops->init_high_key_from_rec(&hkey, rec);
	keyp = xfs_btree_high_key_addr(cur, cur->bc_ptrs[1], keyblock);
	XFS_SCRUB_BTKEY_CHECK(bs, 1,
			cur->bc_ops->diff_two_keys(cur, keyp, &hkey) >= 0);

	return 0;
}

/*
 * Make sure this key is in order and doesn't stray outside of the parent
 * keys.
 */
STATIC int
xfs_scrub_btree_key(
	struct xfs_scrub_btree	*bs,
	int			level)
{
	struct xfs_btree_cur	*cur = bs->cur;
	union xfs_btree_key	*key;
	union xfs_btree_key	*keyp;
	struct xfs_btree_block	*block;
	struct xfs_btree_block	*keyblock;
	struct xfs_buf		*bp;

	block = xfs_btree_get_block(cur, level, &bp);
	key = xfs_btree_key_addr(cur, cur->bc_ptrs[level], block);

	if (bp)
		trace_xfs_scrub_btree_key(cur->bc_mp,
				XFS_FSB_TO_AGNO(cur->bc_mp,
					XFS_DADDR_TO_FSB(cur->bc_mp, bp->b_bn)),
				XFS_FSB_TO_AGBNO(cur->bc_mp,
					XFS_DADDR_TO_FSB(cur->bc_mp, bp->b_bn)),
				cur->bc_btnum, level, cur->bc_nlevels,
				cur->bc_ptrs[level]);
	else if (cur->bc_flags & XFS_BTREE_ROOT_IN_INODE)
		trace_xfs_scrub_btree_key(cur->bc_mp,
				XFS_INO_TO_AGNO(cur->bc_mp,
					cur->bc_private.b.ip->i_ino),
				XFS_INO_TO_AGBNO(cur->bc_mp,
					cur->bc_private.b.ip->i_ino),
				cur->bc_btnum, level, cur->bc_nlevels,
				cur->bc_ptrs[level]);
	else
		trace_xfs_scrub_btree_key(cur->bc_mp,
				NULLAGNUMBER, NULLAGBLOCK,
				cur->bc_btnum, level, cur->bc_nlevels,
				cur->bc_ptrs[level]);

	/* If this isn't the first key, are they in order? */
	XFS_SCRUB_BTKEY_CHECK(bs, level, bs->firstkey[level] ||
			cur->bc_ops->keys_inorder(cur, &bs->lastkey[level],
					key));
	bs->firstkey[level] = false;
	bs->lastkey[level] = *key;

	if (level + 1 >= cur->bc_nlevels)
		return 0;

	/* Is this at least as large as the parent low key? */
	keyblock = xfs_btree_get_block(cur, level + 1, &bp);
	keyp = xfs_btree_key_addr(cur, cur->bc_ptrs[level + 1], keyblock);
	XFS_SCRUB_BTKEY_CHECK(bs, level,
			cur->bc_ops->diff_two_keys(cur, key, keyp) >= 0);

	if (!(cur->bc_flags & XFS_BTREE_OVERLAPPING))
		return 0;

	/* Is this no larger than the parent high key? */
	key = xfs_btree_high_key_addr(cur, cur->bc_ptrs[level], block);
	keyp = xfs_btree_high_key_addr(cur, cur->bc_ptrs[level + 1], keyblock);
	XFS_SCRUB_BTKEY_CHECK(bs, level,
			cur->bc_ops->diff_two_keys(cur, keyp, key) >= 0);

	return 0;
}

/* Check a btree pointer. */
static int
xfs_scrub_btree_ptr(
	struct xfs_scrub_btree		*bs,
	int				level,
	union xfs_btree_ptr		*ptr)
{
	struct xfs_btree_cur		*cur = bs->cur;
	xfs_daddr_t			daddr;
	xfs_daddr_t			eofs;

	if ((cur->bc_flags & XFS_BTREE_ROOT_IN_INODE) &&
			level == cur->bc_nlevels) {
		if (cur->bc_flags & XFS_BTREE_LONG_PTRS) {
			XFS_SCRUB_BTKEY_GOTO(bs, level, ptr->l == 0, corrupt);
		} else {
			XFS_SCRUB_BTKEY_GOTO(bs, level, ptr->s == 0, corrupt);
		}
		return 0;
	}

	if (cur->bc_flags & XFS_BTREE_LONG_PTRS) {
		XFS_SCRUB_BTKEY_GOTO(bs, level,
				ptr->l != cpu_to_be64(NULLFSBLOCK), corrupt);

		daddr = XFS_FSB_TO_DADDR(cur->bc_mp, be64_to_cpu(ptr->l));
	} else {
		XFS_SCRUB_BTKEY_GOTO(bs, level,
				cur->bc_private.a.agno != NULLAGNUMBER, corrupt);
		XFS_SCRUB_BTKEY_GOTO(bs, level,
				ptr->s != cpu_to_be32(NULLAGBLOCK), corrupt);

		daddr = XFS_AGB_TO_DADDR(cur->bc_mp, cur->bc_private.a.agno,
				be32_to_cpu(ptr->s));
	}
	eofs = XFS_FSB_TO_BB(cur->bc_mp, cur->bc_mp->m_sb.sb_dblocks);
	XFS_SCRUB_BTKEY_GOTO(bs, level, daddr != 0, corrupt);
	XFS_SCRUB_BTKEY_GOTO(bs, level, daddr < eofs, corrupt);

	return 0;

corrupt:
	return -EFSCORRUPTED;
}

/* Check the siblings of a large format btree block. */
STATIC int
xfs_scrub_btree_lblock_check_siblings(
	struct xfs_scrub_btree		*bs,
	struct xfs_btree_block		*block)
{
	struct xfs_btree_block		*pblock;
	struct xfs_buf			*pbp;
	struct xfs_btree_cur		*ncur = NULL;
	union xfs_btree_ptr		*pp;
	xfs_fsblock_t			leftsib;
	xfs_fsblock_t			rightsib;
	xfs_fsblock_t			fsbno;
	int				level;
	int				success;
	int				error = 0;

	leftsib = be64_to_cpu(block->bb_u.l.bb_leftsib);
	rightsib = be64_to_cpu(block->bb_u.l.bb_rightsib);
	level = xfs_btree_get_level(block);

	/* Root block should never have siblings. */
	if (level == bs->cur->bc_nlevels - 1) {
		XFS_SCRUB_BTKEY_CHECK(bs, level, leftsib == NULLFSBLOCK);
		XFS_SCRUB_BTKEY_CHECK(bs, level, rightsib == NULLFSBLOCK);
		return error;
	}

	/* Does the left sibling match the parent level left block? */
	if (leftsib != NULLFSBLOCK) {
		error = xfs_btree_dup_cursor(bs->cur, &ncur);
		if (error)
			return error;
		error = xfs_btree_decrement(ncur, level + 1, &success);
		XFS_SCRUB_BTKEY_OP_ERROR_GOTO(bs, level + 1, &error, out_cur);
		XFS_SCRUB_BTKEY_GOTO(bs, level, success, out_cur);

		pblock = xfs_btree_get_block(ncur, level + 1, &pbp);
		pp = xfs_btree_ptr_addr(ncur, ncur->bc_ptrs[level + 1], pblock);
		if (!xfs_scrub_btree_ptr(bs, level + 1, pp)) {
			fsbno = be64_to_cpu(pp->l);
			XFS_SCRUB_BTKEY_CHECK(bs, level, fsbno == leftsib);
		}

		xfs_btree_del_cursor(ncur, XFS_BTREE_ERROR);
		ncur = NULL;
	}

	/* Does the right sibling match the parent level right block? */
	if (!error && rightsib != NULLFSBLOCK) {
		error = xfs_btree_dup_cursor(bs->cur, &ncur);
		if (error)
			return error;
		error = xfs_btree_increment(ncur, level + 1, &success);
		XFS_SCRUB_BTKEY_OP_ERROR_GOTO(bs, level + 1, &error, out_cur);
		XFS_SCRUB_BTKEY_GOTO(bs, level, success, out_cur);

		pblock = xfs_btree_get_block(ncur, level + 1, &pbp);
		pp = xfs_btree_ptr_addr(ncur, ncur->bc_ptrs[level + 1], pblock);
		if (!xfs_scrub_btree_ptr(bs, level + 1, pp)) {
			fsbno = be64_to_cpu(pp->l);
			XFS_SCRUB_BTKEY_CHECK(bs, level, fsbno == rightsib);
		}

		xfs_btree_del_cursor(ncur, XFS_BTREE_ERROR);
		ncur = NULL;
	}

out_cur:
	if (ncur)
		xfs_btree_del_cursor(ncur, XFS_BTREE_ERROR);
	return error;
}

/* Check the siblings of a small format btree block. */
STATIC int
xfs_scrub_btree_sblock_check_siblings(
	struct xfs_scrub_btree		*bs,
	struct xfs_btree_block		*block)
{
	struct xfs_btree_block		*pblock;
	struct xfs_buf			*pbp;
	struct xfs_btree_cur		*ncur = NULL;
	union xfs_btree_ptr		*pp;
	xfs_agblock_t			leftsib;
	xfs_agblock_t			rightsib;
	xfs_agblock_t			agbno;
	int				level;
	int				success;
	int				error = 0;

	leftsib = be32_to_cpu(block->bb_u.s.bb_leftsib);
	rightsib = be32_to_cpu(block->bb_u.s.bb_rightsib);
	level = xfs_btree_get_level(block);

	/* Root block should never have siblings. */
	if (level == bs->cur->bc_nlevels - 1) {
		XFS_SCRUB_BTKEY_CHECK(bs, level, leftsib == NULLAGBLOCK);
		XFS_SCRUB_BTKEY_CHECK(bs, level, rightsib == NULLAGBLOCK);
		return error;
	}

	/* Does the left sibling match the parent level left block? */
	if (leftsib != NULLAGBLOCK) {
		error = xfs_btree_dup_cursor(bs->cur, &ncur);
		if (error)
			return error;
		error = xfs_btree_decrement(ncur, level + 1, &success);
		XFS_SCRUB_BTKEY_OP_ERROR_GOTO(bs, level + 1, &error, out_cur);
		XFS_SCRUB_BTKEY_GOTO(bs, level, success, verify_rightsib);

		pblock = xfs_btree_get_block(ncur, level + 1, &pbp);
		pp = xfs_btree_ptr_addr(ncur, ncur->bc_ptrs[level + 1], pblock);
		if (!xfs_scrub_btree_ptr(bs, level + 1, pp)) {
			agbno = be32_to_cpu(pp->s);
			XFS_SCRUB_BTKEY_CHECK(bs, level, agbno == leftsib);
		}

		xfs_btree_del_cursor(ncur, XFS_BTREE_ERROR);
		ncur = NULL;
	}

verify_rightsib:
	if (ncur) {
		xfs_btree_del_cursor(ncur, XFS_BTREE_ERROR);
		ncur = NULL;
	}

	/* Does the right sibling match the parent level right block? */
	if (rightsib != NULLAGBLOCK) {
		error = xfs_btree_dup_cursor(bs->cur, &ncur);
		if (error)
			return error;
		error = xfs_btree_increment(ncur, level + 1, &success);
		XFS_SCRUB_BTKEY_OP_ERROR_GOTO(bs, level + 1, &error, out_cur);
		XFS_SCRUB_BTKEY_GOTO(bs, level, success, out_cur);

		pblock = xfs_btree_get_block(ncur, level + 1, &pbp);
		pp = xfs_btree_ptr_addr(ncur, ncur->bc_ptrs[level + 1], pblock);
		if (!xfs_scrub_btree_ptr(bs, level + 1, pp)) {
			agbno = be32_to_cpu(pp->s);
			XFS_SCRUB_BTKEY_CHECK(bs, level, agbno == rightsib);
		}

		xfs_btree_del_cursor(ncur, XFS_BTREE_ERROR);
		ncur = NULL;
	}

out_cur:
	if (ncur)
		xfs_btree_del_cursor(ncur, XFS_BTREE_ERROR);
	return error;
}

struct check_owner {
	struct list_head	list;
	xfs_fsblock_t		fsb;
};

/*
 * Make sure this btree block isn't in the free list and that there's
 * an rmap record for it.
 */
STATIC int
xfs_scrub_btree_check_block_owner(
	struct xfs_scrub_btree		*bs,
	xfs_fsblock_t			fsb)
{
	struct xfs_scrub_ag		sa;
	struct xfs_scrub_ag		*psa;
	xfs_agnumber_t			agno;
	xfs_agblock_t			bno;
	bool				is_freesp;
	int				error = 0;
	int				err2;

	agno = XFS_FSB_TO_AGNO(bs->cur->bc_mp, fsb);
	bno = XFS_FSB_TO_AGBNO(bs->cur->bc_mp, fsb);

	if (bs->cur->bc_flags & XFS_BTREE_LONG_PTRS) {
		if (!xfs_scrub_ag_can_lock(bs->sc, agno))
			return -EDEADLOCK;
		error = xfs_scrub_ag_init(bs->sc, agno, &sa);
		if (error)
			return error;
		psa = &sa;
	} else
		psa = &bs->sc->sa;

	/* Check that this block isn't free. */
	if (psa->bno_cur) {
		err2 = xfs_alloc_has_record(psa->bno_cur, bno, 1, &is_freesp);
		if (xfs_scrub_btree_should_xref(bs, err2, NULL))
			XFS_SCRUB_BTREC_CHECK(bs, !is_freesp);
	}

	if (bs->cur->bc_flags & XFS_BTREE_LONG_PTRS)
		xfs_scrub_ag_free(&sa);

	return error;
}

/* Check the owner of a btree block. */
STATIC int
xfs_scrub_btree_check_owner(
	struct xfs_scrub_btree		*bs,
	struct xfs_buf			*bp)
{
	struct xfs_btree_cur		*cur = bs->cur;
	struct check_owner		*co;
	xfs_fsblock_t			fsbno;
	xfs_agnumber_t			agno;

	if ((cur->bc_flags & XFS_BTREE_ROOT_IN_INODE) && bp == NULL)
		return 0;

	fsbno = XFS_DADDR_TO_FSB(cur->bc_mp, bp->b_bn);
	agno = XFS_FSB_TO_AGNO(cur->bc_mp, fsbno);

	/* Turn back if we could deadlock. */
	if ((bs->cur->bc_flags & XFS_BTREE_LONG_PTRS) &&
	    !xfs_scrub_ag_can_lock(bs->sc, agno))
		return -EDEADLOCK;

	/*
	 * We want to cross-reference each btree block with the bnobt
	 * and the rmapbt.  We cannot cross-reference the bnobt or
	 * rmapbt while scanning the bnobt or rmapbt, respectively,
	 * because that would trash the cursor state.  Therefore, save
	 * the block numbers for later scanning.
	 */
	if (cur->bc_btnum == XFS_BTNUM_BNO || cur->bc_btnum == XFS_BTNUM_RMAP) {
		co = kmem_alloc(sizeof(struct check_owner), KM_SLEEP | KM_NOFS);
		co->fsb = fsbno;
		list_add_tail(&co->list, &bs->to_check);
		return 0;
	}

	return xfs_scrub_btree_check_block_owner(bs, fsbno);
}

/* Grab and scrub a btree block. */
STATIC int
xfs_scrub_btree_block(
	struct xfs_scrub_btree		*bs,
	int				level,
	union xfs_btree_ptr		*pp,
	struct xfs_btree_block		**pblock,
	struct xfs_buf			**pbp)
{
	int				error;

	error = xfs_btree_lookup_get_block(bs->cur, level, pp, pblock);
	if (error)
		return error;

	xfs_btree_get_block(bs->cur, level, pbp);
	error = xfs_btree_check_block(bs->cur, *pblock, level, *pbp);
	if (error)
		return error;

	error = xfs_scrub_btree_check_owner(bs, *pbp);
	if (error)
		return error;

	return bs->check_siblings_fn(bs, *pblock);
}

/*
 * Visit all nodes and leaves of a btree.  Check that all pointers and
 * records are in order, that the keys reflect the records, and use a callback
 * so that the caller can verify individual records.  The callback is the same
 * as the one for xfs_btree_query_range, so therefore this function also
 * returns XFS_BTREE_QUERY_RANGE_ABORT, zero, or a negative error code.
 */
int
xfs_scrub_btree(
	struct xfs_scrub_context	*sc,
	struct xfs_btree_cur		*cur,
	xfs_scrub_btree_rec_fn		scrub_fn,
	struct xfs_owner_info		*oinfo,
	void				*private)
{
	struct xfs_scrub_btree		bs = {0};
	union xfs_btree_ptr		ptr;
	union xfs_btree_ptr		*pp;
	union xfs_btree_rec		*recp;
	struct xfs_btree_block		*block;
	int				level;
	struct xfs_buf			*bp;
	struct check_owner		*co;
	struct check_owner		*n;
	int				i;
	int				error = 0;

	/* Finish filling out the scrub state */
	bs.cur = cur;
	bs.scrub_rec = scrub_fn;
	bs.oinfo = oinfo;
	bs.firstrec = true;
	bs.private = private;
	bs.sc = sc;
	for (i = 0; i < XFS_BTREE_MAXLEVELS; i++)
		bs.firstkey[i] = true;
	INIT_LIST_HEAD(&bs.to_check);

	if (cur->bc_flags & XFS_BTREE_LONG_PTRS)
		bs.check_siblings_fn = xfs_scrub_btree_lblock_check_siblings;
	else
		bs.check_siblings_fn = xfs_scrub_btree_sblock_check_siblings;

	/* Don't try to check a tree with a height we can't handle. */
	XFS_SCRUB_BTREC_GOTO(&bs, cur->bc_nlevels > 0, out_badcursor);
	XFS_SCRUB_BTREC_GOTO(&bs, cur->bc_nlevels <= XFS_BTREE_MAXLEVELS,
			out_badcursor);

	/* Make sure the root isn't in the superblock. */
	cur->bc_ops->init_ptr_from_cur(cur, &ptr);
	error = xfs_scrub_btree_ptr(&bs, cur->bc_nlevels, &ptr);
	XFS_SCRUB_BTKEY_OP_ERROR_GOTO(&bs, cur->bc_nlevels, &error,
			out_badcursor);

	/* Load the root of the btree. */
	level = cur->bc_nlevels - 1;
	cur->bc_ops->init_ptr_from_cur(cur, &ptr);
	error = xfs_scrub_btree_block(&bs, level, &ptr, &block, &bp);
	XFS_SCRUB_BTKEY_OP_ERROR_GOTO(&bs, level, &error, out);

	cur->bc_ptrs[level] = 1;

	while (level < cur->bc_nlevels) {
		block = xfs_btree_get_block(cur, level, &bp);

		if (level == 0) {
			/* End of leaf, pop back towards the root. */
			if (cur->bc_ptrs[level] >
			    be16_to_cpu(block->bb_numrecs)) {
				if (level < cur->bc_nlevels - 1)
					cur->bc_ptrs[level + 1]++;
				level++;
				continue;
			}

			/* Records in order for scrub? */
			error = xfs_scrub_btree_rec(&bs);
			if (error)
				goto out;
			recp = xfs_btree_rec_addr(cur, cur->bc_ptrs[0], block);
			error = bs.scrub_rec(&bs, recp);
			if (error < 0 ||
			    error == XFS_BTREE_QUERY_RANGE_ABORT)
				break;
			if (xfs_scrub_should_terminate(&error))
				break;

			cur->bc_ptrs[level]++;
			continue;
		}

		/* End of node, pop back towards the root. */
		if (cur->bc_ptrs[level] > be16_to_cpu(block->bb_numrecs)) {
			if (level < cur->bc_nlevels - 1)
				cur->bc_ptrs[level + 1]++;
			level++;
			continue;
		}

		/* Keys in order for scrub? */
		error = xfs_scrub_btree_key(&bs, level);
		if (error)
			goto out;

		/* Drill another level deeper. */
		pp = xfs_btree_ptr_addr(cur, cur->bc_ptrs[level], block);
		error = xfs_scrub_btree_ptr(&bs, level, pp);
		if (error) {
			error = 0;
			cur->bc_ptrs[level]++;
			continue;
		}
		level--;
		error = xfs_scrub_btree_block(&bs, level, pp, &block, &bp);
		XFS_SCRUB_BTKEY_OP_ERROR_GOTO(&bs, level, &error, out);

		cur->bc_ptrs[level] = 1;
	}

out:
	/*
	 * If we don't end this function with the cursor pointing at a record
	 * block, a subsequent non-error cursor deletion will not release
	 * node-level buffers, causing a buffer leak.  This is quite possible
	 * with a zero-results scrubbing run, so release the buffers if we
	 * aren't pointing at a record.
	 */
	if (cur->bc_bufs[0] == NULL) {
		for (i = 0; i < cur->bc_nlevels; i++) {
			if (cur->bc_bufs[i]) {
				xfs_trans_brelse(cur->bc_tp, cur->bc_bufs[i]);
				cur->bc_bufs[i] = NULL;
				cur->bc_ptrs[i] = 0;
				cur->bc_ra[i] = 0;
			}
		}
	}

	/* Process deferred owner checks on btree blocks. */
	list_for_each_entry_safe(co, n, &bs.to_check, list) {
		if (!error)
			error = xfs_scrub_btree_check_block_owner(&bs, co->fsb);
		list_del(&co->list);
		kmem_free(co);
	}

out_badcursor:
	return error;
}
