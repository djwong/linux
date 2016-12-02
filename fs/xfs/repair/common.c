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
#include "xfs_alloc_btree.h"
#include "xfs_bmap.h"
#include "xfs_bmap_btree.h"
#include "xfs_ialloc.h"
#include "xfs_ialloc_btree.h"
#include "xfs_refcount.h"
#include "xfs_refcount_btree.h"
#include "xfs_rmap.h"
#include "xfs_rmap_btree.h"
#include "xfs_rtalloc.h"
#include "xfs_log.h"
#include "xfs_trans_priv.h"
#include "xfs_icache.h"
#include "xfs_itable.h"
#include "xfs_error.h"
#include "repair/xfs_scrub.h"
#include "repair/common.h"
#include "repair/btree.h"

/*
 * Online Scrub and Repair
 *
 * Traditionally, XFS (the kernel driver) did not know how to check or
 * repair on-disk data structures.  That task was left to the xfs_check
 * and xfs_repair tools, both of which require taking the filesystem
 * offline for a thorough but time consuming examination.  Online
 * scrub & repair, on the other hand, enables us to check the metadata
 * for obvious errors while carefully stepping around the filesystem's
 * ongoing operations, locking rules, etc.
 *
 * Given that most XFS metadata consist of records stored in a btree,
 * most of the checking functions iterate the btree blocks themselves
 * looking for irregularities.  When a record block is encountered, each
 * record can be checked for obviously bad values.  Record values can
 * also be cross-referenced against other btrees to look for potential
 * misunderstandings between pieces of metadata.
 *
 * It is expected that the checkers responsible for per-AG metadata
 * structures will lock the AG headers (AGI, AGF, AGFL), iterate the
 * metadata structure, and perform any relevant cross-referencing before
 * unlocking the AG and returning the results to userspace.  These
 * scrubbers must not keep an AG locked for too long to avoid tying up
 * the block and inode allocators.
 *
 * Block maps and b-trees rooted in an inode present a special challenge
 * because they can involve extents from any AG.  The general scrubber
 * structure of lock -> check -> xref -> unlock still holds, but AG
 * locking order rules /must/ be obeyed to avoid deadlocks.  The
 * ordering rule, of course, is that we must lock in increasing AG
 * order.  Helper functions are provided to track which AG headers we've
 * already locked.  If we detect an imminent locking order violation, we
 * can signal a potential deadlock, in which case the scrubber can jump
 * out to the top level, lock all the AGs in order, and retry the scrub.
 *
 * For file data (directories, extended attributes, symlinks) scrub, we
 * can simply lock the inode and walk the data.  For btree data
 * (directories and attributes) we follow the same btree-scrubbing
 * strategy outlined previously to check the records.
 *
 * We use a bit of trickery with transactions to avoid buffer deadlocks
 * if there is a cycle in the metadata.  The basic problem is that
 * travelling down a btree involves locking the current buffer at each
 * tree level.  If a pointer should somehow point back to a buffer that
 * we've already examined, we will deadlock due to the second buffer
 * locking attempt.  Note however that grabbing a buffer in transaction
 * context links the locked buffer to the transaction.  If we try to
 * re-grab the buffer in the context of the same transaction, we avoid
 * the second lock attempt and continue.  Between the verifier and the
 * scrubber, something will notice that something is amiss and report
 * the corruption.  Therefore, each scrubber will allocate an empty
 * transaction, attach buffers to it, and cancel the transaction at the
 * end of the scrub run.  Cancelling a non-dirty transaction simply
 * unlocks the buffers.
 *
 * There are four pieces of data that scrub can communicate to
 * userspace.  The first is the error code (errno), which can be used to
 * communicate operational errors in performing the scrub.  There are
 * also three flags that can be set in the scrub context.  If the data
 * structure itself is corrupt, the "corrupt" flag should be set.  If
 * the metadata is correct but otherwise suboptimal, there's a "preen"
 * flag to signal that.  Finally, if we were unable to access a data
 * structure to perform cross-referencing, we can signal that as well.
 *
 * If a piece of metadata proves corrupt or suboptimal, the userspace
 * program can ask the kernel to apply some tender loving care (TLC) to
 * the metadata object.  "Corruption" is defined by metadata violating
 * the on-disk specification; operations cannot continue if the
 * violation is left untreated.  It is possible for XFS to continue if
 * an object is "suboptimal", however performance may be degraded.
 * Repairs are usually performed by rebuilding the metadata entirely out
 * of redundant metadata.  Optimizing, on the other hand, can sometimes
 * be done without rebuilding entire structures.
 *
 * Generally speaking, the repair code has the following code structure:
 * Lock -> scrub -> repair -> commit -> re-lock -> re-scrub -> unlock.
 * The first check helps us figure out if we need to rebuild or simply
 * optimize the structure so that the rebuild knows what to do.  The
 * second check evaluates the completeness of the repair; that is what
 * is reported to userspace.
 */

/* Fix something if errors were detected and the user asked for repair. */
static inline bool
xfs_scrub_should_fix(
	struct xfs_scrub_metadata	*sm)
{
	return (sm->sm_flags & XFS_SCRUB_FLAG_REPAIR) &&
	       (sm->sm_flags & (XFS_SCRUB_FLAG_CORRUPT | XFS_SCRUB_FLAG_PREEN));
}

/* Clear the corruption status flags. */
static inline bool
xfs_scrub_reset_corruption_flags(
	struct xfs_scrub_metadata	*sm)
{
	return sm->sm_flags &= ~(XFS_SCRUB_FLAG_CORRUPT | XFS_SCRUB_FLAG_PREEN |
			      XFS_SCRUB_FLAG_XREF_FAIL);
}

/* Check for operational errors. */
bool
xfs_scrub_op_ok(
	struct xfs_scrub_context	*sc,
	xfs_agnumber_t			agno,
	xfs_agblock_t			bno,
	const char			*type,
	int				*error,
	const char			*func,
	int				line)
{
	struct xfs_mount		*mp = sc->tp->t_mountp;

	if (*error == 0)
		return true;

	trace_xfs_scrub_op_error(mp, agno, bno, type, *error, func, line);
	if (*error == -EFSBADCRC || *error == -EFSCORRUPTED) {
		sc->sm->sm_flags |= XFS_SCRUB_FLAG_CORRUPT;
		*error = 0;
	}
	return false;
}

/* Check for operational errors for a file offset. */
bool
xfs_scrub_file_op_ok(
	struct xfs_scrub_context	*sc,
	int				whichfork,
	xfs_fileoff_t			offset,
	const char			*type,
	int				*error,
	const char			*func,
	int				line)
{
	if (*error == 0)
		return true;

	trace_xfs_scrub_file_op_error(sc->ip, whichfork, offset, type, *error,
			func, line);
	if (*error == -EFSBADCRC || *error == -EFSCORRUPTED) {
		sc->sm->sm_flags |= XFS_SCRUB_FLAG_CORRUPT;
		*error = 0;
	}
	return false;
}

/* Check for metadata block optimization possibilities. */
bool
xfs_scrub_block_preen(
	struct xfs_scrub_context	*sc,
	struct xfs_buf			*bp,
	const char			*type,
	bool				fs_ok,
	const char			*check,
	const char			*func,
	int				line)
{
	struct xfs_mount		*mp = sc->tp->t_mountp;
	xfs_fsblock_t			fsbno;
	xfs_agnumber_t			agno;
	xfs_agblock_t			bno;

	if (fs_ok)
		return fs_ok;

	fsbno = XFS_DADDR_TO_FSB(mp, bp->b_bn);
	agno = XFS_FSB_TO_AGNO(mp, fsbno);
	bno = XFS_FSB_TO_AGBNO(mp, fsbno);

	sc->sm->sm_flags |= XFS_SCRUB_FLAG_PREEN;
	trace_xfs_scrub_block_preen(mp, agno, bno, type, check, func, line);
	return fs_ok;
}

/* Check for metadata block corruption. */
bool
xfs_scrub_block_ok(
	struct xfs_scrub_context	*sc,
	struct xfs_buf			*bp,
	const char			*type,
	bool				fs_ok,
	const char			*check,
	const char			*func,
	int				line)
{
	struct xfs_mount		*mp = sc->tp->t_mountp;
	xfs_fsblock_t			fsbno;
	xfs_agnumber_t			agno;
	xfs_agblock_t			bno;

	if (fs_ok)
		return fs_ok;

	fsbno = XFS_DADDR_TO_FSB(mp, bp->b_bn);
	agno = XFS_FSB_TO_AGNO(mp, fsbno);
	bno = XFS_FSB_TO_AGBNO(mp, fsbno);

	sc->sm->sm_flags |= XFS_SCRUB_FLAG_CORRUPT;
	trace_xfs_scrub_block_error(mp, agno, bno, type, check, func, line);
	return fs_ok;
}

/* Check for inode metadata corruption. */
bool
xfs_scrub_ino_ok(
	struct xfs_scrub_context	*sc,
	xfs_ino_t			ino,
	struct xfs_buf			*bp,
	const char			*type,
	bool				fs_ok,
	const char			*check,
	const char			*func,
	int				line)
{
	struct xfs_inode		*ip = sc->ip;
	struct xfs_mount		*mp = sc->tp->t_mountp;
	xfs_fsblock_t			fsbno;
	xfs_agnumber_t			agno;
	xfs_agblock_t			bno;

	if (fs_ok)
		return fs_ok;

	if (bp) {
		fsbno = XFS_DADDR_TO_FSB(mp, bp->b_bn);
		agno = XFS_FSB_TO_AGNO(mp, fsbno);
		bno = XFS_FSB_TO_AGBNO(mp, fsbno);
	} else {
		agno = XFS_INO_TO_AGNO(mp, ip->i_ino);
		bno = XFS_INO_TO_AGINO(mp, ip->i_ino);
	}

	sc->sm->sm_flags |= XFS_SCRUB_FLAG_CORRUPT;
	trace_xfs_scrub_ino_error(mp, ino, agno, bno, type, check, func, line);
	return fs_ok;
}

/* Check for inode metadata optimization possibilities. */
bool
xfs_scrub_ino_preen(
	struct xfs_scrub_context	*sc,
	struct xfs_buf			*bp,
	const char			*type,
	bool				fs_ok,
	const char			*check,
	const char			*func,
	int				line)
{
	struct xfs_inode		*ip = sc->ip;
	struct xfs_mount		*mp = ip->i_mount;
	xfs_fsblock_t			fsbno;
	xfs_agnumber_t			agno;
	xfs_agblock_t			bno;

	if (fs_ok)
		return fs_ok;

	if (bp) {
		fsbno = XFS_DADDR_TO_FSB(mp, bp->b_bn);
		agno = XFS_FSB_TO_AGNO(mp, fsbno);
		bno = XFS_FSB_TO_AGBNO(mp, fsbno);
	} else {
		agno = XFS_INO_TO_AGNO(mp, ip->i_ino);
		bno = XFS_INO_TO_AGINO(mp, ip->i_ino);
	}

	sc->sm->sm_flags |= XFS_SCRUB_FLAG_PREEN;
	trace_xfs_scrub_ino_preen(mp, ip->i_ino, agno, bno, type, check,
			func, line);
	return fs_ok;
}

/* Check for file data block corruption. */
bool
xfs_scrub_data_ok(
	struct xfs_scrub_context	*sc,
	int				whichfork,
	xfs_fileoff_t			offset,
	const char			*type,
	bool				fs_ok,
	const char			*check,
	const char			*func,
	int				line)
{
	if (fs_ok)
		return fs_ok;

	sc->sm->sm_flags |= XFS_SCRUB_FLAG_CORRUPT;
	trace_xfs_scrub_data_error(sc->ip, whichfork, offset, type, check,
			func, line);
	return fs_ok;
}

/* AG scrubbing */

/* Grab all the headers for an AG. */
static int
xfs_scrub_ag_read_headers(
	struct xfs_scrub_context	*sc,
	xfs_agnumber_t			agno,
	struct xfs_buf			**agi,
	struct xfs_buf			**agf,
	struct xfs_buf			**agfl)
{
	struct xfs_mount		*mp = sc->tp->t_mountp;
	int				error;

	error = xfs_ialloc_read_agi(mp, sc->tp, agno, agi);
	if (error)
		goto out;

	error = xfs_alloc_read_agf(mp, sc->tp, agno, 0, agf);
	if (error)
		goto out;

	error = xfs_alloc_read_agfl(mp, sc->tp, agno, agfl);
	if (error)
		goto out;

out:
	return error;
}

/* Release all the AG btree cursors. */
STATIC void
xfs_scrub_ag_btcur_free(
	struct xfs_scrub_ag		*sa)
{
	if (sa->refc_cur)
		xfs_btree_del_cursor(sa->refc_cur, XFS_BTREE_ERROR);
	if (sa->rmap_cur)
		xfs_btree_del_cursor(sa->rmap_cur, XFS_BTREE_ERROR);
	if (sa->fino_cur)
		xfs_btree_del_cursor(sa->fino_cur, XFS_BTREE_ERROR);
	if (sa->ino_cur)
		xfs_btree_del_cursor(sa->ino_cur, XFS_BTREE_ERROR);
	if (sa->cnt_cur)
		xfs_btree_del_cursor(sa->cnt_cur, XFS_BTREE_ERROR);
	if (sa->bno_cur)
		xfs_btree_del_cursor(sa->bno_cur, XFS_BTREE_ERROR);

	sa->refc_cur = NULL;
	sa->rmap_cur = NULL;
	sa->fino_cur = NULL;
	sa->ino_cur = NULL;
	sa->bno_cur = NULL;
	sa->cnt_cur = NULL;
}

/* Initialize all the btree cursors for an AG. */
int
xfs_scrub_ag_btcur_init(
	struct xfs_scrub_context	*sc,
	struct xfs_scrub_ag		*sa)
{
	struct xfs_mount		*mp = sc->tp->t_mountp;
	xfs_agnumber_t			agno = sa->agno;

	if (sa->agf_bp) {
		/* Set up a bnobt cursor for cross-referencing. */
		sa->bno_cur = xfs_allocbt_init_cursor(mp, sc->tp, sa->agf_bp,
				agno, XFS_BTNUM_BNO);
		if (!sa->bno_cur)
			goto err;

		/* Set up a cntbt cursor for cross-referencing. */
		sa->cnt_cur = xfs_allocbt_init_cursor(mp, sc->tp, sa->agf_bp,
				agno, XFS_BTNUM_CNT);
		if (!sa->cnt_cur)
			goto err;
	}

	/* Set up a inobt cursor for cross-referencing. */
	if (sa->agi_bp) {
		sa->ino_cur = xfs_inobt_init_cursor(mp, sc->tp, sa->agi_bp,
					agno, XFS_BTNUM_INO);
		if (!sa->ino_cur)
			goto err;
	}

	/* Set up a finobt cursor for cross-referencing. */
	if (sa->agi_bp && xfs_sb_version_hasfinobt(&mp->m_sb)) {
		sa->fino_cur = xfs_inobt_init_cursor(mp, sc->tp, sa->agi_bp,
				agno, XFS_BTNUM_FINO);
		if (!sa->fino_cur)
			goto err;
	}

	/* Set up a rmapbt cursor for cross-referencing. */
	if (sa->agf_bp && xfs_sb_version_hasrmapbt(&mp->m_sb)) {
		sa->rmap_cur = xfs_rmapbt_init_cursor(mp, sc->tp, sa->agf_bp,
				agno);
		if (!sa->rmap_cur)
			goto err;
	}

	/* Set up a refcountbt cursor for cross-referencing. */
	if (sa->agf_bp && xfs_sb_version_hasreflink(&mp->m_sb)) {
		sa->refc_cur = xfs_refcountbt_init_cursor(mp, sc->tp,
				sa->agf_bp, agno, NULL);
		if (!sa->refc_cur)
			goto err;
	}

	return 0;
err:
	return -ENOMEM;
}

/* Release the AG header context and btree cursors. */
void
xfs_scrub_ag_free(
	struct xfs_scrub_ag		*sa)
{
	xfs_scrub_ag_btcur_free(sa);
	sa->agno = NULLAGNUMBER;
}

/*
 * For scrub, grab the AGI and the AGF headers, in that order.  Locking
 * order requires us to get the AGI before the AGF.  We use the
 * transaction to avoid deadlocking on crosslinked metadata buffers;
 * either the caller passes one in (bmap scrub) or we have to create a
 * transaction ourselves.
 */
int
xfs_scrub_ag_init(
	struct xfs_scrub_context	*sc,
	xfs_agnumber_t			agno,
	struct xfs_scrub_ag		*sa)
{
	int				error;

	memset(sa, 0, sizeof(*sa));
	sa->agno = agno;
	error = xfs_scrub_ag_read_headers(sc, agno, &sa->agi_bp,
			&sa->agf_bp, &sa->agfl_bp);
	if (error)
		goto err;

	error = xfs_scrub_ag_btcur_init(sc, sa);
	if (error)
		goto err;

	return error;
err:
	xfs_scrub_ag_free(sa);
	return error;
}

/* Organize locking of multiple AGs for a scrub. */

/* Initialize the AG lock handler. */
static inline void
xfs_scrub_ag_lock_init(
	struct xfs_mount		*mp,
	struct xfs_scrub_ag_lock	*ag_lock)
{
	if (mp->m_sb.sb_agcount <= XFS_SCRUB_AGMASK_NR)
		ag_lock->agmask = ag_lock->__agmask;
	else
		ag_lock->agmask = kmem_alloc(1 + (mp->m_sb.sb_agcount / NBBY),
				KM_SLEEP | KM_NOFS);
	ag_lock->max_ag = NULLAGNUMBER;
}

/* Can we lock the AG's headers without deadlocking? */
bool
xfs_scrub_ag_can_lock(
	struct xfs_scrub_context	*sc,
	xfs_agnumber_t			agno)
{
	struct xfs_mount		*mp = sc->tp->t_mountp;
	struct xfs_scrub_ag_lock	*ag_lock = &sc->ag_lock;

	ASSERT(agno < mp->m_sb.sb_agcount);

	trace_xfs_scrub_ag_can_lock(mp, ag_lock->max_ag, agno);

	/* Already locked? */
	if (test_bit(agno, ag_lock->agmask))
		return true;

	/* If we can't lock the AG without violating locking order, bail out. */
	if (agno < ag_lock->max_ag) {
		trace_xfs_scrub_ag_may_deadlock(mp, ag_lock->max_ag, agno);
		return false;
	}

	set_bit(agno, ag_lock->agmask);
	ag_lock->max_ag = agno;
	return true;
}

/* Read all AG headers and attach to this transaction. */
int
xfs_scrub_ag_lock_all(
	struct xfs_scrub_context	*sc)
{
	struct xfs_mount		*mp = sc->tp->t_mountp;
	struct xfs_scrub_ag_lock	*ag_lock = &sc->ag_lock;
	struct xfs_buf			*agi;
	struct xfs_buf			*agf;
	struct xfs_buf			*agfl;
	xfs_agnumber_t			agno;
	int				error = 0;

	trace_xfs_scrub_ag_lock_all(mp, ag_lock->max_ag, mp->m_sb.sb_agcount);

	ASSERT(ag_lock->max_ag == NULLAGNUMBER);
	for (agno = 0; agno < mp->m_sb.sb_agcount; agno++) {
		error = xfs_scrub_ag_read_headers(sc, agno, &agi, &agf,
				&agfl);
		if (error)
			break;
		set_bit(agno, ag_lock->agmask);
		ag_lock->max_ag = agno;
	}

	return error;
}

/*
 * Predicate that decides if we need to evaluate the cross-reference check.
 * If there was an error accessing the cross-reference btree, just delete
 * the cursor and skip the check.
 */
bool
__xfs_scrub_should_xref(
	struct xfs_scrub_context	*sc,
	int				error,
	struct xfs_btree_cur		**curpp,
	const char			*func,
	int				line)
{
	struct xfs_mount		*mp = sc->tp->t_mountp;

	/* If not a btree cross-reference, just check the error code. */
	if (curpp == NULL) {
		if (error == 0)
			return true;
		trace_xfs_scrub_xref_error(mp, "unknown", error, func, line);
		return false;
	}

	ASSERT(*curpp != NULL);
	/* If no error or we've already given up on xref, just bail out. */
	if (error == 0 || *curpp == NULL)
		return true;

	/* xref error, delete cursor and bail out. */
	sc->sm->sm_flags |= XFS_SCRUB_FLAG_XREF_FAIL;
	trace_xfs_scrub_xref_error(mp, btree_types[(*curpp)->bc_btnum],
			error, func, line);
	xfs_btree_del_cursor(*curpp, XFS_BTREE_ERROR);
	*curpp = NULL;

	return false;
}
#define xfs_scrub_should_xref(sc, error, curpp) \
	__xfs_scrub_should_xref((sc), (error), (curpp), __func__, __LINE__)
#define xfs_scrub_btree_should_xref(bs, error, curpp) \
	__xfs_scrub_should_xref((bs)->sc, (error), (curpp), __func__, __LINE__)

/* Dummy scrubber */

STATIC int
xfs_scrub_dummy(
	struct xfs_scrub_context	*sc)
{
	if (sc->sm->sm_gen & XFS_SCRUB_FLAG_CORRUPT)
		sc->sm->sm_flags |= XFS_SCRUB_FLAG_CORRUPT;
	if (sc->sm->sm_gen & XFS_SCRUB_FLAG_PREEN)
		sc->sm->sm_flags |= XFS_SCRUB_FLAG_PREEN;
	if (sc->sm->sm_gen & XFS_SCRUB_FLAG_XREF_FAIL)
		sc->sm->sm_flags |= XFS_SCRUB_FLAG_XREF_FAIL;
	if (sc->sm->sm_gen & ~XFS_SCRUB_FLAGS_OUT)
		return -ENOENT;

	return 0;
}

/* Scrub setup and teardown. */

/* Free all the resources and finish the transactions. */
STATIC int
xfs_scrub_teardown(
	struct xfs_scrub_context	*sc,
	struct xfs_inode		*ip_in,
	int				error)
{
	struct xfs_mount		*mp = sc->tp->t_mountp;

	xfs_scrub_ag_free(&sc->sa);
	if (sc->ag_lock.agmask != sc->ag_lock.__agmask)
		kmem_free(sc->ag_lock.agmask);
	sc->ag_lock.agmask = NULL;
	if (error == 0 && (sc->sm->sm_flags & XFS_SCRUB_FLAG_REPAIR))
		error = xfs_trans_commit(sc->tp);
	else
		xfs_trans_cancel(sc->tp);
	sc->tp = NULL;
	if (sc->ip != NULL) {
		xfs_iunlock(sc->ip, XFS_ILOCK_EXCL);
		xfs_iunlock(sc->ip, XFS_IOLOCK_EXCL);
		xfs_iunlock(sc->ip, XFS_MMAPLOCK_EXCL);
		if (sc->ip != ip_in)
			IRELE(sc->ip);
		sc->ip = NULL;
	}
	if (sc->buf) {
		kmem_free(sc->buf);
		sc->buf = NULL;
	}
	if (sc->reset_counters && !error)
		error = xfs_repair_reset_counters(mp);
	return error;
}

/* Set us up with a transaction and an empty context. */
STATIC int
xfs_scrub_setup(
	struct xfs_scrub_context	*sc,
	struct xfs_inode		*ip,
	struct xfs_scrub_metadata	*sm,
	bool				retry_deadlocked)
{
	struct xfs_mount		*mp = ip->i_mount;
	xfs_extlen_t			resblks;

	memset(sc, 0, sizeof(*sc));
	sc->sm = sm;
	resblks = xfs_repair_calc_ag_resblks(sc, ip, sm);
	return xfs_scrub_trans_alloc(sm, mp, &M_RES(mp)->tr_itruncate,
			resblks, 0, 0, &sc->tp);
}

/* Set us up to check an AG header. */
STATIC int
xfs_scrub_setup_ag(
	struct xfs_scrub_context	*sc,
	struct xfs_inode		*ip,
	struct xfs_scrub_metadata	*sm,
	bool				retry_deadlocked)
{
	struct xfs_mount		*mp = ip->i_mount;

	if (sm->sm_agno >= mp->m_sb.sb_agcount)
		return -EINVAL;
	return xfs_scrub_setup(sc, ip, sm, retry_deadlocked);
}

/*
 * Load and verify an AG header for further AG header examination.
 * If this header is not the target of the examination, don't return
 * the buffer if a runtime or verifier error occurs.
 */
STATIC int
xfs_scrub_load_ag_header(
	struct xfs_scrub_context	*sc,
	xfs_daddr_t			daddr,
	struct xfs_buf			**bpp,
	const struct xfs_buf_ops	*ops,
	bool				is_target)
{
	struct xfs_mount		*mp = sc->tp->t_mountp;
	int				error;

	*bpp = NULL;
	error = xfs_trans_read_buf(mp, sc->tp, mp->m_ddev_targp,
			XFS_AG_DADDR(mp, sc->sa.agno, daddr),
			XFS_FSS_TO_BB(mp, 1), 0, bpp, ops);
	return is_target ? error : 0;
}

/*
 * Load as many of the AG headers and btree cursors as we can for an
 * examination and cross-reference of an AG header.
 */
int
xfs_scrub_load_ag_headers(
	struct xfs_scrub_context	*sc,
	xfs_agnumber_t			agno,
	unsigned int			type)
{
	struct xfs_mount		*mp = sc->tp->t_mountp;
	int				error;

	ASSERT(type == XFS_SCRUB_TYPE_AGF || type == XFS_SCRUB_TYPE_AGFL ||
	       type == XFS_SCRUB_TYPE_AGI);
	memset(&sc->sa, 0, sizeof(sc->sa));
	sc->sa.agno = agno;

	error = xfs_scrub_load_ag_header(sc, XFS_AGI_DADDR(mp),
			&sc->sa.agi_bp, &xfs_agi_buf_ops,
			type == XFS_SCRUB_TYPE_AGI);
	if (error)
		return error;

	error = xfs_scrub_load_ag_header(sc, XFS_AGF_DADDR(mp),
			&sc->sa.agf_bp, &xfs_agf_buf_ops,
			type == XFS_SCRUB_TYPE_AGF);
	if (error)
		return error;

	error = xfs_scrub_load_ag_header(sc, XFS_AGFL_DADDR(mp),
			&sc->sa.agfl_bp, &xfs_agfl_buf_ops,
			type == XFS_SCRUB_TYPE_AGFL);
	if (error)
		return error;

	return 0;
}

/* Set us up with AG headers and btree cursors. */
STATIC int
xfs_scrub_setup_ag_header(
	struct xfs_scrub_context	*sc,
	struct xfs_inode		*ip,
	struct xfs_scrub_metadata	*sm,
	bool				retry_deadlocked)
{
	int				error;

	error = xfs_scrub_setup_ag(sc, ip, sm, retry_deadlocked);
	if (error)
		goto out;

	error = xfs_scrub_ag_init(sc, sm->sm_agno, &sc->sa);
	if (error)
		xfs_trans_cancel(sc->tp);
out:
	return error;
}

/*
 * Given an inode and the scrub control structure, return either the
 * inode referenced in the control structure or the inode passed in.
 * The inode is not locked.
 */
STATIC struct xfs_inode *
xfs_scrub_get_inode(
	struct xfs_scrub_context	*sc,
	struct xfs_inode		*ip)
{
	struct xfs_mount		*mp = ip->i_mount;
	struct xfs_inode		*ips = NULL;
	int				error;

	if (sc->sm->sm_gen && !sc->sm->sm_ino)
		return ERR_PTR(-EINVAL);

	if (sc->sm->sm_ino && sc->sm->sm_ino != ip->i_ino) {
		if (xfs_internal_inum(mp, sc->sm->sm_ino))
			return ERR_PTR(-ENOENT);
		error = xfs_iget(mp, NULL, sc->sm->sm_ino,
				XFS_IGET_UNTRUSTED | XFS_IGET_DONTCACHE,
				0, &ips);
		if (error) {
			trace_xfs_scrub_op_error(mp,
					XFS_INO_TO_AGNO(mp, sc->sm->sm_ino),
					XFS_INO_TO_AGBNO(mp, sc->sm->sm_ino),
					"inode", error, __func__, __LINE__);
			goto out_err;
		}
		if (VFS_I(ips)->i_generation != sc->sm->sm_gen) {
			IRELE(ips);
			return ERR_PTR(-ENOENT);
		}

		return ips;
	}

	return ip;
out_err:
	return ERR_PTR(error);
}

/* Set us up with an inode. */
STATIC int
xfs_scrub_setup_inode(
	struct xfs_scrub_context	*sc,
	struct xfs_inode		*ip,
	struct xfs_scrub_metadata	*sm,
	bool				retry_deadlocked)
{
	struct xfs_mount		*mp = ip->i_mount;
	int				error;

	memset(sc, 0, sizeof(*sc));
	sc->sm = sm;
	sc->ip = xfs_scrub_get_inode(sc, ip);
	if (IS_ERR(sc->ip))
		return PTR_ERR(sc->ip);
	else if (sc->ip == NULL)
		return -ENOENT;

	xfs_ilock(sc->ip, XFS_IOLOCK_EXCL);
	xfs_ilock(sc->ip, XFS_MMAPLOCK_EXCL);
	error = xfs_scrub_trans_alloc(sm, mp, &M_RES(mp)->tr_itruncate,
			0, 0, 0, &sc->tp);
	if (error)
		goto out_unlock;
	xfs_ilock(sc->ip, XFS_ILOCK_EXCL);

	xfs_scrub_ag_lock_init(mp, &sc->ag_lock);
	return error;
out_unlock:
	xfs_iunlock(sc->ip, XFS_IOLOCK_EXCL);
	xfs_iunlock(sc->ip, XFS_MMAPLOCK_EXCL);
	if (sc->ip != ip)
		IRELE(sc->ip);
	return error;
}

/* Try to get the in-core inode.  If we can't, we'll just have to do it raw. */
STATIC int
xfs_scrub_setup_inode_raw(
	struct xfs_scrub_context	*sc,
	struct xfs_inode		*ip,
	struct xfs_scrub_metadata	*sm,
	bool				retry_deadlocked)
{
	struct xfs_mount		*mp = ip->i_mount;
	int				error;

	if (sm->sm_ino && xfs_internal_inum(mp, sm->sm_ino))
		return -ENOENT;

	error = xfs_scrub_setup_inode(sc, ip, sm, retry_deadlocked);
	if (error) {
		memset(sc, 0, sizeof(*sc));
		sc->ip = NULL;
		sc->sm = sm;
		return xfs_scrub_trans_alloc(sm, mp,
				&M_RES(mp)->tr_itruncate, 0, 0, 0, &sc->tp);
	}
	return 0;
}

/* Set us up with an inode and AG headers, if needed. */
STATIC int
xfs_scrub_setup_inode_bmap(
	struct xfs_scrub_context	*sc,
	struct xfs_inode		*ip,
	struct xfs_scrub_metadata	*sm,
	bool				retry_deadlocked)
{
	int				error;

	error = xfs_scrub_setup_inode(sc, ip, sm, retry_deadlocked);
	if (error || !retry_deadlocked)
		return error;

	error = xfs_scrub_ag_lock_all(sc);
	if (error)
		return xfs_scrub_teardown(sc, ip, error);
	return 0;
}

/* Set us up with an inode and a buffer for reading xattr values. */
STATIC int
xfs_scrub_setup_inode_xattr(
	struct xfs_scrub_context	*sc,
	struct xfs_inode		*ip,
	struct xfs_scrub_metadata	*sm,
	bool				retry_deadlocked)
{
	void				*buf;
	int				error;

	/* Allocate the buffer without the inode lock held. */
	buf = kmem_zalloc_large(XATTR_SIZE_MAX, KM_SLEEP);
	if (!buf)
		return -ENOMEM;

	error = xfs_scrub_setup_inode(sc, ip, sm, retry_deadlocked);
	if (error) {
		kmem_free(buf);
		return error;
	}

	sc->buf = buf;
	return 0;
}

/* Set us up with an inode and a buffer for reading symlink targets. */
STATIC int
xfs_scrub_setup_inode_symlink(
	struct xfs_scrub_context	*sc,
	struct xfs_inode		*ip,
	struct xfs_scrub_metadata	*sm,
	bool				retry_deadlocked)
{
	void				*buf;
	int				error;

	/* Allocate the buffer without the inode lock held. */
	buf = kmem_zalloc_large(MAXPATHLEN + 1, KM_SLEEP);
	if (!buf)
		return -ENOMEM;

	error = xfs_scrub_setup_inode(sc, ip, sm, retry_deadlocked);
	if (error) {
		kmem_free(buf);
		return error;
	}

	sc->buf = buf;
	return 0;
}

/* Set us up with the realtime metadata locked. */
STATIC int
xfs_scrub_setup_rt(
	struct xfs_scrub_context	*sc,
	struct xfs_inode		*ip,
	struct xfs_scrub_metadata	*sm,
	bool				retry_deadlocked)
{
	struct xfs_mount		*mp = ip->i_mount;
	int				lockmode;
	int				error = 0;

	if (sm->sm_agno || sm->sm_ino || sm->sm_gen)
		return -EINVAL;

	error = xfs_scrub_setup(sc, ip, sm, retry_deadlocked);
	if (error)
		return error;

	lockmode = XFS_ILOCK_EXCL | XFS_ILOCK_RTBITMAP;
	xfs_ilock(mp->m_rbmip, lockmode);
	xfs_trans_ijoin(sc->tp, mp->m_rbmip, lockmode);

	return 0;
}

/* Scrubbing dispatch. */

struct xfs_scrub_meta_fns {
	int	(*setup)(struct xfs_scrub_context *, struct xfs_inode *,
			 struct xfs_scrub_metadata *, bool);
	int	(*scrub)(struct xfs_scrub_context *);
	int	(*repair)(struct xfs_scrub_context *);
	bool	(*has)(struct xfs_sb *);
};

static const struct xfs_scrub_meta_fns meta_scrub_fns[] = {
	{xfs_scrub_setup, xfs_scrub_dummy, NULL, NULL},
	{xfs_scrub_setup_ag, xfs_scrub_superblock, xfs_repair_superblock, NULL},
	{xfs_scrub_setup_ag, xfs_scrub_agf, xfs_repair_agf, NULL},
	{xfs_scrub_setup_ag, xfs_scrub_agfl, xfs_repair_agfl, NULL},
	{xfs_scrub_setup_ag, xfs_scrub_agi, NULL, NULL},
	{xfs_scrub_setup_ag_header, xfs_scrub_bnobt, NULL, NULL},
	{xfs_scrub_setup_ag_header, xfs_scrub_cntbt, NULL, NULL},
	{xfs_scrub_setup_ag_header, xfs_scrub_inobt, NULL, NULL},
	{xfs_scrub_setup_ag_header, xfs_scrub_finobt, NULL, xfs_sb_version_hasfinobt},
	{xfs_scrub_setup_ag_header, xfs_scrub_rmapbt, NULL, xfs_sb_version_hasrmapbt},
	{xfs_scrub_setup_ag_header, xfs_scrub_refcountbt, NULL, xfs_sb_version_hasreflink},
	{xfs_scrub_setup_inode_raw, xfs_scrub_inode, NULL, NULL},
	{xfs_scrub_setup_inode_bmap, xfs_scrub_bmap_data, NULL, NULL},
	{xfs_scrub_setup_inode_bmap, xfs_scrub_bmap_attr, NULL, NULL},
	{xfs_scrub_setup_inode_bmap, xfs_scrub_bmap_cow, NULL, NULL},
	{xfs_scrub_setup_inode, xfs_scrub_directory, NULL, NULL},
	{xfs_scrub_setup_inode_xattr, xfs_scrub_xattr, NULL, NULL},
	{xfs_scrub_setup_inode_symlink, xfs_scrub_symlink, NULL, NULL},
	{xfs_scrub_setup_rt, xfs_scrub_rtbitmap, NULL, xfs_sb_version_hasrealtime},
	{xfs_scrub_setup_rt, xfs_scrub_rtsummary, NULL, xfs_sb_version_hasrealtime},
};

/* Dispatch metadata scrubbing. */
int
xfs_scrub_metadata(
	struct xfs_inode		*ip,
	struct xfs_scrub_metadata	*sm)
{
	struct xfs_scrub_context	sc;
	struct xfs_mount		*mp = ip->i_mount;
	const struct xfs_scrub_meta_fns	*fns;
	bool				deadlocked = false;
	bool				already_fixed = false;
	bool				was_corrupt = false;
	int				error = 0;

	trace_xfs_scrub(ip, sm->sm_type, sm->sm_agno, sm->sm_ino, sm->sm_gen,
			sm->sm_flags, error);

	if (XFS_FORCED_SHUTDOWN(ip->i_mount))
		return -ESHUTDOWN;

	/* Check our inputs. */
	error = -EINVAL;
	sm->sm_flags &= ~XFS_SCRUB_FLAGS_OUT;
	if (sm->sm_flags & ~XFS_SCRUB_FLAGS_IN)
		goto out;
	error = -ENOTTY;
	if (sm->sm_type > XFS_SCRUB_TYPE_MAX)
		goto out;
	fns = &meta_scrub_fns[sm->sm_type];
	if ((sm->sm_flags & XFS_SCRUB_FLAG_REPAIR) &&
	    (fns->repair == NULL || !xfs_sb_version_hascrc(&mp->m_sb)))
		goto out;

	error = -EROFS;
	if ((sm->sm_flags & XFS_SCRUB_FLAG_REPAIR) &&
	    (mp->m_flags & XFS_MOUNT_RDONLY))
		goto out;

	/* Do we even have this type of metadata? */
	error = -ENOENT;
	if (fns->has && !fns->has(&mp->m_sb))
		goto out;

	/* This isn't a stable feature.  Use with care. */
	{
		static bool warned;

		if (!warned)
			xfs_alert(mp,
	"EXPERIMENTAL online scrub feature in use. Use at your own risk!");
		warned = true;
	}

retry_op:
	/* Push everything out of the log onto disk prior to checking. */
	error = _xfs_log_force(mp, XFS_LOG_SYNC, NULL);
	if (error)
		goto out;
	xfs_ail_push_all_sync(mp->m_ail);

	/* Set up for the operation. */
	error = fns->setup(&sc, ip, sm, deadlocked);
	if (error)
		goto out;

	/* Scrub for errors. */
	error = fns->scrub(&sc);
	if (!deadlocked && error == -EDEADLOCK) {
		deadlocked = true;
		error = xfs_scrub_teardown(&sc, ip, error);
		if (error != -EDEADLOCK)
			goto out;
		goto retry_op;
	} else if (error)
		goto out_teardown;

	/* Let debug users force us into the repair routines. */
	if ((sm->sm_flags & XFS_SCRUB_FLAG_REPAIR) && !already_fixed &&
	    XFS_TEST_ERROR(false, mp,
			XFS_ERRTAG_FORCE_SCRUB_REPAIR,
			XFS_RANDOM_FORCE_SCRUB_REPAIR)) {
		sm->sm_flags |= XFS_SCRUB_FLAG_CORRUPT;
	}
	if (!already_fixed)
		was_corrupt = (sm->sm_flags & XFS_SCRUB_FLAG_CORRUPT);

	if (!already_fixed && xfs_scrub_should_fix(sm)) {
		xfs_scrub_ag_btcur_free(&sc.sa);

		/* Ok, something's wrong.  Repair it. */
		trace_xfs_repair_attempt(ip, sm->sm_type, sm->sm_agno,
			sm->sm_ino, sm->sm_gen, sm->sm_flags, error);
		error = fns->repair(&sc);
		trace_xfs_repair_done(ip, sm->sm_type, sm->sm_agno,
			sm->sm_ino, sm->sm_gen, sm->sm_flags, error);
		if (error)
			goto out_teardown;

		/*
		 * Commit the fixes and perform a second dry-run scrub
		 * so that we can tell userspace if we fixed the problem.
		 */
		error = xfs_scrub_teardown(&sc, ip, error);
		if (error)
			goto out;
		xfs_scrub_reset_corruption_flags(sm);
		already_fixed = true;
		goto retry_op;
	}

	if (sm->sm_flags & XFS_SCRUB_FLAG_CORRUPT) {
		char	*errstr;

		if (sm->sm_flags & XFS_SCRUB_FLAG_REPAIR)
			errstr = "Corruption not fixed during online repair.  "
				 "Unmount and run xfs_repair.";
		else
			errstr = "Corruption detected during scrub.";
		xfs_alert_ratelimited(mp, errstr);
	} else if (already_fixed && was_corrupt)
		xfs_alert_ratelimited(mp, "Corruption repaired during scrub.");

out_teardown:
	error = xfs_scrub_teardown(&sc, ip, error);
out:
	trace_xfs_scrub_done(ip, sm->sm_type, sm->sm_agno, sm->sm_ino,
			sm->sm_gen, sm->sm_flags, error);
	return error;
}
