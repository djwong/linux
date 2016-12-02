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
#include "repair/xfs_scrub.h"
#include "repair/common.h"

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
 */

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
	int				error)
{
	xfs_trans_cancel(sc->tp);
	sc->tp = NULL;
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

	memset(sc, 0, sizeof(*sc));
	sc->sm = sm;
	return xfs_scrub_trans_alloc(sm, mp, &M_RES(mp)->tr_itruncate,
			0, 0, 0, &sc->tp);
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
	if (sm->sm_flags & XFS_SCRUB_FLAG_REPAIR)
		goto out;
	error = -ENOTTY;
	if (sm->sm_type > XFS_SCRUB_TYPE_MAX)
		goto out;
	fns = &meta_scrub_fns[sm->sm_type];

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
		error = xfs_scrub_teardown(&sc, error);
		if (error != -EDEADLOCK)
			goto out;
		goto retry_op;
	} else if (error)
		goto out_teardown;

	if (sm->sm_flags & XFS_SCRUB_FLAG_CORRUPT)
		xfs_alert_ratelimited(mp, "Corruption detected during scrub.");

out_teardown:
	error = xfs_scrub_teardown(&sc, error);
out:
	trace_xfs_scrub_done(ip, sm->sm_type, sm->sm_agno, sm->sm_ino,
			sm->sm_gen, sm->sm_flags, error);
	return error;
}
