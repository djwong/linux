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
#ifndef __XFS_REPAIR_COMMON_H__
#define __XFS_REPAIR_COMMON_H__

/* Buffer pointers and btree cursors for an entire AG. */
struct xfs_scrub_ag {
	xfs_agnumber_t			agno;

	/* AG btree roots */
	struct xfs_buf			*agf_bp;
	struct xfs_buf			*agfl_bp;
	struct xfs_buf			*agi_bp;

	/* AG btrees */
	struct xfs_btree_cur		*bno_cur;
	struct xfs_btree_cur		*cnt_cur;
	struct xfs_btree_cur		*ino_cur;
	struct xfs_btree_cur		*fino_cur;
	struct xfs_btree_cur		*rmap_cur;
	struct xfs_btree_cur		*refc_cur;
};

/*
 * Track which AGs for which we've already locked the header buffers.
 * This information helps us avoid deadlocks by ensuring locking order
 * rule compliance.  max_ag is the highest AG number that we've locked;
 * we can only re-lock an AG we've already locked, or lock a higher AG.
 * If we try to lock a lower numbered AG, we must restart the operation
 * with all AG headers locked from the beginning.
 */
#define XFS_SCRUB_AGMASK_NR		128
struct xfs_scrub_ag_lock {
	xfs_agnumber_t			max_ag;
	unsigned long			*agmask;
	unsigned long			__agmask[XFS_SCRUB_AGMASK_NR /
						 sizeof(unsigned long)];
};

struct xfs_scrub_context {
	/* General scrub state. */
	struct xfs_scrub_metadata	*sm;
	struct xfs_trans		*tp;
	struct xfs_inode		*ip;

	/* State tracking for multi-AG operations. */
	struct xfs_scrub_ag_lock	ag_lock;

	/* State tracking for single-AG operations. */
	struct xfs_scrub_ag		sa;
};

/* Should we end the scrub early? */
static inline bool
xfs_scrub_should_terminate(
	int		*error)
{
	if (fatal_signal_pending(current)) {
		if (*error == 0)
			*error = -EAGAIN;
		return true;
	}
	return false;
}

/*
 * Grab a transaction.  If we're going to repair something, we need to
 * ensure there's enough reservation to make all the changes.  If not,
 * we can use an empty transaction.
 */
static inline int
xfs_scrub_trans_alloc(
	struct xfs_scrub_metadata	*sm,
	struct xfs_mount		*mp,
	struct xfs_trans_res		*resp,
	uint				blocks,
	uint				rtextents,
	uint				flags,
	struct xfs_trans		**tpp)
{
	return xfs_trans_alloc_empty(mp, tpp);
}

/* Check for operational errors. */
bool xfs_scrub_op_ok(struct xfs_scrub_context *sc, xfs_agnumber_t agno,
		     xfs_agblock_t bno, const char *type, int *error,
		     const char	*func, int line);
#define XFS_SCRUB_OP_ERROR_GOTO(sc, agno, bno, type, error, label) \
	do { \
		if (!xfs_scrub_op_ok((sc), (agno), (bno), (type), \
				(error), __func__, __LINE__)) \
			goto label; \
	} while (0)

/* Check for operational errors for a file offset. */
bool xfs_scrub_file_op_ok(struct xfs_scrub_context *sc, int whichfork,
			  xfs_fileoff_t offset, const char *type,
			  int *error, const char *func, int line);
#define XFS_SCRUB_FILE_OP_ERROR_GOTO(sc, which, off, type, error, label) \
	do { \
		if (!xfs_scrub_file_op_ok((sc), (which), (off), (type), \
				(error), __func__, __LINE__)) \
			goto label; \
	} while (0)

/* Check for metadata block optimization possibilities. */
bool xfs_scrub_block_preen(struct xfs_scrub_context *sc, struct xfs_buf *bp,
			   const char *type, bool fs_ok, const char *check,
			   const char *func, int line);
#define XFS_SCRUB_PREEN(sc, bp, type, fs_ok) \
	xfs_scrub_block_preen((sc), (bp), (type), (fs_ok), #fs_ok, \
			__func__, __LINE__)

/* Check for inode metadata optimization possibilities. */
bool xfs_scrub_ino_preen(struct xfs_scrub_context *sc, struct xfs_buf *bp,
		      const char *type, bool fs_ok, const char *check,
		      const char *func, int line);
#define XFS_SCRUB_INO_PREEN(sc, bp, type, fs_ok) \
	xfs_scrub_ino_preen((sc), (bp), (type), (fs_ok), #fs_ok, \
			__func__, __LINE__)

/* Check for metadata block corruption. */
bool xfs_scrub_block_ok(struct xfs_scrub_context *sc, struct xfs_buf *bp,
			const char *type, bool fs_ok, const char *check,
			const char *func, int line);
#define XFS_SCRUB_CHECK(sc, bp, type, fs_ok) \
	xfs_scrub_block_ok((sc), (bp), (type), (fs_ok), #fs_ok, \
			__func__, __LINE__)
#define XFS_SCRUB_GOTO(sc, bp, type, fs_ok, label) \
	do { \
		if (!xfs_scrub_block_ok((sc), (bp), (type), (fs_ok), \
				#fs_ok, __func__, __LINE__)) \
			goto label; \
	} while (0)

/* Check for inode metadata corruption. */
bool xfs_scrub_ino_ok(struct xfs_scrub_context *sc, xfs_ino_t ino,
		      struct xfs_buf *bp, const char *type, bool fs_ok,
		      const char *check, const char *func, int line);
#define XFS_SCRUB_INO_CHECK(sc, ino, bp, type, fs_ok) \
	xfs_scrub_ino_ok((sc), (ino), (bp), (type), (fs_ok), #fs_ok, \
			__func__, __LINE__)
#define XFS_SCRUB_INO_GOTO(sc, ino, bp, type, fs_ok, label) \
	do { \
		if (!xfs_scrub_ino_ok((sc), (ino), (bp), (type), (fs_ok), \
				#fs_ok, __func__, __LINE__)) \
			goto label; \
	} while(0)

/* Check for file data block corruption. */
bool xfs_scrub_data_ok(struct xfs_scrub_context *sc, int whichfork,
		       xfs_fileoff_t offset, const char *type, bool fs_ok,
		       const char *check, const char *func, int line);
#define XFS_SCRUB_DATA_CHECK(sc, whichfork, offset, type, fs_ok) \
	xfs_scrub_data_ok((sc), (whichfork), (offset), (type), (fs_ok), \
			#fs_ok, __func__, __LINE__)
#define XFS_SCRUB_DATA_GOTO(sc, whichfork, offset, type, fs_ok, label) \
	do { \
		if (!xfs_scrub_data_ok((sc), (whichfork), (offset), \
				(type), (fs_ok), #fs_ok, __func__, __LINE__)) \
			goto label; \
	} while(0)

bool xfs_scrub_ag_can_lock(struct xfs_scrub_context *sc, xfs_agnumber_t agno);
int xfs_scrub_ag_lock_all(struct xfs_scrub_context *sc);
void xfs_scrub_ag_free(struct xfs_scrub_ag *sa);
int xfs_scrub_ag_init(struct xfs_scrub_context *sc, xfs_agnumber_t agno,
		      struct xfs_scrub_ag *sa);
int xfs_scrub_ag_btcur_init(struct xfs_scrub_context *sc,
			    struct xfs_scrub_ag *sa);

#endif	/* __XFS_REPAIR_COMMON_H__ */
