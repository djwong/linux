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
#include "xfs_icache.h"
#include "xfs_itable.h"
#include "xfs_inode_buf.h"
#include "xfs_inode_fork.h"
#include "xfs_ialloc.h"
#include "xfs_rmap.h"
#include "repair/common.h"

/* Inode core */

#define XFS_SCRUB_INODE_CHECK(fs_ok) \
	XFS_SCRUB_INO_CHECK(sc, ino, bp, "inode", fs_ok);
#define XFS_SCRUB_INODE_GOTO(fs_ok, label) \
	XFS_SCRUB_INO_GOTO(sc, ino, bp, "inode", fs_ok, label);
#define XFS_SCRUB_INODE_OP_ERROR_GOTO(label) \
	XFS_SCRUB_OP_ERROR_GOTO(sc, XFS_INO_TO_AGNO(mp, ino), \
			XFS_INO_TO_AGBNO(mp, ino), "inode", &error, label);
#define XFS_SCRUB_INODE_PREEN(fs_ok) \
	XFS_SCRUB_INO_PREEN(sc, bp, "inode", fs_ok);
/* Scrub an inode. */
int
xfs_scrub_inode(
	struct xfs_scrub_context	*sc)
{
	struct xfs_imap			imap;
	struct xfs_dinode		di;
	struct xfs_mount		*mp = sc->tp->t_mountp;
	struct xfs_ifork		*ifp;
	struct xfs_buf			*bp = NULL;
	struct xfs_dinode		*dip;
	xfs_ino_t			ino;
	unsigned long long		isize;
	uint64_t			flags2;
	uint32_t			nextents;
	uint32_t			extsize;
	uint32_t			cowextsize;
	uint16_t			flags;
	uint16_t			mode;
	int				error = 0;
	int				err2;

	/* Did we get the in-core inode, or are we doing this manually? */
	if (sc->ip) {
		ino = sc->ip->i_ino;
		xfs_inode_to_disk(sc->ip, &di, 0);
		dip = &di;
	} else {
		/* Map & read inode. */
		ino = sc->sm->sm_ino;
		error = xfs_imap(mp, sc->tp, ino, &imap, XFS_IGET_UNTRUSTED);
		XFS_SCRUB_INODE_OP_ERROR_GOTO(out);

		error = xfs_trans_read_buf(mp, sc->tp, mp->m_ddev_targp,
				imap.im_blkno, imap.im_len, XBF_UNMAPPED, &bp,
				NULL);
		XFS_SCRUB_INODE_OP_ERROR_GOTO(out);

		/* Is this really the inode we want? */
		bp->b_ops = &xfs_inode_buf_ops;
		dip = xfs_buf_offset(bp, imap.im_boffset);
		error = xfs_dinode_verify(mp, ino, dip) ? 0 : -EFSCORRUPTED;
		XFS_SCRUB_INODE_OP_ERROR_GOTO(out);
		XFS_SCRUB_INODE_GOTO(
				xfs_dinode_good_version(mp, dip->di_version),
				out);
		if (be32_to_cpu(dip->di_gen) != sc->sm->sm_gen) {
			error = -EINVAL;
			goto out;
		}
	}

	flags = be16_to_cpu(dip->di_flags);
	if (dip->di_version >= 3)
		flags2 = be64_to_cpu(dip->di_flags2);
	else
		flags2 = 0;

	/* di_mode */
	mode = be16_to_cpu(dip->di_mode);
	XFS_SCRUB_INODE_CHECK(!(mode & ~(S_IALLUGO | S_IFMT)));

	/* v1/v2 fields */
	switch (dip->di_version) {
	case 1:
		XFS_SCRUB_INODE_CHECK(dip->di_nlink == 0);
		XFS_SCRUB_INODE_CHECK(dip->di_onlink > 0 || !sc->ip);
		XFS_SCRUB_INODE_CHECK(dip->di_projid_lo == 0);
		XFS_SCRUB_INODE_CHECK(dip->di_projid_hi == 0);
		break;
	case 2:
	case 3:
		XFS_SCRUB_INODE_CHECK(dip->di_onlink == 0);
		XFS_SCRUB_INODE_CHECK(dip->di_nlink > 0 || !sc->ip);
		XFS_SCRUB_INODE_CHECK(dip->di_projid_hi == 0 ||
				xfs_sb_version_hasprojid32bit(&mp->m_sb));
		break;
	default:
		ASSERT(0);
		break;
	}

	/* di_format */
	switch (dip->di_format) {
	case XFS_DINODE_FMT_DEV:
		XFS_SCRUB_INODE_CHECK(S_ISCHR(mode) || S_ISBLK(mode) ||
				      S_ISFIFO(mode) || S_ISSOCK(mode));
		break;
	case XFS_DINODE_FMT_LOCAL:
		XFS_SCRUB_INODE_CHECK(S_ISDIR(mode) || S_ISLNK(mode));
		break;
	case XFS_DINODE_FMT_EXTENTS:
		XFS_SCRUB_INODE_CHECK(S_ISREG(mode) || S_ISDIR(mode) ||
				      S_ISLNK(mode));
		break;
	case XFS_DINODE_FMT_BTREE:
		XFS_SCRUB_INODE_CHECK(S_ISREG(mode) || S_ISDIR(mode));
		break;
	case XFS_DINODE_FMT_UUID:
	default:
		XFS_SCRUB_INODE_CHECK(false);
		break;
	}

	/* di_size */
	isize = be64_to_cpu(dip->di_size);
	XFS_SCRUB_INODE_CHECK(!(isize & (1ULL << 63)));
	if (!S_ISDIR(mode) && !S_ISREG(mode) && !S_ISLNK(mode))
		XFS_SCRUB_INODE_CHECK(isize == 0);

	/* di_nblocks */
	if (flags2 & XFS_DIFLAG2_REFLINK) {
		; /* nblocks can exceed dblocks */
	} else if (flags & XFS_DIFLAG_REALTIME) {
		XFS_SCRUB_INODE_CHECK(be64_to_cpu(dip->di_nblocks) <
				mp->m_sb.sb_dblocks + mp->m_sb.sb_rblocks);
	} else {
		XFS_SCRUB_INODE_CHECK(be64_to_cpu(dip->di_nblocks) <
				mp->m_sb.sb_dblocks);
	}

	/* di_extsize */
	if (flags & XFS_DIFLAG_EXTSIZE) {
		extsize = be32_to_cpu(dip->di_extsize);
		XFS_SCRUB_INODE_CHECK(extsize > 0);
		XFS_SCRUB_INODE_CHECK(extsize <= MAXEXTLEN);
		XFS_SCRUB_INODE_CHECK(extsize <= mp->m_sb.sb_agblocks / 2 ||
				(flags & XFS_DIFLAG_REALTIME));
	}

	/* di_flags */
	XFS_SCRUB_INODE_CHECK(!(flags & XFS_DIFLAG_IMMUTABLE) ||
			      !(flags & XFS_DIFLAG_APPEND));

	XFS_SCRUB_INODE_CHECK(!(flags & XFS_DIFLAG_FILESTREAM) ||
			      !(flags & XFS_DIFLAG_REALTIME));

	/* di_nextents */
	nextents = be32_to_cpu(dip->di_nextents);
	switch (dip->di_format) {
	case XFS_DINODE_FMT_EXTENTS:
		XFS_SCRUB_INODE_CHECK(nextents <=
			XFS_DFORK_DSIZE(dip, mp) / sizeof(struct xfs_bmbt_rec));
		break;
	case XFS_DINODE_FMT_BTREE:
		XFS_SCRUB_INODE_CHECK(nextents >
			XFS_DFORK_DSIZE(dip, mp) / sizeof(struct xfs_bmbt_rec));
		break;
	case XFS_DINODE_FMT_LOCAL:
	case XFS_DINODE_FMT_DEV:
	case XFS_DINODE_FMT_UUID:
	default:
		XFS_SCRUB_INODE_CHECK(nextents == 0);
		break;
	}

	/* di_anextents */
	nextents = be16_to_cpu(dip->di_anextents);
	switch (dip->di_aformat) {
	case XFS_DINODE_FMT_EXTENTS:
		XFS_SCRUB_INODE_CHECK(nextents <=
			XFS_DFORK_ASIZE(dip, mp) / sizeof(struct xfs_bmbt_rec));
		break;
	case XFS_DINODE_FMT_BTREE:
		XFS_SCRUB_INODE_CHECK(nextents >
			XFS_DFORK_ASIZE(dip, mp) / sizeof(struct xfs_bmbt_rec));
		break;
	case XFS_DINODE_FMT_LOCAL:
	case XFS_DINODE_FMT_DEV:
	case XFS_DINODE_FMT_UUID:
	default:
		XFS_SCRUB_INODE_CHECK(nextents == 0);
		break;
	}

	/* di_forkoff */
	XFS_SCRUB_INODE_CHECK(XFS_DFORK_APTR(dip) <
			(char *)dip + mp->m_sb.sb_inodesize);
	XFS_SCRUB_INODE_CHECK(dip->di_anextents == 0 || dip->di_forkoff);

	/* di_aformat */
	XFS_SCRUB_INODE_CHECK(dip->di_aformat == XFS_DINODE_FMT_LOCAL ||
			      dip->di_aformat == XFS_DINODE_FMT_EXTENTS ||
			      dip->di_aformat == XFS_DINODE_FMT_BTREE);

	/* di_cowextsize */
	if (flags2 & XFS_DIFLAG2_COWEXTSIZE) {
		cowextsize = be32_to_cpu(dip->di_cowextsize);
		XFS_SCRUB_INODE_CHECK(xfs_sb_version_hasreflink(&mp->m_sb));
		XFS_SCRUB_INODE_CHECK(cowextsize > 0);
		XFS_SCRUB_INODE_CHECK(cowextsize <= MAXEXTLEN);
		XFS_SCRUB_INODE_CHECK(cowextsize <= mp->m_sb.sb_agblocks / 2);
	}

	/* Now let's do the things that require a live inode. */
	if (!sc->ip)
		goto out;

	/*
	 * If this is a reflink inode with no CoW in progress, maybe we
	 * can turn off the reflink flag?
	 */
	if (xfs_is_reflink_inode(sc->ip)) {
		ifp = XFS_IFORK_PTR(sc->ip, XFS_COW_FORK);
		XFS_SCRUB_INODE_PREEN(ifp->if_bytes > 0);
	}

	/* Make sure the rmap thinks there's an inode here. */
	if (xfs_sb_version_hasrmapbt(&mp->m_sb)) {
		struct xfs_owner_info		oinfo;
		struct xfs_scrub_ag		sa = {0};
		xfs_agnumber_t			agno;
		xfs_agblock_t			agbno;
		bool				has_rmap;

		agno = XFS_INO_TO_AGNO(mp, ino);
		agbno = XFS_INO_TO_AGBNO(mp, ino);
		xfs_rmap_ag_owner(&oinfo, XFS_RMAP_OWN_INODES);
		error = xfs_scrub_ag_init(sc, agno, &sa);
		XFS_SCRUB_INODE_OP_ERROR_GOTO(out);

		err2 = xfs_rmap_record_exists(sa.rmap_cur, agbno,
				1, &oinfo, &has_rmap);
		if (xfs_scrub_should_xref(sc, err2, &sa.rmap_cur))
			XFS_SCRUB_INODE_CHECK(has_rmap);
		xfs_scrub_ag_free(&sa);
	}

out:
	if (bp)
		xfs_trans_brelse(sc->tp, bp);
	return error;
}
#undef XFS_SCRUB_INODE_PREEN
#undef XFS_SCRUB_INODE_OP_ERROR_GOTO
#undef XFS_SCRUB_INODE_GOTO
#undef XFS_SCRUB_INODE_CHECK
