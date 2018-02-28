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
#include "xfs_inode.h"
#include "xfs_icache.h"
#include "xfs_inode_buf.h"
#include "xfs_inode_fork.h"
#include "xfs_ialloc.h"
#include "xfs_da_format.h"
#include "xfs_reflink.h"
#include "xfs_alloc.h"
#include "xfs_rmap.h"
#include "xfs_rmap_btree.h"
#include "xfs_bmap.h"
#include "xfs_bmap_btree.h"
#include "xfs_bmap_util.h"
#include "xfs_dir2.h"
#include "xfs_quota_defs.h"
#include "scrub/xfs_scrub.h"
#include "scrub/scrub.h"
#include "scrub/common.h"
#include "scrub/btree.h"
#include "scrub/trace.h"
#include "scrub/repair.h"

/* Make sure this buffer can pass the inode buffer verifier. */
STATIC void
xfs_repair_inode_buf(
	struct xfs_scrub_context	*sc,
	struct xfs_buf			*bp)
{
	struct xfs_mount		*mp = sc->mp;
	struct xfs_trans		*tp = sc->tp;
	struct xfs_dinode		*dip;
	xfs_agnumber_t			agno;
	xfs_agino_t			agino;
	int				ioff;
	int				i;
	int				ni;
	int				di_ok;
	bool				unlinked_ok;

	ni = XFS_BB_TO_FSB(mp, bp->b_length) * mp->m_sb.sb_inopblock;
	agno = xfs_daddr_to_agno(mp, XFS_BUF_ADDR(bp));
	for (i = 0; i < ni; i++) {
		ioff = i << mp->m_sb.sb_inodelog;
		dip = xfs_buf_offset(bp, ioff);
		agino = be32_to_cpu(dip->di_next_unlinked);
		unlinked_ok = (agino == NULLAGINO ||
			       xfs_verify_agino(sc->mp, agno, agino));
		di_ok = dip->di_magic == cpu_to_be16(XFS_DINODE_MAGIC) &&
			xfs_dinode_good_version(mp, dip->di_version);
		if (di_ok && unlinked_ok)
			continue;
		dip->di_magic = cpu_to_be16(XFS_DINODE_MAGIC);
		dip->di_version = 3;
		if (!unlinked_ok)
			dip->di_next_unlinked = cpu_to_be32(NULLAGINO);
		xfs_dinode_calc_crc(mp, dip);
		xfs_trans_buf_set_type(tp, bp, XFS_BLFT_DINO_BUF);
		xfs_trans_log_buf(tp, bp, ioff, ioff + sizeof(*dip) - 1);
	}
}

struct xfs_repair_inode_fork_counters {
	struct xfs_scrub_context	*sc;
	xfs_rfsblock_t			data_blocks;
	xfs_rfsblock_t			rt_blocks;
	xfs_rfsblock_t			attr_blocks;
	xfs_extnum_t			data_extents;
	xfs_extnum_t			rt_extents;
	xfs_aextnum_t			attr_extents;
};

/* Count extents and blocks for an inode given an rmap. */
STATIC int
xfs_repair_inode_count_rmap(
	struct xfs_btree_cur		*cur,
	struct xfs_rmap_irec		*rec,
	void				*priv)
{
	struct xfs_repair_inode_fork_counters	*rifc = priv;

	/* Is this even the right fork? */
	if (rec->rm_owner != rifc->sc->sm->sm_ino)
		return 0;
	if (rec->rm_flags & XFS_RMAP_ATTR_FORK) {
		rifc->attr_blocks += rec->rm_blockcount;
		if (!(rec->rm_flags & XFS_RMAP_BMBT_BLOCK))
			rifc->attr_extents++;
	} else {
		rifc->data_blocks += rec->rm_blockcount;
		if (!(rec->rm_flags & XFS_RMAP_BMBT_BLOCK))
			rifc->data_extents++;
	}
	return 0;
}

/* Count extents and blocks for an inode from all AG rmap data. */
STATIC int
xfs_repair_inode_count_ag_rmaps(
	struct xfs_repair_inode_fork_counters	*rifc,
	xfs_agnumber_t			agno)
{
	struct xfs_btree_cur		*cur;
	struct xfs_buf			*agf;
	int				error;

	error = xfs_alloc_read_agf(rifc->sc->mp, rifc->sc->tp, agno, 0, &agf);
	if (error)
		return error;

	cur = xfs_rmapbt_init_cursor(rifc->sc->mp, rifc->sc->tp, agf, agno);
	if (!cur) {
		error = -ENOMEM;
		goto out_agf;
	}

	error = xfs_rmap_query_all(cur, xfs_repair_inode_count_rmap, rifc);
	if (error == XFS_BTREE_QUERY_RANGE_ABORT)
		error = 0;

	xfs_btree_del_cursor(cur, XFS_BTREE_ERROR);
out_agf:
	xfs_trans_brelse(rifc->sc->tp, agf);
	return error;
}

/* Count extents and blocks for a given inode from all rmap data. */
STATIC int
xfs_repair_inode_count_rmaps(
	struct xfs_repair_inode_fork_counters	*rifc)
{
	xfs_agnumber_t			agno;
	int				error;

	if (!xfs_sb_version_hasrmapbt(&rifc->sc->mp->m_sb) ||
	    xfs_sb_version_hasrealtime(&rifc->sc->mp->m_sb))
		return -EOPNOTSUPP;

	/* XXX: find rt blocks too */

	for (agno = 0; agno < rifc->sc->mp->m_sb.sb_agcount; agno++) {
		error = xfs_repair_inode_count_ag_rmaps(rifc, agno);
		if (error)
			return error;
	}

	/* Can't have extents on both the rt and the data device. */
	if (rifc->data_extents && rifc->rt_extents)
		return -EFSCORRUPTED;

	return 0;
}

/* Figure out if we need to zap this extents format fork. */
STATIC bool
xfs_repair_inode_core_check_extents_fork(
	struct xfs_scrub_context	*sc,
	struct xfs_dinode		*dip,
	int				dfork_size,
	int				whichfork)
{
	struct xfs_bmbt_irec		new;
	struct xfs_bmbt_rec		*dp;
	bool				isrt;
	int				i;
	int				nex;
	int				fork_size;

	nex = XFS_DFORK_NEXTENTS(dip, whichfork);
	fork_size = nex * sizeof(struct xfs_bmbt_rec);
	if (fork_size < 0 || fork_size > dfork_size)
		return true;
	dp = (struct xfs_bmbt_rec *)XFS_DFORK_PTR(dip, whichfork);

	isrt = dip->di_flags & cpu_to_be16(XFS_DIFLAG_REALTIME);
	for (i = 0; i < nex; i++, dp++) {
		xfs_failaddr_t	fa;

		xfs_bmbt_disk_get_all(dp, &new);
		fa = xfs_bmbt_validate_extent(sc->mp, isrt, whichfork, &new);
		if (fa)
			return true;
	}

	return false;
}

/* Figure out if we need to zap this btree format fork. */
STATIC bool
xfs_repair_inode_core_check_btree_fork(
	struct xfs_scrub_context	*sc,
	struct xfs_dinode		*dip,
	int				dfork_size,
	int				whichfork)
{
	struct xfs_bmdr_block		*dfp;
	int				nrecs;
	int				level;

	if (XFS_DFORK_NEXTENTS(dip, whichfork) <=
			dfork_size / sizeof(struct xfs_bmbt_irec))
		return true;

	dfp = (struct xfs_bmdr_block *)XFS_DFORK_PTR(dip, whichfork);
	nrecs = be16_to_cpu(dfp->bb_numrecs);
	level = be16_to_cpu(dfp->bb_level);

	if (nrecs == 0 || XFS_BMDR_SPACE_CALC(nrecs) > dfork_size)
		return true;
	if (level == 0 || level > XFS_BTREE_MAXLEVELS)
		return true;
	return false;
}

/*
 * Check the data fork for things that will fail the ifork verifiers or the
 * ifork formatters.
 */
STATIC bool
xfs_repair_inode_core_check_data_fork(
	struct xfs_scrub_context	*sc,
	struct xfs_dinode		*dip,
	uint16_t			mode)
{
	uint64_t			size;
	int				dfork_size;

	size = be64_to_cpu(dip->di_size);
	switch (mode & S_IFMT) {
	case S_IFIFO:
	case S_IFCHR:
	case S_IFBLK:
	case S_IFSOCK:
		if (XFS_DFORK_FORMAT(dip, XFS_DATA_FORK) != XFS_DINODE_FMT_DEV)
			return true;
		break;
	case S_IFREG:
	case S_IFLNK:
	case S_IFDIR:
		switch (XFS_DFORK_FORMAT(dip, XFS_DATA_FORK)) {
		case XFS_DINODE_FMT_LOCAL:
		case XFS_DINODE_FMT_EXTENTS:
		case XFS_DINODE_FMT_BTREE:
			break;
		default:
			return true;
		}
		break;
	default:
		return true;
	}
	dfork_size = XFS_DFORK_SIZE(dip, sc->mp, XFS_DATA_FORK);
	switch (XFS_DFORK_FORMAT(dip, XFS_DATA_FORK)) {
	case XFS_DINODE_FMT_DEV:
		break;
	case XFS_DINODE_FMT_LOCAL:
		if (size > dfork_size)
			return true;
		break;
	case XFS_DINODE_FMT_EXTENTS:
		if (xfs_repair_inode_core_check_extents_fork(sc, dip,
				dfork_size, XFS_DATA_FORK))
			return true;
		break;
	case XFS_DINODE_FMT_BTREE:
		if (xfs_repair_inode_core_check_btree_fork(sc, dip,
				dfork_size, XFS_DATA_FORK))
			return true;
		break;
	default:
		return true;
	}

	return false;
}

/* Reset the data fork to something sane. */
STATIC void
xfs_repair_inode_core_zap_data_fork(
	struct xfs_scrub_context	*sc,
	struct xfs_dinode		*dip,
	uint16_t			mode,
	struct xfs_repair_inode_fork_counters	*rifc)
{
	char				*p;
	const struct xfs_dir_ops	*ops;
	struct xfs_dir2_sf_hdr		*sfp;
	int				i8count;

	/* Special files always get reset to DEV */
	switch (mode & S_IFMT) {
	case S_IFIFO:
	case S_IFCHR:
	case S_IFBLK:
	case S_IFSOCK:
		dip->di_format = XFS_DINODE_FMT_DEV;
		dip->di_size = 0;
		return;
	}

	/*
	 * If we have data extents, reset to an empty map and hope the user
	 * will run the bmapbtd checker next.
	 */
	if (rifc->data_extents || rifc->rt_extents || S_ISREG(mode)) {
		dip->di_format = XFS_DINODE_FMT_EXTENTS;
		dip->di_nextents = 0;
		return;
	}

	/* Otherwise, reset the local format to the minimum. */
	switch (mode & S_IFMT) {
	case S_IFLNK:
		/* Blow out symlink; now it points to root dir */
		dip->di_format = XFS_DINODE_FMT_LOCAL;
		dip->di_size = cpu_to_be64(1);
		p = XFS_DFORK_PTR(dip, XFS_DATA_FORK);
		*p = '/';
		break;
	case S_IFDIR:
		/*
		 * Blow out dir, make it point to the root.  In the
		 * future the direction repair will reconstruct this
		 * dir for us.
		 */
		dip->di_format = XFS_DINODE_FMT_LOCAL;
		i8count = sc->mp->m_sb.sb_rootino > XFS_DIR2_MAX_SHORT_INUM;
		ops = xfs_dir_get_ops(sc->mp, NULL);
		sfp = (struct xfs_dir2_sf_hdr *)XFS_DFORK_PTR(dip,
				XFS_DATA_FORK);
		sfp->count = 0;
		sfp->i8count = i8count;
		ops->sf_put_parent_ino(sfp, sc->mp->m_sb.sb_rootino);
		dip->di_size = cpu_to_be64(xfs_dir2_sf_hdr_size(i8count));
		break;
	}
}

/*
 * Check the attr fork for things that will fail the ifork verifiers or the
 * ifork formatters.
 */
STATIC bool
xfs_repair_inode_core_check_attr_fork(
	struct xfs_scrub_context	*sc,
	struct xfs_dinode		*dip)
{
	struct xfs_attr_shortform	*atp;
	int				size;
	int				dfork_size;

	if (XFS_DFORK_BOFF(dip) == 0)
		return dip->di_aformat != XFS_DINODE_FMT_EXTENTS ||
		       dip->di_anextents != 0;

	dfork_size = XFS_DFORK_SIZE(dip, sc->mp, XFS_ATTR_FORK);
	switch (XFS_DFORK_FORMAT(dip, XFS_ATTR_FORK)) {
	case XFS_DINODE_FMT_LOCAL:
		atp = (struct xfs_attr_shortform *)XFS_DFORK_APTR(dip);
		size = be16_to_cpu(atp->hdr.totsize);
		if (size > dfork_size)
			return true;
		break;
	case XFS_DINODE_FMT_EXTENTS:
		if (xfs_repair_inode_core_check_extents_fork(sc, dip,
				dfork_size, XFS_ATTR_FORK))
			return true;
		break;
	case XFS_DINODE_FMT_BTREE:
		if (xfs_repair_inode_core_check_btree_fork(sc, dip,
				dfork_size, XFS_ATTR_FORK))
			return true;
		break;
	default:
		return true;
	}

	return false;
}

/* Reset the attr fork to something sane. */
STATIC void
xfs_repair_inode_core_zap_attr_fork(
	struct xfs_scrub_context	*sc,
	struct xfs_dinode		*dip,
	struct xfs_repair_inode_fork_counters	*rifc)
{
	dip->di_aformat = XFS_DINODE_FMT_EXTENTS;
	dip->di_anextents = 0;
	/*
	 * We leave a nonzero forkoff so that the bmap scrub will look for
	 * attr rmaps.
	 */
	dip->di_forkoff = rifc->attr_extents ? 1 : 0;
}

/*
 * Zap the data/attr forks if we spot anything that isn't going to pass the
 * ifork verifiers or the ifork formatters, because we need to get the inode
 * into good enough shape that the higher level repair functions can run.
 */
STATIC void
xfs_repair_inode_core_zap_forks(
	struct xfs_scrub_context	*sc,
	struct xfs_dinode		*dip,
	uint16_t			mode,
	struct xfs_repair_inode_fork_counters	*rifc)
{
	bool				zap_datafork = false;
	bool				zap_attrfork = false;

	/* Inode counters don't make sense? */
	if (be32_to_cpu(dip->di_nextents) > be64_to_cpu(dip->di_nblocks))
		zap_datafork = true;
	if (be16_to_cpu(dip->di_anextents) > be64_to_cpu(dip->di_nblocks))
		zap_attrfork = true;
	if (be32_to_cpu(dip->di_nextents) + be16_to_cpu(dip->di_anextents) >
			be64_to_cpu(dip->di_nblocks))
		zap_datafork = zap_attrfork = true;

	if (!zap_datafork)
		zap_datafork = xfs_repair_inode_core_check_data_fork(sc, dip,
				mode);
	if (!zap_attrfork)
		zap_attrfork = xfs_repair_inode_core_check_attr_fork(sc, dip);

	/* Zap whatever's bad. */
	if (zap_attrfork)
		xfs_repair_inode_core_zap_attr_fork(sc, dip, rifc);
	if (zap_datafork)
		xfs_repair_inode_core_zap_data_fork(sc, dip, mode, rifc);
	dip->di_nblocks = 0;
	if (!zap_attrfork)
		be64_add_cpu(&dip->di_nblocks, rifc->attr_blocks);
	if (!zap_datafork) {
		be64_add_cpu(&dip->di_nblocks, rifc->data_blocks);
		be64_add_cpu(&dip->di_nblocks, rifc->rt_blocks);
	}
}

/* Inode didn't pass verifiers, so fix the raw buffer and retry iget. */
STATIC int
xfs_repair_inode_core(
	struct xfs_scrub_context	*sc)
{
	struct xfs_repair_inode_fork_counters	rifc;
	struct xfs_imap			imap;
	struct xfs_buf			*bp;
	struct xfs_dinode		*dip;
	xfs_ino_t			ino;
	uint64_t			flags2;
	uint16_t			flags;
	uint16_t			mode;
	int				error;

	/* Figure out what this inode had mapped in both forks. */
	memset(&rifc, 0, sizeof(rifc));
	rifc.sc = sc;
	error = xfs_repair_inode_count_rmaps(&rifc);
	if (error)
		return error;

	/* Map & read inode. */
	ino = sc->sm->sm_ino;
	error = xfs_imap(sc->mp, sc->tp, ino, &imap, XFS_IGET_UNTRUSTED);
	if (error)
		return error;

	error = xfs_trans_read_buf(sc->mp, sc->tp, sc->mp->m_ddev_targp,
			imap.im_blkno, imap.im_len, XBF_UNMAPPED, &bp, NULL);
	if (error)
		return error;

	/* Make sure we can pass the inode buffer verifier. */
	xfs_repair_inode_buf(sc, bp);
	bp->b_ops = &xfs_inode_buf_ops;

	/* Fix everything the verifier will complain about. */
	dip = xfs_buf_offset(bp, imap.im_boffset);
	mode = be16_to_cpu(dip->di_mode);
	if (mode && xfs_mode_to_ftype(mode) == XFS_DIR3_FT_UNKNOWN) {
		/* bad mode, so we set it to a file that only root can read */
		mode = S_IFREG;
		dip->di_mode = cpu_to_be16(mode);
		dip->di_uid = 0;
		dip->di_gid = 0;
	}
	dip->di_magic = cpu_to_be16(XFS_DINODE_MAGIC);
	if (!xfs_dinode_good_version(sc->mp, dip->di_version))
		dip->di_version = 3;
	dip->di_ino = cpu_to_be64(ino);
	uuid_copy(&dip->di_uuid, &sc->mp->m_sb.sb_meta_uuid);
	flags = be16_to_cpu(dip->di_flags);
	flags2 = be64_to_cpu(dip->di_flags2);
	if (rifc.rt_extents)
		flags |= XFS_DIFLAG_REALTIME;
	else
		flags &= ~XFS_DIFLAG_REALTIME;
	if (xfs_sb_version_hasreflink(&sc->mp->m_sb) && S_ISREG(mode))
		flags2 |= XFS_DIFLAG2_REFLINK;
	else
		flags2 &= ~(XFS_DIFLAG2_REFLINK | XFS_DIFLAG2_COWEXTSIZE);
	if (flags & XFS_DIFLAG_REALTIME)
		flags2 &= ~XFS_DIFLAG2_REFLINK;
	if (flags2 & XFS_DIFLAG2_REFLINK)
		flags2 &= ~XFS_DIFLAG2_DAX;
	dip->di_flags = cpu_to_be16(flags);
	dip->di_flags2 = cpu_to_be64(flags2);
	dip->di_gen = cpu_to_be32(sc->sm->sm_gen);
	if (be64_to_cpu(dip->di_size) & (1ULL << 63))
		dip->di_size = cpu_to_be64((1ULL << 63) - 1);

	xfs_repair_inode_core_zap_forks(sc, dip, mode, &rifc);

	/* Write out the inode... */
	xfs_dinode_calc_crc(sc->mp, dip);
	xfs_trans_buf_set_type(sc->tp, bp, XFS_BLFT_DINO_BUF);
	xfs_trans_log_buf(sc->tp, bp, imap.im_boffset,
			imap.im_boffset + sc->mp->m_sb.sb_inodesize - 1);
	error = xfs_trans_commit(sc->tp);
	if (error)
		return error;
	sc->tp = NULL;

	/* ...and reload it? */
	error = xfs_iget(sc->mp, sc->tp, ino,
			XFS_IGET_UNTRUSTED | XFS_IGET_DONTCACHE, 0, &sc->ip);
	if (error)
		return error;
	sc->ilock_flags = XFS_IOLOCK_EXCL | XFS_MMAPLOCK_EXCL;
	xfs_ilock(sc->ip, sc->ilock_flags);
	error = xfs_scrub_trans_alloc(sc->sm, sc->mp, 0, &sc->tp);
	if (error)
		return error;
	sc->ilock_flags |= XFS_ILOCK_EXCL;
	xfs_ilock(sc->ip, XFS_ILOCK_EXCL);

	return 0;
}

/* Fix di_extsize hint. */
STATIC void
xfs_repair_inode_extsize(
	struct xfs_scrub_context	*sc)
{
	xfs_failaddr_t			fa;

	fa = xfs_inode_validate_extsize(sc->mp, sc->ip->i_d.di_extsize,
			VFS_I(sc->ip)->i_mode, sc->ip->i_d.di_flags);
	if (!fa)
		return;

	sc->ip->i_d.di_extsize = 0;
	sc->ip->i_d.di_flags &= ~(XFS_DIFLAG_EXTSIZE | XFS_DIFLAG_EXTSZINHERIT);
}

/* Fix di_cowextsize hint. */
STATIC void
xfs_repair_inode_cowextsize(
	struct xfs_scrub_context	*sc)
{
	xfs_failaddr_t			fa;

	if (sc->ip->i_d.di_version < 3)
		return;

	fa = xfs_inode_validate_cowextsize(sc->mp, sc->ip->i_d.di_cowextsize,
			VFS_I(sc->ip)->i_mode, sc->ip->i_d.di_flags,
			sc->ip->i_d.di_flags2);
	if (!fa)
		return;

	sc->ip->i_d.di_cowextsize = 0;
	sc->ip->i_d.di_flags2 &= ~XFS_DIFLAG2_COWEXTSIZE;
}

/* Fix inode flags. */
STATIC void
xfs_repair_inode_flags(
	struct xfs_scrub_context	*sc)
{
	uint16_t			mode;

	mode = VFS_I(sc->ip)->i_mode;

	if (sc->ip->i_d.di_flags & ~XFS_DIFLAG_ANY)
		sc->ip->i_d.di_flags &= ~XFS_DIFLAG_ANY;

	if (sc->ip->i_ino == sc->mp->m_sb.sb_rbmino)
		sc->ip->i_d.di_flags |= XFS_DIFLAG_NEWRTBM;
	else
		sc->ip->i_d.di_flags &= ~XFS_DIFLAG_NEWRTBM;

	if (!S_ISDIR(mode))
		sc->ip->i_d.di_flags &= ~(XFS_DIFLAG_RTINHERIT |
					  XFS_DIFLAG_EXTSZINHERIT |
					  XFS_DIFLAG_PROJINHERIT |
					  XFS_DIFLAG_NOSYMLINKS);
	if (!S_ISREG(mode))
		sc->ip->i_d.di_flags &= ~(XFS_DIFLAG_REALTIME |
					  XFS_DIFLAG_EXTSIZE);

	if (sc->ip->i_d.di_flags & XFS_DIFLAG_REALTIME)
		sc->ip->i_d.di_flags &= ~XFS_DIFLAG_FILESTREAM;
}

/* Fix inode flags2 */
STATIC void
xfs_repair_inode_flags2(
	struct xfs_scrub_context	*sc)
{
	struct xfs_mount		*mp = sc->mp;
	uint16_t			mode;

	if (sc->ip->i_d.di_version < 3)
		return;

	mode = VFS_I(sc->ip)->i_mode;

	if (sc->ip->i_d.di_flags2 & ~XFS_DIFLAG2_ANY)
		sc->ip->i_d.di_flags2 &= ~XFS_DIFLAG2_ANY;

	if (!xfs_sb_version_hasreflink(&mp->m_sb) ||
	    !S_ISREG(mode))
		sc->ip->i_d.di_flags2 &= ~XFS_DIFLAG2_REFLINK;

	if (!(S_ISREG(mode) || S_ISDIR(mode)))
		sc->ip->i_d.di_flags2 &= ~XFS_DIFLAG2_DAX;

	if (sc->ip->i_d.di_flags & XFS_DIFLAG_REALTIME)
		sc->ip->i_d.di_flags2 &= ~XFS_DIFLAG2_REFLINK;

	if (sc->ip->i_d.di_flags2 & XFS_DIFLAG2_REFLINK)
		sc->ip->i_d.di_flags2 &= ~XFS_DIFLAG2_DAX;
}

/* Repair an inode's fields. */
int
xfs_repair_inode(
	struct xfs_scrub_context	*sc)
{
	struct xfs_mount		*mp = sc->mp;
	struct xfs_inode		*ip;
	xfs_filblks_t			count;
	xfs_filblks_t			acount;
	xfs_extnum_t			nextents;
	uint16_t			flags;
	bool				invalidate_quota = false;
	int				error = 0;

	if (!xfs_sb_version_hascrc(&mp->m_sb))
		return -EOPNOTSUPP;

	/* Skip inode core repair if w're here only for preening. */
	if (sc->ip &&
	    (sc->sm->sm_flags & XFS_SCRUB_OFLAG_PREEN) &&
	    !(sc->sm->sm_flags & XFS_SCRUB_OFLAG_CORRUPT) &&
	    !(sc->sm->sm_flags & XFS_SCRUB_OFLAG_XCORRUPT))
		goto preen_only;

	if (!sc->ip) {
		error = xfs_repair_inode_core(sc);
		if (error)
			goto out;
		if (XFS_IS_UQUOTA_ON(mp) || XFS_IS_GQUOTA_ON(mp))
			invalidate_quota = true;
	}
	ASSERT(sc->ip);

	ip = sc->ip;
	xfs_trans_ijoin(sc->tp, ip, 0);

	/* di_[acm]time.nsec */
	if ((unsigned long)VFS_I(ip)->i_atime.tv_nsec >= NSEC_PER_SEC)
		VFS_I(ip)->i_atime.tv_nsec = 0;
	if ((unsigned long)VFS_I(ip)->i_mtime.tv_nsec >= NSEC_PER_SEC)
		VFS_I(ip)->i_mtime.tv_nsec = 0;
	if ((unsigned long)VFS_I(ip)->i_ctime.tv_nsec >= NSEC_PER_SEC)
		VFS_I(ip)->i_ctime.tv_nsec = 0;
	if (ip->i_d.di_version > 2 &&
	    (unsigned long)ip->i_d.di_crtime.t_nsec >= NSEC_PER_SEC)
		ip->i_d.di_crtime.t_nsec = 0;

	/* di_size */
	if (!S_ISDIR(VFS_I(ip)->i_mode) && !S_ISREG(VFS_I(ip)->i_mode) &&
	    !S_ISLNK(VFS_I(ip)->i_mode)) {
		i_size_write(VFS_I(ip), 0);
		ip->i_d.di_size = 0;
	}

	/* di_flags */
	flags = ip->i_d.di_flags;
	if ((flags & XFS_DIFLAG_IMMUTABLE) && (flags & XFS_DIFLAG_APPEND))
		flags &= ~XFS_DIFLAG_APPEND;

	if ((flags & XFS_DIFLAG_FILESTREAM) && (flags & XFS_DIFLAG_REALTIME))
		flags &= ~XFS_DIFLAG_FILESTREAM;
	ip->i_d.di_flags = flags;

	/* di_nblocks/di_nextents/di_anextents */
	error = xfs_bmap_count_blocks(sc->tp, sc->ip, XFS_DATA_FORK,
			&nextents, &count);
	if (error)
		goto out;
	ip->i_d.di_nextents = nextents;

	error = xfs_bmap_count_blocks(sc->tp, sc->ip, XFS_ATTR_FORK,
			&nextents, &acount);
	if (error)
		goto out;
	ip->i_d.di_anextents = nextents;

	ip->i_d.di_nblocks = count + acount;
	if (ip->i_d.di_anextents != 0 && ip->i_d.di_forkoff == 0)
		ip->i_d.di_anextents = 0;

	/* Invalid uid/gid? */
	if (ip->i_d.di_uid == -1U) {
		ip->i_d.di_uid = 0;
		VFS_I(ip)->i_mode &= ~(S_ISUID | S_ISGID);
		if (XFS_IS_UQUOTA_ON(mp))
			invalidate_quota = true;
	}
	if (ip->i_d.di_gid == -1U) {
		ip->i_d.di_gid = 0;
		VFS_I(ip)->i_mode &= ~(S_ISUID | S_ISGID);
		if (XFS_IS_GQUOTA_ON(mp))
			invalidate_quota = true;
	}

	/* Invalid flags? */
	xfs_repair_inode_flags(sc);
	xfs_repair_inode_flags2(sc);

	/* Invalid extent size hints? */
	xfs_repair_inode_extsize(sc);
	xfs_repair_inode_cowextsize(sc);

	/* Commit inode core changes. */
	xfs_trans_log_inode(sc->tp, ip, XFS_ILOG_CORE);
	error = xfs_trans_roll_inode(&sc->tp, ip);
	if (error)
		goto out;

	/* We changed uid/gid, force a quotacheck. */
	if (invalidate_quota) {
		mp->m_qflags &= ~XFS_ALL_QUOTA_CHKD;
		spin_lock(&mp->m_sb_lock);
		mp->m_sb.sb_qflags = mp->m_qflags & XFS_MOUNT_QUOTA_ALL;
		spin_unlock(&mp->m_sb_lock);
		xfs_log_sb(sc->tp);
	}

preen_only:
	if (xfs_is_reflink_inode(sc->ip))
		return xfs_reflink_clear_inode_flag(sc->ip, &sc->tp);

out:
	return error;
}
