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
#include "repair/common.h"

/* Superblock */

#define XFS_SCRUB_SB_CHECK(fs_ok) \
	XFS_SCRUB_CHECK(sc, bp, "superblock", fs_ok)
#define XFS_SCRUB_SB_PREEN(fs_ok) \
	XFS_SCRUB_PREEN(sc, bp, "superblock", fs_ok)
#define XFS_SCRUB_SB_OP_ERROR_GOTO(label) \
	XFS_SCRUB_OP_ERROR_GOTO(sc, agno, 0, "superblock", &error, out)
/* Scrub the filesystem superblock. */
int
xfs_scrub_superblock(
	struct xfs_scrub_context	*sc)
{
	struct xfs_mount		*mp = sc->tp->t_mountp;
	struct xfs_buf			*bp;
	struct xfs_sb			sb;
	xfs_agnumber_t			agno;
	uint32_t			v2_ok;
	int				error;

	agno = sc->sm->sm_agno;

	error = xfs_trans_read_buf(mp, sc->tp, mp->m_ddev_targp,
		  XFS_AGB_TO_DADDR(mp, agno, XFS_SB_BLOCK(mp)),
		  XFS_FSS_TO_BB(mp, 1), 0, &bp, &xfs_sb_buf_ops);
	if (error) {
		trace_xfs_scrub_block_error(mp, agno, XFS_SB_BLOCK(mp),
				"superblock", "error != 0", __func__, __LINE__);
		error = 0;
		sc->sm->sm_flags |= XFS_SCRUB_FLAG_CORRUPT;
		goto out;
	}

	/*
	 * The in-core sb is a more up-to-date copy of AG 0's sb,
	 * so there's no point in comparing the two.
	 */
	if (agno == 0)
		goto out;

	xfs_sb_from_disk(&sb, XFS_BUF_TO_SBP(bp));

	/* Verify the geometries match. */
#define XFS_SCRUB_SB_FIELD(fn) \
		XFS_SCRUB_SB_CHECK(sb.sb_##fn == mp->m_sb.sb_##fn)
#define XFS_PREEN_SB_FIELD(fn) \
		XFS_SCRUB_SB_PREEN(sb.sb_##fn == mp->m_sb.sb_##fn)
	XFS_SCRUB_SB_FIELD(blocksize);
	XFS_SCRUB_SB_FIELD(dblocks);
	XFS_SCRUB_SB_FIELD(rblocks);
	XFS_SCRUB_SB_FIELD(rextents);
	XFS_SCRUB_SB_PREEN(uuid_equal(&sb.sb_uuid, &mp->m_sb.sb_uuid));
	XFS_SCRUB_SB_FIELD(logstart);
	XFS_PREEN_SB_FIELD(rootino);
	XFS_PREEN_SB_FIELD(rbmino);
	XFS_PREEN_SB_FIELD(rsumino);
	XFS_SCRUB_SB_FIELD(rextsize);
	XFS_SCRUB_SB_FIELD(agblocks);
	XFS_SCRUB_SB_FIELD(agcount);
	XFS_SCRUB_SB_FIELD(rbmblocks);
	XFS_SCRUB_SB_FIELD(logblocks);
	XFS_SCRUB_SB_CHECK(!(sb.sb_versionnum & ~XFS_SB_VERSION_OKBITS));
	XFS_SCRUB_SB_CHECK(XFS_SB_VERSION_NUM(&sb) ==
			   XFS_SB_VERSION_NUM(&mp->m_sb));
	XFS_SCRUB_SB_FIELD(sectsize);
	XFS_SCRUB_SB_FIELD(inodesize);
	XFS_SCRUB_SB_FIELD(inopblock);
	XFS_SCRUB_SB_PREEN(memcmp(sb.sb_fname, mp->m_sb.sb_fname,
			   sizeof(sb.sb_fname)) == 0);
	XFS_SCRUB_SB_FIELD(blocklog);
	XFS_SCRUB_SB_FIELD(sectlog);
	XFS_SCRUB_SB_FIELD(inodelog);
	XFS_SCRUB_SB_FIELD(inopblog);
	XFS_SCRUB_SB_FIELD(agblklog);
	XFS_SCRUB_SB_FIELD(rextslog);
	XFS_PREEN_SB_FIELD(imax_pct);
	XFS_PREEN_SB_FIELD(uquotino);
	XFS_PREEN_SB_FIELD(gquotino);
	XFS_SCRUB_SB_FIELD(shared_vn);
	XFS_SCRUB_SB_FIELD(inoalignmt);
	XFS_PREEN_SB_FIELD(unit);
	XFS_PREEN_SB_FIELD(width);
	XFS_SCRUB_SB_FIELD(dirblklog);
	XFS_SCRUB_SB_FIELD(logsectlog);
	XFS_SCRUB_SB_FIELD(logsectsize);
	XFS_SCRUB_SB_FIELD(logsunit);
	v2_ok = XFS_SB_VERSION2_OKBITS;
	if (XFS_SB_VERSION_NUM(&sb) >= XFS_SB_VERSION_5)
		v2_ok |= XFS_SB_VERSION2_CRCBIT;
	XFS_SCRUB_SB_CHECK(!(sb.sb_features2 & ~v2_ok));
	XFS_SCRUB_SB_PREEN(sb.sb_features2 != sb.sb_bad_features2);
	XFS_SCRUB_SB_CHECK(!sb.sb_features2 ||
			xfs_sb_version_hasmorebits(&mp->m_sb));
	if (xfs_sb_version_hascrc(&mp->m_sb)) {
		XFS_SCRUB_SB_CHECK(!xfs_sb_has_compat_feature(&sb,
				XFS_SB_FEAT_COMPAT_UNKNOWN));
		XFS_SCRUB_SB_CHECK(!xfs_sb_has_ro_compat_feature(&sb,
				XFS_SB_FEAT_RO_COMPAT_UNKNOWN));
		XFS_SCRUB_SB_CHECK(!xfs_sb_has_incompat_feature(&sb,
				XFS_SB_FEAT_INCOMPAT_UNKNOWN));
		XFS_SCRUB_SB_CHECK(!xfs_sb_has_incompat_log_feature(&sb,
				XFS_SB_FEAT_INCOMPAT_LOG_UNKNOWN));
		XFS_SCRUB_SB_FIELD(spino_align);
		XFS_PREEN_SB_FIELD(pquotino);
	}
	if (xfs_sb_version_hasmetauuid(&mp->m_sb))
		XFS_SCRUB_SB_CHECK(uuid_equal(&sb.sb_meta_uuid,
					&mp->m_sb.sb_meta_uuid));
	else
		XFS_SCRUB_SB_CHECK(uuid_equal(&sb.sb_uuid,
					&mp->m_sb.sb_meta_uuid));
#undef XFS_SCRUB_SB_FIELD

#define XFS_SCRUB_SB_FEAT(fn) \
		XFS_SCRUB_SB_CHECK(xfs_sb_version_has##fn(&sb) == \
		xfs_sb_version_has##fn(&mp->m_sb))
	XFS_SCRUB_SB_FEAT(align);
	XFS_SCRUB_SB_FEAT(dalign);
	XFS_SCRUB_SB_FEAT(logv2);
	XFS_SCRUB_SB_FEAT(extflgbit);
	XFS_SCRUB_SB_FEAT(sector);
	XFS_SCRUB_SB_FEAT(asciici);
	XFS_SCRUB_SB_FEAT(morebits);
	XFS_SCRUB_SB_FEAT(lazysbcount);
	XFS_SCRUB_SB_FEAT(crc);
	XFS_SCRUB_SB_FEAT(_pquotino);
	XFS_SCRUB_SB_FEAT(ftype);
	XFS_SCRUB_SB_FEAT(finobt);
	XFS_SCRUB_SB_FEAT(sparseinodes);
	XFS_SCRUB_SB_FEAT(metauuid);
	XFS_SCRUB_SB_FEAT(rmapbt);
	XFS_SCRUB_SB_FEAT(reflink);
#undef XFS_SCRUB_SB_FEAT

out:
	return error;
}
#undef XFS_SCRUB_SB_OP_ERROR_GOTO
#undef XFS_SCRUB_SB_CHECK
