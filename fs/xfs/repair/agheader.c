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
#include "xfs_ialloc.h"
#include "xfs_rmap.h"
#include "xfs_refcount.h"
#include "repair/common.h"

/* Find the size of the AG, in blocks. */
static inline xfs_agblock_t
xfs_scrub_ag_blocks(
	struct xfs_mount	*mp,
	xfs_agnumber_t		agno)
{
	ASSERT(agno < mp->m_sb.sb_agcount);

	if (agno < mp->m_sb.sb_agcount - 1)
		return mp->m_sb.sb_agblocks;
	return mp->m_sb.sb_dblocks - (agno * mp->m_sb.sb_agblocks);
}

/* Walk all the blocks in the AGFL. */
int
xfs_scrub_walk_agfl(
	struct xfs_scrub_context	*sc,
	int				(*fn)(struct xfs_scrub_context *,
					      xfs_agblock_t bno, void *),
	void				*priv)
{
	struct xfs_agf			*agf;
	__be32				*agfl_bno;
	struct xfs_mount		*mp = sc->tp->t_mountp;
	unsigned int			flfirst;
	unsigned int			fllast;
	int				i;
	int				error;

	agf = XFS_BUF_TO_AGF(sc->sa.agf_bp);
	agfl_bno = XFS_BUF_TO_AGFL_BNO(mp, sc->sa.agfl_bp);
	flfirst = be32_to_cpu(agf->agf_flfirst);
	fllast = be32_to_cpu(agf->agf_fllast);

	/* Skip an empty AGFL. */
	if (agf->agf_flcount == cpu_to_be32(0))
		return 0;

	/* first to last is a consecutive list. */
	if (fllast >= flfirst) {
		for (i = flfirst; i <= fllast; i++) {
			error = fn(sc, be32_to_cpu(agfl_bno[i]), priv);
			if (error)
				return error;
		}

		return 0;
	}

	/* first to the end */
	for (i = flfirst; i < XFS_AGFL_SIZE(mp); i++) {
		error = fn(sc, be32_to_cpu(agfl_bno[i]), priv);
		if (error)
			return error;
	}

	/* the start to last. */
	for (i = 0; i <= fllast; i++) {
		error = fn(sc, be32_to_cpu(agfl_bno[i]), priv);
		if (error)
			return error;
	}

	return 0;
}

/* Does this AG extent cover the AG headers? */
bool
xfs_scrub_extent_covers_ag_head(
	struct xfs_mount	*mp,
	xfs_agblock_t		agbno,
	xfs_extlen_t		len)
{
	xfs_agblock_t		bno;

	bno = XFS_SB_BLOCK(mp);
	if (bno >= agbno && bno < agbno + len)
		return true;
	bno = XFS_AGF_BLOCK(mp);
	if (bno >= agbno && bno < agbno + len)
		return true;
	bno = XFS_AGFL_BLOCK(mp);
	if (bno >= agbno && bno < agbno + len)
		return true;
	bno = XFS_AGI_BLOCK(mp);
	if (bno >= agbno && bno < agbno + len)
		return true;
	return false;
}

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
	struct xfs_scrub_ag		*psa;
	struct xfs_sb			sb;
	struct xfs_owner_info		oinfo;
	xfs_agnumber_t			agno;
	uint32_t			v2_ok;
	bool				is_freesp;
	bool				has_inodes;
	bool				has_rmap;
	bool				has_refcount;
	int				error;
	int				err2;

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
		goto btree_xref;

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
	XFS_SCRUB_SB_FEAT(realtime);
#undef XFS_SCRUB_SB_FEAT

	if (error)
		goto out;

btree_xref:

	err2 = xfs_scrub_ag_init(sc, agno, &sc->sa);
	if (!xfs_scrub_should_xref(sc, err2, NULL))
		goto out;

	psa = &sc->sa;
	/* Cross-reference with bnobt. */
	if (psa->bno_cur) {
		err2 = xfs_alloc_has_record(psa->bno_cur, XFS_SB_BLOCK(mp),
				1, &is_freesp);
		if (xfs_scrub_should_xref(sc, err2, &psa->bno_cur))
			XFS_SCRUB_SB_CHECK(!is_freesp);
	}

	/* Cross-reference with inobt. */
	if (psa->ino_cur) {
		err2 = xfs_ialloc_has_inodes_at_extent(psa->ino_cur,
				XFS_SB_BLOCK(mp), 1, &has_inodes);
		if (xfs_scrub_should_xref(sc, err2, &psa->ino_cur))
			XFS_SCRUB_SB_CHECK(!has_inodes);
	}

	/* Cross-reference with finobt. */
	if (psa->fino_cur) {
		err2 = xfs_ialloc_has_inodes_at_extent(psa->fino_cur,
				XFS_SB_BLOCK(mp), 1, &has_inodes);
		if (xfs_scrub_should_xref(sc, err2, &psa->fino_cur))
			XFS_SCRUB_SB_CHECK(!has_inodes);
	}

	/* Cross-reference with the rmapbt. */
	if (psa->rmap_cur) {
		xfs_rmap_ag_owner(&oinfo, XFS_RMAP_OWN_FS);
		err2 = xfs_rmap_record_exists(psa->rmap_cur, XFS_SB_BLOCK(mp),
				1, &oinfo, &has_rmap);
		if (xfs_scrub_should_xref(sc, err2, &psa->rmap_cur))
			XFS_SCRUB_SB_CHECK(has_rmap);
	}

	/* Cross-reference with the refcountbt. */
	if (psa->refc_cur) {
		err2 = xfs_refcount_has_record(psa->refc_cur, XFS_SB_BLOCK(mp),
				1, &has_refcount);
		if (xfs_scrub_should_xref(sc, err2, &psa->refc_cur))
			XFS_SCRUB_SB_CHECK(!has_refcount);
	}

out:
	return error;
}
#undef XFS_SCRUB_SB_OP_ERROR_GOTO
#undef XFS_SCRUB_SB_CHECK

/* Repair the superblock. */
int
xfs_repair_superblock(
	struct xfs_scrub_context	*sc)
{
	struct xfs_mount		*mp = sc->tp->t_mountp;
	struct xfs_buf			*bp;
	struct xfs_dsb			*sbp;
	xfs_agnumber_t			agno;
	int				error;

	/* Don't try to repair AG 0's sb; let xfs_repair deal with it. */
	agno = sc->sm->sm_agno;
	if (agno == 0)
		return -ENOTTY;

	error = xfs_trans_read_buf(mp, sc->tp, mp->m_ddev_targp,
		  XFS_AG_DADDR(mp, agno, XFS_SB_BLOCK(mp)),
		  XFS_FSS_TO_BB(mp, 1), 0, &bp, NULL);
	if (error)
		return error;
	bp->b_ops = &xfs_sb_buf_ops;

	/* Copy AG 0's superblock to this one. */
	sbp = XFS_BUF_TO_SBP(bp);
	memset(sbp, 0, mp->m_sb.sb_sectsize);
	xfs_sb_to_disk(sbp, &mp->m_sb);

	/* Write this to disk. */
	xfs_trans_buf_set_type(sc->tp, bp, XFS_BLFT_SB_BUF);
	xfs_trans_log_buf(sc->tp, bp, 0, mp->m_sb.sb_sectsize - 1);
	return error;
}

/* AGF */

/* Tally freespace record lengths. */
STATIC int
xfs_scrub_agf_record_bno_lengths(
	struct xfs_btree_cur		*cur,
	struct xfs_alloc_rec_incore	*rec,
	void				*priv)
{
	xfs_extlen_t			*blocks = priv;

	(*blocks) += rec->ar_blockcount;
	return 0;
}

#define XFS_SCRUB_AGF_CHECK(fs_ok) \
	XFS_SCRUB_CHECK(sc, sc->sa.agf_bp, "AGF", fs_ok)
#define XFS_SCRUB_AGF_OP_ERROR_GOTO(error, label) \
	XFS_SCRUB_OP_ERROR_GOTO(sc, sc->sm->sm_agno, \
			XFS_AGF_BLOCK(sc->tp->t_mountp), "AGF", error, label)
/* Scrub the AGF. */
int
xfs_scrub_agf(
	struct xfs_scrub_context	*sc)
{
	struct xfs_owner_info		oinfo;
	struct xfs_mount		*mp = sc->tp->t_mountp;
	struct xfs_agf			*agf;
	struct xfs_scrub_ag		*psa;
	xfs_daddr_t			daddr;
	xfs_daddr_t			eofs;
	xfs_agnumber_t			agno;
	xfs_agblock_t			agbno;
	xfs_agblock_t			eoag;
	xfs_agblock_t			agfl_first;
	xfs_agblock_t			agfl_last;
	xfs_agblock_t			agfl_count;
	xfs_agblock_t			fl_count;
	xfs_extlen_t			blocks;
	xfs_extlen_t			btreeblks = 0;
	bool				is_freesp;
	bool				has_inodes;
	bool				has_rmap;
	bool				has_refcount;
	int				have;
	int				level;
	int				error = 0;
	int				err2;

	agno = sc->sm->sm_agno;
	error = xfs_scrub_load_ag_headers(sc, agno, XFS_SCRUB_TYPE_AGF);
	XFS_SCRUB_AGF_OP_ERROR_GOTO(&error, out);

	agf = XFS_BUF_TO_AGF(sc->sa.agf_bp);
	eofs = XFS_FSB_TO_BB(mp, mp->m_sb.sb_dblocks);

	/* Check the AG length */
	eoag = be32_to_cpu(agf->agf_length);
	XFS_SCRUB_AGF_CHECK(eoag == xfs_scrub_ag_blocks(mp, agno));

	/* Check the AGF btree roots and levels */
	agbno = be32_to_cpu(agf->agf_roots[XFS_BTNUM_BNO]);
	daddr = XFS_AGB_TO_DADDR(mp, agno, agbno);
	XFS_SCRUB_AGF_CHECK(agbno > XFS_AGI_BLOCK(mp));
	XFS_SCRUB_AGF_CHECK(agbno < mp->m_sb.sb_agblocks);
	XFS_SCRUB_AGF_CHECK(agbno < eoag);
	XFS_SCRUB_AGF_CHECK(daddr < eofs);

	agbno = be32_to_cpu(agf->agf_roots[XFS_BTNUM_CNT]);
	daddr = XFS_AGB_TO_DADDR(mp, agno, agbno);
	XFS_SCRUB_AGF_CHECK(agbno > XFS_AGI_BLOCK(mp));
	XFS_SCRUB_AGF_CHECK(agbno < mp->m_sb.sb_agblocks);
	XFS_SCRUB_AGF_CHECK(agbno < eoag);
	XFS_SCRUB_AGF_CHECK(daddr < eofs);

	level = be32_to_cpu(agf->agf_levels[XFS_BTNUM_BNO]);
	XFS_SCRUB_AGF_CHECK(level > 0);
	XFS_SCRUB_AGF_CHECK(level <= XFS_BTREE_MAXLEVELS);

	level = be32_to_cpu(agf->agf_levels[XFS_BTNUM_CNT]);
	XFS_SCRUB_AGF_CHECK(level > 0);
	XFS_SCRUB_AGF_CHECK(level <= XFS_BTREE_MAXLEVELS);

	if (xfs_sb_version_hasrmapbt(&mp->m_sb)) {
		agbno = be32_to_cpu(agf->agf_roots[XFS_BTNUM_RMAP]);
		daddr = XFS_AGB_TO_DADDR(mp, agno, agbno);
		XFS_SCRUB_AGF_CHECK(agbno > XFS_AGI_BLOCK(mp));
		XFS_SCRUB_AGF_CHECK(agbno < mp->m_sb.sb_agblocks);
		XFS_SCRUB_AGF_CHECK(agbno < eoag);
		XFS_SCRUB_AGF_CHECK(daddr < eofs);

		level = be32_to_cpu(agf->agf_levels[XFS_BTNUM_RMAP]);
		XFS_SCRUB_AGF_CHECK(level > 0);
		XFS_SCRUB_AGF_CHECK(level <= XFS_BTREE_MAXLEVELS);
	}

	if (xfs_sb_version_hasreflink(&mp->m_sb)) {
		agbno = be32_to_cpu(agf->agf_refcount_root);
		daddr = XFS_AGB_TO_DADDR(mp, agno, agbno);
		XFS_SCRUB_AGF_CHECK(agbno > XFS_AGI_BLOCK(mp));
		XFS_SCRUB_AGF_CHECK(agbno < mp->m_sb.sb_agblocks);
		XFS_SCRUB_AGF_CHECK(agbno < eoag);
		XFS_SCRUB_AGF_CHECK(daddr < eofs);

		level = be32_to_cpu(agf->agf_refcount_level);
		XFS_SCRUB_AGF_CHECK(level > 0);
		XFS_SCRUB_AGF_CHECK(level <= XFS_BTREE_MAXLEVELS);
	}

	/* Check the AGFL counters */
	agfl_first = be32_to_cpu(agf->agf_flfirst);
	agfl_last = be32_to_cpu(agf->agf_fllast);
	agfl_count = be32_to_cpu(agf->agf_flcount);
	if (agfl_last > agfl_first)
		fl_count = agfl_last - agfl_first + 1;
	else
		fl_count = XFS_AGFL_SIZE(mp) - agfl_first + agfl_last + 1;
	XFS_SCRUB_AGF_CHECK(agfl_count == 0 || fl_count == agfl_count);

	/* Load btrees for xref if the AGF is ok. */
	psa = &sc->sa;
	if (error || (sc->sm->sm_flags & XFS_SCRUB_FLAG_CORRUPT))
		goto out;
	error = xfs_scrub_ag_btcur_init(sc, psa);
	if (error)
		goto out;

	/* Cross-reference with the bnobt. */
	if (psa->bno_cur) {
		err2 = xfs_alloc_has_record(psa->bno_cur, XFS_AGF_BLOCK(mp),
				1, &is_freesp);
		if (!xfs_scrub_should_xref(sc, err2, &psa->bno_cur))
			goto skip_bnobt;
		XFS_SCRUB_AGF_CHECK(!is_freesp);

		blocks = 0;
		err2 = xfs_alloc_query_all(psa->bno_cur,
				xfs_scrub_agf_record_bno_lengths, &blocks);
		if (!xfs_scrub_should_xref(sc, err2, &psa->bno_cur))
			goto skip_bnobt;
		XFS_SCRUB_AGF_CHECK(blocks == be32_to_cpu(agf->agf_freeblks));
	}
skip_bnobt:

	/* Cross-reference with the cntbt. */
	if (psa->cnt_cur) {
		err2 = xfs_alloc_lookup_le(psa->cnt_cur, 0, -1U, &have);
		if (!xfs_scrub_should_xref(sc, err2, &psa->cnt_cur))
			goto skip_cntbt;
		if (!have) {
			XFS_SCRUB_AGF_CHECK(agf->agf_freeblks ==
					be32_to_cpu(0));
			goto skip_cntbt;
		}
		err2 = xfs_alloc_get_rec(psa->cnt_cur, &agbno, &blocks, &have);
		if (!xfs_scrub_should_xref(sc, err2, &psa->cnt_cur))
			goto skip_cntbt;
		XFS_SCRUB_AGF_CHECK(have);
		XFS_SCRUB_AGF_CHECK(!have ||
				blocks == be32_to_cpu(agf->agf_longest));
	}
skip_cntbt:

	/* Cross-reference with inobt. */
	if (psa->ino_cur) {
		err2 = xfs_ialloc_has_inodes_at_extent(psa->ino_cur,
				XFS_AGF_BLOCK(mp), 1, &has_inodes);
		if (xfs_scrub_should_xref(sc, err2, &psa->ino_cur))
			XFS_SCRUB_AGF_CHECK(!has_inodes);
	}

	/* Cross-reference with finobt. */
	if (psa->fino_cur) {
		err2 = xfs_ialloc_has_inodes_at_extent(psa->fino_cur,
				XFS_AGF_BLOCK(mp), 1, &has_inodes);
		if (xfs_scrub_should_xref(sc, err2, &psa->fino_cur))
			XFS_SCRUB_AGF_CHECK(!has_inodes);
	}

	/* Cross-reference with the rmapbt. */
	if (psa->rmap_cur) {
		xfs_rmap_ag_owner(&oinfo, XFS_RMAP_OWN_FS);
		err2 = xfs_rmap_record_exists(psa->rmap_cur, XFS_AGF_BLOCK(mp),
				1, &oinfo, &has_rmap);
		if (xfs_scrub_should_xref(sc, err2, &psa->rmap_cur))
			XFS_SCRUB_AGF_CHECK(has_rmap);
	}
	if (psa->rmap_cur) {
		err2 = xfs_btree_count_blocks(psa->rmap_cur, &blocks);
		if (xfs_scrub_should_xref(sc, err2, &psa->rmap_cur)) {
			btreeblks = blocks - 1;
			XFS_SCRUB_AGF_CHECK(blocks == be32_to_cpu(
					agf->agf_rmap_blocks));
		}
	}

	/* Check btreeblks */
	if ((!xfs_sb_version_hasrmapbt(&mp->m_sb) || psa->rmap_cur) &&
	    psa->bno_cur && psa->cnt_cur) {
		err2 = xfs_btree_count_blocks(psa->bno_cur, &blocks);
		if (xfs_scrub_should_xref(sc, err2, &psa->bno_cur))
			btreeblks += blocks - 1;
		err2 = xfs_btree_count_blocks(psa->cnt_cur, &blocks);
		if (xfs_scrub_should_xref(sc, err2, &psa->cnt_cur))
			btreeblks += blocks - 1;
		if (psa->bno_cur && psa->cnt_cur)
			XFS_SCRUB_AGF_CHECK(btreeblks == be32_to_cpu(
					agf->agf_btreeblks));
	}

	/* Cross-reference with the refcountbt. */
	if (psa->refc_cur) {
		err2 = xfs_refcount_has_record(psa->refc_cur, XFS_AGF_BLOCK(mp),
				1, &has_refcount);
		if (xfs_scrub_should_xref(sc, err2, &psa->refc_cur))
			XFS_SCRUB_AGF_CHECK(!has_refcount);
	}
	if (psa->refc_cur) {
		err2 = xfs_btree_count_blocks(psa->refc_cur, &blocks);
		if (xfs_scrub_should_xref(sc, err2, &psa->refc_cur))
			XFS_SCRUB_AGF_CHECK(blocks == be32_to_cpu(
					agf->agf_refcount_blocks));
	}

out:
	return error;
}
#undef XFS_SCRUB_AGF_OP_ERROR_GOTO
#undef XFS_SCRUB_AGF_CHECK

/* AGFL */

#define XFS_SCRUB_AGFL_CHECK(fs_ok) \
	XFS_SCRUB_CHECK(sc, sc->sa.agfl_bp, "AGFL", fs_ok)
struct xfs_scrub_agfl {
	struct xfs_owner_info		oinfo;
	xfs_agblock_t			eoag;
	xfs_daddr_t			eofs;
};

/* Scrub an AGFL block. */
STATIC int
xfs_scrub_agfl_block(
	struct xfs_scrub_context	*sc,
	xfs_agblock_t			agbno,
	void				*priv)
{
	struct xfs_mount		*mp = sc->tp->t_mountp;
	xfs_agnumber_t			agno = sc->sa.agno;
	struct xfs_scrub_agfl		*sagfl = priv;
	bool				is_freesp;
	bool				has_inodes;
	bool				has_rmap;
	bool				has_refcount;
	int				err2;

	XFS_SCRUB_AGFL_CHECK(agbno > XFS_AGI_BLOCK(mp));
	XFS_SCRUB_AGFL_CHECK(XFS_AGB_TO_DADDR(mp, agno, agbno) < sagfl->eofs);
	XFS_SCRUB_AGFL_CHECK(agbno < mp->m_sb.sb_agblocks);
	XFS_SCRUB_AGFL_CHECK(agbno < sagfl->eoag);

	/* Cross-reference with the AG headers. */
	XFS_SCRUB_AGFL_CHECK(!xfs_scrub_extent_covers_ag_head(mp, agbno, 1));

	/* Cross-reference with the bnobt. */
	if (sc->sa.bno_cur) {
		err2 = xfs_alloc_has_record(sc->sa.bno_cur, agbno,
				1, &is_freesp);
		if (xfs_scrub_should_xref(sc, err2, &sc->sa.bno_cur))
			XFS_SCRUB_AGFL_CHECK(!is_freesp);
	}

	/* Cross-reference with inobt. */
	if (sc->sa.ino_cur) {
		err2 = xfs_ialloc_has_inodes_at_extent(sc->sa.ino_cur,
				agbno, 1, &has_inodes);
		if (xfs_scrub_should_xref(sc, err2, &sc->sa.ino_cur))
			XFS_SCRUB_AGFL_CHECK(!has_inodes);
	}

	/* Cross-reference with finobt. */
	if (sc->sa.fino_cur) {
		err2 = xfs_ialloc_has_inodes_at_extent(sc->sa.fino_cur,
				agbno, 1, &has_inodes);
		if (xfs_scrub_should_xref(sc, err2, &sc->sa.fino_cur))
			XFS_SCRUB_AGFL_CHECK(!has_inodes);
	}

	/* Cross-reference with the rmapbt. */
	if (sc->sa.rmap_cur) {
		err2 = xfs_rmap_record_exists(sc->sa.rmap_cur, agbno, 1,
				&sagfl->oinfo, &has_rmap);
		if (xfs_scrub_should_xref(sc, err2, &sc->sa.rmap_cur))
			XFS_SCRUB_AGFL_CHECK(has_rmap);
	}

	/* Cross-reference with the refcountbt. */
	if (sc->sa.refc_cur) {
		err2 = xfs_refcount_has_record(sc->sa.refc_cur, agbno, 1,
				&has_refcount);
		if (xfs_scrub_should_xref(sc, err2, &sc->sa.refc_cur))
			XFS_SCRUB_AGFL_CHECK(!has_refcount);
	}

	return 0;
}

#define XFS_SCRUB_AGFL_OP_ERROR_GOTO(error, label) \
	XFS_SCRUB_OP_ERROR_GOTO(sc, sc->sm->sm_agno, \
			XFS_AGFL_BLOCK(sc->tp->t_mountp), "AGFL", error, label)
/* Scrub the AGFL. */
int
xfs_scrub_agfl(
	struct xfs_scrub_context	*sc)
{
	struct xfs_scrub_agfl		sagfl;
	struct xfs_mount		*mp = sc->tp->t_mountp;
	struct xfs_agf			*agf;
	bool				is_freesp;
	bool				has_inodes;
	bool				has_rmap;
	bool				has_refcount;
	int				error;
	int				err2;

	error = xfs_scrub_load_ag_headers(sc, sc->sm->sm_agno,
			XFS_SCRUB_TYPE_AGFL);
	XFS_SCRUB_AGFL_OP_ERROR_GOTO(&error, out);
	if (!sc->sa.agf_bp)
		return -EFSCORRUPTED;

	agf = XFS_BUF_TO_AGF(sc->sa.agf_bp);
	sagfl.eofs = XFS_FSB_TO_BB(mp, mp->m_sb.sb_dblocks);
	sagfl.eoag = be32_to_cpu(agf->agf_length);

	/* Cross-reference with the bnobt. */
	if (sc->sa.bno_cur) {
		err2 = xfs_alloc_has_record(sc->sa.bno_cur, XFS_AGFL_BLOCK(mp),
				1, &is_freesp);
		if (xfs_scrub_should_xref(sc, err2, &sc->sa.bno_cur))
			XFS_SCRUB_AGFL_CHECK(!is_freesp);
	}

	/* Cross-reference with inobt. */
	if (sc->sa.ino_cur) {
		err2 = xfs_ialloc_has_inodes_at_extent(sc->sa.ino_cur,
			XFS_AGFL_BLOCK(mp), 1, &has_inodes);
		if (xfs_scrub_should_xref(sc, err2, &sc->sa.ino_cur))
			XFS_SCRUB_AGFL_CHECK(!has_inodes);
	}

	/* Cross-reference with finobt. */
	if (sc->sa.fino_cur) {
		err2 = xfs_ialloc_has_inodes_at_extent(sc->sa.fino_cur,
				XFS_AGFL_BLOCK(mp), 1, &has_inodes);
		if (xfs_scrub_should_xref(sc, err2, &sc->sa.fino_cur))
			XFS_SCRUB_AGFL_CHECK(!has_inodes);
	}

	/* Set up cross-reference with rmapbt. */
	if (sc->sa.rmap_cur) {
		xfs_rmap_ag_owner(&sagfl.oinfo, XFS_RMAP_OWN_FS);
		err2 = xfs_rmap_record_exists(sc->sa.rmap_cur,
				XFS_AGFL_BLOCK(mp), 1, &sagfl.oinfo, &has_rmap);
		if (xfs_scrub_should_xref(sc, err2, &sc->sa.rmap_cur))
			XFS_SCRUB_AGFL_CHECK(has_rmap);
	}

	/* Set up cross-reference with refcountbt. */
	if (sc->sa.refc_cur) {
		err2 = xfs_refcount_has_record(sc->sa.refc_cur,
				XFS_AGFL_BLOCK(mp), 1, &has_refcount);
		if (xfs_scrub_should_xref(sc, err2, &sc->sa.refc_cur))
			XFS_SCRUB_AGFL_CHECK(!has_refcount);
	}

	/* Check the blocks in the AGFL. */
	xfs_rmap_ag_owner(&sagfl.oinfo, XFS_RMAP_OWN_AG);
	return xfs_scrub_walk_agfl(sc, xfs_scrub_agfl_block, &sagfl);
out:
	return error;
}
#undef XFS_SCRUB_AGFL_OP_ERROR_GOTO
#undef XFS_SCRUB_AGFL_CHECK

/* AGI */

#define XFS_SCRUB_AGI_CHECK(fs_ok) \
	XFS_SCRUB_CHECK(sc, sc->sa.agi_bp, "AGI", fs_ok)
#define XFS_SCRUB_AGI_OP_ERROR_GOTO(error, label) \
	XFS_SCRUB_OP_ERROR_GOTO(sc, sc->sm->sm_agno, \
			XFS_AGI_BLOCK(sc->tp->t_mountp), "AGI", error, label)
/* Scrub the AGI. */
int
xfs_scrub_agi(
	struct xfs_scrub_context	*sc)
{
	struct xfs_owner_info		oinfo;
	struct xfs_mount		*mp = sc->tp->t_mountp;
	struct xfs_agi			*agi;
	struct xfs_scrub_ag		*psa;
	xfs_daddr_t			daddr;
	xfs_daddr_t			eofs;
	xfs_agnumber_t			agno;
	xfs_agblock_t			agbno;
	xfs_agblock_t			eoag;
	xfs_agino_t			agino;
	xfs_agino_t			first_agino;
	xfs_agino_t			last_agino;
	xfs_agino_t			count;
	xfs_agino_t			freecount;
	bool				is_freesp;
	bool				has_inodes;
	bool				has_rmap;
	bool				has_refcount;
	int				i;
	int				level;
	int				error = 0;
	int				err2;

	agno = sc->sm->sm_agno;
	error = xfs_scrub_load_ag_headers(sc, agno, XFS_SCRUB_TYPE_AGI);
	XFS_SCRUB_AGI_OP_ERROR_GOTO(&error, out);

	agi = XFS_BUF_TO_AGI(sc->sa.agi_bp);
	eofs = XFS_FSB_TO_BB(mp, mp->m_sb.sb_dblocks);

	/* Check the AG length */
	eoag = be32_to_cpu(agi->agi_length);
	XFS_SCRUB_AGI_CHECK(eoag == xfs_scrub_ag_blocks(mp, agno));

	/* Check btree roots and levels */
	agbno = be32_to_cpu(agi->agi_root);
	daddr = XFS_AGB_TO_DADDR(mp, agno, agbno);
	XFS_SCRUB_AGI_CHECK(agbno > XFS_AGI_BLOCK(mp));
	XFS_SCRUB_AGI_CHECK(agbno < mp->m_sb.sb_agblocks);
	XFS_SCRUB_AGI_CHECK(agbno < eoag);
	XFS_SCRUB_AGI_CHECK(daddr < eofs);

	level = be32_to_cpu(agi->agi_level);
	XFS_SCRUB_AGI_CHECK(level > 0);
	XFS_SCRUB_AGI_CHECK(level <= XFS_BTREE_MAXLEVELS);

	if (xfs_sb_version_hasfinobt(&mp->m_sb)) {
		agbno = be32_to_cpu(agi->agi_free_root);
		daddr = XFS_AGB_TO_DADDR(mp, agno, agbno);
		XFS_SCRUB_AGI_CHECK(agbno > XFS_AGI_BLOCK(mp));
		XFS_SCRUB_AGI_CHECK(agbno < mp->m_sb.sb_agblocks);
		XFS_SCRUB_AGI_CHECK(agbno < eoag);
		XFS_SCRUB_AGI_CHECK(daddr < eofs);

		level = be32_to_cpu(agi->agi_free_level);
		XFS_SCRUB_AGI_CHECK(level > 0);
		XFS_SCRUB_AGI_CHECK(level <= XFS_BTREE_MAXLEVELS);
	}

	/* Check inode counters */
	first_agino = XFS_OFFBNO_TO_AGINO(mp, XFS_AGI_BLOCK(mp) + 1, 0);
	last_agino = XFS_OFFBNO_TO_AGINO(mp, eoag + 1, 0) - 1;
	agino = be32_to_cpu(agi->agi_count);
	XFS_SCRUB_AGI_CHECK(agino <= last_agino - first_agino + 1);
	XFS_SCRUB_AGI_CHECK(agino >= be32_to_cpu(agi->agi_freecount));

	/* Check inode pointers */
	agino = be32_to_cpu(agi->agi_newino);
	if (agino != NULLAGINO) {
		XFS_SCRUB_AGI_CHECK(agino >= first_agino);
		XFS_SCRUB_AGI_CHECK(agino <= last_agino);
	}
	agino = be32_to_cpu(agi->agi_dirino);
	if (agino != NULLAGINO) {
		XFS_SCRUB_AGI_CHECK(agino >= first_agino);
		XFS_SCRUB_AGI_CHECK(agino <= last_agino);
	}

	/* Check unlinked inode buckets */
	for (i = 0; i < XFS_AGI_UNLINKED_BUCKETS; i++) {
		agino = be32_to_cpu(agi->agi_unlinked[i]);
		if (agino == NULLAGINO)
			continue;
		XFS_SCRUB_AGI_CHECK(agino >= first_agino);
		XFS_SCRUB_AGI_CHECK(agino <= last_agino);
	}

	/* Load btrees for xref if the AGI is ok. */
	psa = &sc->sa;
	if (error || (sc->sm->sm_flags & XFS_SCRUB_FLAG_CORRUPT))
		goto out;
	error = xfs_scrub_ag_btcur_init(sc, &sc->sa);
	if (error)
		goto out;

	/* Cross-reference with bnobt. */
	if (psa->bno_cur) {
		err2 = xfs_alloc_has_record(psa->bno_cur, XFS_AGI_BLOCK(mp),
				1, &is_freesp);
		if (xfs_scrub_should_xref(sc, err2, &psa->bno_cur))
			XFS_SCRUB_AGI_CHECK(!is_freesp);
	}

	/* Cross-reference with inobt. */
	if (psa->ino_cur) {
		err2 = xfs_ialloc_has_inodes_at_extent(psa->ino_cur,
				XFS_AGI_BLOCK(mp), 1, &has_inodes);
		if (!xfs_scrub_should_xref(sc, err2, &psa->ino_cur))
			goto skip_inobt_xref;
		XFS_SCRUB_AGI_CHECK(!has_inodes);
		err2 = xfs_ialloc_count_inodes(psa->ino_cur, &count,
				&freecount);
		if (xfs_scrub_should_xref(sc, err2, &psa->ino_cur)) {
			XFS_SCRUB_AGI_CHECK(be32_to_cpu(agi->agi_count) ==
					count);
			XFS_SCRUB_AGI_CHECK(be32_to_cpu(agi->agi_freecount) ==
					freecount);
		}
	}

skip_inobt_xref:
	/* Cross-reference with finobt. */
	if (psa->fino_cur) {
		err2 = xfs_ialloc_has_inodes_at_extent(psa->fino_cur,
				XFS_AGI_BLOCK(mp), 1, &has_inodes);
		if (xfs_scrub_should_xref(sc, err2, &psa->fino_cur))
			XFS_SCRUB_AGI_CHECK(!has_inodes);
	}

	/* Cross-reference with the rmapbt. */
	if (psa->rmap_cur) {
		xfs_rmap_ag_owner(&oinfo, XFS_RMAP_OWN_FS);
		err2 = xfs_rmap_record_exists(psa->rmap_cur, XFS_AGI_BLOCK(mp),
				1, &oinfo, &has_rmap);
		if (xfs_scrub_should_xref(sc, err2, &psa->rmap_cur))
			XFS_SCRUB_AGI_CHECK(has_rmap);
	}

	/* Cross-reference with the refcountbt. */
	if (psa->refc_cur) {
		err2 = xfs_refcount_has_record(psa->refc_cur, XFS_AGI_BLOCK(mp),
				1, &has_refcount);
		if (xfs_scrub_should_xref(sc, err2, &psa->refc_cur))
			XFS_SCRUB_AGI_CHECK(!has_refcount);
	}

out:
	return error;
}
#undef XFS_SCRUB_AGI_CHECK
