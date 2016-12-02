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
#include "xfs_da_format.h"
#include "xfs_da_btree.h"
#include "xfs_dir2.h"
#include "xfs_dir2_priv.h"
#include "repair/common.h"
#include "repair/dabtree.h"

/* Directories */

/* Scrub a directory entry. */

struct xfs_scrub_dir_ctx {
	struct dir_context		dc;
	struct xfs_scrub_context	*sc;
};

#define XFS_SCRUB_DIR_CHECK(fs_ok) \
	XFS_SCRUB_DATA_CHECK(sdc->sc, XFS_DATA_FORK, offset, "dir", fs_ok)
#define XFS_SCRUB_DIR_GOTO(fs_ok, label) \
	XFS_SCRUB_DATA_GOTO(sdc->sc, XFS_DATA_FORK, offset, "dir", fs_ok, label)
#define XFS_SCRUB_DIR_OP_ERROR_GOTO(label) \
	XFS_SCRUB_FILE_OP_ERROR_GOTO(sdc->sc, XFS_DATA_FORK, offset, "dir", &error, label)
/* Check that an inode's mode matches a given DT_ type. */
STATIC int
xfs_scrub_dir_check_ftype(
	struct xfs_scrub_dir_ctx	*sdc,
	xfs_fileoff_t			offset,
	xfs_ino_t			inum,
	int				dtype)
{
	struct xfs_mount		*mp = sdc->sc->ip->i_mount;
	struct xfs_inode		*ip;
	int				ino_dtype;
	int				error = 0;

	if (!xfs_sb_version_hasftype(&mp->m_sb)) {
		XFS_SCRUB_DIR_CHECK(dtype == DT_UNKNOWN || dtype == DT_DIR);
		goto out;
	}

	error = xfs_iget(mp, sdc->sc->tp, inum, 0, 0, &ip);
	XFS_SCRUB_OP_ERROR_GOTO(sdc->sc,
			XFS_INO_TO_AGNO(mp, inum),
			XFS_INO_TO_AGBNO(mp, inum),
			"inode", &error, out);
	ino_dtype = (VFS_I(ip)->i_mode & S_IFMT) >> S_SHIFT;
	XFS_SCRUB_DIR_CHECK(ino_dtype == dtype);
	IRELE(ip);
out:
	return error;
}

/* Scrub a single directory entry. */
STATIC int
xfs_scrub_dir_actor(
	struct dir_context		*dc,
	const char			*name,
	int				namelen,
	loff_t				pos,
	u64				ino,
	unsigned			type)
{
	struct xfs_mount		*mp;
	struct xfs_inode		*ip;
	struct xfs_scrub_dir_ctx	*sdc;
	struct xfs_name			xname;
	xfs_ino_t			lookup_ino;
	xfs_dablk_t			offset;
	int				error = 0;

	sdc = container_of(dc, struct xfs_scrub_dir_ctx, dc);
	ip = sdc->sc->ip;
	mp = ip->i_mount;
	offset = xfs_dir2_db_to_da(mp->m_dir_geo,
			xfs_dir2_dataptr_to_db(mp->m_dir_geo, pos));

	/* Does this inode number make sense? */
	XFS_SCRUB_DIR_GOTO(xfs_dir_ino_validate(mp, ino) == 0, out);
	XFS_SCRUB_DIR_GOTO(!xfs_internal_inum(mp, ino), out);

	/* Verify that we can look up this name by hash. */
	xname.name = name;
	xname.len = namelen;
	xname.type = XFS_DIR3_FT_UNKNOWN;

	error = xfs_dir_lookup(sdc->sc->tp, ip, &xname, &lookup_ino, NULL);
	XFS_SCRUB_DIR_OP_ERROR_GOTO(fail_xref);
	XFS_SCRUB_DIR_GOTO(lookup_ino == ino, out);

	if (!memcmp(".", name, namelen)) {
		/* If this is "." then check that the inum matches the dir. */
		if (xfs_sb_version_hasftype(&mp->m_sb))
			XFS_SCRUB_DIR_CHECK(type == DT_DIR);
		XFS_SCRUB_DIR_CHECK(ino == ip->i_ino);
	} else if (!memcmp("..", name, namelen)) {
		/*
		 * If this is ".." in the root inode, check that the inum
		 * matches this dir.
		 */
		if (xfs_sb_version_hasftype(&mp->m_sb))
			XFS_SCRUB_DIR_CHECK(type == DT_DIR);
		if (ip->i_ino == mp->m_sb.sb_rootino)
			XFS_SCRUB_DIR_CHECK(ino == ip->i_ino);
	}
	if (error)
		goto out;

	/* Verify the file type. */
	error = xfs_scrub_dir_check_ftype(sdc, offset, lookup_ino, type);
	if (error)
		goto out;
out:
	return error;
fail_xref:
	return error ? error : -EFSCORRUPTED;
}
#undef XFS_SCRUB_DIR_OP_ERROR_GOTO
#undef XFS_SCRUB_DIR_GOTO
#undef XFS_SCRUB_DIR_CHECK

#define XFS_SCRUB_DIRENT_CHECK(fs_ok) \
	XFS_SCRUB_DATA_CHECK(ds->sc, XFS_DATA_FORK, rec_bno, "dir", fs_ok)
#define XFS_SCRUB_DIRENT_GOTO(fs_ok, label) \
	XFS_SCRUB_DATA_GOTO(ds->sc, XFS_DATA_FORK, rec_bno, "dir", fs_ok, label)
#define XFS_SCRUB_DIRENT_OP_ERROR_GOTO(label) \
	XFS_SCRUB_FILE_OP_ERROR_GOTO(ds->sc, XFS_DATA_FORK, rec_bno, "dir", &error, label)
/* Scrub a directory btree record. */
STATIC int
xfs_scrub_dir_rec(
	struct xfs_scrub_da_btree	*ds,
	int				level,
	void				*rec)
{
	struct xfs_mount		*mp = ds->state->mp;
	struct xfs_dir2_leaf_entry	*ent = rec;
	struct xfs_inode		*dp = ds->dargs.dp;
	struct xfs_dir2_data_entry	*dent;
	struct xfs_buf			*bp;
	xfs_ino_t			ino;
	xfs_dablk_t			rec_bno;
	xfs_dir2_db_t			db;
	xfs_dir2_data_aoff_t		off;
	xfs_dir2_dataptr_t		ptr;
	xfs_dahash_t			calc_hash;
	xfs_dahash_t			hash;
	unsigned int			tag;
	int				error;

	/* Check the hash of the entry. */
	error = xfs_scrub_da_btree_hash(ds, level, &ent->hashval);
	if (error)
		goto out;

	/* Valid hash pointer? */
	ptr = be32_to_cpu(ent->address);
	if (ptr == 0)
		return 0;

	/* Find the directory entry's location. */
	db = xfs_dir2_dataptr_to_db(mp->m_dir_geo, ptr);
	off = xfs_dir2_dataptr_to_off(mp->m_dir_geo, ptr);
	rec_bno = xfs_dir2_db_to_da(mp->m_dir_geo, db);

	XFS_SCRUB_DA_GOTO(ds, rec_bno < mp->m_dir_geo->leafblk, out);
	error = xfs_dir3_data_read(ds->dargs.trans, dp, rec_bno, -2, &bp);
	XFS_SCRUB_DIRENT_OP_ERROR_GOTO(out);
	XFS_SCRUB_DIRENT_GOTO(bp != NULL, out);

	/* Retrieve the entry and check it. */
	dent = (struct xfs_dir2_data_entry *)(((char *)bp->b_addr) + off);
	ino = be64_to_cpu(dent->inumber);
	hash = be32_to_cpu(ent->hashval);
	tag = be16_to_cpup(dp->d_ops->data_entry_tag_p(dent));
	XFS_SCRUB_DIRENT_CHECK(xfs_dir_ino_validate(mp, ino) == 0);
	XFS_SCRUB_DIRENT_CHECK(!xfs_internal_inum(mp, ino));
	XFS_SCRUB_DIRENT_CHECK(tag == off);
	XFS_SCRUB_DIRENT_GOTO(dent->namelen < MAXNAMELEN, out_relse);
	calc_hash = xfs_da_hashname(dent->name, dent->namelen);
	XFS_SCRUB_DIRENT_CHECK(calc_hash == hash);

out_relse:
	xfs_trans_brelse(ds->dargs.trans, bp);
out:
	return error;
}
#undef XFS_SCRUB_DIRENT_OP_ERROR_GOTO
#undef XFS_SCRUB_DIRENT_GOTO
#undef XFS_SCRUB_DIRENT_CHECK

/* Scrub a whole directory. */
int
xfs_scrub_directory(
	struct xfs_scrub_context	*sc)
{
	struct xfs_scrub_dir_ctx	sdc = {
		.dc.actor = xfs_scrub_dir_actor,
		.dc.pos = 0,
	};
	struct xfs_mount		*mp = sc->tp->t_mountp;
	size_t				bufsize;
	loff_t				oldpos;
	int				error;

	if (!S_ISDIR(VFS_I(sc->ip)->i_mode))
		return -ENOENT;

	/* Check directory tree structure */
	error = xfs_scrub_da_btree(sc, XFS_DATA_FORK, xfs_scrub_dir_rec);
	if (error)
		return error;

	/* Check that every dirent we see can also be looked up by hash. */
	bufsize = (size_t)min_t(loff_t, 32768, sc->ip->i_d.di_size);
	sdc.sc = sc;

	oldpos = 0;
	xfs_iunlock(sc->ip, XFS_ILOCK_EXCL);
	while (true) {
		error = xfs_readdir_trans(sc->tp, sc->ip, &sdc.dc, bufsize);
		XFS_SCRUB_OP_ERROR_GOTO(sc,
				XFS_INO_TO_AGNO(mp, sc->ip->i_ino),
				XFS_INO_TO_AGBNO(mp, sc->ip->i_ino),
				"inode", &error, out_unlock);
		if (oldpos == sdc.dc.pos)
			break;
		oldpos = sdc.dc.pos;
	}

out_unlock:
	xfs_ilock(sc->ip, XFS_ILOCK_EXCL);
	return error;
}
