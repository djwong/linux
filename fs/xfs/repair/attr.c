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
#include "xfs_da_format.h"
#include "xfs_da_btree.h"
#include "xfs_dir2.h"
#include "xfs_attr.h"
#include "xfs_attr_leaf.h"
#include "repair/common.h"
#include "repair/dabtree.h"

#include <linux/posix_acl_xattr.h>
#include <linux/xattr.h>

/* Extended Attributes */

struct xfs_scrub_xattr {
	struct xfs_attr_list_context	context;
	struct xfs_scrub_context	*sc;
};

#define XFS_SCRUB_ATTR_CHECK(fs_ok) \
	XFS_SCRUB_DATA_CHECK(sx->sc, XFS_ATTR_FORK, args.blkno, "attr", fs_ok)
#define XFS_SCRUB_ATTR_OP_ERROR_GOTO(label) \
	XFS_SCRUB_FILE_OP_ERROR_GOTO(sx->sc, XFS_ATTR_FORK, args.blkno, "attr", &error, label)
/* Check that an extended attribute key can be looked up by hash. */
static void
xfs_scrub_xattr_listent(
	struct xfs_attr_list_context	*context,
	int				flags,
	unsigned char			*name,
	int				namelen,
	int				valuelen)
{
	struct xfs_scrub_xattr		*sx;
	struct xfs_da_args		args = {0};
	int				error = 0;

	sx = container_of(context, struct xfs_scrub_xattr, context);

	args.flags = ATTR_KERNOTIME;
	if (flags & XFS_ATTR_ROOT)
		args.flags |= ATTR_ROOT;
	else if (flags & XFS_ATTR_SECURE)
		args.flags |= ATTR_SECURE;
	args.geo = context->dp->i_mount->m_attr_geo;
	args.whichfork = XFS_ATTR_FORK;
	args.dp = context->dp;
	args.name = name;
	args.namelen = namelen;
	args.hashval = xfs_da_hashname(args.name, args.namelen);
	args.trans = context->tp;
	args.value = sx->sc->buf;
	args.valuelen = XATTR_SIZE_MAX;

	error = xfs_attr_get_locked(context->dp, &args);
	if (error == -EEXIST)
		error = 0;
	XFS_SCRUB_ATTR_OP_ERROR_GOTO(fail_xref);
	XFS_SCRUB_ATTR_CHECK(args.valuelen == valuelen);
fail_xref:
	return;
}
#undef XFS_SCRUB_ATTR_OP_ERROR_GOTO
#undef XFS_SCRUB_ATTR_CHECK

/* Scrub a attribute btree record. */
STATIC int
xfs_scrub_xattr_rec(
	struct xfs_scrub_da_btree	*ds,
	int				level,
	void				*rec)
{
	struct xfs_mount		*mp = ds->state->mp;
	struct xfs_attr_leaf_entry	*ent = rec;
	struct xfs_da_state_blk		*blk;
	struct xfs_attr_leaf_name_local	*lentry;
	struct xfs_attr_leaf_name_remote	*rentry;
	struct xfs_buf			*bp;
	xfs_dahash_t			calc_hash;
	xfs_dahash_t			hash;
	int				nameidx;
	int				hdrsize;
	unsigned int			badflags;
	int				error;

	blk = &ds->state->path.blk[level];

	/* Check the hash of the entry. */
	error = xfs_scrub_da_btree_hash(ds, level, &ent->hashval);
	if (error)
		goto out;

	/* Find the attr entry's location. */
	bp = blk->bp;
	hdrsize = xfs_attr3_leaf_hdr_size(bp->b_addr);
	nameidx = be16_to_cpu(ent->nameidx);
	XFS_SCRUB_DA_GOTO(ds, nameidx >= hdrsize, out);
	XFS_SCRUB_DA_GOTO(ds, nameidx < mp->m_attr_geo->blksize, out);

	/* Retrieve the entry and check it. */
	hash = be32_to_cpu(ent->hashval);
	badflags = ~(XFS_ATTR_LOCAL | XFS_ATTR_ROOT | XFS_ATTR_SECURE |
			XFS_ATTR_INCOMPLETE);
	XFS_SCRUB_DA_CHECK(ds, (ent->flags & badflags) == 0);
	if (ent->flags & XFS_ATTR_LOCAL) {
		lentry = (struct xfs_attr_leaf_name_local *)
				(((char *)bp->b_addr) + nameidx);
		XFS_SCRUB_DA_GOTO(ds, lentry->namelen < MAXNAMELEN, out);
		calc_hash = xfs_da_hashname(lentry->nameval, lentry->namelen);
	} else {
		rentry = (struct xfs_attr_leaf_name_remote *)
				(((char *)bp->b_addr) + nameidx);
		XFS_SCRUB_DA_GOTO(ds, rentry->namelen < MAXNAMELEN, out);
		calc_hash = xfs_da_hashname(rentry->name, rentry->namelen);
	}
	XFS_SCRUB_DA_CHECK(ds, calc_hash == hash);

out:
	return error;
}

/* Scrub the extended attribute metadata. */
int
xfs_scrub_xattr(
	struct xfs_scrub_context	*sc)
{
	struct xfs_scrub_xattr		sx = { 0 };
	struct attrlist_cursor_kern	cursor = { 0 };
	struct xfs_mount		*mp = sc->ip->i_mount;
	int				error = 0;

	if (!xfs_inode_hasattr(sc->ip))
		return -ENOENT;

	/* Check attribute tree structure */
	error = xfs_scrub_da_btree(sc, XFS_ATTR_FORK, xfs_scrub_xattr_rec);
	if (error)
		goto out;

	/* Check that every attr key can also be looked up by hash. */
	sx.context.dp = sc->ip;
	sx.context.cursor = &cursor;
	sx.context.resynch = 1;
	sx.context.put_listent = xfs_scrub_xattr_listent;
	sx.context.tp = sc->tp;
	sx.sc = sc;

	xfs_iunlock(sc->ip, XFS_ILOCK_EXCL);
	error = xfs_attr_list_int(&sx.context);
	xfs_ilock(sc->ip, XFS_ILOCK_EXCL);

	XFS_SCRUB_OP_ERROR_GOTO(sc,
			XFS_INO_TO_AGNO(mp, sc->ip->i_ino),
			XFS_INO_TO_AGBNO(mp, sc->ip->i_ino),
			"inode", &error, out);
out:
	return error;
}
