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
#include "xfs_inode_fork.h"
#include "xfs_symlink.h"
#include "repair/common.h"

/* Symbolic links. */

#define XFS_SCRUB_SYMLINK_CHECK(fs_ok) \
	XFS_SCRUB_INO_CHECK(sc, ip->i_ino, NULL, "symlink", fs_ok)
#define XFS_SCRUB_SYMLINK_GOTO(fs_ok, label) \
	XFS_SCRUB_INO_GOTO(sc, ip->i_ino, NULL, "symlink", fs_ok, label)
int
xfs_scrub_symlink(
	struct xfs_scrub_context	*sc)
{
	struct xfs_inode		*ip = sc->ip;
	struct xfs_ifork		*ifp;
	loff_t				len;
	int				error = 0;

	if (!S_ISLNK(VFS_I(ip)->i_mode))
		return -ENOENT;
	ifp = XFS_IFORK_PTR(ip, XFS_DATA_FORK);
	len = i_size_read(VFS_I(ip));

	/* Plausible size? */
	XFS_SCRUB_SYMLINK_GOTO(len <= MAXPATHLEN, out);

	/* Inline symlink? */
	if (ifp->if_flags & XFS_IFINLINE) {
		XFS_SCRUB_SYMLINK_GOTO((ifp->if_u1.if_data && len > 0) ||
				(ifp->if_u1.if_data == NULL && len == 0), out);
		if (len == 0)
			goto out;
		XFS_SCRUB_SYMLINK_CHECK(len <= XFS_IFORK_DSIZE(ip));
		XFS_SCRUB_SYMLINK_CHECK(len <= strnlen(ifp->if_u1.if_data,
				XFS_IFORK_DSIZE(ip)));
		goto out;
	}

	/* Remote symlink; must read. */
	xfs_iunlock(sc->ip, XFS_ILOCK_EXCL);
	error = xfs_readlink(sc->ip, sc->buf);
	xfs_ilock(sc->ip, XFS_ILOCK_EXCL);
	XFS_SCRUB_FILE_OP_ERROR_GOTO(sc, XFS_DATA_FORK, 0, "symlink",
			&error, out);
	XFS_SCRUB_SYMLINK_CHECK(len <= strnlen(sc->buf, MAXPATHLEN));
out:
	return error;
}
#undef XFS_SCRUB_SYMLINK_GOTO
#undef XFS_SCRUB_SYMLINK_CHECK
