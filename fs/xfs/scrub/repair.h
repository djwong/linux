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
#ifndef __XFS_SCRUB_REPAIR_H__
#define __XFS_SCRUB_REPAIR_H__

#ifdef CONFIG_XFS_ONLINE_REPAIR

int xfs_repair_probe(struct xfs_scrub_context *sc);

/* Repair helpers */

struct xfs_repair_find_ag_btree {
	uint64_t			rmap_owner;
	const struct xfs_buf_ops	*buf_ops;
	uint32_t			magic;
	xfs_agblock_t			root;
	unsigned int			level;
};

struct xfs_repair_extent {
	struct list_head		list;
	xfs_fsblock_t			fsbno;
	xfs_extlen_t			len;
};

struct xfs_repair_extent_list {
	struct list_head		list;
};

static inline void
xfs_repair_init_extent_list(
	struct xfs_repair_extent_list	*exlist)
{
	INIT_LIST_HEAD(&exlist->list);
}

#define for_each_xfs_repair_extent_safe(rbe, n, exlist) \
	list_for_each_entry_safe((rbe), (n), &(exlist)->list, list)

int xfs_repair_roll_ag_trans(struct xfs_scrub_context *sc);
bool xfs_repair_ag_has_space(struct xfs_perag *pag, xfs_extlen_t nr_blocks,
		enum xfs_ag_resv_type type);
int xfs_repair_alloc_ag_block(struct xfs_scrub_context *sc,
		struct xfs_owner_info *oinfo, xfs_fsblock_t *fsbno,
		enum xfs_ag_resv_type resv);
int xfs_repair_init_btblock(struct xfs_scrub_context *sc, xfs_fsblock_t fsb,
		struct xfs_buf **bpp, xfs_btnum_t btnum,
		const struct xfs_buf_ops *ops);
int xfs_repair_fix_freelist(struct xfs_scrub_context *sc, bool can_shrink);
int xfs_repair_put_freelist(struct xfs_scrub_context *sc, xfs_agblock_t agbno);
int xfs_repair_collect_btree_extent(struct xfs_scrub_context *sc,
		struct xfs_repair_extent_list *btlist, xfs_fsblock_t fsbno,
		xfs_extlen_t len);
int xfs_repair_invalidate_blocks(struct xfs_scrub_context *sc,
		struct xfs_repair_extent_list *btlist);
int xfs_repair_reap_btree_extents(struct xfs_scrub_context *sc,
		struct xfs_repair_extent_list *btlist,
		struct xfs_owner_info *oinfo, enum xfs_ag_resv_type type);
void xfs_repair_cancel_btree_extents(struct xfs_scrub_context *sc,
		struct xfs_repair_extent_list *btlist);
int xfs_repair_subtract_extents(struct xfs_scrub_context *sc,
		struct xfs_repair_extent_list *exlist,
		struct xfs_repair_extent_list *sublist);
int xfs_repair_find_ag_btree_roots(struct xfs_scrub_context *sc,
		struct xfs_buf *agf_bp,
		struct xfs_repair_find_ag_btree *btree_info,
		struct xfs_buf *agfl_bp);
int xfs_repair_reset_counters(struct xfs_mount *mp);
xfs_extlen_t xfs_repair_calc_ag_resblks(struct xfs_scrub_context *sc);
int xfs_repair_setup_btree_extent_collection(struct xfs_scrub_context *sc);
int xfs_repair_fs_freeze(struct xfs_scrub_context *sc);
int xfs_repair_fs_thaw(struct xfs_scrub_context *sc);
int xfs_repair_grab_all_ag_headers(struct xfs_scrub_context *sc);
int xfs_repair_rmapbt_setup(struct xfs_scrub_context *sc, struct xfs_inode *ip);

/* Metadata repairers */
int xfs_repair_superblock(struct xfs_scrub_context *sc);
int xfs_repair_agf(struct xfs_scrub_context *sc);
int xfs_repair_agfl(struct xfs_scrub_context *sc);
int xfs_repair_agi(struct xfs_scrub_context *sc);
int xfs_repair_allocbt(struct xfs_scrub_context *sc);
int xfs_repair_iallocbt(struct xfs_scrub_context *sc);
int xfs_repair_rmapbt(struct xfs_scrub_context *sc);

#else

#define xfs_repair_probe		(NULL)

static inline int xfs_repair_reset_counters(struct xfs_mount *mp)
{
	ASSERT(0);
	return -EIO;
}

static inline xfs_extlen_t
xfs_repair_calc_ag_resblks(
	struct xfs_scrub_context	*sc)
{
	ASSERT(!(sc->sm->sm_flags & XFS_SCRUB_IFLAG_REPAIR));
	return 0;
}

static inline int xfs_repair_fs_thaw(struct xfs_scrub_context *sc)
{
	ASSERT(0);
	return -EIO;
}

static inline int xfs_repair_rmapbt_setup(
	struct xfs_scrub_context	*sc,
	struct xfs_inode		*ip)
{
	/* We don't support rmap repair, but we can still do a scan. */
	return xfs_scrub_setup_ag_btree(sc, ip, false);
}

#define xfs_repair_superblock		(NULL)
#define xfs_repair_agf			(NULL)
#define xfs_repair_agfl			(NULL)
#define xfs_repair_agi			(NULL)
#define xfs_repair_allocbt		(NULL)
#define xfs_repair_iallocbt		(NULL)
#define xfs_repair_rmapbt		(NULL)

#endif /* CONFIG_XFS_ONLINE_REPAIR */

#endif	/* __XFS_SCRUB_REPAIR_H__ */
