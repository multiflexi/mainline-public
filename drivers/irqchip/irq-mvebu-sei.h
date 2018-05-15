/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __MVEBU_SEI_H__
#define __MVEBU_SEI_H__

#include <linux/types.h>

struct device_node;

int mvebu_sei_get_doorbells(struct device_node *dn, phys_addr_t *set,
			    phys_addr_t *clr);

#endif /* __MVEBU_SEI_H__ */
