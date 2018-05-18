/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Classifier and RSS definitions for the Marvell PPv2 driver
 *
 */

#ifndef _MVPP2_CLS_H_
#define _MVPP2_CLS_H_

/* Classifier constants */
#define MVPP2_CLS_FLOWS_TBL_SIZE	512
#define MVPP2_CLS_FLOWS_TBL_DATA_WORDS	3
#define MVPP2_CLS_LKP_TBL_SIZE		64
#define MVPP2_CLS_RX_QUEUES		256

/* RSS constants */
#define MVPP22_RSS_TABLE_ENTRIES	32

struct mvpp2_cls_flow_entry {
	u32 index;
	u32 data[MVPP2_CLS_FLOWS_TBL_DATA_WORDS];
};

struct mvpp2_cls_lookup_entry {
	u32 lkpid;
	u32 way;
	u32 data;
};

/* Definitions
 */

void mvpp22_init_rss(struct mvpp2_port *port);

void mvpp2_cls_init(struct mvpp2 *priv);

void mvpp2_cls_port_config(struct mvpp2_port *port);

void mvpp2_cls_oversize_rxq_set(struct mvpp2_port *port);

#endif
