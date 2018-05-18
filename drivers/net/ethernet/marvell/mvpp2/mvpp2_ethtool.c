/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Ethtool ops for the Marvell PPv2 driver
 *
 */

#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/platform_device.h>

#include "mvpp2.h"
#include "mvpp2_prs.h"

/* Due to the fact that software statistics and hardware statistics are, by
 * design, incremented at different moments in the chain of packet processing,
 * it is very likely that incoming packets could have been dropped after being
 * counted by hardware but before reaching software statistics (most probably
 * multicast packets), and in the oppposite way, during transmission, FCS bytes
 * are added in between as well as TSO skb will be split and header bytes added.
 * Hence, statistics gathered from userspace with ifconfig (software) and
 * ethtool (hardware) cannot be compared.
 */
const struct mvpp2_ethtool_counter mvpp2_ethtool_regs[] = {
	{ MVPP2_MIB_GOOD_OCTETS_RCVD, "good_octets_received", true },
	{ MVPP2_MIB_BAD_OCTETS_RCVD, "bad_octets_received" },
	{ MVPP2_MIB_CRC_ERRORS_SENT, "crc_errors_sent" },
	{ MVPP2_MIB_UNICAST_FRAMES_RCVD, "unicast_frames_received" },
	{ MVPP2_MIB_BROADCAST_FRAMES_RCVD, "broadcast_frames_received" },
	{ MVPP2_MIB_MULTICAST_FRAMES_RCVD, "multicast_frames_received" },
	{ MVPP2_MIB_FRAMES_64_OCTETS, "frames_64_octets" },
	{ MVPP2_MIB_FRAMES_65_TO_127_OCTETS, "frames_65_to_127_octet" },
	{ MVPP2_MIB_FRAMES_128_TO_255_OCTETS, "frames_128_to_255_octet" },
	{ MVPP2_MIB_FRAMES_256_TO_511_OCTETS, "frames_256_to_511_octet" },
	{ MVPP2_MIB_FRAMES_512_TO_1023_OCTETS, "frames_512_to_1023_octet" },
	{ MVPP2_MIB_FRAMES_1024_TO_MAX_OCTETS, "frames_1024_to_max_octet" },
	{ MVPP2_MIB_GOOD_OCTETS_SENT, "good_octets_sent", true },
	{ MVPP2_MIB_UNICAST_FRAMES_SENT, "unicast_frames_sent" },
	{ MVPP2_MIB_MULTICAST_FRAMES_SENT, "multicast_frames_sent" },
	{ MVPP2_MIB_BROADCAST_FRAMES_SENT, "broadcast_frames_sent" },
	{ MVPP2_MIB_FC_SENT, "fc_sent" },
	{ MVPP2_MIB_FC_RCVD, "fc_received" },
	{ MVPP2_MIB_RX_FIFO_OVERRUN, "rx_fifo_overrun" },
	{ MVPP2_MIB_UNDERSIZE_RCVD, "undersize_received" },
	{ MVPP2_MIB_FRAGMENTS_RCVD, "fragments_received" },
	{ MVPP2_MIB_OVERSIZE_RCVD, "oversize_received" },
	{ MVPP2_MIB_JABBER_RCVD, "jabber_received" },
	{ MVPP2_MIB_MAC_RCV_ERROR, "mac_receive_error" },
	{ MVPP2_MIB_BAD_CRC_EVENT, "bad_crc_event" },
	{ MVPP2_MIB_COLLISION, "collision" },
	{ MVPP2_MIB_LATE_COLLISION, "late_collision" },
};

int mvpp2_ethtool_nb_stats(void)
{
	return ARRAY_SIZE(mvpp2_ethtool_regs);
}

static void mvpp2_ethtool_get_strings(struct net_device *netdev, u32 sset,
				      u8 *data)
{
	if (sset == ETH_SS_STATS) {
		int i;

		for (i = 0; i < ARRAY_SIZE(mvpp2_ethtool_regs); i++)
			memcpy(data + i * ETH_GSTRING_LEN,
			       &mvpp2_ethtool_regs[i].string, ETH_GSTRING_LEN);
	}
}

static u64 mvpp2_read_count(struct mvpp2_port *port,
		     const struct mvpp2_ethtool_counter *counter)
{
	u64 val;

	val = readl(port->stats_base + counter->offset);
	if (counter->reg_is_64b)
		val += (u64)readl(port->stats_base + counter->offset + 4) << 32;

	return val;
}

void mvpp2_gather_hw_statistics(struct work_struct *work)
{
	struct delayed_work *del_work = to_delayed_work(work);
	struct mvpp2_port *port = container_of(del_work, struct mvpp2_port,
					       stats_work);
	u64 *pstats;
	int i;

	mutex_lock(&port->gather_stats_lock);

	pstats = port->ethtool_stats;
	for (i = 0; i < ARRAY_SIZE(mvpp2_ethtool_regs); i++)
		*pstats++ += mvpp2_read_count(port, &mvpp2_ethtool_regs[i]);

	/* No need to read again the counters right after this function if it
	 * was called asynchronously by the user (ie. use of ethtool).
	 */
	cancel_delayed_work(&port->stats_work);
	queue_delayed_work(port->priv->stats_queue, &port->stats_work,
			   MVPP2_MIB_COUNTERS_STATS_DELAY);

	mutex_unlock(&port->gather_stats_lock);
}

void mvpp2_stats_clear_all(struct mvpp2_port *port)
{
	unsigned int i;

	/* Read the GOP statistics to reset the hardware counters */
	for (i = 0; i < ARRAY_SIZE(mvpp2_ethtool_regs); i++)
		mvpp2_read_count(port, &mvpp2_ethtool_regs[i]);
}

static int mvpp2_check_ringparam_valid(struct net_device *dev,
				       struct ethtool_ringparam *ring)
{
	u16 new_rx_pending = ring->rx_pending;
	u16 new_tx_pending = ring->tx_pending;

	if (ring->rx_pending == 0 || ring->tx_pending == 0)
		return -EINVAL;

	if (ring->rx_pending > MVPP2_MAX_RXD_MAX)
		new_rx_pending = MVPP2_MAX_RXD_MAX;
	else if (!IS_ALIGNED(ring->rx_pending, 16))
		new_rx_pending = ALIGN(ring->rx_pending, 16);

	if (ring->tx_pending > MVPP2_MAX_TXD_MAX)
		new_tx_pending = MVPP2_MAX_TXD_MAX;
	else if (!IS_ALIGNED(ring->tx_pending, 32))
		new_tx_pending = ALIGN(ring->tx_pending, 32);

	/* The Tx ring size cannot be smaller than the minimum number of
	 * descriptors needed for TSO.
	 */
	if (new_tx_pending < MVPP2_MAX_SKB_DESCS)
		new_tx_pending = ALIGN(MVPP2_MAX_SKB_DESCS, 32);

	if (ring->rx_pending != new_rx_pending) {
		netdev_info(dev, "illegal Rx ring size value %d, round to %d\n",
			    ring->rx_pending, new_rx_pending);
		ring->rx_pending = new_rx_pending;
	}

	if (ring->tx_pending != new_tx_pending) {
		netdev_info(dev, "illegal Tx ring size value %d, round to %d\n",
			    ring->tx_pending, new_tx_pending);
		ring->tx_pending = new_tx_pending;
	}

	return 0;
}

static void mvpp2_ethtool_get_stats(struct net_device *dev,
				    struct ethtool_stats *stats, u64 *data)
{
	struct mvpp2_port *port = netdev_priv(dev);

	/* Update statistics for the given port, then take the lock to avoid
	 * concurrent accesses on the ethtool_stats structure during its copy.
	 */
	mvpp2_gather_hw_statistics(&port->stats_work.work);

	mutex_lock(&port->gather_stats_lock);
	memcpy(data, port->ethtool_stats,
	       sizeof(u64) * ARRAY_SIZE(mvpp2_ethtool_regs));
	mutex_unlock(&port->gather_stats_lock);
}

static int mvpp2_ethtool_get_sset_count(struct net_device *dev, int sset)
{
	if (sset == ETH_SS_STATS)
		return ARRAY_SIZE(mvpp2_ethtool_regs);

	return -EOPNOTSUPP;
}

/* Ethtool methods */

static int mvpp2_ethtool_nway_reset(struct net_device *dev)
{
	struct mvpp2_port *port = netdev_priv(dev);

	if (!port->phylink)
		return -ENOTSUPP;

	return phylink_ethtool_nway_reset(port->phylink);
}

/* Set interrupt coalescing for ethtools */
static int mvpp2_ethtool_set_coalesce(struct net_device *dev,
				      struct ethtool_coalesce *c)
{
	struct mvpp2_port *port = netdev_priv(dev);
	int queue;

	for (queue = 0; queue < port->nrxqs; queue++) {
		struct mvpp2_rx_queue *rxq = port->rxqs[queue];

		rxq->time_coal = c->rx_coalesce_usecs;
		rxq->pkts_coal = c->rx_max_coalesced_frames;
		mvpp2_rx_pkts_coal_set(port, rxq);
		mvpp2_rx_time_coal_set(port, rxq);
	}

	if (port->has_tx_irqs) {
		port->tx_time_coal = c->tx_coalesce_usecs;
		mvpp2_tx_time_coal_set(port);
	}

	for (queue = 0; queue < port->ntxqs; queue++) {
		struct mvpp2_tx_queue *txq = port->txqs[queue];

		txq->done_pkts_coal = c->tx_max_coalesced_frames;

		if (port->has_tx_irqs)
			mvpp2_tx_pkts_coal_set(port, txq);
	}

	return 0;
}

/* get coalescing for ethtools */
static int mvpp2_ethtool_get_coalesce(struct net_device *dev,
				      struct ethtool_coalesce *c)
{
	struct mvpp2_port *port = netdev_priv(dev);

	c->rx_coalesce_usecs       = port->rxqs[0]->time_coal;
	c->rx_max_coalesced_frames = port->rxqs[0]->pkts_coal;
	c->tx_max_coalesced_frames = port->txqs[0]->done_pkts_coal;
	c->tx_coalesce_usecs       = port->tx_time_coal;
	return 0;
}

static void mvpp2_ethtool_get_drvinfo(struct net_device *dev,
				      struct ethtool_drvinfo *drvinfo)
{
	strlcpy(drvinfo->driver, MVPP2_DRIVER_NAME,
		sizeof(drvinfo->driver));
	strlcpy(drvinfo->version, MVPP2_DRIVER_VERSION,
		sizeof(drvinfo->version));
	strlcpy(drvinfo->bus_info, dev_name(&dev->dev),
		sizeof(drvinfo->bus_info));
}

static void mvpp2_ethtool_get_ringparam(struct net_device *dev,
					struct ethtool_ringparam *ring)
{
	struct mvpp2_port *port = netdev_priv(dev);

	ring->rx_max_pending = MVPP2_MAX_RXD_MAX;
	ring->tx_max_pending = MVPP2_MAX_TXD_MAX;
	ring->rx_pending = port->rx_ring_size;
	ring->tx_pending = port->tx_ring_size;
}

static int mvpp2_ethtool_set_ringparam(struct net_device *dev,
				       struct ethtool_ringparam *ring)
{
	struct mvpp2_port *port = netdev_priv(dev);
	u16 prev_rx_ring_size = port->rx_ring_size;
	u16 prev_tx_ring_size = port->tx_ring_size;
	int err;

	err = mvpp2_check_ringparam_valid(dev, ring);
	if (err)
		return err;

	if (!netif_running(dev)) {
		port->rx_ring_size = ring->rx_pending;
		port->tx_ring_size = ring->tx_pending;
		return 0;
	}

	/* The interface is running, so we have to force a
	 * reallocation of the queues
	 */
	mvpp2_stop_dev(port);
	mvpp2_cleanup_rxqs(port);
	mvpp2_cleanup_txqs(port);

	port->rx_ring_size = ring->rx_pending;
	port->tx_ring_size = ring->tx_pending;

	err = mvpp2_setup_rxqs(port);
	if (err) {
		/* Reallocate Rx queues with the original ring size */
		port->rx_ring_size = prev_rx_ring_size;
		ring->rx_pending = prev_rx_ring_size;
		err = mvpp2_setup_rxqs(port);
		if (err)
			goto err_out;
	}
	err = mvpp2_setup_txqs(port);
	if (err) {
		/* Reallocate Tx queues with the original ring size */
		port->tx_ring_size = prev_tx_ring_size;
		ring->tx_pending = prev_tx_ring_size;
		err = mvpp2_setup_txqs(port);
		if (err)
			goto err_clean_rxqs;
	}

	mvpp2_start_dev(port);
	mvpp2_egress_enable(port);
	mvpp2_ingress_enable(port);

	return 0;

err_clean_rxqs:
	mvpp2_cleanup_rxqs(port);
err_out:
	netdev_err(dev, "failed to change ring parameters");
	return err;
}

static void mvpp2_ethtool_get_pause_param(struct net_device *dev,
					  struct ethtool_pauseparam *pause)
{
	struct mvpp2_port *port = netdev_priv(dev);

	if (!port->phylink)
		return;

	phylink_ethtool_get_pauseparam(port->phylink, pause);
}

static int mvpp2_ethtool_set_pause_param(struct net_device *dev,
					 struct ethtool_pauseparam *pause)
{
	struct mvpp2_port *port = netdev_priv(dev);

	if (!port->phylink)
		return -ENOTSUPP;

	return phylink_ethtool_set_pauseparam(port->phylink, pause);
}

static int mvpp2_ethtool_get_link_ksettings(struct net_device *dev,
					    struct ethtool_link_ksettings *cmd)
{
	struct mvpp2_port *port = netdev_priv(dev);

	if (!port->phylink)
		return -ENOTSUPP;

	return phylink_ethtool_ksettings_get(port->phylink, cmd);
}

static int mvpp2_ethtool_set_link_ksettings(struct net_device *dev,
					    const struct ethtool_link_ksettings *cmd)
{
	struct mvpp2_port *port = netdev_priv(dev);

	if (!port->phylink)
		return -ENOTSUPP;

	return phylink_ethtool_ksettings_set(port->phylink, cmd);
}

const struct ethtool_ops mvpp2_eth_tool_ops = {
	.nway_reset		= mvpp2_ethtool_nway_reset,
	.get_link		= ethtool_op_get_link,
	.set_coalesce		= mvpp2_ethtool_set_coalesce,
	.get_coalesce		= mvpp2_ethtool_get_coalesce,
	.get_drvinfo		= mvpp2_ethtool_get_drvinfo,
	.get_ringparam		= mvpp2_ethtool_get_ringparam,
	.set_ringparam		= mvpp2_ethtool_set_ringparam,
	.get_strings		= mvpp2_ethtool_get_strings,
	.get_ethtool_stats	= mvpp2_ethtool_get_stats,
	.get_sset_count		= mvpp2_ethtool_get_sset_count,
	.get_pauseparam		= mvpp2_ethtool_get_pause_param,
	.set_pauseparam		= mvpp2_ethtool_set_pause_param,
	.get_link_ksettings	= mvpp2_ethtool_get_link_ksettings,
	.set_link_ksettings	= mvpp2_ethtool_set_link_ksettings,
};

