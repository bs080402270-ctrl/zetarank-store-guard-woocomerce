<?php
/**
 * Uninstall handler.
 *
 * @package ZetaRank_StoreGuard
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

delete_option( 'zrsg_settings' );

global $wpdb;
$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_zrsg_%' OR option_name LIKE '_transient_timeout_zrsg_%'" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching

if ( is_multisite() ) {
	$site_ids = get_sites( array( 'fields' => 'ids' ) );
	foreach ( $site_ids as $site_id ) {
		switch_to_blog( $site_id );
		delete_option( 'zrsg_settings' );
		$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_zrsg_%' OR option_name LIKE '_transient_timeout_zrsg_%'" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		restore_current_blog();
	}
}
