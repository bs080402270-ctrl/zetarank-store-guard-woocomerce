<?php
/**
 * Plugin Name:       ZetaRank StoreGuard for WooCommerce
 * Plugin URI:        https://zetarank.com
 * Description:       Protects WooCommerce login, registration, lost password, and checkout forms with CAPTCHA, brute-force protection, rate limiting, honeypots, and bot checks.
 * Version:           2.1.0
 * Requires at least: 6.0
 * Requires PHP:      7.4
 * Author:            programmer
 * Author URI:        https://www.fiverr.com/s/wbAXwBg
 * License:           GPL v2 or later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       zetarank-storeguard
 * Domain Path:       /languages
 * WC requires at least: 7.0
 * WC tested up to:      10.1
 *
 * @package ZetaRank_StoreGuard
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'ZRSG_VERSION', '2.1.0' );
define( 'ZRSG_FILE', __FILE__ );
define( 'ZRSG_PATH', plugin_dir_path( __FILE__ ) );
define( 'ZRSG_URL', plugin_dir_url( __FILE__ ) );

add_action(
	'init',
	function () {
		load_plugin_textdomain( 'zetarank-storeguard', false, dirname( plugin_basename( ZRSG_FILE ) ) . '/languages' );
	}
);

add_action(
	'plugins_loaded',
	function () {
		if ( ! class_exists( 'WooCommerce' ) ) {
			add_action(
				'admin_notices',
				function () {
					echo '<div class="notice notice-error"><p>' . esc_html__( 'ZetaRank StoreGuard for WooCommerce requires WooCommerce to be installed and active.', 'zetarank-storeguard' ) . '</p></div>';
				}
			);
			return;
		}

		require_once ZRSG_PATH . 'includes/class-zrsg-settings.php';
		require_once ZRSG_PATH . 'includes/class-zrsg-security.php';
		require_once ZRSG_PATH . 'includes/class-zrsg-math-captcha.php';
		require_once ZRSG_PATH . 'includes/class-zrsg-recaptcha.php';
		require_once ZRSG_PATH . 'includes/class-zrsg-core.php';
		require_once ZRSG_PATH . 'includes/class-zrsg-block-checkout.php';

		ZRSG_Core::instance();
		ZRSG_Block_Checkout::init();
	}
);

add_action(
	'before_woocommerce_init',
	function () {
		if ( class_exists( \Automattic\WooCommerce\Utilities\FeaturesUtil::class ) ) {
			\Automattic\WooCommerce\Utilities\FeaturesUtil::declare_compatibility( 'custom_order_tables', ZRSG_FILE, true );
			\Automattic\WooCommerce\Utilities\FeaturesUtil::declare_compatibility( 'cart_checkout_blocks', ZRSG_FILE, true );
		}
	}
);

register_activation_hook( __FILE__, 'zrsg_activate' );
function zrsg_activate() {
	$defaults = array(
		'provider'                  => 'math',
		'enable_register'           => 'yes',
		'enable_login'              => 'yes',
		'enable_lostpass'           => 'yes',
		'enable_checkout'           => 'yes',
		'enable_checkout_block'     => 'yes',
		'enable_cf7'                => 'no',
		'enable_bot_blocking'       => 'yes',
		'enable_bruteforce'         => 'yes',
		'recaptcha_site'            => '',
		'recaptcha_secret'          => '',
		'max_attempts'              => 5,
		'lockout_minutes'           => 15,
		'registration_max_attempts' => 5,
		'checkout_max_attempts'     => 8,
		'min_form_seconds'          => 1,
	);
	if ( ! get_option( 'zrsg_settings' ) ) {
		add_option( 'zrsg_settings', $defaults );
	}
	set_transient( 'zrsg_activation_notice', true, 60 );
}

add_action(
	'admin_notices',
	function () {
		if ( ! get_transient( 'zrsg_activation_notice' ) || ! current_user_can( 'manage_woocommerce' ) ) {
			return;
		}
		delete_transient( 'zrsg_activation_notice' );
		$link = '<a href="' . esc_url( admin_url( 'admin.php?page=zrsg-settings' ) ) . '">' . esc_html__( 'Configure StoreGuard', 'zetarank-storeguard' ) . '</a>';
		printf(
			'<div class="notice notice-success is-dismissible"><p>%s</p></div>',
			wp_kses_post( sprintf( /* translators: %s: settings page link. */ __( 'ZetaRank StoreGuard is active. %s', 'zetarank-storeguard' ), $link ) )
		);
	}
);

register_deactivation_hook( __FILE__, 'zrsg_deactivate' );
function zrsg_deactivate() {
	global $wpdb;
	$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_zrsg_%' OR option_name LIKE '_transient_timeout_zrsg_%'" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
}
