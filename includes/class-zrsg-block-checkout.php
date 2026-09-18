<?php
/**
 * WooCommerce Checkout Block / Store API protection.
 *
 * @package ZetaRank_StoreGuard
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class ZRSG_Block_Checkout {
	const FIELD_ID = 'zetarank-storeguard/security-answer';

	public static function init() {
		add_action( 'woocommerce_init', array( __CLASS__, 'register_field' ) );
		add_action( 'woocommerce_blocks_validate_location_other_fields', array( __CLASS__, 'validate_field' ), 10, 3 );
		add_action( 'woocommerce_store_api_checkout_order_processed', array( __CLASS__, 'cleanup_order_meta' ), 10, 1 );
	}

	private static function enabled() {
		return ZRSG_Settings::get( 'enable_checkout_block', 'yes' ) === 'yes';
	}

	public static function register_field() {
		if ( ! self::enabled() || ! function_exists( 'woocommerce_register_additional_checkout_field' ) ) {
			return;
		}

		$challenge = self::challenge();

		woocommerce_register_additional_checkout_field(
			array(
				'id'            => self::FIELD_ID,
				'label'         => sprintf(
					/* translators: 1: first number, 2: second number. */
					__( 'Security check: What is %1$d + %2$d?', 'zetarank-storeguard' ),
					$challenge['a'],
					$challenge['b']
				),
				'location'      => 'other',
				'type'          => 'text',
				'required'      => true,
				'attributes'    => array(
					'autocomplete' => 'off',
					'inputmode'    => 'numeric',
				),
				'sanitize_callback' => function ( $value ) {
					return sanitize_text_field( (string) $value );
				},
			)
		);
	}

	public static function validate_field( $errors, $fields, $group ) {
		if ( ! self::enabled() || 'other' !== $group ) {
			return;
		}

		$security = new ZRSG_Security();
		$ip       = $security->get_ip();
		$limit    = max( 1, (int) ZRSG_Settings::get( 'checkout_max_attempts', 8 ) );
		$minutes  = max( 1, (int) ZRSG_Settings::get( 'lockout_minutes', 15 ) );
		$key      = 'block_checkout_' . $ip;

		if ( $security->is_rate_limited( $key, $limit, $minutes ) ) {
			$errors->add(
				'zrsg_block_rate_limit',
				sprintf(
					/* translators: %d: number of minutes. */
					__( 'Too many checkout security attempts. Please try again in %d minutes.', 'zetarank-storeguard' ),
					$minutes
				)
			);
			return;
		}

		if ( ! self::passes_minimum_time() ) {
			$security->record_rate_attempt( $key, $minutes );
			$errors->add( 'zrsg_block_timing', __( 'Please wait a moment and try the checkout security check again.', 'zetarank-storeguard' ) );
			return;
		}

		$value = isset( $fields[ self::FIELD_ID ] ) ? sanitize_text_field( (string) $fields[ self::FIELD_ID ] ) : '';
		if ( ! self::verify_answer( $value ) ) {
			$security->record_rate_attempt( $key, $minutes );
			$errors->add( 'zrsg_block_answer', __( 'Incorrect checkout security answer. Please try again.', 'zetarank-storeguard' ) );
			return;
		}

		$security->clear_rate_attempts( $key );
		self::mark_passed();
	}

	private static function challenge() {
		$token = self::shopper_token();
		$slice = (int) floor( time() / HOUR_IN_SECONDS );
		$seed  = hash_hmac( 'sha256', $token . '|' . $slice, wp_salt( 'nonce' ) );
		$a     = ( hexdec( substr( $seed, 0, 2 ) ) % 9 ) + 1;
		$b     = ( hexdec( substr( $seed, 2, 2 ) ) % 9 ) + 1;

		self::ensure_start_time();

		return array(
			'a'     => $a,
			'b'     => $b,
			'answer'=> $a + $b,
			'slice' => $slice,
		);
	}

	private static function verify_answer( $value ) {
		if ( '' === trim( $value ) || ! preg_match( '/^-?\d+$/', trim( $value ) ) ) {
			return false;
		}

		$token = self::shopper_token();
		$given = (int) $value;
		$now   = (int) floor( time() / HOUR_IN_SECONDS );

		foreach ( array( $now, $now - 1 ) as $slice ) {
			$seed = hash_hmac( 'sha256', $token . '|' . $slice, wp_salt( 'nonce' ) );
			$a    = ( hexdec( substr( $seed, 0, 2 ) ) % 9 ) + 1;
			$b    = ( hexdec( substr( $seed, 2, 2 ) ) % 9 ) + 1;
			if ( $given === ( $a + $b ) ) {
				return true;
			}
		}
		return false;
	}

	private static function shopper_token() {
		if ( function_exists( 'WC' ) && WC()->session ) {
			$key = WC()->session->get( 'zrsg_block_token' );
			if ( ! $key ) {
				$key = wp_generate_password( 24, false, false );
				WC()->session->set( 'zrsg_block_token', $key );
			}
			return $key;
		}

		$security = new ZRSG_Security();
		return hash_hmac( 'sha256', $security->get_ip(), wp_salt( 'auth' ) );
	}

	private static function ensure_start_time() {
		if ( function_exists( 'WC' ) && WC()->session && ! WC()->session->get( 'zrsg_block_started' ) ) {
			WC()->session->set( 'zrsg_block_started', time() );
		}
	}

	private static function passes_minimum_time() {
		$minimum = max( 0, (int) ZRSG_Settings::get( 'min_form_seconds', 1 ) );
		if ( 0 === $minimum || ! function_exists( 'WC' ) || ! WC()->session ) {
			return true;
		}
		$started = (int) WC()->session->get( 'zrsg_block_started' );
		return ! $started || ( time() - $started ) >= $minimum;
	}

	private static function mark_passed() {
		if ( function_exists( 'WC' ) && WC()->session ) {
			WC()->session->set( 'zrsg_block_started', time() );
		}
	}

	public static function cleanup_order_meta( $order ) {
		if ( is_a( $order, 'WC_Order' ) ) {
			$order->delete_meta_data( '_wc_other/' . self::FIELD_ID );
			$order->delete_meta_data( self::FIELD_ID );
			$order->save();
		}
	}
}
