<?php
/**
 * Security helpers.
 *
 * @package ZetaRank_StoreGuard
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class ZRSG_Security {
	public function get_ip() {
		$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '0.0.0.0';
		return filter_var( $ip, FILTER_VALIDATE_IP ) ? $ip : '0.0.0.0';
	}

	private function transient_key( $prefix, $value ) {
		return 'zrsg_' . sanitize_key( $prefix ) . '_' . substr( hash( 'sha256', (string) $value ), 0, 32 );
	}

	public function is_rate_limited( $key, $limit, $minutes ) {
		$data = get_transient( $this->transient_key( 'rate', $key ) );
		if ( ! is_array( $data ) ) {
			return false;
		}
		return isset( $data['count'] ) && (int) $data['count'] >= max( 1, (int) $limit );
	}

	public function record_rate_attempt( $key, $minutes ) {
		$tkey = $this->transient_key( 'rate', $key );
		$data = get_transient( $tkey );
		if ( ! is_array( $data ) ) {
			$data = array( 'count' => 0 );
		}
		$data['count']++;
		set_transient( $tkey, $data, max( 1, (int) $minutes ) * MINUTE_IN_SECONDS );
	}

	public function clear_rate_attempts( $key ) {
		delete_transient( $this->transient_key( 'rate', $key ) );
	}

	public function is_login_locked( $username = '' ) {
		$ip_key   = $this->transient_key( 'login_ip', $this->get_ip() );
		$user_key = $this->transient_key( 'login_user', strtolower( trim( $username ) ) );
		$limit    = max( 1, (int) ZRSG_Settings::get( 'max_attempts', 5 ) );
		$ip       = get_transient( $ip_key );
		$user     = $username ? get_transient( $user_key ) : false;
		return (int) $ip >= $limit || (int) $user >= $limit;
	}

	public function record_login_failure( $username ) {
		$minutes = max( 1, (int) ZRSG_Settings::get( 'lockout_minutes', 15 ) );
		$ttl     = $minutes * MINUTE_IN_SECONDS;
		foreach ( array(
			$this->transient_key( 'login_ip', $this->get_ip() ),
			$this->transient_key( 'login_user', strtolower( trim( $username ) ) ),
		) as $key ) {
			$count = (int) get_transient( $key );
			set_transient( $key, $count + 1, $ttl );
		}
	}

	public function clear_login_failures( $username ) {
		delete_transient( $this->transient_key( 'login_ip', $this->get_ip() ) );
		delete_transient( $this->transient_key( 'login_user', strtolower( trim( $username ) ) ) );
	}

	public function render_bot_fields( $context ) {
		if ( ZRSG_Settings::get( 'enable_bot_blocking', 'yes' ) !== 'yes' ) {
			return;
		}
		$issued = time();
		$token  = hash_hmac( 'sha256', sanitize_key( $context ) . '|' . $issued, wp_salt( 'auth' ) );
		printf(
			'<div aria-hidden="true" style="position:absolute;left:-10000px;width:1px;height:1px;overflow:hidden"><label>%1$s<input type="text" name="zrsg_website" value="" tabindex="-1" autocomplete="off"></label></div><input type="hidden" name="zrsg_form_issued" value="%2$d"><input type="hidden" name="zrsg_form_token" value="%3$s">',
			esc_html__( 'Leave this field empty', 'zetarank-storeguard' ),
			(int) $issued,
			esc_attr( $token )
		);
	}

	public function bot_check_passes( $context ) {
		if ( ZRSG_Settings::get( 'enable_bot_blocking', 'yes' ) !== 'yes' ) {
			return true;
		}
		$honeypot = isset( $_POST['zrsg_website'] ) ? sanitize_text_field( wp_unslash( $_POST['zrsg_website'] ) ) : '';
		$issued   = isset( $_POST['zrsg_form_issued'] ) ? absint( $_POST['zrsg_form_issued'] ) : 0;
		$token    = isset( $_POST['zrsg_form_token'] ) ? sanitize_text_field( wp_unslash( $_POST['zrsg_form_token'] ) ) : '';
		if ( '' !== $honeypot || ! $issued || ! $token ) {
			return false;
		}
		$expected = hash_hmac( 'sha256', sanitize_key( $context ) . '|' . $issued, wp_salt( 'auth' ) );
		if ( ! hash_equals( $expected, $token ) ) {
			return false;
		}
		$minimum = max( 0, (int) ZRSG_Settings::get( 'min_form_seconds', 1 ) );
		return time() >= $issued && ( time() - $issued ) >= $minimum && ( time() - $issued ) <= HOUR_IN_SECONDS;
	}
}
