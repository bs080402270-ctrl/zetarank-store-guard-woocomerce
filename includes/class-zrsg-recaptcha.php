<?php
/**
 * Google reCAPTCHA v2 provider.
 *
 * @package ZetaRank_StoreGuard
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class ZRSG_Recaptcha {
	public static function render() {
		$site = trim( (string) ZRSG_Settings::get( 'recaptcha_site', '' ) );
		if ( '' === $site ) {
			echo '<p>' . esc_html__( 'reCAPTCHA site key is not configured.', 'zetarank-storeguard' ) . '</p>';
			return;
		}
		wp_enqueue_script( 'google-recaptcha', 'https://www.google.com/recaptcha/api.js', array(), null, true ); // phpcs:ignore WordPress.WP.EnqueuedResourceParameters.MissingVersion
		printf( '<div class="g-recaptcha" data-sitekey="%s"></div>', esc_attr( $site ) );
	}

	public static function verify() {
		$secret = trim( (string) ZRSG_Settings::get( 'recaptcha_secret', '' ) );
		$token  = isset( $_POST['g-recaptcha-response'] ) ? sanitize_text_field( wp_unslash( $_POST['g-recaptcha-response'] ) ) : '';
		if ( '' === $secret || '' === $token ) {
			return false;
		}

		$response = wp_remote_post(
			'https://www.google.com/recaptcha/api/siteverify',
			array(
				'timeout' => 10,
				'body'    => array(
					'secret'   => $secret,
					'response' => $token,
				),
			)
		);
		if ( is_wp_error( $response ) ) {
			return false;
		}
		$body = json_decode( wp_remote_retrieve_body( $response ), true );
		return ! empty( $body['success'] );
	}
}
