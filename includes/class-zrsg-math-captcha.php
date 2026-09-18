<?php
/**
 * Math CAPTCHA provider.
 *
 * @package ZetaRank_StoreGuard
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class ZRSG_Math_Captcha {
	const TOKEN_TTL = 1800;

	public static function render( $context = 'generic' ) {
		$a      = wp_rand( 1, 9 );
		$b      = wp_rand( 1, 9 );
		$issued = time();
		$answer = $a + $b;
		$token  = self::token( $context, $issued, $answer );

		printf(
			'<p class="form-row form-row-wide zrsg-captcha"><label>%1$s <span class="required">*</span></label><input type="number" name="zrsg_answer" required inputmode="numeric" autocomplete="off"><input type="hidden" name="zrsg_math_issued" value="%2$d"><input type="hidden" name="zrsg_math_token" value="%3$s"></p>',
			esc_html( sprintf( /* translators: 1: first number, 2: second number. */ __( 'Security check: What is %1$d + %2$d?', 'zetarank-storeguard' ), $a, $b ) ),
			(int) $issued,
			esc_attr( $token )
		);
	}

	public static function verify( $context = 'generic' ) {
		$answer = isset( $_POST['zrsg_answer'] ) ? sanitize_text_field( wp_unslash( $_POST['zrsg_answer'] ) ) : '';
		$issued = isset( $_POST['zrsg_math_issued'] ) ? absint( $_POST['zrsg_math_issued'] ) : 0;
		$token  = isset( $_POST['zrsg_math_token'] ) ? sanitize_text_field( wp_unslash( $_POST['zrsg_math_token'] ) ) : '';

		if ( '' === $answer || ! $issued || ! $token || ! preg_match( '/^-?\d+$/', $answer ) ) {
			return false;
		}
		if ( time() < $issued || ( time() - $issued ) > self::TOKEN_TTL ) {
			return false;
		}

		for ( $expected = 2; $expected <= 18; $expected++ ) {
			if ( hash_equals( self::token( $context, $issued, $expected ), $token ) ) {
				return (int) $answer === $expected;
			}
		}
		return false;
	}

	private static function token( $context, $issued, $answer ) {
		return hash_hmac(
			'sha256',
			sanitize_key( $context ) . '|' . (int) $issued . '|' . (int) $answer,
			wp_salt( 'nonce' )
		);
	}
}
