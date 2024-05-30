<?php

namespace VinsanityShred\Google2fa\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use PragmaRX\Google2FA\Exceptions\IncompatibleWithGoogleAuthenticatorException;
use PragmaRX\Google2FA\Exceptions\InvalidCharactersException;
use PragmaRX\Google2FA\Exceptions\SecretKeyTooShortException;
use PragmaRX\Google2FA\Google2FA as G2fa;
use PragmaRX\Recovery\Recovery;
use VinsanityShred\Google2fa\Google2FAAuthenticator;

/**
 * @package VinsanityShred\Google2fa\Http\Middleware
 */
class Google2fa
{
    /**
     * Handle an incoming request.
     *
     * @throws IncompatibleWithGoogleAuthenticatorException
     * @throws InvalidCharactersException
     * @throws SecretKeyTooShortException
     */
    public function handle(Request $request, Closure $next): mixed
    {
        if (!config('vinsanityshred2fa.enabled')) {
            return $next($request);
        }
        if ($request->path() === 'los/2fa/confirm' || $request->path() === 'los/2fa/authenticate'
            || $request->path() === 'los/2fa/register') {
            return $next($request);
        }
        $authenticator = app(Google2FAAuthenticator::class)->boot($request);
        if (auth('nova')->guest() || $authenticator->isAuthenticated()) {
            return $next($request);
        }
        if (empty(auth('nova')->user()->user2fa) || auth('nova')->user()->user2fa->google2fa_enable === 0) {
            $google2fa        = new G2fa();
            $recovery         = new Recovery();
            $secretKey        = $google2fa->generateSecretKey();
            $data['recovery'] = $recovery
                ->setCount(config('vinsanityshred2fa.recovery_codes.count'))
                ->setBlocks(config('vinsanityshred2fa.recovery_codes.blocks'))
                ->setChars(config('vinsanityshred2fa.recovery_codes.chars_in_block'))
                ->toArray();

            $user2faModel = config('vinsanityshred2fa.models.user2fa');
            $user2faModel::where('user_id', auth('nova')->user()->getKey())->delete();

            $user2fa                   = new $user2faModel();
            $user2fa->user_id          = auth('nova')->user()->getKey();
            $user2fa->google2fa_secret = $secretKey;
            $user2fa->recovery         = json_encode($data['recovery']);
            $user2fa->save();

            return response(view('google2fa::recovery', $data));
        }

        return response(view('google2fa::authenticate'));
    }
}
