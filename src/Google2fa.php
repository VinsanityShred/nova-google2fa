<?php

namespace VinsanityShred\Google2fa;

use BaconQrCode\Renderer\Image\SvgImageBackEnd;
use BaconQrCode\Renderer\ImageRenderer;
use BaconQrCode\Renderer\RendererStyle\RendererStyle;
use BaconQrCode\Writer;
use Illuminate\Contracts\Routing\ResponseFactory;
use Illuminate\Contracts\View\Factory;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Request;
use Illuminate\View\View;
use Laravel\Nova\Tool;
use PragmaRX\Google2FA\Exceptions\IncompatibleWithGoogleAuthenticatorException;
use PragmaRX\Google2FA\Exceptions\InvalidCharactersException;
use PragmaRX\Google2FA\Exceptions\SecretKeyTooShortException;
use PragmaRX\Google2FA\Google2FA as G2fa;
use PragmaRX\Recovery\Recovery;

class Google2fa extends Tool
{
    public function confirm(): Factory|RedirectResponse|View
    {
        if (app(Google2FAAuthenticator::class)->isAuthenticated()) {
            auth('nova')->user()->user2fa->google2fa_enable = 1;
            auth('nova')->user()->user2fa->save();

            return response()->redirectTo(config('nova.path'));
        }

        $data['google2fa_url'] = $this->getQrCodeUrl();
        $data['error']         = 'Secret is invalid.';

        return view('google2fa::register', $data);
    }

    public function register(): Factory|View
    {
        new Writer(
            new ImageRenderer(
                new RendererStyle(400),
                new SvgImageBackEnd()
            )
        );

        $data['google2fa_url'] = $this->getQrCodeUrl();

        return view('google2fa::register', $data);
    }

    private function isRecoveryValid($recover, $recoveryHashes): bool
    {
        foreach ($recoveryHashes as $recoveryHash) {
            if (password_verify($recover, $recoveryHash)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @throws IncompatibleWithGoogleAuthenticatorException
     * @throws SecretKeyTooShortException
     * @throws InvalidCharactersException
     */
    public function authenticate(): ResponseFactory|Factory|RedirectResponse|Response|View
    {
        if ($recover = Request::get('recover')) {
            if ($this->isRecoveryValid($recover, json_decode(auth('nova')->user()->user2fa->recovery, true)) === false) {
                $data['error'] = 'Recovery key is invalid.';

                return view('google2fa::authenticate', $data);
            }

            $google2fa        = new G2fa();
            $recovery         = new Recovery();
            $secretKey        = $google2fa->generateSecretKey();
            $data['recovery'] = $recovery
                ->setCount(config('vinsanityshred2fa.recovery_codes.count'))
                ->setBlocks(config('vinsanityshred2fa.recovery_codes.blocks'))
                ->setChars(config('vinsanityshred2fa.recovery_codes.chars_in_block'))
                ->toArray();

            $recoveryHashes = $data['recovery'];
            array_walk($recoveryHashes, function (&$value) {
                $value = password_hash($value, config('vinsanityshred2fa.recovery_codes.hashing_algorithm'));
            });

            $user2faModel = config('vinsanityshred2fa.models.user2fa');

            $user2faModel::where('user_id', auth('nova')->user()->getKey())->delete();
            $user2fa                   = new $user2faModel();
            $user2fa->user_id          = auth('nova')->user()->getKey();
            $user2fa->google2fa_secret = $secretKey;
            $user2fa->recovery         = json_encode($recoveryHashes);
            $user2fa->save();

            return response(view('google2fa::recovery', $data));
        }

        if (app(Google2FAAuthenticator::class)->isAuthenticated()) {
            return response()->redirectTo(config('nova.path'));
        }

        $data['error'] = 'One time password is invalid.';

        return view('google2fa::authenticate', $data);
    }

    protected function getQrCodeUrl(): string
    {
        $writer = new Writer(
            new ImageRenderer(
                new RendererStyle(400),
                new SvgImageBackEnd()
            )
        );

        return 'data:image/svg+xml;base64, ' . base64_encode(
                $writer->writeString(
                    (new G2fa)->getQRCodeUrl(
                        config('app.name'),
                        auth('nova')->user()->email,
                        auth('nova')->user()->user2fa->google2fa_secret
                    )
                )
            );
    }

    public function menu(\Illuminate\Http\Request $request)
    {
        //
    }
}
