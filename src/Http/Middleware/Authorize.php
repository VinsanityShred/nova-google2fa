<?php

namespace VinsanityShred\Google2fa\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use VinsanityShred\Google2fa\Google2fa;

class Authorize
{
    /**
     * Handle the incoming request.
     */
    public function handle(Request $request, Closure $next): mixed
    {
        return resolve(Google2fa::class)->authorize($request) ? $next($request) : abort(403);
    }
}
